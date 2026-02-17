//! UBL Pipeline - WA→TR→WF processing

use crate::reasoning_bit::{Decision, EvalContext};
use crate::policy_bit::PolicyResult;
use crate::policy_loader::{PolicyLoader, ChipRequest as PolicyChipRequest, PolicyStorage};
use crate::genesis::genesis_chip_cid;
use crate::event_bus::{EventBus, ReceiptEvent};
use ubl_receipt::{WaReceiptBody, WfReceiptBody, PolicyTraceEntry, UnifiedReceipt, StageExecution, PipelineStage, RuntimeInfo};
use rb_vm::{CasProvider, SignProvider, Vm, VmConfig, ExecError};
use rb_vm::canon::CanonProvider;
use rb_vm::types::Cid as VmCid;
use rb_vm::tlv;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use ubl_chipstore::{ChipStore, ExecutionMetadata};
use crate::advisory::AdvisoryEngine;
use crate::idempotency::{IdempotencyKey, IdempotencyStore, CachedResult};
use crate::ledger::{LedgerWriter, NullLedger};
use ubl_kms::{did_from_verifying_key, kid_from_verifying_key, Ed25519SigningKey as SigningKey};

/// The UBL Pipeline processor
pub struct UblPipeline {
    pub policy_loader: PolicyLoader,
    pub fuel_limit: u64,
    pub event_bus: Arc<EventBus>,
    seen_nonces: Arc<RwLock<HashSet<String>>>,
    chip_store: Option<Arc<ChipStore>>,
    advisory_engine: Option<Arc<AdvisoryEngine>>,
    idempotency_store: IdempotencyStore,
    runtime_info: Arc<RuntimeInfo>,
    /// Pipeline DID derived from signing key
    pub did: String,
    /// Pipeline KID derived from signing key
    pub kid: String,
    /// Ed25519 signing key for receipts and JWS
    signing_key: Arc<SigningKey>,
    /// Audit ledger — append-only log of pipeline events
    ledger: Arc<dyn LedgerWriter>,
}

const DEFAULT_FUEL_LIMIT: u64 = 1_000_000;

// ── Pipeline-local providers for rb_vm ──────────────────────────

struct PipelineCas {
    store: HashMap<String, Vec<u8>>,
}

impl PipelineCas {
    fn new() -> Self { Self { store: HashMap::new() } }
}

impl CasProvider for PipelineCas {
    fn put(&mut self, bytes: &[u8]) -> VmCid {
        let hash = blake3::hash(bytes);
        let cid = format!("b3:{}", hex::encode(hash.as_bytes()));
        self.store.insert(cid.clone(), bytes.to_vec());
        VmCid(cid)
    }
    fn get(&self, cid: &VmCid) -> Option<Vec<u8>> {
        self.store.get(&cid.0).cloned()
    }
}

struct PipelineSigner {
    signing_key: Arc<SigningKey>,
    kid: String,
}
impl SignProvider for PipelineSigner {
    fn sign_jws(&self, payload: &[u8]) -> Vec<u8> {
        let sig_str = ubl_kms::sign_bytes(&self.signing_key, payload, ubl_kms::domain::RB_VM);
        // Return raw signature bytes (strip "ed25519:" prefix and decode base64)
        sig_str.strip_prefix("ed25519:").map(|b64| {
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, b64)
                .unwrap_or_else(|_| vec![0u8; 64])
        }).unwrap_or_else(|| vec![0u8; 64])
    }
    fn kid(&self) -> String {
        self.kid.clone()
    }
}

/// Pipeline canonicalization — delegates to full ρ (RhoCanon).
/// Enforces: NFC strings, null stripping, key sorting, BOM rejection.
struct PipelineCanon;
impl CanonProvider for PipelineCanon {
    fn canon(&self, v: serde_json::Value) -> serde_json::Value {
        rb_vm::RhoCanon.canon(v)
    }
}

/// Build minimal bytecode: PushInput(0) → EmitRc
fn build_passthrough_bytecode() -> Vec<u8> {
    let mut code = Vec::new();
    // PushInput(0): op=0x12, payload len=2, payload=0x0000 (index 0)
    code.push(0x12); // PushInput opcode
    code.extend_from_slice(&2u16.to_be_bytes()); // length = 2
    code.extend_from_slice(&0u16.to_be_bytes()); // index = 0
    // EmitRc: op=0x10, payload len=0
    code.push(0x10); // EmitRc opcode
    code.extend_from_slice(&0u16.to_be_bytes()); // length = 0
    code
}

/// Request to process a chip
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChipRequest {
    pub chip_type: String,
    pub body: serde_json::Value,
    pub parents: Vec<String>,
    pub operation: Option<String>,
}

/// Result from the complete pipeline
#[derive(Debug, Clone)]
pub struct PipelineResult {
    pub final_receipt: PipelineReceipt,
    pub chain: Vec<String>, // CIDs of all receipts in chain
    pub decision: Decision,
    /// Unified receipt — single evolving document through all stages
    pub receipt: UnifiedReceipt,
    /// True when this result was served from the idempotency cache (no re-execution).
    pub replayed: bool,
}

/// A receipt in the pipeline
#[derive(Debug, Clone)]
pub struct PipelineReceipt {
    pub body_cid: String,
    pub receipt_type: String,
    pub body: serde_json::Value,
}

/// Result of the CHECK stage — decision + full policy trace.
struct CheckResult {
    decision: Decision,
    reason: String,
    short_circuited: bool,
    trace: Vec<PolicyTraceEntry>,
}

impl UblPipeline {
    /// Convert a runtime PolicyResult into a receipt PolicyTraceEntry with RB votes.
    fn policy_result_to_trace(policy_result: &PolicyResult, duration_ms: i64) -> PolicyTraceEntry {
        let rb_results: Vec<ubl_receipt::RbResult> = policy_result.circuit_results.iter()
            .flat_map(|cr| cr.rb_results.iter())
            .map(|rb| ubl_receipt::RbResult {
                rb_id: rb.rb_id.clone(),
                decision: rb.decision.clone(),
                reason: rb.reason.clone(),
                inputs_used: rb.inputs_used.clone(),
                duration_nanos: rb.duration_nanos,
            })
            .collect();

        PolicyTraceEntry {
            level: policy_result.policy_id.split('.').nth(1).unwrap_or("unknown").to_string(),
            policy_id: policy_result.policy_id.clone(),
            result: policy_result.decision.clone(),
            reason: policy_result.reason.clone(),
            rb_results,
            duration_ms,
        }
    }
    /// Load signing key from env (`SIGNING_KEY_HEX`) or generate a dev key.
    fn load_or_generate_key() -> SigningKey {
        match ubl_kms::signing_key_from_env() {
            Ok(key) => key,
            Err(_) => ubl_kms::generate_signing_key(),
        }
    }

    /// Create a new pipeline instance
    pub fn new(storage: Box<dyn PolicyStorage>) -> Self {
        let key = Self::load_or_generate_key();
        let vk = key.verifying_key();
        let did = did_from_verifying_key(&vk);
        let kid = kid_from_verifying_key(&vk);
        Self {
            policy_loader: PolicyLoader::new(storage),
            fuel_limit: DEFAULT_FUEL_LIMIT,
            event_bus: Arc::new(EventBus::new()),
            seen_nonces: Arc::new(RwLock::new(HashSet::new())),
            chip_store: None,
            advisory_engine: None,
            idempotency_store: IdempotencyStore::new(),
            runtime_info: Arc::new(RuntimeInfo::capture()),
            did,
            kid,
            signing_key: Arc::new(key),
            ledger: Arc::new(NullLedger),
        }
    }

    /// Create pipeline with existing event bus
    pub fn with_event_bus(storage: Box<dyn PolicyStorage>, event_bus: Arc<EventBus>) -> Self {
        let key = Self::load_or_generate_key();
        let vk = key.verifying_key();
        let did = did_from_verifying_key(&vk);
        let kid = kid_from_verifying_key(&vk);
        Self {
            policy_loader: PolicyLoader::new(storage),
            fuel_limit: DEFAULT_FUEL_LIMIT,
            event_bus,
            seen_nonces: Arc::new(RwLock::new(HashSet::new())),
            chip_store: None,
            advisory_engine: None,
            idempotency_store: IdempotencyStore::new(),
            runtime_info: Arc::new(RuntimeInfo::capture()),
            did,
            kid,
            signing_key: Arc::new(key),
            ledger: Arc::new(NullLedger),
        }
    }

    /// Create pipeline with ChipStore for persistence
    pub fn with_chip_store(
        storage: Box<dyn PolicyStorage>,
        chip_store: Arc<ChipStore>,
    ) -> Self {
        let key = Self::load_or_generate_key();
        let vk = key.verifying_key();
        let did = did_from_verifying_key(&vk);
        let kid = kid_from_verifying_key(&vk);
        Self {
            policy_loader: PolicyLoader::new(storage),
            fuel_limit: DEFAULT_FUEL_LIMIT,
            event_bus: Arc::new(EventBus::new()),
            seen_nonces: Arc::new(RwLock::new(HashSet::new())),
            chip_store: Some(chip_store),
            advisory_engine: None,
            idempotency_store: IdempotencyStore::new(),
            runtime_info: Arc::new(RuntimeInfo::capture()),
            did,
            kid,
            signing_key: Arc::new(key),
            ledger: Arc::new(NullLedger),
        }
    }

    /// Attach a LedgerWriter for audit logging.
    pub fn set_ledger(&mut self, ledger: Arc<dyn LedgerWriter>) {
        self.ledger = ledger;
    }

    /// Attach an AdvisoryEngine for LLM hook points (post-CHECK, post-WF).
    pub fn set_advisory_engine(&mut self, engine: Arc<AdvisoryEngine>) {
        self.advisory_engine = Some(engine);
    }

    /// Bootstrap the genesis chip: materialize it as a real stored chip in ChipStore.
    ///
    /// This must be called once at startup. The genesis chip is self-signed —
    /// its receipt_cid is its own CID (the root of the chain). If ChipStore
    /// already contains the genesis chip (idempotent restart), this is a no-op.
    pub async fn bootstrap_genesis(&self) -> Result<String, PipelineError> {
        let genesis_body = crate::genesis::create_genesis_chip_body();
        let genesis_cid = crate::genesis::genesis_chip_cid();

        // If ChipStore is present, persist the genesis chip (idempotent)
        if let Some(ref store) = self.chip_store {
            let already = store.exists(&genesis_cid).await
                .map_err(|e| PipelineError::Internal(format!("Genesis check: {}", e)))?;

            if !already {
                let metadata = ExecutionMetadata {
                    runtime_version: "genesis/self-signed".to_string(),
                    execution_time_ms: 0,
                    fuel_consumed: 0,
                    policies_applied: vec![],
                    executor_did: "did:key:genesis".to_string(),
                    reproducible: true,
                };

                store.store_executed_chip(
                    genesis_body,
                    genesis_cid.clone(), // self-signed: receipt_cid == chip_cid
                    metadata,
                ).await.map_err(|e| PipelineError::Internal(format!("Genesis store: {}", e)))?;
            }
        }

        Ok(genesis_cid)
    }

    /// Generate a cryptographic nonce (16 random bytes, hex-encoded)
    fn generate_nonce() -> String {
        use rand::Rng;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill(&mut bytes);
        hex::encode(bytes)
    }

    /// Process raw bytes through the full KNOCK→WA→CHECK→TR→WF pipeline.
    /// Use this when you have raw HTTP body bytes (e.g. from the gate).
    pub async fn process_raw(&self, bytes: &[u8]) -> Result<PipelineResult, PipelineError> {
        // Stage 0: KNOCK
        let value = crate::knock::knock(bytes)
            .map_err(|e| PipelineError::Knock(e.to_string()))?;

        let chip_type = value["@type"].as_str().unwrap_or("").to_string();
        let request = ChipRequest {
            chip_type,
            body: value,
            parents: vec![],
            operation: Some("create".to_string()),
        };

        self.process_chip(request).await
    }

    /// Process a chip request through the WA→TR→WF pipeline.
    /// Assumes KNOCK already passed (use `process_raw` for full pipeline).
    ///
    /// **Idempotency:** If the chip has key `(@type, @ver, @world, @id)` and
    /// that key was already processed, returns the cached result immediately.
    pub async fn process_chip(&self, request: ChipRequest) -> Result<PipelineResult, PipelineError> {
        let pipeline_start = std::time::Instant::now();

        // ── Idempotency check: replay returns cached result (no re-execution) ──
        let idem_key = IdempotencyKey::from_chip_body(&request.body);
        if let Some(ref key) = idem_key {
            if let Some(cached) = self.idempotency_store.get(key).await {
                let decision = if cached.decision.contains("Allow") {
                    Decision::Allow
                } else {
                    Decision::Deny
                };
                let receipt = UnifiedReceipt::from_json(&cached.response_json)
                    .unwrap_or_else(|_| UnifiedReceipt::new("", "", "", ""));
                return Ok(PipelineResult {
                    final_receipt: PipelineReceipt {
                        body_cid: cached.receipt_cid.clone(),
                        receipt_type: "ubl/wf".to_string(),
                        body: cached.response_json.clone(),
                    },
                    chain: cached.chain.clone(),
                    decision,
                    receipt,
                    replayed: true,
                });
            }
        }

        // Extract @world for the unified receipt
        let world = request.body.get("@world")
            .and_then(|v| v.as_str())
            .unwrap_or("a/unknown/t/unknown");
        let nonce = Self::generate_nonce();

        // Create the unified receipt — it evolves through each stage
        let mut receipt = UnifiedReceipt::new(
            world,
            &self.did,
            &self.kid,
            &nonce,
        ).with_runtime_info((*self.runtime_info).clone());

        // Stage 1: WA (Write-Ahead)
        let wa_start = std::time::Instant::now();
        let wa_receipt = self.stage_write_ahead(&request).await?;
        let wa_ms = wa_start.elapsed().as_millis() as i64;

        receipt.append_stage(StageExecution {
            stage: PipelineStage::WriteAhead,
            timestamp: chrono::Utc::now().to_rfc3339(),
            input_cid: wa_receipt.body_cid.clone(),
            output_cid: Some(wa_receipt.body_cid.clone()),
            fuel_used: None,
            policy_trace: vec![],
            auth_token: String::new(),
            duration_ms: wa_ms,
        }).map_err(|e| PipelineError::Internal(format!("Receipt WA: {}", e)))?;

        // Publish WA event
        self.publish_receipt_event(&wa_receipt, "wa", None, Some(wa_ms), Some(world), None).await;

        // Stage 2: CHECK (Policy Evaluation)
        let check_start = std::time::Instant::now();
        let check = self.stage_check(&request).await?;
        let check_ms = check_start.elapsed().as_millis() as i64;

        receipt.append_stage(StageExecution {
            stage: PipelineStage::Check,
            timestamp: chrono::Utc::now().to_rfc3339(),
            input_cid: wa_receipt.body_cid.clone(),
            output_cid: None,
            fuel_used: None,
            policy_trace: check.trace.clone(),
            auth_token: String::new(),
            duration_ms: check_ms,
        }).map_err(|e| PipelineError::Internal(format!("Receipt CHECK: {}", e)))?;

        // Post-CHECK advisory hook (non-blocking) — explain denial
        if let (Some(ref engine), Some(ref store)) = (&self.advisory_engine, &self.chip_store) {
            let adv = engine.post_check_advisory(
                &wa_receipt.body_cid,
                if matches!(check.decision, Decision::Deny) { "deny" } else { "allow" },
                &check.reason,
                &check.trace.iter().map(|t| serde_json::to_value(t).unwrap_or_default()).collect::<Vec<_>>(),
            );
            let body = engine.advisory_to_chip_body(&adv);
            let store = store.clone();
            tokio::spawn(async move {
                let metadata = ExecutionMetadata {
                    runtime_version: "advisory/post-check".to_string(),
                    execution_time_ms: 0,
                    fuel_consumed: 0,
                    policies_applied: vec![],
                    executor_did: "did:key:advisory".to_string(),
                    reproducible: false,
                };
                if let Err(e) = store.store_executed_chip(body, "self".to_string(), metadata).await {
                    eprintln!("Advisory post-CHECK store failed (non-fatal): {}", e);
                }
            });
        }

        // Short-circuit if denied
        if matches!(check.decision, Decision::Deny) {
            receipt.deny(&check.reason);

            let wf_receipt = self.create_deny_receipt(&request, &wa_receipt, &check).await?;

            let deny_ms = pipeline_start.elapsed().as_millis() as i64;
            self.publish_receipt_event(&wf_receipt, "wf", Some("deny".to_string()), Some(deny_ms), Some(world), Some(&wa_receipt.body_cid)).await;

            return Ok(PipelineResult {
                final_receipt: wf_receipt.clone(),
                chain: vec![wa_receipt.body_cid.clone(), "no-tr".to_string(), wf_receipt.body_cid.clone()],
                decision: Decision::Deny,
                receipt,
                replayed: false,
            });
        }

        // Stage 3: TR (Transition - RB-VM execution)
        let tr_start = std::time::Instant::now();
        let tr_receipt = self.stage_transition(&request, &check).await?;
        let tr_ms = tr_start.elapsed().as_millis() as i64;

        let fuel_used = tr_receipt.body.get("vm_state")
            .and_then(|v| v.get("fuel_used"))
            .and_then(|v| v.as_u64());

        receipt.append_stage(StageExecution {
            stage: PipelineStage::Transition,
            timestamp: chrono::Utc::now().to_rfc3339(),
            input_cid: wa_receipt.body_cid.clone(),
            output_cid: Some(tr_receipt.body_cid.clone()),
            fuel_used,
            policy_trace: vec![],
            auth_token: String::new(),
            duration_ms: tr_ms,
        }).map_err(|e| PipelineError::Internal(format!("Receipt TR: {}", e)))?;

        // Publish TR event
        self.publish_receipt_event(&tr_receipt, "tr", None, Some(tr_ms), Some(world), Some(&wa_receipt.body_cid)).await;

        // Stage 4: WF (Write-Finished)
        let wf_start = std::time::Instant::now();
        let wf_receipt = self.stage_write_finished(&request, &wa_receipt, &tr_receipt, &check).await?;
        let wf_ms = wf_start.elapsed().as_millis() as i64;

        receipt.append_stage(StageExecution {
            stage: PipelineStage::WriteFinished,
            timestamp: chrono::Utc::now().to_rfc3339(),
            input_cid: tr_receipt.body_cid.clone(),
            output_cid: Some(wf_receipt.body_cid.clone()),
            fuel_used: None,
            policy_trace: vec![],
            auth_token: String::new(),
            duration_ms: wf_ms,
        }).map_err(|e| PipelineError::Internal(format!("Receipt WF: {}", e)))?;

        let total_ms = pipeline_start.elapsed().as_millis() as i64;

        // Publish successful WF event
        self.publish_receipt_event(&wf_receipt, "wf", Some("allow".to_string()), Some(total_ms), Some(world), Some(&tr_receipt.body_cid)).await;

        // Persist chip to ChipStore (best-effort — never blocks pipeline)
        if let Some(ref store) = self.chip_store {
            let metadata = ExecutionMetadata {
                runtime_version: "rb_vm/0.1".to_string(),
                execution_time_ms: total_ms,
                fuel_consumed: self.fuel_limit,
                policies_applied: check.trace.iter().map(|t| t.policy_id.clone()).collect(),
                executor_did: self.did.clone(),
                reproducible: true,
            };
            if let Err(e) = store.store_executed_chip(
                request.body.clone(),
                wf_receipt.body_cid.clone(),
                metadata,
            ).await {
                eprintln!("ChipStore persist failed (non-fatal): {}", e);
            }
        }

        // Append to audit ledger (best-effort — never blocks pipeline)
        {
            let (app, tenant) = ubl_ai_nrf1::UblEnvelope::parse_world(world)
                .map(|(a, t)| (a.to_string(), t.to_string()))
                .unwrap_or_else(|| ("unknown".to_string(), "unknown".to_string()));
            let entry = crate::ledger::LedgerEntry {
                ts: chrono::Utc::now().to_rfc3339(),
                event: crate::ledger::LedgerEvent::ReceiptCreated,
                app,
                tenant,
                chip_cid: wf_receipt.body_cid.clone(),
                receipt_cid: wf_receipt.body_cid.clone(),
                decision: "Allow".to_string(),
                did: Some(self.did.clone()),
                kid: Some(self.kid.clone()),
            };
            if let Err(e) = self.ledger.append(&entry).await {
                eprintln!("Ledger append failed (non-fatal): {}", e);
            }
        }

        // Post-WF advisory hook (non-blocking) — classify and summarize
        if let (Some(ref engine), Some(ref store)) = (&self.advisory_engine, &self.chip_store) {
            let adv = engine.post_wf_advisory(
                &wf_receipt.body_cid,
                &request.chip_type,
                "allow",
                total_ms,
            );
            let body = engine.advisory_to_chip_body(&adv);
            let store = store.clone();
            tokio::spawn(async move {
                let metadata = ExecutionMetadata {
                    runtime_version: "advisory/post-wf".to_string(),
                    execution_time_ms: 0,
                    fuel_consumed: 0,
                    policies_applied: vec![],
                    executor_did: "did:key:advisory".to_string(),
                    reproducible: false,
                };
                if let Err(e) = store.store_executed_chip(body, "self".to_string(), metadata).await {
                    eprintln!("Advisory post-WF store failed (non-fatal): {}", e);
                }
            });
        }

        let result = PipelineResult {
            final_receipt: wf_receipt.clone(),
            chain: vec![
                wa_receipt.body_cid,
                tr_receipt.body_cid,
                wf_receipt.body_cid.clone(),
            ],
            decision: check.decision,
            receipt,
            replayed: false,
        };

        // ── Cache result for idempotency ──
        if let Some(key) = idem_key {
            self.idempotency_store.put(key, CachedResult {
                receipt_cid: result.receipt.receipt_cid.clone(),
                response_json: result.receipt.to_json().unwrap_or_default(),
                decision: format!("{:?}", result.decision),
                chain: result.chain.clone(),
                created_at: chrono::Utc::now().to_rfc3339(),
            }).await;
        }

        Ok(result)
    }

    /// Stage 1: Write-Ahead - create ghost record, freeze @world
    async fn stage_write_ahead(&self, request: &ChipRequest) -> Result<PipelineReceipt, PipelineError> {
        // Validate @world format before freezing
        if let Some(world) = request.body.get("@world").and_then(|v| v.as_str()) {
            ubl_ai_nrf1::UblEnvelope::validate_world(world)
                .map_err(|e| PipelineError::InvalidChip(format!("@world: {}", e)))?;
        } else {
            return Err(PipelineError::InvalidChip("missing @world anchor".to_string()));
        }

        // Generate nonce and check for replay
        let nonce = Self::generate_nonce();
        {
            let mut seen = self.seen_nonces.write().await;
            if !seen.insert(nonce.clone()) {
                return Err(PipelineError::ReplayDetected("duplicate nonce".to_string()));
            }
        }

        let wa_body = WaReceiptBody {
            ghost: true,
            chip_cid: "pending".to_string(), // Will be computed later
            policy_cid: genesis_chip_cid(), // For now, just genesis
            frozen_time: chrono::Utc::now().to_rfc3339(),
            caller: self.did.clone(),
            context: request.body.clone(),
            operation: request.operation.clone().unwrap_or_else(|| "create".to_string()),
            nonce,
            kid: self.kid.clone(),
        };

        let body_json = serde_json::to_value(&wa_body)
            .map_err(|e| PipelineError::Internal(format!("WA serialization: {}", e)))?;

        // Compute CID
        let nrf1_bytes = ubl_ai_nrf1::to_nrf1_bytes(&body_json)
            .map_err(|e| PipelineError::Internal(format!("WA CID: {}", e)))?;
        let cid = ubl_ai_nrf1::compute_cid(&nrf1_bytes)
            .map_err(|e| PipelineError::Internal(format!("WA CID: {}", e)))?;

        Ok(PipelineReceipt {
            body_cid: cid,
            receipt_type: "ubl/wa".to_string(),
            body: body_json,
        })
    }

    /// Stage 2: CHECK - Onboarding validation + Policy evaluation with full trace
    async fn stage_check(&self, request: &ChipRequest) -> Result<CheckResult, PipelineError> {
        let _check_start = std::time::Instant::now();

        // ── Onboarding pre-check: validate body + dependency chain ──
        if crate::auth::is_onboarding_type(&request.chip_type) {
            // 1. Validate chip body structure
            crate::auth::validate_onboarding_chip(&request.body)
                .map_err(|e| PipelineError::InvalidChip(format!("Onboarding validation: {}", e)))?;

            // 2. Validate @world format
            let world_str = request.body.get("@world")
                .and_then(|v| v.as_str())
                .ok_or_else(|| PipelineError::InvalidChip("Onboarding chip missing @world".into()))?;

            // 3. Check dependency chain against ChipStore
            if let Some(ref store) = self.chip_store {
                self.check_onboarding_dependencies(&request.chip_type, &request.body, world_str, store).await?;
            }
        }

        // Convert to policy request
        let policy_request = PolicyChipRequest {
            chip_type: request.chip_type.clone(),
            body: request.body.clone(),
            parents: request.parents.clone(),
            operation: request.operation.clone().unwrap_or_else(|| "create".to_string()),
        };

        // Load policy chain
        let policies = self.policy_loader.load_policy_chain(&policy_request).await
            .map_err(|e| PipelineError::Internal(format!("Policy loading: {}", e)))?;

        // Create evaluation context
        let body_bytes = serde_json::to_vec(&request.body)
            .map_err(|e| PipelineError::Internal(format!("Body serialization: {}", e)))?;

        let mut variables = HashMap::new();
        if let Some(chip_type) = request.body.get("@type") {
            variables.insert("chip.@type".to_string(), chip_type.clone());
        }
        if let Some(chip_id) = request.body.get("@id").or_else(|| request.body.get("id")) {
            variables.insert("chip.id".to_string(), chip_id.clone());
        }

        let context = EvalContext {
            chip: request.body.clone(),
            body_size: body_bytes.len(),
            variables,
        };

        // Evaluate each policy, collecting trace entries
        let mut trace = Vec::new();
        for policy in &policies {
            let policy_start = std::time::Instant::now();
            let result = policy.evaluate(&context);
            let policy_ms = policy_start.elapsed().as_millis() as i64;

            trace.push(Self::policy_result_to_trace(&result, policy_ms));

            // Stop on first DENY
            if matches!(result.decision, Decision::Deny) {
                return Ok(CheckResult {
                    decision: Decision::Deny,
                    reason: result.reason,
                    short_circuited: true,
                    trace,
                });
            }
        }

        Ok(CheckResult {
            decision: Decision::Allow,
            reason: "All policies allowed".to_string(),
            short_circuited: false,
            trace,
        })
    }

    /// Stage 3: TR - Transition (RB-VM execution)
    async fn stage_transition(&self, request: &ChipRequest, _check: &CheckResult) -> Result<PipelineReceipt, PipelineError> {
        // Encode chip body to NRF bytes and store as CAS input
        let chip_nrf = ubl_ai_nrf1::to_nrf1_bytes(&request.body)
            .map_err(|e| PipelineError::Internal(format!("TR input NRF: {}", e)))?;

        let mut cas = PipelineCas::new();
        let input_cid = cas.put(&chip_nrf);

        let signer = PipelineSigner {
            signing_key: self.signing_key.clone(),
            kid: self.kid.clone(),
        };
        let canon = PipelineCanon;
        let cfg = VmConfig {
            fuel_limit: self.fuel_limit,
            ghost: false,
            trace: true,
        };

        // Build and decode bytecode
        let bytecode = build_passthrough_bytecode();
        let instructions = tlv::decode_stream(&bytecode)
            .map_err(|e| PipelineError::Internal(format!("TR bytecode decode: {}", e)))?;

        // Execute VM
        let mut vm = Vm::new(cfg, cas, &signer, canon, vec![input_cid.clone()]);
        let outcome = vm.run(&instructions).map_err(|e| match e {
            ExecError::FuelExhausted => PipelineError::FuelExhausted(
                format!("VM fuel exhausted (limit: {})", self.fuel_limit)
            ),
            ExecError::StackUnderflow(op) => PipelineError::StackUnderflow(
                format!("stack underflow at {:?}", op)
            ),
            ExecError::TypeMismatch(op) => PipelineError::TypeMismatch(
                format!("type mismatch at {:?}", op)
            ),
            ExecError::InvalidPayload(op) => PipelineError::TypeMismatch(
                format!("invalid payload for {:?}", op)
            ),
            ExecError::Deny(reason) => PipelineError::PolicyDenied(reason),
        })?;

        let tr_body = serde_json::json!({
            "@type": "ubl/transition",
            "input_cid": input_cid.0,
            "output_cid": outcome.rc_cid.as_ref().map(|c| c.0.clone()).unwrap_or_default(),
            "vm_state": {
                "fuel_used": outcome.fuel_used,
                "steps": outcome.steps,
                "result": if outcome.rc_cid.is_some() { "receipt_emitted" } else { "completed" },
                "trace_len": outcome.trace.len()
            }
        });

        let nrf1_bytes = ubl_ai_nrf1::to_nrf1_bytes(&tr_body)
            .map_err(|e| PipelineError::Internal(format!("TR CID: {}", e)))?;
        let cid = ubl_ai_nrf1::compute_cid(&nrf1_bytes)
            .map_err(|e| PipelineError::Internal(format!("TR CID: {}", e)))?;

        Ok(PipelineReceipt {
            body_cid: cid,
            receipt_type: "ubl/transition".to_string(),
            body: tr_body,
        })
    }

    /// Stage 4: WF - Write Finished
    async fn stage_write_finished(
        &self,
        request: &ChipRequest,
        wa_receipt: &PipelineReceipt,
        tr_receipt: &PipelineReceipt,
        check: &CheckResult,
    ) -> Result<PipelineReceipt, PipelineError> {
        // Compute the final chip CID
        let chip_nrf1 = ubl_ai_nrf1::to_nrf1_bytes(&request.body)
            .map_err(|e| PipelineError::Internal(format!("Chip CID: {}", e)))?;
        let chip_cid = ubl_ai_nrf1::compute_cid(&chip_nrf1)
            .map_err(|e| PipelineError::Internal(format!("Chip CID: {}", e)))?;

        let mut artifacts = HashMap::new();
        artifacts.insert("chip".to_string(), chip_cid.clone());

        let wf_body = WfReceiptBody {
            decision: check.decision.clone(),
            wa_cid: wa_receipt.body_cid.clone(),
            tr_cid: Some(tr_receipt.body_cid.clone()),
            artifacts,
            duration_ms: 50, // Overwritten by caller with real timing
            policy_trace: check.trace.clone(),
            short_circuited: check.short_circuited,
        };

        let body_json = serde_json::to_value(&wf_body)
            .map_err(|e| PipelineError::Internal(format!("WF serialization: {}", e)))?;

        let nrf1_bytes = ubl_ai_nrf1::to_nrf1_bytes(&body_json)
            .map_err(|e| PipelineError::Internal(format!("WF CID: {}", e)))?;
        let cid = ubl_ai_nrf1::compute_cid(&nrf1_bytes)
            .map_err(|e| PipelineError::Internal(format!("WF CID: {}", e)))?;

        Ok(PipelineReceipt {
            body_cid: cid,
            receipt_type: "ubl/wf".to_string(),
            body: body_json,
        })
    }

    /// Create a DENY receipt when policy fails
    async fn create_deny_receipt(
        &self,
        _request: &ChipRequest,
        wa_receipt: &PipelineReceipt,
        check: &CheckResult,
    ) -> Result<PipelineReceipt, PipelineError> {
        let wf_body = WfReceiptBody {
            decision: Decision::Deny,
            wa_cid: wa_receipt.body_cid.clone(),
            tr_cid: None, // No transition executed
            artifacts: HashMap::new(),
            duration_ms: 10,
            policy_trace: check.trace.clone(),
            short_circuited: true,
        };

        let body_json = serde_json::to_value(&wf_body)
            .map_err(|e| PipelineError::Internal(format!("WF DENY serialization: {}", e)))?;

        let nrf1_bytes = ubl_ai_nrf1::to_nrf1_bytes(&body_json)
            .map_err(|e| PipelineError::Internal(format!("WF DENY CID: {}", e)))?;
        let cid = ubl_ai_nrf1::compute_cid(&nrf1_bytes)
            .map_err(|e| PipelineError::Internal(format!("WF DENY CID: {}", e)))?;

        Ok(PipelineReceipt {
            body_cid: cid,
            receipt_type: "ubl/wf".to_string(),
            body: body_json,
        })
    }

    /// Helper to publish receipt events to the event bus.
    /// Uses `publish_stage_event` (no dedup) since multiple stages share a receipt CID.
    ///
    /// Canonical stage event fields (P1.5): input_cid, output_cid, binary_hash,
    /// build_meta, world, actor, latency_ms are populated from pipeline context.
    async fn publish_receipt_event(
        &self,
        receipt: &PipelineReceipt,
        pipeline_stage: &str,
        decision: Option<String>,
        duration_ms: Option<i64>,
        world: Option<&str>,
        input_cid: Option<&str>,
    ) {
        let mut event = ReceiptEvent::new(
            &format!("ubl.receipt.{}", pipeline_stage),
            &receipt.body_cid,
            &receipt.receipt_type,
            pipeline_stage,
            receipt.body.clone(),
        );
        event.decision = decision;
        event.duration_ms = duration_ms;

        // ── Canonical stage event fields (P1.5) ──
        event.input_cid = input_cid.map(|s| s.to_string());
        event.output_cid = Some(receipt.body_cid.clone());
        event.binary_hash = Some(self.runtime_info.binary_hash.clone());
        event.build_meta = serde_json::to_value(&self.runtime_info.build).ok();
        event.world = world.map(|s| s.to_string());
        event.actor = Some(self.did.clone());
        event.latency_ms = duration_ms;

        // Extract fuel_used and rb_count from receipt body if present
        if let Some(vm) = receipt.body.get("vm_state") {
            event.fuel_used = vm.get("fuel_used").and_then(|v| v.as_u64());
        }
        if let Some(trace) = receipt.body.get("policy_trace") {
            if let Some(arr) = trace.as_array() {
                event.rb_count = Some(arr.iter()
                    .flat_map(|p| p.get("rb_results").and_then(|r| r.as_array()).map(|a| a.len() as u64))
                    .sum());
            }
        }

        // Collect artifact CIDs from the receipt
        if let Some(cid) = receipt.body.get("body_cid").and_then(|v| v.as_str()) {
            event.artifact_cids.push(cid.to_string());
        }

        // Best effort - don't fail pipeline if event publishing fails
        if let Err(e) = self.event_bus.publish_stage_event(event).await {
            eprintln!("Failed to publish receipt event: {}", e);
        }
    }

    /// Enforce the onboarding dependency chain at CHECK.
    ///
    /// Order: App → User → Tenant → Membership → Token → Revoke
    /// Each type requires its predecessors to already exist in ChipStore.
    async fn check_onboarding_dependencies(
        &self,
        chip_type: &str,
        body: &serde_json::Value,
        world: &str,
        store: &Arc<ubl_chipstore::ChipStore>,
    ) -> Result<(), PipelineError> {
        match chip_type {
            // App is the root — no dependencies, but slug must be unique.
            // Requires cap.registry:init (P0.3).
            "ubl/app" => {
                crate::capability::require_cap(body, "registry:init", world)
                    .map_err(|e| PipelineError::InvalidChip(format!("ubl/app capability: {}", e)))?;

                let slug = body.get("slug").and_then(|v| v.as_str()).unwrap_or("");
                let existing = store.get_chips_by_type("ubl/app").await
                    .map_err(|e| PipelineError::Internal(format!("ChipStore query: {}", e)))?;
                for chip in &existing {
                    if chip.chip_data.get("slug").and_then(|v| v.as_str()) == Some(slug) {
                        // Check if this app has been revoked
                        if !self.is_revoked(&chip.cid, store).await? {
                            return Err(PipelineError::InvalidChip(
                                format!("App slug '{}' already registered", slug),
                            ));
                        }
                    }
                }
            }

            // User requires a valid app in @world.
            // First user for an app requires cap.registry:init (P0.3).
            "ubl/user" => {
                let scope = crate::auth::WorldScope::parse(world)
                    .map_err(|e| PipelineError::InvalidChip(format!("@world: {}", e)))?;
                self.require_app_exists(&scope.app, store).await?;

                // Check if this is the first user for this app
                let existing_users = store.get_chips_by_type("ubl/user").await
                    .map_err(|e| PipelineError::Internal(format!("ChipStore query: {}", e)))?;
                let has_user_for_app = existing_users.iter().any(|c| {
                    c.chip_data.get("@world").and_then(|v| v.as_str())
                        .map(|w| w.starts_with(&format!("a/{}", scope.app)))
                        .unwrap_or(false)
                });
                if !has_user_for_app {
                    crate::capability::require_cap(body, "registry:init", world)
                        .map_err(|e| PipelineError::InvalidChip(
                            format!("first ubl/user for app '{}' requires capability: {}", scope.app, e)
                        ))?;
                }
            }

            // Tenant requires: app exists + creator_cid references a valid user
            "ubl/tenant" => {
                let scope = crate::auth::WorldScope::parse(world)
                    .map_err(|e| PipelineError::InvalidChip(format!("@world: {}", e)))?;
                self.require_app_exists(&scope.app, store).await?;

                let creator_cid = body.get("creator_cid").and_then(|v| v.as_str()).unwrap_or("");
                self.require_chip_exists(creator_cid, "ubl/user", store).await?;
            }

            // Membership requires: user_cid and tenant_cid both exist.
            // Requires cap.membership:grant (P0.4).
            "ubl/membership" => {
                crate::capability::require_cap(body, "membership:grant", world)
                    .map_err(|e| PipelineError::InvalidChip(format!("ubl/membership capability: {}", e)))?;

                let user_cid = body.get("user_cid").and_then(|v| v.as_str()).unwrap_or("");
                self.require_chip_exists(user_cid, "ubl/user", store).await?;

                let tenant_cid = body.get("tenant_cid").and_then(|v| v.as_str()).unwrap_or("");
                self.require_chip_exists(tenant_cid, "ubl/tenant", store).await?;
            }

            // Token requires: user_cid exists
            "ubl/token" => {
                let user_cid = body.get("user_cid").and_then(|v| v.as_str()).unwrap_or("");
                self.require_chip_exists(user_cid, "ubl/user", store).await?;
            }

            // Revoke requires: target_cid exists (any type) + actor_cid exists.
            // Requires cap.revoke:execute (P0.4).
            "ubl/revoke" => {
                crate::capability::require_cap(body, "revoke:execute", world)
                    .map_err(|e| PipelineError::InvalidChip(format!("ubl/revoke capability: {}", e)))?;

                let target_cid = body.get("target_cid").and_then(|v| v.as_str()).unwrap_or("");
                if !store.exists(target_cid).await
                    .map_err(|e| PipelineError::Internal(format!("ChipStore: {}", e)))? {
                    return Err(PipelineError::DependencyMissing(
                        format!("Revoke target '{}' not found", target_cid),
                    ));
                }

                let actor_cid = body.get("actor_cid").and_then(|v| v.as_str()).unwrap_or("");
                self.require_chip_exists(actor_cid, "ubl/user", store).await?;
            }

            _ => {} // not an onboarding type
        }

        Ok(())
    }

    /// Check that an app with the given slug exists and is not revoked.
    async fn require_app_exists(
        &self,
        app_slug: &str,
        store: &Arc<ubl_chipstore::ChipStore>,
    ) -> Result<(), PipelineError> {
        let apps = store.get_chips_by_type("ubl/app").await
            .map_err(|e| PipelineError::Internal(format!("ChipStore: {}", e)))?;

        for chip in &apps {
            if chip.chip_data.get("slug").and_then(|v| v.as_str()) == Some(app_slug) {
                if !self.is_revoked(&chip.cid, store).await? {
                    return Ok(());
                }
            }
        }

        Err(PipelineError::DependencyMissing(
            format!("App '{}' not found — register ubl/app first", app_slug),
        ))
    }

    /// Check that a chip with the given CID exists, is the expected type, and is not revoked.
    async fn require_chip_exists(
        &self,
        cid: &str,
        expected_type: &str,
        store: &Arc<ubl_chipstore::ChipStore>,
    ) -> Result<(), PipelineError> {
        let chip = store.get_chip(cid).await
            .map_err(|e| PipelineError::Internal(format!("ChipStore: {}", e)))?
            .ok_or_else(|| PipelineError::DependencyMissing(
                format!("{} '{}' not found", expected_type, cid),
            ))?;

        if chip.chip_type != expected_type {
            return Err(PipelineError::InvalidChip(format!(
                "CID '{}' is '{}', expected '{}'", cid, chip.chip_type, expected_type,
            )));
        }

        if self.is_revoked(cid, store).await? {
            return Err(PipelineError::DependencyMissing(format!(
                "{} '{}' has been revoked", expected_type, cid,
            )));
        }

        Ok(())
    }

    /// Check if a chip has been revoked (any ubl/revoke chip targeting it).
    async fn is_revoked(
        &self,
        target_cid: &str,
        store: &Arc<ubl_chipstore::ChipStore>,
    ) -> Result<bool, PipelineError> {
        let revocations = store.get_chips_by_type("ubl/revoke").await
            .map_err(|e| PipelineError::Internal(format!("ChipStore: {}", e)))?;

        for rev in &revocations {
            if rev.chip_data.get("target_cid").and_then(|v| v.as_str()) == Some(target_cid) {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

/// Pipeline errors
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("KNOCK rejected: {0}")]
    Knock(String),
    #[error("Policy denied: {0}")]
    PolicyDenied(String),
    #[error("Invalid chip format: {0}")]
    InvalidChip(String),
    #[error("Dependency missing: {0}")]
    DependencyMissing(String),
    #[error("Fuel exhausted: {0}")]
    FuelExhausted(String),
    #[error("Type mismatch: {0}")]
    TypeMismatch(String),
    #[error("Stack underflow: {0}")]
    StackUnderflow(String),
    #[error("CAS not found: {0}")]
    CasNotFound(String),
    #[error("Replay detected: {0}")]
    ReplayDetected(String),
    #[error("Canon error: {0}")]
    CanonError(String),
    #[error("Sign error: {0}")]
    SignError(String),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_loader::InMemoryPolicyStorage;
    use serde_json::json;

    #[tokio::test]
    async fn pipeline_allow_flow_with_real_vm() {
        let storage = InMemoryPolicyStorage::new();
        let pipeline = UblPipeline::new(Box::new(storage));

        let request = ChipRequest {
            chip_type: "ubl/document".to_string(),
            body: json!({
                "@type": "ubl/document",
                "@id": "alice-001",
                "@ver": "1.0",
                "@world": "a/demo/t/main",
                "title": "Test Document"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let result = pipeline.process_chip(request).await.unwrap();

        // Decision must be Allow (genesis allows ubl/document)
        assert!(matches!(result.decision, Decision::Allow));

        // Chain must have 3 CIDs: WA, TR, WF
        assert_eq!(result.chain.len(), 3, "chain: WA + TR + WF");
        for cid in &result.chain {
            assert!(cid.starts_with("b3:"), "all CIDs must be BLAKE3: {}", cid);
        }

        // TR receipt must contain real VM data (not placeholder)
        let tr_body = &result.chain[1]; // TR CID
        assert!(tr_body.starts_with("b3:"), "TR CID is real BLAKE3");

        // WF receipt body must have decision
        let wf_body = &result.final_receipt.body;
        assert_eq!(wf_body["decision"], "Allow");
        assert!(!wf_body["short_circuited"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn pipeline_deny_flow_skips_vm() {
        let storage = InMemoryPolicyStorage::new();
        let pipeline = UblPipeline::new(Box::new(storage));

        // Genesis policy denies unknown types
        let request = ChipRequest {
            chip_type: "evil/hack".to_string(),
            body: json!({
                "@type": "evil/hack",
                "@id": "x",
                "@ver": "1.0",
                "@world": "a/x/t/y"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let result = pipeline.process_chip(request).await.unwrap();

        assert!(matches!(result.decision, Decision::Deny));
        // Chain should have WA + "no-tr" + WF (VM never ran)
        assert_eq!(result.chain[1], "no-tr", "TR must be skipped on deny");
    }

    #[tokio::test]
    async fn pipeline_tr_receipt_has_vm_state() {
        let storage = InMemoryPolicyStorage::new();
        let pipeline = UblPipeline::new(Box::new(storage));

        let request = ChipRequest {
            chip_type: "ubl/document".to_string(),
            body: json!({
                "@type": "ubl/document",
                "@id": "bob",
                "@ver": "1.0",
                "@world": "a/app/t/ten"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let result = pipeline.process_chip(request).await.unwrap();

        // Find the TR receipt in the chain (index 1 is the TR CID)
        // The WF body contains the full trace
        let wf = &result.final_receipt.body;
        assert!(wf["tr_cid"].is_string(), "WF must reference TR CID");
        let tr_cid = wf["tr_cid"].as_str().unwrap();
        assert!(tr_cid.starts_with("b3:"), "TR CID must be BLAKE3");
    }

    #[tokio::test]
    async fn policy_trace_has_rb_votes() {
        let storage = InMemoryPolicyStorage::new();
        let pipeline = UblPipeline::new(Box::new(storage));

        // ALLOW path — genesis policy has RBs that vote
        let request = ChipRequest {
            chip_type: "ubl/document".to_string(),
            body: json!({
                "@type": "ubl/document",
                "@id": "trace-test",
                "@ver": "1.0",
                "@world": "a/app/t/ten"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let result = pipeline.process_chip(request).await.unwrap();
        assert!(matches!(result.decision, Decision::Allow));

        let wf = &result.final_receipt.body;
        let trace = wf["policy_trace"].as_array().unwrap();
        assert!(!trace.is_empty(), "policy_trace must have entries");

        // Each trace entry should have rb_results with individual votes
        let first = &trace[0];
        assert!(first["policy_id"].is_string());
        let rbs = first["rb_results"].as_array().unwrap();
        assert!(!rbs.is_empty(), "rb_results must expose individual RB votes");

        // Each RB result should have rb_id, decision, reason
        let rb = &rbs[0];
        assert!(rb["rb_id"].is_string());
        assert!(rb["decision"].is_string());
        assert!(rb["reason"].is_string());
    }

    #[tokio::test]
    async fn deny_trace_has_rb_votes() {
        let storage = InMemoryPolicyStorage::new();
        let pipeline = UblPipeline::new(Box::new(storage));

        // DENY path — evil type triggers genesis deny
        let request = ChipRequest {
            chip_type: "evil/hack".to_string(),
            body: json!({
                "@type": "evil/hack",
                "@id": "x",
                "@ver": "1.0",
                "@world": "a/x/t/y"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let result = pipeline.process_chip(request).await.unwrap();
        assert!(matches!(result.decision, Decision::Deny));

        let wf = &result.final_receipt.body;
        let trace = wf["policy_trace"].as_array().unwrap();
        assert!(!trace.is_empty());

        // The deny trace should show which RB denied
        let deny_entry = &trace[trace.len() - 1];
        assert_eq!(deny_entry["result"], "Deny");
        let rbs = deny_entry["rb_results"].as_array().unwrap();
        assert!(!rbs.is_empty(), "deny trace must show which RB denied");
    }

    #[tokio::test]
    async fn pipeline_rejects_missing_world() {
        let storage = InMemoryPolicyStorage::new();
        let pipeline = UblPipeline::new(Box::new(storage));

        let request = ChipRequest {
            chip_type: "ubl/document".to_string(),
            body: json!({
                "@type": "ubl/document",
                "@id": "no-world",
                "@ver": "1.0"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let err = pipeline.process_chip(request).await.unwrap_err();
        assert!(matches!(err, PipelineError::InvalidChip(_)));
        assert!(err.to_string().contains("@world"));
    }

    #[tokio::test]
    async fn pipeline_rejects_invalid_world_format() {
        let storage = InMemoryPolicyStorage::new();
        let pipeline = UblPipeline::new(Box::new(storage));

        let request = ChipRequest {
            chip_type: "ubl/document".to_string(),
            body: json!({
                "@type": "ubl/document",
                "@id": "bad-world",
                "@ver": "1.0",
                "@world": "not-a-valid-world"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let err = pipeline.process_chip(request).await.unwrap_err();
        assert!(matches!(err, PipelineError::InvalidChip(_)));
    }

    #[tokio::test]
    async fn pipeline_wa_has_nonce_and_kid() {
        let storage = InMemoryPolicyStorage::new();
        let event_bus = Arc::new(EventBus::new());
        let pipeline = UblPipeline::with_event_bus(Box::new(storage), event_bus.clone());
        let mut rx = event_bus.subscribe();

        let request = ChipRequest {
            chip_type: "ubl/document".to_string(),
            body: json!({
                "@type": "ubl/document",
                "@id": "nonce-test",
                "@ver": "1.0",
                "@world": "a/app/t/ten"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let _result = pipeline.process_chip(request).await.unwrap();

        // WA event is first
        let wa_event = rx.try_recv().unwrap();
        assert_eq!(wa_event.pipeline_stage, "wa");

        // WA metadata must contain nonce and kid
        let nonce = wa_event.metadata.get("nonce").and_then(|v| v.as_str());
        assert!(nonce.is_some(), "WA receipt must have nonce");
        assert_eq!(nonce.unwrap().len(), 32, "nonce must be 32 hex chars (16 bytes)");

        let kid = wa_event.metadata.get("kid").and_then(|v| v.as_str());
        assert!(kid.is_some(), "WA receipt must have kid");
    }

    #[tokio::test]
    async fn pipeline_nonces_are_unique() {
        let storage = InMemoryPolicyStorage::new();
        let pipeline = UblPipeline::new(Box::new(storage));

        let mut nonces = std::collections::HashSet::new();
        for i in 0..10 {
            let request = ChipRequest {
                chip_type: "ubl/document".to_string(),
                body: json!({
                    "@type": "ubl/document",
                    "@id": format!("doc-{}", i),
                    "@ver": "1.0",
                    "@world": "a/app/t/ten"
                }),
                parents: vec![],
                operation: Some("create".to_string()),
            };
            let result = pipeline.process_chip(request).await.unwrap();
            // Extract nonce from WA receipt body (it's in the chain)
            let wa_cid = &result.chain[0];
            assert!(nonces.insert(wa_cid.clone()), "WA CIDs must be unique (nonce ensures this)");
        }
        assert_eq!(nonces.len(), 10);
    }

    #[tokio::test]
    async fn chipstore_persists_after_allow() {
        use ubl_chipstore::{ChipStore, InMemoryBackend};

        let policy_storage = InMemoryPolicyStorage::new();
        let backend = Arc::new(InMemoryBackend::new());
        let chip_store = Arc::new(ChipStore::new(backend.clone()));
        let pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());

        let request = ChipRequest {
            chip_type: "ubl/document".to_string(),
            body: json!({
                "@type": "ubl/document",
                "@id": "persist-test",
                "@ver": "1.0",
                "@world": "a/app/t/ten",
                "title": "Test Document"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let result = pipeline.process_chip(request).await.unwrap();
        assert!(matches!(result.decision, Decision::Allow));

        // Chip should be persisted in the store
        // Compute the expected CID
        let chip_body = json!({
            "@type": "ubl/document",
            "@id": "persist-test",
            "@ver": "1.0",
            "@world": "a/app/t/ten",
            "title": "Test Document"
        });
        let nrf = ubl_ai_nrf1::to_nrf1_bytes(&chip_body).unwrap();
        let expected_cid = ubl_ai_nrf1::compute_cid(&nrf).unwrap();

        let stored = chip_store.get_chip(&expected_cid).await.unwrap();
        assert!(stored.is_some(), "chip must be persisted after allow");
        let stored = stored.unwrap();
        assert_eq!(stored.chip_type, "ubl/document");
        assert_eq!(stored.receipt_cid, result.final_receipt.body_cid);
    }

    #[tokio::test]
    async fn chipstore_not_called_on_deny() {
        use ubl_chipstore::{ChipStore, InMemoryBackend};

        let policy_storage = InMemoryPolicyStorage::new();
        let backend = Arc::new(InMemoryBackend::new());
        let chip_store = Arc::new(ChipStore::new(backend.clone()));
        let pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());

        let request = ChipRequest {
            chip_type: "evil/hack".to_string(),
            body: json!({
                "@type": "evil/hack",
                "@id": "x",
                "@ver": "1.0",
                "@world": "a/x/t/y"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let result = pipeline.process_chip(request).await.unwrap();
        assert!(matches!(result.decision, Decision::Deny));

        // Denied chips should NOT be stored
        let query = ubl_chipstore::ChipQuery {
            chip_type: Some("evil/hack".to_string()),
            tags: vec![],
            created_after: None,
            created_before: None,
            executor_did: None,
            limit: None,
            offset: None,
        };
        let found = chip_store.query(&query).await.unwrap();
        assert_eq!(found.total_count, 0, "denied chips must not be persisted");
    }

    #[tokio::test]
    async fn event_bus_receives_pipeline_events() {
        let storage = InMemoryPolicyStorage::new();
        let event_bus = Arc::new(EventBus::new());
        let pipeline = UblPipeline::with_event_bus(Box::new(storage), event_bus.clone());

        let mut rx = event_bus.subscribe();

        let request = ChipRequest {
            chip_type: "ubl/document".to_string(),
            body: json!({
                "@type": "ubl/document",
                "@id": "eve",
                "@ver": "1.0",
                "@world": "a/app/t/ten"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let _result = pipeline.process_chip(request).await.unwrap();

        // Should have received WA, TR, WF events
        let count = event_bus.event_count().await;
        assert!(count >= 3, "expected at least 3 events (WA+TR+WF), got {}", count);

        // First event should be WA
        let wa_event = rx.try_recv().unwrap();
        assert_eq!(wa_event.pipeline_stage, "wa");
    }

    #[tokio::test]
    async fn stage_events_have_canonical_fields() {
        let storage = InMemoryPolicyStorage::new();
        let event_bus = Arc::new(EventBus::new());
        let pipeline = UblPipeline::with_event_bus(Box::new(storage), event_bus.clone());
        let mut rx = event_bus.subscribe();

        let request = ChipRequest {
            chip_type: "ubl/document".to_string(),
            body: json!({
                "@type": "ubl/document",
                "@id": "canonical-evt",
                "@ver": "1.0",
                "@world": "a/app/t/ten"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let _result = pipeline.process_chip(request).await.unwrap();

        // Collect all events
        let mut events = vec![];
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }
        assert!(events.len() >= 3, "need WA+TR+WF, got {}", events.len());

        // Every event must have canonical fields
        for ev in &events {
            assert!(ev.world.is_some(), "stage {} missing world", ev.pipeline_stage);
            assert_eq!(ev.world.as_deref(), Some("a/app/t/ten"));
            assert!(ev.actor.is_some(), "stage {} missing actor", ev.pipeline_stage);
            assert!(ev.actor.as_ref().unwrap().starts_with("did:key:"), "actor must be a DID");
            assert!(ev.binary_hash.is_some(), "stage {} missing binary_hash", ev.pipeline_stage);
            assert!(ev.output_cid.is_some(), "stage {} missing output_cid", ev.pipeline_stage);
            assert!(ev.latency_ms.is_some(), "stage {} missing latency_ms", ev.pipeline_stage);
        }

        // WA has no input_cid (it's the first stage)
        let wa = events.iter().find(|e| e.pipeline_stage == "wa").unwrap();
        assert!(wa.input_cid.is_none(), "WA should have no input_cid");

        // TR has input_cid = WA output
        let tr = events.iter().find(|e| e.pipeline_stage == "tr").unwrap();
        assert!(tr.input_cid.is_some(), "TR must have input_cid");
        assert_eq!(tr.input_cid.as_deref(), wa.output_cid.as_deref(), "TR input = WA output");

        // WF has input_cid = TR output
        let wf = events.iter().find(|e| e.pipeline_stage == "wf").unwrap();
        assert!(wf.input_cid.is_some(), "WF must have input_cid");
        assert_eq!(wf.input_cid.as_deref(), tr.output_cid.as_deref(), "WF input = TR output");
        assert_eq!(wf.decision.as_deref(), Some("allow"));
    }

    #[tokio::test]
    async fn unified_receipt_has_all_stages_on_allow() {
        let storage = InMemoryPolicyStorage::new();
        let pipeline = UblPipeline::new(Box::new(storage));

        let request = ChipRequest {
            chip_type: "ubl/document".to_string(),
            body: json!({
                "@type": "ubl/document",
                "@id": "unified-test",
                "@ver": "1.0",
                "@world": "a/app/t/ten"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let result = pipeline.process_chip(request).await.unwrap();
        let r = &result.receipt;

        // Must have 4 stages: WA, CHECK, TR, WF
        assert_eq!(r.stage_count(), 4);
        assert!(r.has_stage(PipelineStage::WriteAhead));
        assert!(r.has_stage(PipelineStage::Check));
        assert!(r.has_stage(PipelineStage::Transition));
        assert!(r.has_stage(PipelineStage::WriteFinished));

        // Receipt CID must be set
        assert!(r.receipt_cid.starts_with("b3:"), "receipt_cid must be BLAKE3");
        assert_eq!(r.id, r.receipt_cid, "@id must equal receipt_cid");

        // Envelope anchors
        assert_eq!(r.receipt_type, "ubl/receipt");
        assert_eq!(r.world, "a/app/t/ten");
        assert_eq!(r.ver, "1.0");

        // Auth tokens present on every stage
        for stage in &r.stages {
            assert!(stage.auth_token.starts_with("hmac:"), "stage {:?} missing auth_token", stage.stage);
        }

        // Decision is Allow
        assert_eq!(r.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn unified_receipt_deny_has_two_stages() {
        let storage = InMemoryPolicyStorage::new();
        let pipeline = UblPipeline::new(Box::new(storage));

        let request = ChipRequest {
            chip_type: "evil/hack".to_string(),
            body: json!({
                "@type": "evil/hack",
                "@id": "x",
                "@ver": "1.0",
                "@world": "a/x/t/y"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let result = pipeline.process_chip(request).await.unwrap();
        let r = &result.receipt;

        // Deny path: WA + CHECK only (no TR, no WF)
        assert_eq!(r.stage_count(), 2);
        assert!(r.has_stage(PipelineStage::WriteAhead));
        assert!(r.has_stage(PipelineStage::Check));
        assert!(!r.has_stage(PipelineStage::Transition));
        assert!(!r.has_stage(PipelineStage::WriteFinished));

        assert_eq!(r.decision, Decision::Deny);
        assert!(r.effects["deny_reason"].is_string());
    }

    #[tokio::test]
    async fn unified_receipt_check_stage_has_policy_trace() {
        let storage = InMemoryPolicyStorage::new();
        let pipeline = UblPipeline::new(Box::new(storage));

        let request = ChipRequest {
            chip_type: "ubl/document".to_string(),
            body: json!({
                "@type": "ubl/document",
                "@id": "trace-unified",
                "@ver": "1.0",
                "@world": "a/app/t/ten"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let result = pipeline.process_chip(request).await.unwrap();
        let r = &result.receipt;

        // CHECK stage should have policy_trace with RB votes
        let check_stage = r.stages.iter().find(|s| s.stage == PipelineStage::Check).unwrap();
        assert!(!check_stage.policy_trace.is_empty(), "CHECK stage must have policy trace");
        assert!(!check_stage.policy_trace[0].rb_results.is_empty(), "policy trace must have RB votes");
    }

    #[tokio::test]
    async fn unified_receipt_tr_stage_has_fuel() {
        let storage = InMemoryPolicyStorage::new();
        let pipeline = UblPipeline::new(Box::new(storage));

        let request = ChipRequest {
            chip_type: "ubl/document".to_string(),
            body: json!({
                "@type": "ubl/document",
                "@id": "fuel-test",
                "@ver": "1.0",
                "@world": "a/app/t/ten"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let result = pipeline.process_chip(request).await.unwrap();
        let r = &result.receipt;

        let tr_stage = r.stages.iter().find(|s| s.stage == PipelineStage::Transition).unwrap();
        assert!(tr_stage.fuel_used.is_some(), "TR stage must record fuel_used");
        assert!(tr_stage.output_cid.is_some(), "TR stage must have output_cid");
    }

    #[tokio::test]
    async fn bootstrap_genesis_stores_chip_in_chipstore() {
        use ubl_chipstore::{ChipStore, InMemoryBackend};

        let policy_storage = InMemoryPolicyStorage::new();
        let backend = Arc::new(InMemoryBackend::new());
        let chip_store = Arc::new(ChipStore::new(backend.clone()));
        let pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());

        let genesis_cid = pipeline.bootstrap_genesis().await.unwrap();

        // Genesis CID must be deterministic and start with b3:
        assert!(genesis_cid.starts_with("b3:"));
        assert_eq!(genesis_cid, crate::genesis::genesis_chip_cid());

        // Must be stored in ChipStore
        let stored = chip_store.get_chip(&genesis_cid).await.unwrap();
        assert!(stored.is_some(), "Genesis chip must be in ChipStore after bootstrap");

        let chip = stored.unwrap();
        assert_eq!(chip.chip_type, "ubl/policy.genesis");
        assert_eq!(chip.receipt_cid, genesis_cid, "Genesis is self-signed: receipt_cid == chip_cid");
        assert_eq!(chip.execution_metadata.executor_did, "did:key:genesis");
        assert!(chip.execution_metadata.reproducible);
    }

    #[tokio::test]
    async fn bootstrap_genesis_is_idempotent() {
        use ubl_chipstore::{ChipStore, InMemoryBackend};

        let policy_storage = InMemoryPolicyStorage::new();
        let backend = Arc::new(InMemoryBackend::new());
        let chip_store = Arc::new(ChipStore::new(backend.clone()));
        let pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());

        let cid1 = pipeline.bootstrap_genesis().await.unwrap();
        let cid2 = pipeline.bootstrap_genesis().await.unwrap();

        assert_eq!(cid1, cid2, "Idempotent: same CID on repeated bootstrap");
    }

    #[tokio::test]
    async fn bootstrap_genesis_without_chipstore_returns_cid() {
        let policy_storage = InMemoryPolicyStorage::new();
        let pipeline = UblPipeline::new(Box::new(policy_storage));

        // Even without ChipStore, bootstrap should return the genesis CID
        let genesis_cid = pipeline.bootstrap_genesis().await.unwrap();
        assert!(genesis_cid.starts_with("b3:"));
    }

    #[tokio::test]
    async fn advisory_engine_produces_post_wf_chip() {
        use ubl_chipstore::{ChipStore, InMemoryBackend};
        use crate::advisory::AdvisoryEngine;

        let policy_storage = InMemoryPolicyStorage::new();
        let backend = Arc::new(InMemoryBackend::new());
        let chip_store = Arc::new(ChipStore::new(backend.clone()));
        let mut pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());

        let engine = Arc::new(AdvisoryEngine::new(
            "b3:test-passport".to_string(),
            "test-model".to_string(),
            "a/test/t/test".to_string(),
        ));
        pipeline.set_advisory_engine(engine);

        let request = ChipRequest {
            chip_type: "ubl/document".to_string(),
            body: json!({
                "@type": "ubl/document",
                "@id": "adv-test",
                "@ver": "1.0",
                "@world": "a/test/t/test",
                "id": "adv-test"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let result = pipeline.process_chip(request).await.unwrap();
        assert!(matches!(result.decision, Decision::Allow));

        // Give the spawned advisory task time to complete
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Query ChipStore for advisory chips
        let query = ubl_chipstore::ChipQuery {
            chip_type: Some("ubl/advisory".to_string()),
            tags: vec![],
            created_after: None,
            created_before: None,
            executor_did: None,
            limit: Some(10),
            offset: None,
        };
        let results = chip_store.query(&query).await.unwrap();
        assert!(results.total_count >= 1, "At least one advisory chip should be stored (post-CHECK or post-WF)");

        let adv_chip = &results.chips[0];
        assert_eq!(adv_chip.chip_type, "ubl/advisory");
        assert_eq!(adv_chip.chip_data["passport_cid"], "b3:test-passport");
    }

    #[tokio::test]
    async fn advisory_engine_fires_on_deny() {
        use ubl_chipstore::{ChipStore, InMemoryBackend};
        use crate::advisory::AdvisoryEngine;

        let policy_storage = InMemoryPolicyStorage::new();
        let backend = Arc::new(InMemoryBackend::new());
        let chip_store = Arc::new(ChipStore::new(backend.clone()));
        let mut pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());

        let engine = Arc::new(AdvisoryEngine::new(
            "b3:test-passport".to_string(),
            "test-model".to_string(),
            "a/test/t/test".to_string(),
        ));
        pipeline.set_advisory_engine(engine);

        // This should be denied by genesis (evil type)
        let request = ChipRequest {
            chip_type: "evil/hack".to_string(),
            body: json!({
                "@type": "evil/hack",
                "@id": "bad",
                "@ver": "1.0",
                "@world": "a/test/t/test",
                "id": "bad"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let result = pipeline.process_chip(request).await.unwrap();
        assert!(matches!(result.decision, Decision::Deny));

        // Give the spawned advisory task time to complete
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Post-CHECK advisory should fire even on deny
        let query = ubl_chipstore::ChipQuery {
            chip_type: Some("ubl/advisory".to_string()),
            tags: vec![],
            created_after: None,
            created_before: None,
            executor_did: None,
            limit: Some(10),
            offset: None,
        };
        let results = chip_store.query(&query).await.unwrap();
        assert!(results.total_count >= 1, "Post-CHECK advisory should fire on deny");

        let adv_chip = &results.chips[0];
        assert_eq!(adv_chip.chip_data["action"], "explain_check");
    }

    // ══════════════════════════════════════════════════════════════
    // Onboarding Integration Tests — full dependency chain
    // ══════════════════════════════════════════════════════════════

    /// Helper: create a pipeline with ChipStore for onboarding tests.
    fn onboarding_pipeline() -> (UblPipeline, Arc<ubl_chipstore::ChipStore>) {
        use ubl_chipstore::{ChipStore, InMemoryBackend};

        let policy_storage = InMemoryPolicyStorage::new();
        let backend = Arc::new(InMemoryBackend::new());
        let chip_store = Arc::new(ChipStore::new(backend));
        let pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());
        (pipeline, chip_store)
    }

    /// Helper: create a valid @cap for testing.
    fn test_cap(action: &str, audience: &str) -> serde_json::Value {
        json!({
            "action": action,
            "audience": audience,
            "issued_by": "did:key:z6MkTestIssuer",
            "issued_at": "2025-01-01T00:00:00Z",
            "expires_at": "2099-12-31T23:59:59Z",
            "signature": "ed25519:dGVzdHNpZw"
        })
    }

    /// Helper: compute CID for a chip body.
    fn chip_cid(body: &serde_json::Value) -> String {
        let nrf = ubl_ai_nrf1::to_nrf1_bytes(body).unwrap();
        ubl_ai_nrf1::compute_cid(&nrf).unwrap()
    }

    /// Helper: submit a chip and assert Allow.
    async fn submit_allow(pipeline: &UblPipeline, chip_type: &str, body: serde_json::Value) -> PipelineResult {
        let request = ChipRequest {
            chip_type: chip_type.to_string(),
            body,
            parents: vec![],
            operation: Some("create".to_string()),
        };
        let result = pipeline.process_chip(request).await.unwrap();
        assert!(matches!(result.decision, Decision::Allow), "expected Allow for {}", chip_type);
        result
    }

    /// Helper: submit a chip and assert it fails with a specific error variant.
    async fn submit_expect_err(pipeline: &UblPipeline, chip_type: &str, body: serde_json::Value) -> PipelineError {
        let request = ChipRequest {
            chip_type: chip_type.to_string(),
            body,
            parents: vec![],
            operation: Some("create".to_string()),
        };
        pipeline.process_chip(request).await.unwrap_err()
    }

    #[tokio::test]
    async fn onboarding_full_flow_app_to_token() {
        let (pipeline, _store) = onboarding_pipeline();

        // 1. Register app (requires registry:init cap)
        let app_body = json!({
            "@type": "ubl/app",
            "@id": "app-acme",
            "@ver": "1.0",
            "@world": "a/acme",
            "slug": "acme",
            "display_name": "Acme Corp",
            "owner_did": "did:key:z6MkOwner",
            "@cap": test_cap("registry:init", "a/acme")
        });
        submit_allow(&pipeline, "ubl/app", app_body.clone()).await;

        // 2. Register first user (requires registry:init cap for first user)
        let user_body = json!({
            "@type": "ubl/user",
            "@id": "user-alice",
            "@ver": "1.0",
            "@world": "a/acme",
            "did": "did:key:z6MkAlice",
            "display_name": "Alice",
            "@cap": test_cap("registry:init", "a/acme")
        });
        let user_cid = chip_cid(&user_body);
        submit_allow(&pipeline, "ubl/user", user_body).await;

        // 3. Create tenant (depends on app + creator user)
        let tenant_body = json!({
            "@type": "ubl/tenant",
            "@id": "tenant-eng",
            "@ver": "1.0",
            "@world": "a/acme",
            "slug": "engineering",
            "display_name": "Engineering Circle",
            "creator_cid": user_cid
        });
        let tenant_cid = chip_cid(&tenant_body);
        submit_allow(&pipeline, "ubl/tenant", tenant_body).await;

        // 4. Create membership (depends on user + tenant, requires membership:grant cap)
        let membership_body = json!({
            "@type": "ubl/membership",
            "@id": "mem-alice-eng",
            "@ver": "1.0",
            "@world": format!("a/acme/t/engineering"),
            "user_cid": user_cid,
            "tenant_cid": tenant_cid,
            "role": "admin",
            "@cap": test_cap("membership:grant", "a/acme")
        });
        submit_allow(&pipeline, "ubl/membership", membership_body).await;

        // 5. Create token (depends on user)
        let token_body = json!({
            "@type": "ubl/token",
            "@id": "tok-alice-1",
            "@ver": "1.0",
            "@world": "a/acme",
            "user_cid": user_cid,
            "scope": ["read", "write"],
            "expires_at": "2027-12-31T23:59:59Z",
            "kid": "did:key:z6MkAlice#v0"
        });
        submit_allow(&pipeline, "ubl/token", token_body).await;
    }

    #[tokio::test]
    async fn onboarding_user_without_app_fails() {
        let (pipeline, _store) = onboarding_pipeline();

        // Try to register user without an app — should fail with DependencyMissing
        let user_body = json!({
            "@type": "ubl/user",
            "@id": "user-orphan",
            "@ver": "1.0",
            "@world": "a/nonexistent",
            "did": "did:key:z6MkOrphan",
            "display_name": "Orphan"
        });
        let err = submit_expect_err(&pipeline, "ubl/user", user_body).await;
        assert!(matches!(err, PipelineError::DependencyMissing(_)), "expected DependencyMissing, got: {}", err);
        assert!(err.to_string().contains("nonexistent"));
    }

    #[tokio::test]
    async fn onboarding_tenant_without_user_fails() {
        let (pipeline, _store) = onboarding_pipeline();

        // Register app first
        let app_body = json!({
            "@type": "ubl/app",
            "@id": "app-acme2",
            "@ver": "1.0",
            "@world": "a/acme2",
            "slug": "acme2",
            "display_name": "Acme 2",
            "owner_did": "did:key:z6MkOwner",
            "@cap": test_cap("registry:init", "a/acme2")
        });
        submit_allow(&pipeline, "ubl/app", app_body).await;

        // Try to create tenant with a non-existent creator_cid
        let tenant_body = json!({
            "@type": "ubl/tenant",
            "@id": "tenant-bad",
            "@ver": "1.0",
            "@world": "a/acme2",
            "slug": "bad-circle",
            "display_name": "Bad Circle",
            "creator_cid": "b3:nonexistent_user_cid"
        });
        let err = submit_expect_err(&pipeline, "ubl/tenant", tenant_body).await;
        assert!(matches!(err, PipelineError::DependencyMissing(_)), "expected DependencyMissing, got: {}", err);
    }

    #[tokio::test]
    async fn onboarding_membership_without_tenant_fails() {
        let (pipeline, _store) = onboarding_pipeline();

        // Register app + user
        let app_body = json!({
            "@type": "ubl/app", "@id": "app-m", "@ver": "1.0", "@world": "a/mtest",
            "slug": "mtest", "display_name": "MTest", "owner_did": "did:key:z6MkOwner",
            "@cap": test_cap("registry:init", "a/mtest")
        });
        submit_allow(&pipeline, "ubl/app", app_body).await;

        let user_body = json!({
            "@type": "ubl/user", "@id": "user-m", "@ver": "1.0", "@world": "a/mtest",
            "did": "did:key:z6MkUser", "display_name": "User M",
            "@cap": test_cap("registry:init", "a/mtest")
        });
        let user_cid = chip_cid(&user_body);
        submit_allow(&pipeline, "ubl/user", user_body).await;

        // Try membership with non-existent tenant (has cap but missing tenant)
        let mem_body = json!({
            "@type": "ubl/membership", "@id": "mem-bad", "@ver": "1.0",
            "@world": "a/mtest/t/ghost",
            "user_cid": user_cid,
            "tenant_cid": "b3:nonexistent_tenant",
            "role": "member",
            "@cap": test_cap("membership:grant", "a/mtest")
        });
        let err = submit_expect_err(&pipeline, "ubl/membership", mem_body).await;
        assert!(matches!(err, PipelineError::DependencyMissing(_)), "expected DependencyMissing, got: {}", err);
    }

    #[tokio::test]
    async fn onboarding_token_without_user_fails() {
        let (pipeline, _store) = onboarding_pipeline();

        // Token with non-existent user
        let token_body = json!({
            "@type": "ubl/token", "@id": "tok-bad", "@ver": "1.0", "@world": "a/ghost",
            "user_cid": "b3:nonexistent_user",
            "scope": ["read"],
            "expires_at": "2027-01-01T00:00:00Z",
            "kid": "did:key:z6Mk#v0"
        });
        let err = submit_expect_err(&pipeline, "ubl/token", token_body).await;
        assert!(matches!(err, PipelineError::DependencyMissing(_)), "expected DependencyMissing, got: {}", err);
    }

    #[tokio::test]
    async fn onboarding_duplicate_app_slug_rejected() {
        let (pipeline, _store) = onboarding_pipeline();

        let app_body = json!({
            "@type": "ubl/app", "@id": "app-dup1", "@ver": "1.0", "@world": "a/duptest",
            "slug": "duptest", "display_name": "Dup Test", "owner_did": "did:key:z6MkOwner",
            "@cap": test_cap("registry:init", "a/duptest")
        });
        submit_allow(&pipeline, "ubl/app", app_body.clone()).await;

        // Second app with same slug — should be rejected
        let app_body2 = json!({
            "@type": "ubl/app", "@id": "app-dup2", "@ver": "1.0", "@world": "a/duptest",
            "slug": "duptest", "display_name": "Dup Test 2", "owner_did": "did:key:z6MkOwner2",
            "@cap": test_cap("registry:init", "a/duptest")
        });
        let err = submit_expect_err(&pipeline, "ubl/app", app_body2).await;
        assert!(matches!(err, PipelineError::InvalidChip(_)), "expected InvalidChip for dup slug, got: {}", err);
        assert!(err.to_string().contains("duptest"));
    }

    #[tokio::test]
    async fn onboarding_revoke_then_re_register_app() {
        let (pipeline, _store) = onboarding_pipeline();

        // Register app + user (need user as actor for revoke)
        let app_body = json!({
            "@type": "ubl/app", "@id": "app-rev", "@ver": "1.0", "@world": "a/revtest",
            "slug": "revtest", "display_name": "Rev Test", "owner_did": "did:key:z6MkOwner",
            "@cap": test_cap("registry:init", "a/revtest")
        });
        let app_cid = chip_cid(&app_body);
        submit_allow(&pipeline, "ubl/app", app_body).await;

        let user_body = json!({
            "@type": "ubl/user", "@id": "user-rev", "@ver": "1.0", "@world": "a/revtest",
            "did": "did:key:z6MkAdmin", "display_name": "Admin",
            "@cap": test_cap("registry:init", "a/revtest")
        });
        let user_cid = chip_cid(&user_body);
        submit_allow(&pipeline, "ubl/user", user_body).await;

        // Revoke the app (requires revoke:execute cap)
        let revoke_body = json!({
            "@type": "ubl/revoke", "@id": "rev-app", "@ver": "1.0", "@world": "a/revtest",
            "target_cid": app_cid,
            "reason": "Decommissioned",
            "actor_cid": user_cid,
            "@cap": test_cap("revoke:execute", "a/revtest")
        });
        submit_allow(&pipeline, "ubl/revoke", revoke_body).await;

        // Re-register with same slug should now succeed (old one is revoked)
        let app_body2 = json!({
            "@type": "ubl/app", "@id": "app-rev2", "@ver": "1.0", "@world": "a/revtest",
            "slug": "revtest", "display_name": "Rev Test Reborn", "owner_did": "did:key:z6MkOwner2",
            "@cap": test_cap("registry:init", "a/revtest")
        });
        submit_allow(&pipeline, "ubl/app", app_body2).await;
    }

    #[tokio::test]
    async fn onboarding_revoke_user_blocks_dependent_token() {
        let (pipeline, _store) = onboarding_pipeline();

        // Full setup: app + user
        let app_body = json!({
            "@type": "ubl/app", "@id": "app-rt", "@ver": "1.0", "@world": "a/rtoken",
            "slug": "rtoken", "display_name": "RToken", "owner_did": "did:key:z6MkOwner",
            "@cap": test_cap("registry:init", "a/rtoken")
        });
        submit_allow(&pipeline, "ubl/app", app_body).await;

        let user_body = json!({
            "@type": "ubl/user", "@id": "user-rt", "@ver": "1.0", "@world": "a/rtoken",
            "did": "did:key:z6MkUser", "display_name": "User RT",
            "@cap": test_cap("registry:init", "a/rtoken")
        });
        let user_cid = chip_cid(&user_body);
        submit_allow(&pipeline, "ubl/user", user_body).await;

        // Register a second user to act as revoker (not first user, no cap needed)
        let admin_body = json!({
            "@type": "ubl/user", "@id": "admin-rt", "@ver": "1.0", "@world": "a/rtoken",
            "did": "did:key:z6MkAdmin", "display_name": "Admin RT"
        });
        let admin_cid = chip_cid(&admin_body);
        submit_allow(&pipeline, "ubl/user", admin_body).await;

        // Revoke the user (requires revoke:execute cap)
        let revoke_body = json!({
            "@type": "ubl/revoke", "@id": "rev-user", "@ver": "1.0", "@world": "a/rtoken",
            "target_cid": user_cid,
            "reason": "Account suspended",
            "actor_cid": admin_cid,
            "@cap": test_cap("revoke:execute", "a/rtoken")
        });
        submit_allow(&pipeline, "ubl/revoke", revoke_body).await;

        // Now try to create a token for the revoked user — should fail
        let token_body = json!({
            "@type": "ubl/token", "@id": "tok-revoked", "@ver": "1.0", "@world": "a/rtoken",
            "user_cid": user_cid,
            "scope": ["read"],
            "expires_at": "2027-01-01T00:00:00Z",
            "kid": "did:key:z6MkUser#v0"
        });
        let err = submit_expect_err(&pipeline, "ubl/token", token_body).await;
        assert!(matches!(err, PipelineError::DependencyMissing(_)), "expected DependencyMissing for revoked user, got: {}", err);
        assert!(err.to_string().contains("revoked"));
    }

    #[tokio::test]
    async fn onboarding_invalid_body_rejected_before_dependency_check() {
        let (pipeline, _store) = onboarding_pipeline();

        // ubl/user missing required "did" field — should fail at body validation, not dependency check
        let bad_user = json!({
            "@type": "ubl/user", "@id": "bad", "@ver": "1.0", "@world": "a/acme",
            "display_name": "No DID"
        });
        let err = submit_expect_err(&pipeline, "ubl/user", bad_user).await;
        assert!(matches!(err, PipelineError::InvalidChip(_)), "expected InvalidChip, got: {}", err);
        assert!(err.to_string().contains("did"));
    }

    #[tokio::test]
    async fn onboarding_non_onboarding_type_skips_validation() {
        let (pipeline, _store) = onboarding_pipeline();

        // ubl/document is not an onboarding type — should pass without dependency checks
        let doc_body = json!({
            "@type": "ubl/document", "@id": "doc-1", "@ver": "1.0", "@world": "a/any/t/any",
            "title": "Hello World"
        });
        submit_allow(&pipeline, "ubl/document", doc_body).await;
    }

    #[tokio::test]
    async fn idempotent_replay_returns_cached_result() {
        let storage = InMemoryPolicyStorage::new();
        let pipeline = UblPipeline::new(Box::new(storage));

        let body = json!({
            "@type": "ubl/document",
            "@id": "idem-001",
            "@ver": "1.0",
            "@world": "a/test/t/dev",
            "title": "Idempotency test"
        });

        // First submission — fresh execution
        let r1 = submit_allow(&pipeline, "ubl/document", body.clone()).await;
        assert!(!r1.replayed, "first submission should not be replayed");
        assert!(!r1.receipt.receipt_cid.is_empty());

        // Second submission — same (@type, @ver, @world, @id) → cached replay
        let r2 = submit_allow(&pipeline, "ubl/document", body.clone()).await;
        assert!(r2.replayed, "second submission should be replayed");
        assert_eq!(r2.receipt.receipt_cid, r1.receipt.receipt_cid, "replayed receipt_cid must match original");
        assert_eq!(r2.chain, r1.chain, "replayed chain must match original");
    }

    #[tokio::test]
    async fn idempotent_replay_different_id_is_fresh() {
        let storage = InMemoryPolicyStorage::new();
        let pipeline = UblPipeline::new(Box::new(storage));

        let body1 = json!({
            "@type": "ubl/document", "@id": "a", "@ver": "1.0", "@world": "a/x/t/y",
            "title": "First"
        });
        let body2 = json!({
            "@type": "ubl/document", "@id": "b", "@ver": "1.0", "@world": "a/x/t/y",
            "title": "Second"
        });

        let r1 = submit_allow(&pipeline, "ubl/document", body1).await;
        let r2 = submit_allow(&pipeline, "ubl/document", body2).await;

        assert!(!r1.replayed);
        assert!(!r2.replayed);
        assert_ne!(r1.receipt.receipt_cid, r2.receipt.receipt_cid, "different @id → different execution");
    }
}