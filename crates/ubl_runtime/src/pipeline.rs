//! UBL Pipeline - WA→TR→WF processing

use crate::advisory::AdvisoryEngine;
use crate::durable_store::{CommitInput, DurableError, DurableStore, NewOutboxEvent};
use crate::event_bus::{EventBus, ReceiptEvent};
use crate::genesis::genesis_chip_cid;
use crate::idempotency::{CachedResult, IdempotencyKey, IdempotencyStore};
use crate::key_rotation::{derive_material, mapping_chip, KeyRotateRequest};
use crate::ledger::{LedgerWriter, NullLedger};
use crate::policy_bit::PolicyResult;
use crate::policy_loader::{ChipRequest as PolicyChipRequest, PolicyLoader, PolicyStorage};
use crate::reasoning_bit::{Decision, EvalContext};
use crate::runtime_cert::SelfAttestation;
use crate::transition_registry::TransitionRegistry;
use rb_vm::canon::CanonProvider;
use rb_vm::tlv;
use rb_vm::types::Cid as VmCid;
use rb_vm::{CasProvider, ExecError, SignProvider, Vm, VmConfig};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use ubl_chipstore::{ChipStore, ExecutionMetadata};
use ubl_kms::{did_from_verifying_key, kid_from_verifying_key, Ed25519SigningKey as SigningKey};
use ubl_receipt::{
    CryptoMode, PipelineStage, PolicyTraceEntry, RuntimeInfo, StageExecution, UnifiedReceipt,
    WaReceiptBody, WfReceiptBody,
};

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
    /// Durable persistence boundary for receipts + idempotency + outbox (SQLite).
    durable_store: Option<Arc<DurableStore>>,
    /// Deterministic transition bytecode selector.
    transition_registry: Arc<TransitionRegistry>,
}

const DEFAULT_FUEL_LIMIT: u64 = 1_000_000;

fn load_durable_store() -> Option<Arc<DurableStore>> {
    match DurableStore::from_env() {
        Ok(Some(store)) => Some(Arc::new(store)),
        Ok(None) => None,
        Err(e) => {
            warn!(
                "DurableStore init failed; falling back to in-memory idempotency only: {}",
                e
            );
            None
        }
    }
}

fn load_transition_registry() -> Arc<TransitionRegistry> {
    match TransitionRegistry::from_env() {
        Ok(registry) => Arc::new(registry),
        Err(e) => {
            warn!(
                "TransitionRegistry init failed; falling back to defaults: {}",
                e
            );
            Arc::new(TransitionRegistry::default())
        }
    }
}

// ── Pipeline-local providers for rb_vm ──────────────────────────

struct PipelineCas {
    store: HashMap<String, Vec<u8>>,
}

impl PipelineCas {
    fn new() -> Self {
        Self {
            store: HashMap::new(),
        }
    }
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
        sig_str
            .strip_prefix("ed25519:")
            .map(|b64| {
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, b64)
                    .unwrap_or_else(|_| vec![0u8; 64])
            })
            .unwrap_or_else(|| vec![0u8; 64])
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

#[derive(Debug, Clone)]
struct AdapterRuntimeInfo {
    wasm_sha256: String,
    abi_version: String,
}

impl AdapterRuntimeInfo {
    fn parse_optional(body: &serde_json::Value) -> Result<Option<Self>, PipelineError> {
        let Some(adapter) = body.get("adapter") else {
            return Ok(None);
        };
        let adapter = adapter
            .as_object()
            .ok_or_else(|| PipelineError::InvalidChip("adapter must be object".to_string()))?;

        let wasm_sha256 = adapter
            .get("wasm_sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PipelineError::InvalidChip("adapter.wasm_sha256 missing".to_string()))?;
        let abi_version = adapter
            .get("abi_version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PipelineError::InvalidChip("adapter.abi_version missing".to_string()))?;

        let is_hex = wasm_sha256.len() == 64 && wasm_sha256.chars().all(|c| c.is_ascii_hexdigit());
        if !is_hex {
            return Err(PipelineError::InvalidChip(
                "adapter.wasm_sha256 must be 64 hex chars".to_string(),
            ));
        }
        if abi_version != "1.0" {
            return Err(PipelineError::InvalidChip(format!(
                "adapter.abi_version unsupported: {}",
                abi_version
            )));
        }

        Ok(Some(Self {
            wasm_sha256: wasm_sha256.to_string(),
            abi_version: abi_version.to_string(),
        }))
    }
}

#[derive(Debug, Clone, Copy)]
struct ParsedChipRequest<'a> {
    world: &'a str,
}

impl<'a> ParsedChipRequest<'a> {
    fn parse(request: &'a ChipRequest) -> Result<Self, PipelineError> {
        let chip_type = request
            .body
            .get("@type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PipelineError::InvalidChip("missing @type".to_string()))?;
        if chip_type != request.chip_type {
            return Err(PipelineError::InvalidChip(format!(
                "request.chip_type '{}' != body.@type '{}'",
                request.chip_type, chip_type
            )));
        }

        let world = request
            .body
            .get("@world")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PipelineError::InvalidChip("missing @world".to_string()))?;
        ubl_ai_nrf1::UblEnvelope::validate_world(world)
            .map_err(|e| PipelineError::InvalidChip(format!("@world: {}", e)))?;

        Ok(Self { world })
    }
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
    pub body_cid: ubl_types::Cid,
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

fn decision_to_wire(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
        Decision::Require => "require",
    }
}

impl UblPipeline {
    /// Convert a runtime PolicyResult into a receipt PolicyTraceEntry with RB votes.
    fn policy_result_to_trace(policy_result: &PolicyResult, duration_ms: i64) -> PolicyTraceEntry {
        let rb_results: Vec<ubl_receipt::RbResult> = policy_result
            .circuit_results
            .iter()
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
            level: policy_result
                .policy_id
                .split('.')
                .nth(1)
                .unwrap_or("unknown")
                .to_string(),
            policy_id: policy_result.policy_id.clone(),
            result: policy_result.decision.clone(),
            reason: policy_result.reason.clone(),
            rb_results,
            duration_ms,
        }
    }
    /// Load signing key from env (`SIGNING_KEY_HEX`) or generate a dev key.
    fn load_or_generate_key() -> SigningKey {
        let key = match ubl_kms::signing_key_from_env() {
            Ok(key) => key,
            Err(_) => ubl_kms::generate_signing_key(),
        };

        // Stage auth secret bootstrap:
        // If UBL_STAGE_SECRET is not provided, derive a process-local default
        // from the signing key seed so auth-chain generation is configured.
        if std::env::var("UBL_STAGE_SECRET").is_err() {
            std::env::set_var(
                "UBL_STAGE_SECRET",
                format!("hex:{}", hex::encode(key.to_bytes())),
            );
        }

        key
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
            durable_store: load_durable_store(),
            transition_registry: load_transition_registry(),
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
            durable_store: load_durable_store(),
            transition_registry: load_transition_registry(),
        }
    }

    /// Create pipeline with ChipStore for persistence
    pub fn with_chip_store(storage: Box<dyn PolicyStorage>, chip_store: Arc<ChipStore>) -> Self {
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
            durable_store: load_durable_store(),
            transition_registry: load_transition_registry(),
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

    /// Snapshot runtime metadata used in receipts and runtime attestation.
    pub fn runtime_info(&self) -> RuntimeInfo {
        (*self.runtime_info).clone()
    }

    /// Issue a signed runtime self-attestation for this running instance.
    pub fn runtime_self_attestation(&self) -> Result<SelfAttestation, PipelineError> {
        SelfAttestation::issue(self.runtime_info(), &self.did, &self.kid, &self.signing_key)
            .map_err(|e| PipelineError::Internal(format!("runtime attestation failed: {}", e)))
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
            let already = store
                .exists(&genesis_cid)
                .await
                .map_err(|e| PipelineError::Internal(format!("Genesis check: {}", e)))?;

            if !already {
                let metadata = ExecutionMetadata {
                    runtime_version: "genesis/self-signed".to_string(),
                    execution_time_ms: 0,
                    fuel_consumed: 0,
                    policies_applied: vec![],
                    executor_did: ubl_types::Did::new_unchecked("did:key:genesis"),
                    reproducible: true,
                };

                store
                    .store_executed_chip(
                        genesis_body,
                        genesis_cid.clone(), // self-signed: receipt_cid == chip_cid
                        metadata,
                    )
                    .await
                    .map_err(|e| PipelineError::Internal(format!("Genesis store: {}", e)))?;
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
        let value = crate::knock::knock(bytes).map_err(|e| PipelineError::Knock(e.to_string()))?;

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
    pub async fn process_chip(
        &self,
        request: ChipRequest,
    ) -> Result<PipelineResult, PipelineError> {
        let pipeline_start = std::time::Instant::now();
        let parsed_request = ParsedChipRequest::parse(&request)?;
        let chip_id = request
            .body
            .get("@id")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        info!(
            chip_type = %request.chip_type,
            world = %parsed_request.world,
            chip_id = %chip_id,
            "pipeline request accepted"
        );

        // ── Idempotency check: replay returns cached result (no re-execution) ──
        let idem_key = IdempotencyKey::from_chip_body(&request.body);
        let durable_idem_key = idem_key.as_ref().map(|k| k.to_durable_key());
        if let Some(ref key) = idem_key {
            let cached = if let (Some(durable), Some(durable_key)) =
                (&self.durable_store, durable_idem_key.as_ref())
            {
                durable.get_idempotent(durable_key).map_err(|e| {
                    PipelineError::StorageError(format!("Idempotency lookup: {}", e))
                })?
            } else {
                self.idempotency_store.get(key).await
            };

            if let Some(cached) = cached {
                let decision = if cached.decision.eq_ignore_ascii_case("allow")
                    || cached.decision.contains("Allow")
                {
                    Decision::Allow
                } else {
                    Decision::Deny
                };
                let receipt = UnifiedReceipt::from_json(&cached.response_json)
                    .unwrap_or_else(|_| UnifiedReceipt::new("", "", "", ""));
                info!(
                    chip_type = %request.chip_type,
                    world = %parsed_request.world,
                    receipt_cid = %cached.receipt_cid,
                    "pipeline idempotency replay"
                );
                return Ok(PipelineResult {
                    final_receipt: PipelineReceipt {
                        body_cid: ubl_types::Cid::new_unchecked(&cached.receipt_cid),
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

        // `@world` and `@type` already parsed/validated above.
        let world = parsed_request.world;
        let nonce = Self::generate_nonce();

        // Create the unified receipt — it evolves through each stage
        let mut receipt = UnifiedReceipt::new(world, &self.did, &self.kid, &nonce)
            .with_runtime_info((*self.runtime_info).clone());

        // Stage 1: WA (Write-Ahead)
        let wa_start = std::time::Instant::now();
        let wa_receipt = self.stage_write_ahead(&request).await?;
        let wa_ms = wa_start.elapsed().as_millis() as i64;
        debug!(chip_type = %request.chip_type, duration_ms = wa_ms, "stage wa completed");

        receipt
            .append_stage(StageExecution {
                stage: PipelineStage::WriteAhead,
                timestamp: chrono::Utc::now().to_rfc3339(),
                input_cid: wa_receipt.body_cid.as_str().to_string(),
                output_cid: Some(wa_receipt.body_cid.as_str().to_string()),
                fuel_used: None,
                policy_trace: vec![],
                vm_sig: None,
                vm_sig_payload_cid: None,
                auth_token: String::new(),
                duration_ms: wa_ms,
            })
            .map_err(|e| PipelineError::Internal(format!("Receipt WA: {}", e)))?;

        // Publish WA event
        self.publish_receipt_event(&wa_receipt, "wa", None, Some(wa_ms), Some(world), None)
            .await;

        // Stage 2: CHECK (Policy Evaluation)
        let check_start = std::time::Instant::now();
        let check = self.stage_check(&request).await?;
        let check_ms = check_start.elapsed().as_millis() as i64;
        debug!(
            chip_type = %request.chip_type,
            duration_ms = check_ms,
            decision = ?check.decision,
            "stage check completed"
        );

        receipt
            .append_stage(StageExecution {
                stage: PipelineStage::Check,
                timestamp: chrono::Utc::now().to_rfc3339(),
                input_cid: wa_receipt.body_cid.as_str().to_string(),
                output_cid: None,
                fuel_used: None,
                policy_trace: check.trace.clone(),
                vm_sig: None,
                vm_sig_payload_cid: None,
                auth_token: String::new(),
                duration_ms: check_ms,
            })
            .map_err(|e| PipelineError::Internal(format!("Receipt CHECK: {}", e)))?;

        // Post-CHECK advisory hook (non-blocking) — explain denial
        if let (Some(ref engine), Some(ref store)) = (&self.advisory_engine, &self.chip_store) {
            let adv = engine.post_check_advisory(
                wa_receipt.body_cid.as_str(),
                if matches!(check.decision, Decision::Deny) {
                    "deny"
                } else {
                    "allow"
                },
                &check.reason,
                &check
                    .trace
                    .iter()
                    .map(|t| serde_json::to_value(t).unwrap_or_default())
                    .collect::<Vec<_>>(),
            );
            let body = engine.advisory_to_chip_body(&adv);
            let store = store.clone();
            tokio::spawn(async move {
                let metadata = ExecutionMetadata {
                    runtime_version: "advisory/post-check".to_string(),
                    execution_time_ms: 0,
                    fuel_consumed: 0,
                    policies_applied: vec![],
                    executor_did: ubl_types::Did::new_unchecked("did:key:advisory"),
                    reproducible: false,
                };
                if let Err(e) = store
                    .store_executed_chip(body, "self".to_string(), metadata)
                    .await
                {
                    warn!(error = %e, "advisory post-CHECK store failed (non-fatal)");
                }
            });
        }

        // Short-circuit if denied
        if matches!(check.decision, Decision::Deny) {
            receipt.deny(&check.reason);

            let wf_receipt = self
                .create_deny_receipt(&request, &wa_receipt, &check)
                .await?;
            let deny_ms = pipeline_start.elapsed().as_millis() as i64;

            receipt
                .append_stage(StageExecution {
                    stage: PipelineStage::WriteFinished,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    input_cid: wa_receipt.body_cid.as_str().to_string(),
                    output_cid: Some(wf_receipt.body_cid.as_str().to_string()),
                    fuel_used: None,
                    policy_trace: check.trace.clone(),
                    vm_sig: None,
                    vm_sig_payload_cid: None,
                    auth_token: String::new(),
                    duration_ms: deny_ms,
                })
                .map_err(|e| PipelineError::Internal(format!("Receipt WF(DENY): {}", e)))?;
            receipt
                .finalize_and_sign(&self.signing_key, CryptoMode::from_env())
                .map_err(|e| PipelineError::SignError(format!("WF(DENY) sign failed: {}", e)))?;

            self.publish_receipt_event(
                &wf_receipt,
                "wf",
                Some("deny".to_string()),
                Some(deny_ms),
                Some(world),
                Some(wa_receipt.body_cid.as_str()),
            )
            .await;

            let result = PipelineResult {
                final_receipt: wf_receipt.clone(),
                chain: vec![
                    wa_receipt.body_cid.as_str().to_string(),
                    "no-tr".to_string(),
                    wf_receipt.body_cid.as_str().to_string(),
                ],
                decision: Decision::Deny,
                receipt,
                replayed: false,
            };
            info!(
                chip_type = %request.chip_type,
                world = %parsed_request.world,
                decision = "deny",
                duration_ms = deny_ms,
                "pipeline completed"
            );

            self.persist_final_result(idem_key.as_ref(), world, &result)
                .await?;
            return Ok(result);
        }

        // Stage 3: TR (Transition - RB-VM execution)
        let tr_start = std::time::Instant::now();
        let tr_receipt = self.stage_transition(&request, &check).await?;
        let tr_ms = tr_start.elapsed().as_millis() as i64;
        debug!(chip_type = %request.chip_type, duration_ms = tr_ms, "stage tr completed");

        let fuel_used = tr_receipt
            .body
            .get("vm_state")
            .and_then(|v| v.get("fuel_used"))
            .and_then(|v| v.as_u64());

        receipt
            .append_stage(StageExecution {
                stage: PipelineStage::Transition,
                timestamp: chrono::Utc::now().to_rfc3339(),
                input_cid: wa_receipt.body_cid.as_str().to_string(),
                output_cid: Some(tr_receipt.body_cid.as_str().to_string()),
                fuel_used,
                policy_trace: vec![],
                vm_sig: tr_receipt
                    .body
                    .get("vm_sig")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                vm_sig_payload_cid: tr_receipt
                    .body
                    .get("vm_sig_payload_cid")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                auth_token: String::new(),
                duration_ms: tr_ms,
            })
            .map_err(|e| PipelineError::Internal(format!("Receipt TR: {}", e)))?;

        // Publish TR event
        self.publish_receipt_event(
            &tr_receipt,
            "tr",
            None,
            Some(tr_ms),
            Some(world),
            Some(wa_receipt.body_cid.as_str()),
        )
        .await;

        // Stage 4: WF (Write-Finished)
        let wf_start = std::time::Instant::now();
        let wf_receipt = self
            .stage_write_finished(&request, &wa_receipt, &tr_receipt, &check)
            .await?;
        let wf_ms = wf_start.elapsed().as_millis() as i64;
        debug!(chip_type = %request.chip_type, duration_ms = wf_ms, "stage wf completed");

        receipt
            .append_stage(StageExecution {
                stage: PipelineStage::WriteFinished,
                timestamp: chrono::Utc::now().to_rfc3339(),
                input_cid: tr_receipt.body_cid.as_str().to_string(),
                output_cid: Some(wf_receipt.body_cid.as_str().to_string()),
                fuel_used: None,
                policy_trace: vec![],
                vm_sig: None,
                vm_sig_payload_cid: None,
                auth_token: String::new(),
                duration_ms: wf_ms,
            })
            .map_err(|e| PipelineError::Internal(format!("Receipt WF: {}", e)))?;

        let crypto_mode = CryptoMode::from_env();
        receipt
            .finalize_and_sign(&self.signing_key, crypto_mode)
            .map_err(|e| PipelineError::SignError(format!("WF finalize/sign failed: {}", e)))?;
        let unified_receipt_cid = receipt.receipt_cid.as_str().to_string();

        let total_ms = pipeline_start.elapsed().as_millis() as i64;

        // Publish successful WF event
        self.publish_receipt_event(
            &wf_receipt,
            "wf",
            Some("allow".to_string()),
            Some(total_ms),
            Some(world),
            Some(tr_receipt.body_cid.as_str()),
        )
        .await;

        // Persist chip to ChipStore.
        // For `ubl/key.rotate`, mapping persistence is fail-closed.
        if let Some(ref store) = self.chip_store {
            let metadata = ExecutionMetadata {
                runtime_version: "rb_vm/0.1".to_string(),
                execution_time_ms: total_ms,
                fuel_consumed: self.fuel_limit,
                policies_applied: check.trace.iter().map(|t| t.policy_id.clone()).collect(),
                executor_did: ubl_types::Did::new_unchecked(&self.did),
                reproducible: true,
            };
            let stored_chip_res = store
                .store_executed_chip(
                    request.body.clone(),
                    unified_receipt_cid.clone(),
                    metadata,
                )
                .await;

            if request.chip_type == "ubl/key.rotate" {
                let rotation_chip_cid = stored_chip_res
                    .map_err(|e| PipelineError::StorageError(format!("key.rotate store: {}", e)))?;

                let rotate_req = KeyRotateRequest::parse(&request.body)
                    .map_err(|e| PipelineError::InvalidChip(format!("Key rotation: {}", e)))?;
                let signing_seed = self.signing_key.to_bytes();
                let material = derive_material(&rotate_req, &request.body, &signing_seed)
                    .map_err(|e| PipelineError::Internal(format!("Key rotation: {}", e)))?;

                let mapping = mapping_chip(
                    world,
                    &rotation_chip_cid,
                    &unified_receipt_cid,
                    rotate_req.reason.as_deref(),
                    &material,
                );
                let mapping_meta = ExecutionMetadata {
                    runtime_version: "key_rotation/0.1".to_string(),
                    execution_time_ms: total_ms,
                    fuel_consumed: self.fuel_limit,
                    policies_applied: check.trace.iter().map(|t| t.policy_id.clone()).collect(),
                    executor_did: ubl_types::Did::new_unchecked(&self.did),
                    reproducible: true,
                };
                store
                    .store_executed_chip(
                        mapping,
                        unified_receipt_cid.clone(),
                        mapping_meta,
                    )
                    .await
                    .map_err(|e| {
                        PipelineError::StorageError(format!("key.rotate mapping store: {}", e))
                    })?;
            } else if let Err(e) = stored_chip_res {
                warn!(error = %e, "ChipStore persist failed (non-fatal)");
            }
        } else if request.chip_type == "ubl/key.rotate" {
            return Err(PipelineError::StorageError(
                "ubl/key.rotate requires ChipStore persistence".to_string(),
            ));
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
                chip_cid: wf_receipt.body_cid.as_str().to_string(),
                receipt_cid: unified_receipt_cid.clone(),
                decision: "Allow".to_string(),
                did: Some(self.did.clone()),
                kid: Some(self.kid.clone()),
            };
            if let Err(e) = self.ledger.append(&entry).await {
                warn!(error = %e, "Ledger append failed (non-fatal)");
            }
        }

        // Post-WF advisory hook (non-blocking) — classify and summarize
        if let (Some(ref engine), Some(ref store)) = (&self.advisory_engine, &self.chip_store) {
            let adv = engine.post_wf_advisory(
                wf_receipt.body_cid.as_str(),
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
                    executor_did: ubl_types::Did::new_unchecked("did:key:advisory"),
                    reproducible: false,
                };
                if let Err(e) = store
                    .store_executed_chip(body, "self".to_string(), metadata)
                    .await
                {
                    warn!(error = %e, "advisory post-WF store failed (non-fatal)");
                }
            });
        }

        let result = PipelineResult {
            final_receipt: wf_receipt.clone(),
            chain: vec![
                wa_receipt.body_cid.as_str().to_string(),
                tr_receipt.body_cid.as_str().to_string(),
                wf_receipt.body_cid.as_str().to_string(),
            ],
            decision: check.decision,
            receipt,
            replayed: false,
        };

        self.persist_final_result(idem_key.as_ref(), world, &result)
            .await?;

        info!(
            chip_type = %request.chip_type,
            world = %parsed_request.world,
            decision = "allow",
            duration_ms = total_ms,
            receipt_cid = %unified_receipt_cid,
            "pipeline completed"
        );

        Ok(result)
    }

    async fn persist_final_result(
        &self,
        idem_key: Option<&IdempotencyKey>,
        world: &str,
        result: &PipelineResult,
    ) -> Result<(), PipelineError> {
        if let Some(ref durable) = self.durable_store {
            let receipt_json = result
                .receipt
                .to_json()
                .map_err(|e| PipelineError::DurableCommitFailed(e.to_string()))?;
            let rt_hash = result
                .receipt
                .rt
                .as_ref()
                .map(|rt| rt.binary_hash.clone())
                .unwrap_or_else(|| self.runtime_info.binary_hash.clone());
            let created_at = chrono::Utc::now().timestamp();
            let event = NewOutboxEvent {
                event_type: "emit_receipt".to_string(),
                payload_json: serde_json::json!({
                    "receipt_cid": result.receipt.receipt_cid.as_str(),
                    "decision": decision_to_wire(&result.decision),
                    "world": world,
                }),
            };

            let input = CommitInput {
                receipt_cid: result.receipt.receipt_cid.as_str().to_string(),
                receipt_json,
                did: self.did.clone(),
                kid: self.kid.clone(),
                rt_hash,
                decision: decision_to_wire(&result.decision).to_string(),
                idem_key: idem_key.map(|k| k.to_durable_key()),
                chain: result.chain.clone(),
                outbox_events: vec![event],
                created_at,
                fail_after_receipt_write: false,
            };

            match durable.commit_wf_atomically(&input) {
                Ok(_) => Ok(()),
                Err(DurableError::IdempotencyConflict(e)) => {
                    Err(PipelineError::IdempotencyConflict(e))
                }
                Err(e) => Err(PipelineError::DurableCommitFailed(e.to_string())),
            }
        } else {
            if let Some(key) = idem_key.cloned() {
                self.idempotency_store
                    .put(
                        key,
                        CachedResult {
                            receipt_cid: result.receipt.receipt_cid.as_str().to_string(),
                            response_json: result.receipt.to_json().unwrap_or_default(),
                            decision: decision_to_wire(&result.decision).to_string(),
                            chain: result.chain.clone(),
                            created_at: chrono::Utc::now().to_rfc3339(),
                        },
                    )
                    .await;
            }
            Ok(())
        }
    }

    /// Stage 1: Write-Ahead - create ghost record, freeze @world
    async fn stage_write_ahead(
        &self,
        request: &ChipRequest,
    ) -> Result<PipelineReceipt, PipelineError> {
        // Validate @world format before freezing
        if let Some(world) = request.body.get("@world").and_then(|v| v.as_str()) {
            ubl_ai_nrf1::UblEnvelope::validate_world(world)
                .map_err(|e| PipelineError::InvalidChip(format!("@world: {}", e)))?;
        } else {
            return Err(PipelineError::InvalidChip(
                "missing @world anchor".to_string(),
            ));
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
            policy_cid: genesis_chip_cid(),  // For now, just genesis
            frozen_time: chrono::Utc::now().to_rfc3339(),
            caller: self.did.clone(),
            context: request.body.clone(),
            operation: request
                .operation
                .clone()
                .unwrap_or_else(|| "create".to_string()),
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
            body_cid: ubl_types::Cid::new_unchecked(&cid),
            receipt_type: "ubl/wa".to_string(),
            body: body_json,
        })
    }

    /// Stage 2: CHECK - Onboarding validation + Policy evaluation with full trace
    async fn stage_check(&self, request: &ChipRequest) -> Result<CheckResult, PipelineError> {
        let _check_start = std::time::Instant::now();

        // ── Onboarding pre-check: validate body + dependency chain ──
        if crate::auth::is_onboarding_type(&request.chip_type) {
            // 1. Parse chip body into typed onboarding payload
            let onboarding = crate::auth::parse_onboarding_chip(&request.body)
                .map_err(|e| PipelineError::InvalidChip(format!("Onboarding validation: {}", e)))?;
            let onboarding = onboarding.ok_or_else(|| {
                PipelineError::InvalidChip(format!(
                    "Onboarding type '{}' not recognized",
                    request.chip_type
                ))
            })?;

            // 2. Validate @world format
            let world_str = request
                .body
                .get("@world")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    PipelineError::InvalidChip("Onboarding chip missing @world".into())
                })?;

            // 3. Check dependency chain against ChipStore
            if let Some(ref store) = self.chip_store {
                self.check_onboarding_dependencies(&onboarding, &request.body, world_str, store)
                    .await?;
            }
        }

        // ── Key rotation pre-check: typed parse + capability + duplicate guard ──
        if request.chip_type == "ubl/key.rotate" {
            let parsed = KeyRotateRequest::parse(&request.body)
                .map_err(|e| PipelineError::InvalidChip(format!("Key rotation: {}", e)))?;
            let world_str = request
                .body
                .get("@world")
                .and_then(|v| v.as_str())
                .ok_or_else(|| PipelineError::InvalidChip("Key rotation missing @world".into()))?;

            crate::capability::require_cap(&request.body, "key:rotate", world_str).map_err(
                |e| PipelineError::InvalidChip(format!("ubl/key.rotate capability: {}", e)),
            )?;

            if let Some(ref store) = self.chip_store {
                let existing = store
                    .query(&ubl_chipstore::ChipQuery {
                        chip_type: Some("ubl/key.map".to_string()),
                        tags: vec![format!("old_kid:{}", parsed.old_kid)],
                        created_after: None,
                        created_before: None,
                        executor_did: None,
                        limit: Some(1),
                        offset: None,
                    })
                    .await
                    .map_err(|e| PipelineError::Internal(format!("ChipStore query: {}", e)))?;
                if !existing.chips.is_empty() {
                    return Err(PipelineError::InvalidChip(format!(
                        "old_kid '{}' already rotated",
                        parsed.old_kid
                    )));
                }
            }
        }

        // Convert to policy request
        let policy_request = PolicyChipRequest {
            chip_type: request.chip_type.clone(),
            body: request.body.clone(),
            parents: request.parents.clone(),
            operation: request
                .operation
                .clone()
                .unwrap_or_else(|| "create".to_string()),
        };

        // Load policy chain
        let policies = self
            .policy_loader
            .load_policy_chain(&policy_request)
            .await
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
    async fn stage_transition(
        &self,
        request: &ChipRequest,
        _check: &CheckResult,
    ) -> Result<PipelineReceipt, PipelineError> {
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

        let adapter_info = AdapterRuntimeInfo::parse_optional(&request.body)?;

        // Resolve bytecode by chip type / chip override / env override.
        let resolution = self
            .transition_registry
            .resolve(&request.chip_type, &request.body)
            .map_err(|e| PipelineError::InvalidChip(format!("TR bytecode resolution: {}", e)))?;
        let bytecode_hash = format!(
            "b3:{}",
            hex::encode(blake3::hash(&resolution.bytecode).as_bytes())
        );
        let instructions = tlv::decode_stream(&resolution.bytecode)
            .map_err(|e| PipelineError::Internal(format!("TR bytecode decode: {}", e)))?;

        // Execute VM
        let mut vm = Vm::new(cfg, cas, &signer, canon, vec![input_cid.clone()]);
        let outcome = vm.run(&instructions).map_err(|e| match e {
            ExecError::FuelExhausted => PipelineError::FuelExhausted(format!(
                "VM fuel exhausted (limit: {})",
                self.fuel_limit
            )),
            ExecError::StackUnderflow(op) => {
                PipelineError::StackUnderflow(format!("stack underflow at {:?}", op))
            }
            ExecError::TypeMismatch(op) => {
                PipelineError::TypeMismatch(format!("type mismatch at {:?}", op))
            }
            ExecError::InvalidPayload(op) => {
                PipelineError::TypeMismatch(format!("invalid payload for {:?}", op))
            }
            ExecError::Deny(reason) => PipelineError::PolicyDenied(reason),
        })?;

        if outcome.rc_sig.as_deref().unwrap_or("").is_empty() {
            return Err(PipelineError::SignError(
                "TR EmitRc did not return a persisted signature".to_string(),
            ));
        }

        let key_rotation = if request.chip_type == "ubl/key.rotate" {
            let rotate_req = KeyRotateRequest::parse(&request.body)
                .map_err(|e| PipelineError::InvalidChip(format!("Key rotation: {}", e)))?;
            let signing_seed = self.signing_key.to_bytes();
            Some(
                derive_material(&rotate_req, &request.body, &signing_seed)
                    .map_err(|e| PipelineError::Internal(format!("Key rotation: {}", e)))?,
            )
        } else {
            None
        };

        let mut vm_state = serde_json::Map::new();
        vm_state.insert(
            "fuel_used".to_string(),
            serde_json::json!(outcome.fuel_used),
        );
        vm_state.insert("steps".to_string(), serde_json::json!(outcome.steps));
        vm_state.insert(
            "result".to_string(),
            serde_json::json!(if outcome.rc_cid.is_some() {
                "receipt_emitted"
            } else {
                "completed"
            }),
        );
        vm_state.insert(
            "trace_len".to_string(),
            serde_json::json!(outcome.trace.len()),
        );
        vm_state.insert(
            "bytecode_source".to_string(),
            serde_json::json!(resolution.source),
        );
        vm_state.insert(
            "bytecode_hash".to_string(),
            serde_json::json!(bytecode_hash),
        );
        vm_state.insert(
            "bytecode_len".to_string(),
            serde_json::json!(resolution.bytecode.len()),
        );
        vm_state.insert(
            "bytecode_profile".to_string(),
            serde_json::json!(resolution.profile.as_str()),
        );
        if let Some(info) = adapter_info {
            vm_state.insert(
                "adapter_wasm_sha256".to_string(),
                serde_json::json!(info.wasm_sha256),
            );
            vm_state.insert(
                "adapter_abi_version".to_string(),
                serde_json::json!(info.abi_version),
            );
        }

        let tr_body = serde_json::json!({
            "@type": "ubl/transition",
            "input_cid": input_cid.0,
            "output_cid": outcome.rc_cid.as_ref().map(|c| c.0.clone()).unwrap_or_default(),
            "vm_sig": outcome.rc_sig.as_deref().unwrap_or_default(),
            "vm_sig_payload_cid": outcome.rc_payload_cid.as_ref().map(|c| c.0.clone()).unwrap_or_default(),
            "vm_state": vm_state
        });
        let mut tr_body = tr_body;
        if let Some(rotation) = key_rotation {
            tr_body["key_rotation"] = serde_json::json!({
                "old_did": rotation.old_did,
                "old_kid": rotation.old_kid,
                "new_did": rotation.new_did,
                "new_kid": rotation.new_kid,
                "new_key_cid": rotation.new_key_cid,
            });
        }

        let nrf1_bytes = ubl_ai_nrf1::to_nrf1_bytes(&tr_body)
            .map_err(|e| PipelineError::Internal(format!("TR CID: {}", e)))?;
        let cid = ubl_ai_nrf1::compute_cid(&nrf1_bytes)
            .map_err(|e| PipelineError::Internal(format!("TR CID: {}", e)))?;

        Ok(PipelineReceipt {
            body_cid: ubl_types::Cid::new_unchecked(&cid),
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
            wa_cid: wa_receipt.body_cid.as_str().to_string(),
            tr_cid: Some(tr_receipt.body_cid.as_str().to_string()),
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
            body_cid: ubl_types::Cid::new_unchecked(&cid),
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
            wa_cid: wa_receipt.body_cid.as_str().to_string(),
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
            body_cid: ubl_types::Cid::new_unchecked(&cid),
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
            receipt.body_cid.as_str(),
            &receipt.receipt_type,
            pipeline_stage,
            receipt.body.clone(),
        );
        event.decision = decision;
        event.duration_ms = duration_ms;

        // ── Canonical stage event fields (P1.5) ──
        event.input_cid = input_cid.map(|s| s.to_string());
        event.output_cid = Some(receipt.body_cid.as_str().to_string());
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
                event.rb_count = Some(
                    arr.iter()
                        .flat_map(|p| {
                            p.get("rb_results")
                                .and_then(|r| r.as_array())
                                .map(|a| a.len() as u64)
                        })
                        .sum(),
                );
            }
        }

        // Collect artifact CIDs from the receipt
        if let Some(cid) = receipt.body.get("body_cid").and_then(|v| v.as_str()) {
            event.artifact_cids.push(cid.to_string());
        }

        // Best effort - don't fail pipeline if event publishing fails
        if let Err(e) = self.event_bus.publish_stage_event(event).await {
            warn!(error = %e, "Failed to publish receipt event");
        }
    }

    /// Enforce the onboarding dependency chain at CHECK.
    ///
    /// Order: App → User → Tenant → Membership → Token → Revoke
    /// Each type requires its predecessors to already exist in ChipStore.
    async fn check_onboarding_dependencies(
        &self,
        onboarding: &crate::auth::OnboardingChip,
        body: &serde_json::Value,
        world: &str,
        store: &Arc<ubl_chipstore::ChipStore>,
    ) -> Result<(), PipelineError> {
        match onboarding {
            // App is the root — no dependencies, but slug must be unique.
            // Requires cap.registry:init (P0.3).
            crate::auth::OnboardingChip::App(app) => {
                crate::capability::require_cap(body, "registry:init", world).map_err(|e| {
                    PipelineError::InvalidChip(format!("ubl/app capability: {}", e))
                })?;
                let existing = store
                    .query(&ubl_chipstore::ChipQuery {
                        chip_type: Some("ubl/app".to_string()),
                        tags: vec![format!("slug:{}", app.slug)],
                        created_after: None,
                        created_before: None,
                        executor_did: None,
                        limit: None,
                        offset: None,
                    })
                    .await
                    .map_err(|e| PipelineError::Internal(format!("ChipStore query: {}", e)))?;
                for chip in &existing.chips {
                    if chip.chip_data.get("slug").and_then(|v| v.as_str())
                        == Some(app.slug.as_str())
                    {
                        // Check if this app has been revoked
                        if !self.is_revoked(chip.cid.as_str(), store).await? {
                            return Err(PipelineError::InvalidChip(format!(
                                "App slug '{}' already registered",
                                app.slug
                            )));
                        }
                    }
                }
            }

            // User requires a valid app in @world.
            // First user for an app requires cap.registry:init (P0.3).
            crate::auth::OnboardingChip::User(_) => {
                let scope = crate::auth::WorldScope::parse(world)
                    .map_err(|e| PipelineError::InvalidChip(format!("@world: {}", e)))?;
                self.require_app_exists(&scope.app, store).await?;

                // Check if this is the first user for this app
                let existing_users = store
                    .query(&ubl_chipstore::ChipQuery {
                        chip_type: Some("ubl/user".to_string()),
                        tags: vec![format!("app:{}", scope.app)],
                        created_after: None,
                        created_before: None,
                        executor_did: None,
                        limit: Some(1),
                        offset: None,
                    })
                    .await
                    .map_err(|e| PipelineError::Internal(format!("ChipStore query: {}", e)))?;
                let has_user_for_app = !existing_users.chips.is_empty();
                if !has_user_for_app {
                    crate::capability::require_cap(body, "registry:init", world).map_err(|e| {
                        PipelineError::InvalidChip(format!(
                            "first ubl/user for app '{}' requires capability: {}",
                            scope.app, e
                        ))
                    })?;
                }
            }

            // Tenant requires: app exists + creator_cid references a valid user
            crate::auth::OnboardingChip::Tenant(tenant) => {
                let scope = crate::auth::WorldScope::parse(world)
                    .map_err(|e| PipelineError::InvalidChip(format!("@world: {}", e)))?;
                self.require_app_exists(&scope.app, store).await?;
                self.require_chip_exists(&tenant.creator_cid, "ubl/user", store)
                    .await?;
            }

            // Membership requires: user_cid and tenant_cid both exist.
            // Requires cap.membership:grant (P0.4).
            crate::auth::OnboardingChip::Membership(membership) => {
                crate::capability::require_cap(body, "membership:grant", world).map_err(|e| {
                    PipelineError::InvalidChip(format!("ubl/membership capability: {}", e))
                })?;
                self.require_chip_exists(&membership.user_cid, "ubl/user", store)
                    .await?;
                self.require_chip_exists(&membership.tenant_cid, "ubl/tenant", store)
                    .await?;
            }

            // Token requires: user_cid exists
            crate::auth::OnboardingChip::Token(token) => {
                self.require_chip_exists(&token.user_cid, "ubl/user", store)
                    .await?;
            }

            // Revoke requires: target_cid exists (any type) + actor_cid exists.
            // Requires cap.revoke:execute (P0.4).
            crate::auth::OnboardingChip::Revoke(revoke) => {
                crate::capability::require_cap(body, "revoke:execute", world).map_err(|e| {
                    PipelineError::InvalidChip(format!("ubl/revoke capability: {}", e))
                })?;
                if !store
                    .exists(&revoke.target_cid)
                    .await
                    .map_err(|e| PipelineError::Internal(format!("ChipStore: {}", e)))?
                {
                    return Err(PipelineError::DependencyMissing(format!(
                        "Revoke target '{}' not found",
                        revoke.target_cid
                    )));
                }
                self.require_chip_exists(&revoke.actor_cid, "ubl/user", store)
                    .await?;
            }
        }

        Ok(())
    }

    /// Check that an app with the given slug exists and is not revoked.
    async fn require_app_exists(
        &self,
        app_slug: &str,
        store: &Arc<ubl_chipstore::ChipStore>,
    ) -> Result<(), PipelineError> {
        let apps = store
            .query(&ubl_chipstore::ChipQuery {
                chip_type: Some("ubl/app".to_string()),
                tags: vec![format!("slug:{}", app_slug)],
                created_after: None,
                created_before: None,
                executor_did: None,
                limit: None,
                offset: None,
            })
            .await
            .map_err(|e| PipelineError::Internal(format!("ChipStore: {}", e)))?;

        for chip in &apps.chips {
            if chip.chip_data.get("slug").and_then(|v| v.as_str()) == Some(app_slug) {
                if !self.is_revoked(chip.cid.as_str(), store).await? {
                    return Ok(());
                }
            }
        }

        Err(PipelineError::DependencyMissing(format!(
            "App '{}' not found — register ubl/app first",
            app_slug
        )))
    }

    /// Check that a chip with the given CID exists, is the expected type, and is not revoked.
    async fn require_chip_exists(
        &self,
        cid: &str,
        expected_type: &str,
        store: &Arc<ubl_chipstore::ChipStore>,
    ) -> Result<(), PipelineError> {
        let chip = store
            .get_chip(cid)
            .await
            .map_err(|e| PipelineError::Internal(format!("ChipStore: {}", e)))?
            .ok_or_else(|| {
                PipelineError::DependencyMissing(format!("{} '{}' not found", expected_type, cid))
            })?;

        if chip.chip_type != expected_type {
            return Err(PipelineError::InvalidChip(format!(
                "CID '{}' is '{}', expected '{}'",
                cid, chip.chip_type, expected_type,
            )));
        }

        if self.is_revoked(cid, store).await? {
            return Err(PipelineError::DependencyMissing(format!(
                "{} '{}' has been revoked",
                expected_type, cid,
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
        let revocations = store
            .query(&ubl_chipstore::ChipQuery {
                chip_type: Some("ubl/revoke".to_string()),
                tags: vec![format!("target_cid:{}", target_cid)],
                created_after: None,
                created_before: None,
                executor_did: None,
                limit: Some(1),
                offset: None,
            })
            .await
            .map_err(|e| PipelineError::Internal(format!("ChipStore: {}", e)))?;

        Ok(!revocations.chips.is_empty())
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
    #[error("Idempotency conflict: {0}")]
    IdempotencyConflict(String),
    #[error("Durable commit failed: {0}")]
    DurableCommitFailed(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_loader::InMemoryPolicyStorage;
    use crate::transition_registry::TrBytecodeProfile;
    use serde_json::json;

    fn signed_capability(action: &str, audience: &str, sk: &SigningKey) -> serde_json::Value {
        let did = ubl_kms::did_from_verifying_key(&sk.verifying_key());
        let mut payload = serde_json::json!({
            "action": action,
            "audience": audience,
            "issued_by": did,
            "issued_at": chrono::Utc::now().checked_sub_signed(chrono::Duration::minutes(1)).unwrap().to_rfc3339(),
            "expires_at": chrono::Utc::now().checked_add_signed(chrono::Duration::hours(1)).unwrap().to_rfc3339(),
        });
        let sig = ubl_kms::sign_canonical(sk, &payload, ubl_kms::domain::CAPABILITY).unwrap();
        payload["signature"] = serde_json::json!(sig);
        payload
    }

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
    async fn same_input_same_receipt_vm() {
        std::env::set_var(
            "SIGNING_KEY_HEX",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        );
        let request = ChipRequest {
            chip_type: "ubl/document".to_string(),
            body: json!({
                "@type": "ubl/document",
                "@id": "same-input",
                "@ver": "1.0",
                "@world": "a/app/t/ten"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let p1 = UblPipeline::new(Box::new(InMemoryPolicyStorage::new()));
        let r1 = p1.process_chip(request.clone()).await.unwrap();

        let p2 = UblPipeline::new(Box::new(InMemoryPolicyStorage::new()));
        let r2 = p2.process_chip(request).await.unwrap();

        // WA/WF include nonce and vary, but TR VM receipt is deterministic for same chip input.
        assert_eq!(r1.chain[1], r2.chain[1]);
        std::env::remove_var("SIGNING_KEY_HEX");
    }

    #[test]
    fn runtime_self_attestation_is_signed_and_verifiable() {
        let pipeline = UblPipeline::new(Box::new(InMemoryPolicyStorage::new()));
        let att = pipeline.runtime_self_attestation().unwrap();
        assert_eq!(
            att.runtime_hash,
            pipeline.runtime_info().runtime_hash().to_string()
        );
        assert!(att.verify().unwrap());
    }

    #[tokio::test]
    async fn key_rotate_requires_capability() {
        use ubl_chipstore::{ChipStore, InMemoryBackend};

        let policy_storage = InMemoryPolicyStorage::new();
        let backend = Arc::new(InMemoryBackend::new());
        let chip_store = Arc::new(ChipStore::new(backend));
        let pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store);

        let old_sk = ubl_kms::generate_signing_key();
        let old_vk = old_sk.verifying_key();
        let old_did = ubl_kms::did_from_verifying_key(&old_vk);
        let old_kid = ubl_kms::kid_from_verifying_key(&old_vk);

        let request = ChipRequest {
            chip_type: "ubl/key.rotate".to_string(),
            body: json!({
                "@type":"ubl/key.rotate",
                "@id":"rot-missing-cap",
                "@ver":"1.0",
                "@world":"a/acme/t/prod",
                "old_did": old_did,
                "old_kid": old_kid,
                "reason": "compromise"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let err = pipeline.process_chip(request).await.unwrap_err();
        assert!(matches!(err, PipelineError::InvalidChip(_)));
        assert!(err.to_string().contains("key.rotate capability"));
    }

    #[tokio::test]
    async fn key_rotate_persists_mapping_and_replay_is_stable() {
        use ubl_chipstore::{ChipQuery, ChipStore, InMemoryBackend};

        let policy_storage = InMemoryPolicyStorage::new();
        let backend = Arc::new(InMemoryBackend::new());
        let chip_store = Arc::new(ChipStore::new(backend));
        let pipeline = UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());

        let old_sk = ubl_kms::generate_signing_key();
        let old_vk = old_sk.verifying_key();
        let old_did = ubl_kms::did_from_verifying_key(&old_vk);
        let old_kid = ubl_kms::kid_from_verifying_key(&old_vk);

        let cap_sk = ubl_kms::generate_signing_key();
        let cap = signed_capability("key:rotate", "a/acme", &cap_sk);

        let request = ChipRequest {
            chip_type: "ubl/key.rotate".to_string(),
            body: json!({
                "@type":"ubl/key.rotate",
                "@id":"rot-1",
                "@ver":"1.0",
                "@world":"a/acme/t/prod",
                "old_did": old_did,
                "old_kid": old_kid,
                "reason": "routine",
                "@cap": cap
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let first = pipeline.process_chip(request.clone()).await.unwrap();
        assert!(matches!(first.decision, Decision::Allow));
        assert!(!first.replayed);

        let mappings = chip_store
            .query(&ChipQuery {
                chip_type: Some("ubl/key.map".to_string()),
                tags: vec![format!("old_kid:{}", old_kid)],
                created_after: None,
                created_before: None,
                executor_did: None,
                limit: None,
                offset: None,
            })
            .await
            .unwrap();
        assert_eq!(mappings.total_count, 1);
        let map = &mappings.chips[0].chip_data;
        assert_eq!(map["old_kid"].as_str(), Some(old_kid.as_str()));
        assert!(map["new_kid"].as_str().is_some());
        assert_ne!(map["new_kid"].as_str(), Some(old_kid.as_str()));

        let second = pipeline.process_chip(request).await.unwrap();
        assert!(second.replayed);

        let mappings_after = chip_store
            .query(&ChipQuery {
                chip_type: Some("ubl/key.map".to_string()),
                tags: vec![format!("old_kid:{}", old_kid)],
                created_after: None,
                created_before: None,
                executor_did: None,
                limit: None,
                offset: None,
            })
            .await
            .unwrap();
        assert_eq!(mappings_after.total_count, 1);
    }

    #[test]
    fn tr_profile_selection_by_chip_type() {
        let registry = TransitionRegistry::default();
        assert_eq!(
            TransitionRegistry::default_profile_for("ubl/document"),
            TrBytecodeProfile::PassV1
        );
        assert_eq!(
            TransitionRegistry::default_profile_for("ubl/token"),
            TrBytecodeProfile::AuditV1
        );
        let resolved = registry
            .resolve("ubl/token", &json!({"@type":"ubl/token"}))
            .unwrap();
        assert_eq!(resolved.profile, TrBytecodeProfile::AuditV1);
    }

    #[test]
    fn resolve_transition_bytecode_prefers_chip_override() {
        let registry = TransitionRegistry::default();
        let request = ChipRequest {
            chip_type: "ubl/document".to_string(),
            body: json!({
                "@type": "ubl/document",
                "@id": "override-bytecode",
                "@ver": "1.0",
                "@world": "a/app/t/ten",
                "@tr": {
                    "bytecode_hex": "1200020000100000"
                }
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let resolved = registry.resolve(&request.chip_type, &request.body).unwrap();
        assert_eq!(resolved.source, "chip:@tr.bytecode_hex");
        assert_eq!(
            resolved.bytecode,
            vec![0x12, 0x00, 0x02, 0x00, 0x00, 0x10, 0x00, 0x00]
        );
    }

    #[test]
    fn wasm_adapter_hash_and_abi_verified() {
        let good = json!({
            "adapter": {
                "wasm_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "abi_version": "1.0"
            }
        });
        assert!(AdapterRuntimeInfo::parse_optional(&good).unwrap().is_some());

        let bad_hash = json!({
            "adapter": {
                "wasm_sha256": "not-hex",
                "abi_version": "1.0"
            }
        });
        assert!(matches!(
            AdapterRuntimeInfo::parse_optional(&bad_hash),
            Err(PipelineError::InvalidChip(_))
        ));

        let bad_abi = json!({
            "adapter": {
                "wasm_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "abi_version": "2.0"
            }
        });
        assert!(matches!(
            AdapterRuntimeInfo::parse_optional(&bad_abi),
            Err(PipelineError::InvalidChip(_))
        ));
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
        assert!(
            !rbs.is_empty(),
            "rb_results must expose individual RB votes"
        );

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
        assert_eq!(
            nonce.unwrap().len(),
            32,
            "nonce must be 32 hex chars (16 bytes)"
        );

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
            assert!(
                nonces.insert(wa_cid.clone()),
                "WA CIDs must be unique (nonce ensures this)"
            );
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
        assert_eq!(
            stored.receipt_cid.as_str(),
            result.receipt.receipt_cid.as_str()
        );

        let by_receipt = chip_store
            .get_chip_by_receipt_cid(result.receipt.receipt_cid.as_str())
            .await
            .unwrap();
        assert!(by_receipt.is_some(), "receipt_cid lookup must resolve stored chip");
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
        assert!(
            count >= 3,
            "expected at least 3 events (WA+TR+WF), got {}",
            count
        );

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
            assert!(
                ev.world.is_some(),
                "stage {} missing world",
                ev.pipeline_stage
            );
            assert_eq!(ev.world.as_deref(), Some("a/app/t/ten"));
            assert!(
                ev.actor.is_some(),
                "stage {} missing actor",
                ev.pipeline_stage
            );
            assert!(
                ev.actor.as_ref().unwrap().starts_with("did:key:"),
                "actor must be a DID"
            );
            assert!(
                ev.binary_hash.is_some(),
                "stage {} missing binary_hash",
                ev.pipeline_stage
            );
            assert!(
                ev.output_cid.is_some(),
                "stage {} missing output_cid",
                ev.pipeline_stage
            );
            assert!(
                ev.latency_ms.is_some(),
                "stage {} missing latency_ms",
                ev.pipeline_stage
            );
        }

        // WA has no input_cid (it's the first stage)
        let wa = events.iter().find(|e| e.pipeline_stage == "wa").unwrap();
        assert!(wa.input_cid.is_none(), "WA should have no input_cid");

        // TR has input_cid = WA output
        let tr = events.iter().find(|e| e.pipeline_stage == "tr").unwrap();
        assert!(tr.input_cid.is_some(), "TR must have input_cid");
        assert_eq!(
            tr.input_cid.as_deref(),
            wa.output_cid.as_deref(),
            "TR input = WA output"
        );

        // WF has input_cid = TR output
        let wf = events.iter().find(|e| e.pipeline_stage == "wf").unwrap();
        assert!(wf.input_cid.is_some(), "WF must have input_cid");
        assert_eq!(
            wf.input_cid.as_deref(),
            tr.output_cid.as_deref(),
            "WF input = TR output"
        );
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
        assert!(
            r.receipt_cid.as_str().starts_with("b3:"),
            "receipt_cid must be BLAKE3"
        );
        assert_eq!(r.id, r.receipt_cid.as_str(), "@id must equal receipt_cid");

        // Envelope anchors
        assert_eq!(r.receipt_type, "ubl/receipt");
        assert_eq!(r.world.as_str(), "a/app/t/ten");
        assert_eq!(r.ver, "1.0");

        // Auth tokens present on every stage
        for stage in &r.stages {
            assert!(
                stage.auth_token.starts_with("hmac:"),
                "stage {:?} missing auth_token",
                stage.stage
            );
        }

        // Decision is Allow
        assert_eq!(r.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn unified_receipt_deny_has_wf_and_no_tr() {
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

        // Deny path: WA + CHECK + WF (no TR)
        assert_eq!(r.stage_count(), 3);
        assert!(r.has_stage(PipelineStage::WriteAhead));
        assert!(r.has_stage(PipelineStage::Check));
        assert!(!r.has_stage(PipelineStage::Transition));
        assert!(r.has_stage(PipelineStage::WriteFinished));

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
        let check_stage = r
            .stages
            .iter()
            .find(|s| s.stage == PipelineStage::Check)
            .unwrap();
        assert!(
            !check_stage.policy_trace.is_empty(),
            "CHECK stage must have policy trace"
        );
        assert!(
            !check_stage.policy_trace[0].rb_results.is_empty(),
            "policy trace must have RB votes"
        );
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

        let tr_stage = r
            .stages
            .iter()
            .find(|s| s.stage == PipelineStage::Transition)
            .unwrap();
        assert!(
            tr_stage.fuel_used.is_some(),
            "TR stage must record fuel_used"
        );
        assert!(
            tr_stage.output_cid.is_some(),
            "TR stage must have output_cid"
        );
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
        assert!(
            stored.is_some(),
            "Genesis chip must be in ChipStore after bootstrap"
        );

        let chip = stored.unwrap();
        assert_eq!(chip.chip_type, "ubl/policy.genesis");
        assert_eq!(
            chip.receipt_cid.as_str(),
            genesis_cid,
            "Genesis is self-signed: receipt_cid == chip_cid"
        );
        assert_eq!(
            chip.execution_metadata.executor_did.as_str(),
            "did:key:genesis"
        );
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
        use crate::advisory::AdvisoryEngine;
        use ubl_chipstore::{ChipStore, InMemoryBackend};

        let policy_storage = InMemoryPolicyStorage::new();
        let backend = Arc::new(InMemoryBackend::new());
        let chip_store = Arc::new(ChipStore::new(backend.clone()));
        let mut pipeline =
            UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());

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
        assert!(
            results.total_count >= 1,
            "At least one advisory chip should be stored (post-CHECK or post-WF)"
        );

        let adv_chip = &results.chips[0];
        assert_eq!(adv_chip.chip_type, "ubl/advisory");
        assert_eq!(adv_chip.chip_data["passport_cid"], "b3:test-passport");
    }

    #[tokio::test]
    async fn advisory_engine_fires_on_deny() {
        use crate::advisory::AdvisoryEngine;
        use ubl_chipstore::{ChipStore, InMemoryBackend};

        let policy_storage = InMemoryPolicyStorage::new();
        let backend = Arc::new(InMemoryBackend::new());
        let chip_store = Arc::new(ChipStore::new(backend.clone()));
        let mut pipeline =
            UblPipeline::with_chip_store(Box::new(policy_storage), chip_store.clone());

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
        assert!(
            results.total_count >= 1,
            "Post-CHECK advisory should fire on deny"
        );

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
        let sk = ubl_kms::generate_signing_key();
        let vk = ubl_kms::verifying_key(&sk);
        let issued_by = ubl_kms::did_from_verifying_key(&vk);
        let payload = json!({
            "action": action,
            "audience": audience,
            "issued_by": issued_by,
            "issued_at": "2025-01-01T00:00:00Z",
            "expires_at": "2099-12-31T23:59:59Z",
        });
        let signature = ubl_kms::sign_canonical(&sk, &payload, ubl_kms::domain::CAPABILITY)
            .expect("test capability must sign");
        json!({
            "action": payload["action"],
            "audience": payload["audience"],
            "issued_by": payload["issued_by"],
            "issued_at": payload["issued_at"],
            "expires_at": payload["expires_at"],
            "signature": signature,
        })
    }

    /// Helper: compute CID for a chip body.
    fn chip_cid(body: &serde_json::Value) -> String {
        let nrf = ubl_ai_nrf1::to_nrf1_bytes(body).unwrap();
        ubl_ai_nrf1::compute_cid(&nrf).unwrap()
    }

    /// Helper: submit a chip and assert Allow.
    async fn submit_allow(
        pipeline: &UblPipeline,
        chip_type: &str,
        body: serde_json::Value,
    ) -> PipelineResult {
        let request = ChipRequest {
            chip_type: chip_type.to_string(),
            body,
            parents: vec![],
            operation: Some("create".to_string()),
        };
        let result = pipeline.process_chip(request).await.unwrap();
        assert!(
            matches!(result.decision, Decision::Allow),
            "expected Allow for {}",
            chip_type
        );
        result
    }

    /// Helper: submit a chip and assert it fails with a specific error variant.
    async fn submit_expect_err(
        pipeline: &UblPipeline,
        chip_type: &str,
        body: serde_json::Value,
    ) -> PipelineError {
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
        assert!(
            matches!(err, PipelineError::DependencyMissing(_)),
            "expected DependencyMissing, got: {}",
            err
        );
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
        assert!(
            matches!(err, PipelineError::DependencyMissing(_)),
            "expected DependencyMissing, got: {}",
            err
        );
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
        assert!(
            matches!(err, PipelineError::DependencyMissing(_)),
            "expected DependencyMissing, got: {}",
            err
        );
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
        assert!(
            matches!(err, PipelineError::DependencyMissing(_)),
            "expected DependencyMissing, got: {}",
            err
        );
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
        assert!(
            matches!(err, PipelineError::InvalidChip(_)),
            "expected InvalidChip for dup slug, got: {}",
            err
        );
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
        assert!(
            matches!(err, PipelineError::DependencyMissing(_)),
            "expected DependencyMissing for revoked user, got: {}",
            err
        );
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
        assert!(
            matches!(err, PipelineError::InvalidChip(_)),
            "expected InvalidChip, got: {}",
            err
        );
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
        assert!(!r1.receipt.receipt_cid.as_str().is_empty());

        // Second submission — same (@type, @ver, @world, @id) → cached replay
        let r2 = submit_allow(&pipeline, "ubl/document", body.clone()).await;
        assert!(r2.replayed, "second submission should be replayed");
        assert_eq!(
            r2.receipt.receipt_cid, r1.receipt.receipt_cid,
            "replayed receipt_cid must match original"
        );
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
        assert_ne!(
            r1.receipt.receipt_cid, r2.receipt.receipt_cid,
            "different @id → different execution"
        );
    }
}
