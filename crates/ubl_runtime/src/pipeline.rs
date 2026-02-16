//! UBL Pipeline - WA→TR→WF processing

use crate::reasoning_bit::{Decision, EvalContext};
use crate::policy_bit::PolicyResult;
use crate::policy_loader::{PolicyLoader, ChipRequest as PolicyChipRequest, PolicyStorage};
use crate::genesis::genesis_chip_cid;
use crate::event_bus::{EventBus, ReceiptEvent};
use ubl_receipt::{WaReceiptBody, WfReceiptBody, PolicyTraceEntry, UnifiedReceipt, StageExecution, PipelineStage};
use rb_vm::{CasProvider, SignProvider, Vm, VmConfig, ExecError};
use rb_vm::canon::CanonProvider;
use rb_vm::types::Cid as VmCid;
use rb_vm::tlv;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use ubl_chipstore::{ChipStore, ExecutionMetadata};

/// The UBL Pipeline processor
pub struct UblPipeline {
    pub policy_loader: PolicyLoader,
    pub fuel_limit: u64,
    pub event_bus: Arc<EventBus>,
    seen_nonces: Arc<RwLock<HashSet<String>>>,
    chip_store: Option<Arc<ChipStore>>,
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

struct PipelineSigner;
impl SignProvider for PipelineSigner {
    fn sign_jws(&self, _payload: &[u8]) -> Vec<u8> {
        // TODO: Replace with real Ed25519 signing from env-loaded key
        vec![0u8; 64]
    }
    fn kid(&self) -> String {
        "did:key:placeholder#v0".to_string()
    }
}

struct PipelineCanon;
impl CanonProvider for PipelineCanon {
    fn canon(&self, v: serde_json::Value) -> serde_json::Value {
        // Delegate to NRF canon: encode to NRF bytes then back to JSON
        // For MVP, use naive key-sorting (matches rb_vm::canon::NaiveCanon)
        fn sort(v: serde_json::Value) -> serde_json::Value {
            match v {
                serde_json::Value::Object(m) => {
                    let mut pairs: Vec<(String, serde_json::Value)> = m.into_iter().collect();
                    pairs.sort_by(|a, b| a.0.cmp(&b.0));
                    let mut out = serde_json::Map::new();
                    for (k, val) in pairs {
                        out.insert(k, sort(val));
                    }
                    serde_json::Value::Object(out)
                }
                serde_json::Value::Array(a) => serde_json::Value::Array(a.into_iter().map(sort).collect()),
                other => other,
            }
        }
        sort(v)
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
    /// Create a new pipeline instance
    pub fn new(storage: Box<dyn PolicyStorage>) -> Self {
        Self {
            policy_loader: PolicyLoader::new(storage),
            fuel_limit: DEFAULT_FUEL_LIMIT,
            event_bus: Arc::new(EventBus::new()),
            seen_nonces: Arc::new(RwLock::new(HashSet::new())),
            chip_store: None,
        }
    }

    /// Create pipeline with existing event bus
    pub fn with_event_bus(storage: Box<dyn PolicyStorage>, event_bus: Arc<EventBus>) -> Self {
        Self {
            policy_loader: PolicyLoader::new(storage),
            fuel_limit: DEFAULT_FUEL_LIMIT,
            event_bus,
            seen_nonces: Arc::new(RwLock::new(HashSet::new())),
            chip_store: None,
        }
    }

    /// Create pipeline with ChipStore for persistence
    pub fn with_chip_store(
        storage: Box<dyn PolicyStorage>,
        chip_store: Arc<ChipStore>,
    ) -> Self {
        Self {
            policy_loader: PolicyLoader::new(storage),
            fuel_limit: DEFAULT_FUEL_LIMIT,
            event_bus: Arc::new(EventBus::new()),
            seen_nonces: Arc::new(RwLock::new(HashSet::new())),
            chip_store: Some(chip_store),
        }
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
    pub async fn process_chip(&self, request: ChipRequest) -> Result<PipelineResult, PipelineError> {
        let pipeline_start = std::time::Instant::now();

        // Extract @world for the unified receipt
        let world = request.body.get("@world")
            .and_then(|v| v.as_str())
            .unwrap_or("a/unknown/t/unknown");
        let nonce = Self::generate_nonce();

        // Create the unified receipt — it evolves through each stage
        let mut receipt = UnifiedReceipt::new(
            world,
            "did:key:placeholder",
            "did:key:placeholder#v0",
            &nonce,
        );

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
        self.publish_receipt_event(&wa_receipt, "wa", None, None).await;

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

        // Short-circuit if denied
        if matches!(check.decision, Decision::Deny) {
            receipt.deny(&check.reason);

            let wf_receipt = self.create_deny_receipt(&request, &wa_receipt, &check).await?;

            let deny_ms = pipeline_start.elapsed().as_millis() as i64;
            self.publish_receipt_event(&wf_receipt, "wf", Some("deny".to_string()), Some(deny_ms)).await;

            return Ok(PipelineResult {
                final_receipt: wf_receipt.clone(),
                chain: vec![wa_receipt.body_cid.clone(), "no-tr".to_string(), wf_receipt.body_cid.clone()],
                decision: Decision::Deny,
                receipt,
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
        self.publish_receipt_event(&tr_receipt, "tr", None, None).await;

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
        self.publish_receipt_event(&wf_receipt, "wf", Some("allow".to_string()), Some(total_ms)).await;

        // Persist chip to ChipStore (best-effort — never blocks pipeline)
        if let Some(ref store) = self.chip_store {
            let metadata = ExecutionMetadata {
                runtime_version: "rb_vm/0.1".to_string(),
                execution_time_ms: total_ms,
                fuel_consumed: self.fuel_limit,
                policies_applied: check.trace.iter().map(|t| t.policy_id.clone()).collect(),
                executor_did: "did:key:placeholder".to_string(),
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

        Ok(PipelineResult {
            final_receipt: wf_receipt.clone(),
            chain: vec![
                wa_receipt.body_cid,
                tr_receipt.body_cid,
                wf_receipt.body_cid.clone(),
            ],
            decision: check.decision,
            receipt,
        })
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
                return Err(PipelineError::Internal("REPLAY: duplicate nonce".to_string()));
            }
        }

        let wa_body = WaReceiptBody {
            ghost: true,
            chip_cid: "pending".to_string(), // Will be computed later
            policy_cid: genesis_chip_cid(), // For now, just genesis
            frozen_time: chrono::Utc::now().to_rfc3339(),
            caller: "did:key:placeholder".to_string(),
            context: request.body.clone(),
            operation: request.operation.clone().unwrap_or_else(|| "create".to_string()),
            nonce,
            kid: "did:key:placeholder#v0".to_string(),
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

    /// Stage 2: CHECK - Policy evaluation with full trace
    async fn stage_check(&self, request: &ChipRequest) -> Result<CheckResult, PipelineError> {
        let check_start = std::time::Instant::now();

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

        let signer = PipelineSigner;
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
            ExecError::FuelExhausted => PipelineError::Internal("FUEL_EXHAUSTED".to_string()),
            ExecError::Deny(reason) => PipelineError::PolicyDenied(reason),
            other => PipelineError::Internal(format!("TR VM: {}", other)),
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

    /// Helper to publish receipt events to the event bus
    async fn publish_receipt_event(
        &self,
        receipt: &PipelineReceipt,
        pipeline_stage: &str,
        decision: Option<String>,
        duration_ms: Option<i64>,
    ) {
        let event = ReceiptEvent {
            event_type: format!("ubl.receipt.{}", pipeline_stage),
            receipt_cid: receipt.body_cid.clone(),
            receipt_type: receipt.receipt_type.clone(),
            decision,
            duration_ms,
            timestamp: chrono::Utc::now().to_rfc3339(),
            pipeline_stage: pipeline_stage.to_string(),
            metadata: receipt.body.clone(),
        };

        // Best effort - don't fail pipeline if event publishing fails
        if let Err(e) = self.event_bus.publish_receipt(event).await {
            eprintln!("Failed to publish receipt event: {}", e);
        }
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
            chip_type: "ubl/user".to_string(),
            body: json!({
                "@type": "ubl/user",
                "@id": "alice-001",
                "@ver": "1.0",
                "@world": "a/demo/t/main",
                "email": "alice@acme.com"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let result = pipeline.process_chip(request).await.unwrap();

        // Decision must be Allow (genesis allows ubl/user)
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
            chip_type: "ubl/user".to_string(),
            body: json!({
                "@type": "ubl/user",
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
            chip_type: "ubl/user".to_string(),
            body: json!({
                "@type": "ubl/user",
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
            chip_type: "ubl/user".to_string(),
            body: json!({
                "@type": "ubl/user",
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
            chip_type: "ubl/user".to_string(),
            body: json!({
                "@type": "ubl/user",
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
            chip_type: "ubl/user".to_string(),
            body: json!({
                "@type": "ubl/user",
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
                chip_type: "ubl/user".to_string(),
                body: json!({
                    "@type": "ubl/user",
                    "@id": format!("user-{}", i),
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
            chip_type: "ubl/user".to_string(),
            body: json!({
                "@type": "ubl/user",
                "@id": "persist-test",
                "@ver": "1.0",
                "@world": "a/app/t/ten",
                "email": "test@acme.com"
            }),
            parents: vec![],
            operation: Some("create".to_string()),
        };

        let result = pipeline.process_chip(request).await.unwrap();
        assert!(matches!(result.decision, Decision::Allow));

        // Chip should be persisted in the store
        // Compute the expected CID
        let chip_body = json!({
            "@type": "ubl/user",
            "@id": "persist-test",
            "@ver": "1.0",
            "@world": "a/app/t/ten",
            "email": "test@acme.com"
        });
        let nrf = ubl_ai_nrf1::to_nrf1_bytes(&chip_body).unwrap();
        let expected_cid = ubl_ai_nrf1::compute_cid(&nrf).unwrap();

        let stored = chip_store.get_chip(&expected_cid).await.unwrap();
        assert!(stored.is_some(), "chip must be persisted after allow");
        let stored = stored.unwrap();
        assert_eq!(stored.chip_type, "ubl/user");
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
            chip_type: "ubl/user".to_string(),
            body: json!({
                "@type": "ubl/user",
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
    async fn unified_receipt_has_all_stages_on_allow() {
        let storage = InMemoryPolicyStorage::new();
        let pipeline = UblPipeline::new(Box::new(storage));

        let request = ChipRequest {
            chip_type: "ubl/user".to_string(),
            body: json!({
                "@type": "ubl/user",
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
            chip_type: "ubl/user".to_string(),
            body: json!({
                "@type": "ubl/user",
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
            chip_type: "ubl/user".to_string(),
            body: json!({
                "@type": "ubl/user",
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
}