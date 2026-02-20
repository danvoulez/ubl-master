//! UBL Pipeline - WA→TR→WF processing
mod processing;
mod providers;
mod stages;
mod types;

use self::providers::{PipelineCanon, PipelineCas, PipelineSigner};
use self::types::{decision_to_wire, AdapterRuntimeInfo, CheckResult, ParsedChipRequest};
use crate::advisory::AdvisoryEngine;
use crate::durable_store::{CommitInput, DurableError, DurableStore, NewOutboxEvent};
use crate::event_bus::{EventBus, StageEventContext};
use crate::genesis::genesis_chip_cid;
use crate::idempotency::{CachedResult, IdempotencyKey, IdempotencyStore};
use crate::key_rotation::{derive_material, mapping_chip, KeyRotateRequest};
use crate::ledger::{LedgerWriter, NullLedger};
use crate::policy_bit::PolicyResult;
use crate::policy_loader::{ChipRequest as PolicyChipRequest, PolicyLoader, PolicyStorage};
use crate::reasoning_bit::{Decision, EvalContext};
use crate::runtime_cert::SelfAttestation;
use crate::transition_registry::TransitionRegistry;
use rb_vm::tlv;
use rb_vm::{CasProvider, ExecError, Vm, VmConfig};
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
    // NOTE: session-only replay guard. This set is in-memory and is reset on process restart.
    // Cross-restart replay protection is enforced by durable idempotency on
    // (@type,@ver,@world,@id) when SQLite durable store is enabled.
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

/// GAP-15: if the DurableStore has a persisted stage-secret row, load it into env
/// so that `UnifiedReceipt::verify_auth_chain` uses the correct current/prev values
/// after a restart that followed a key rotation.
fn apply_persisted_stage_secrets(durable: &Option<Arc<DurableStore>>) {
    let Some(ds) = durable else { return };
    match ds.get_stage_secrets() {
        Ok(Some(row)) => {
            std::env::set_var("UBL_STAGE_SECRET", row.current);
            if let Some(prev) = row.prev {
                std::env::set_var("UBL_STAGE_SECRET_PREV", prev);
            }
        }
        Ok(None) => {}
        Err(_) => {}
    }
}

pub(crate) fn derive_stage_secret(signing_key: &SigningKey) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(&signing_key.to_bytes());
    hasher.update(b"ubl.stage_secret.v1");
    *hasher.finalize().as_bytes()
}

fn is_non_dev_env() -> bool {
    let env_value = std::env::var("UBL_ENV")
        .or_else(|_| std::env::var("APP_ENV"))
        .or_else(|_| std::env::var("RUST_ENV"))
        .or_else(|_| std::env::var("ENVIRONMENT"))
        .unwrap_or_else(|_| "dev".to_string())
        .to_ascii_lowercase();
    !matches!(env_value.as_str(), "dev" | "local" | "test")
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
        // using domain-separated BLAKE3 keyed mode (never raw signing key bytes).
        if std::env::var("UBL_STAGE_SECRET").is_err() {
            let derived = derive_stage_secret(&key);
            std::env::set_var("UBL_STAGE_SECRET", format!("hex:{}", hex::encode(derived)));
            if is_non_dev_env() {
                warn!(
                    "UBL_STAGE_SECRET missing; derived fallback injected. Set UBL_STAGE_SECRET explicitly in non-dev environments."
                );
            }
        }

        key
    }

    /// Create a new pipeline instance
    pub fn new(storage: Box<dyn PolicyStorage>) -> Self {
        let key = Self::load_or_generate_key();
        let vk = key.verifying_key();
        let did = did_from_verifying_key(&vk);
        let kid = kid_from_verifying_key(&vk);
        let durable_store = load_durable_store();
        apply_persisted_stage_secrets(&durable_store);
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
            durable_store,
            transition_registry: load_transition_registry(),
        }
    }

    /// Create pipeline with existing event bus
    pub fn with_event_bus(storage: Box<dyn PolicyStorage>, event_bus: Arc<EventBus>) -> Self {
        let key = Self::load_or_generate_key();
        let vk = key.verifying_key();
        let did = did_from_verifying_key(&vk);
        let kid = kid_from_verifying_key(&vk);
        let durable_store = load_durable_store();
        apply_persisted_stage_secrets(&durable_store);
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
            durable_store,
            transition_registry: load_transition_registry(),
        }
    }

    /// Create pipeline with ChipStore for persistence
    pub fn with_chip_store(storage: Box<dyn PolicyStorage>, chip_store: Arc<ChipStore>) -> Self {
        let key = Self::load_or_generate_key();
        let vk = key.verifying_key();
        let did = did_from_verifying_key(&vk);
        let kid = kid_from_verifying_key(&vk);
        let durable_store = load_durable_store();
        apply_persisted_stage_secrets(&durable_store);
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
            durable_store,
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
mod tests;
