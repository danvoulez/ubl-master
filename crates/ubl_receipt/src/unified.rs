//! Unified Receipt — a single evolving receipt that grows through pipeline stages.
//!
//! Follows ARCHITECTURE.md §5.2:
//! - Universal Envelope format (`@type` first, `@id` second, all four anchors)
//! - `stages: Vec<StageExecution>` — append-only
//! - Auth chain: `auth_token = HMAC-BLAKE3(stage_secret, prev_cid || stage_name)`
//! - `receipt_cid` recomputed after each stage append
//! - The receipt IS a chip that an LLM can read without special-casing

use crate::pipeline_types::{Decision, PolicyTraceEntry};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use ubl_canon::{cid_of, CryptoMode as CanonCryptoMode};
use ubl_types::{
    Cid as TypedCid, Did as TypedDid, Kid as TypedKid, Nonce as TypedNonce, World as TypedWorld,
};

/// Pipeline stages in execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineStage {
    #[serde(rename = "KNOCK")]
    Knock,
    #[serde(rename = "WA")]
    WriteAhead,
    #[serde(rename = "CHECK")]
    Check,
    #[serde(rename = "TR")]
    Transition,
    #[serde(rename = "WF")]
    WriteFinished,
}

impl PipelineStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Knock => "KNOCK",
            Self::WriteAhead => "WA",
            Self::Check => "CHECK",
            Self::Transition => "TR",
            Self::WriteFinished => "WF",
        }
    }
}

/// A single stage execution record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageExecution {
    pub stage: PipelineStage,
    pub timestamp: String,
    pub input_cid: String,
    pub output_cid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fuel_used: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub policy_trace: Vec<PolicyTraceEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_sig: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_sig_payload_cid: Option<String>,
    pub auth_token: String,
    pub duration_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoMode {
    CompatV1,
    HashFirstV2,
}

impl CryptoMode {
    pub fn from_env() -> Self {
        match std::env::var("UBL_CRYPTO_MODE") {
            Ok(v) if v.eq_ignore_ascii_case("hash_first_v2") => Self::HashFirstV2,
            _ => Self::CompatV1,
        }
    }

    fn as_canon(self) -> CanonCryptoMode {
        match self {
            Self::CompatV1 => CanonCryptoMode::CompatV1,
            Self::HashFirstV2 => CanonCryptoMode::HashFirstV2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    V1Only,
    V2Only,
    Dual,
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub valid: bool,
    pub v1_valid: bool,
    pub v2_valid: bool,
}

/// Build provenance metadata — collected at compile time and startup.
/// Supports PF-01 invariant I-03: every receipt carries build provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildMeta {
    /// Rust compiler version (from `rustc --version` or `RUSTC_VERSION` env)
    pub rustc: String,
    /// Operating system
    pub os: String,
    /// Architecture (e.g. "x86_64", "aarch64")
    pub arch: String,
    /// Build profile ("debug" or "release")
    pub profile: String,
    /// Git commit hash (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    /// Whether the working tree was dirty at build time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_dirty: Option<bool>,
}

impl BuildMeta {
    /// Capture build metadata from compile-time and runtime environment.
    pub fn capture() -> Self {
        Self {
            rustc: option_env!("RUSTC_VERSION")
                .or(option_env!("CARGO_PKG_RUST_VERSION"))
                .filter(|s| !s.is_empty())
                .unwrap_or("unknown")
                .to_string(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
            .to_string(),
            git_commit: option_env!("GIT_COMMIT").map(|s| s.to_string()),
            git_dirty: option_env!("GIT_DIRTY").map(|s| s == "true"),
        }
    }
}

/// Runtime information captured at startup and embedded in every receipt.
/// Supports PF-01: binary_hash is observability for forensic auditing, not a trust anchor.
/// Trust comes from the Ed25519 signature chain via ubl_kms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeInfo {
    /// BLAKE3 hash of the running binary (hex-encoded, "b3:..." prefix)
    pub binary_hash: String,
    /// Alias for runtime binary hash used by policy/rollout tooling.
    /// Kept alongside `binary_hash` for wire compatibility during migration.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub runtime_hash: String,
    /// Crate version from Cargo.toml
    pub version: String,
    /// Build provenance (compiler, OS, git commit, etc.)
    pub build: BuildMeta,
    /// Arbitrary environment labels (e.g. "cluster": "us-east-1")
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub env: BTreeMap<String, String>,
    /// Runtime certification references (e.g. sbom CID, slsa statement CID).
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub certs: BTreeMap<String, String>,
}

impl RuntimeInfo {
    /// Capture runtime info by hashing the current executable binary.
    /// Call once at startup and reuse for all receipts.
    pub fn capture() -> Self {
        let binary_hash = match std::env::current_exe() {
            Ok(path) => match std::fs::read(&path) {
                Ok(bytes) => {
                    let hash = blake3::hash(&bytes);
                    format!("b3:{}", hex::encode(hash.as_bytes()))
                }
                Err(_) => "b3:unavailable".to_string(),
            },
            Err(_) => "b3:unavailable".to_string(),
        };

        Self {
            runtime_hash: binary_hash.clone(),
            binary_hash,
            version: env!("CARGO_PKG_VERSION").to_string(),
            build: BuildMeta::capture(),
            env: capture_labeled_map("UBL_RUNTIME_ENV_LABELS", "UBL_RUNTIME_ENV_"),
            certs: capture_labeled_map("UBL_RUNTIME_CERTS", "UBL_RUNTIME_CERT_"),
        }
    }

    /// Create a RuntimeInfo with explicit values (for testing or remote attestation).
    pub fn new(binary_hash: &str, version: &str) -> Self {
        Self {
            runtime_hash: binary_hash.to_string(),
            binary_hash: binary_hash.to_string(),
            version: version.to_string(),
            build: BuildMeta::capture(),
            env: BTreeMap::new(),
            certs: BTreeMap::new(),
        }
    }

    /// Add an environment label.
    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env.insert(key.to_string(), value.to_string());
        self
    }

    /// Add a runtime certification label.
    pub fn with_cert(mut self, key: &str, value: &str) -> Self {
        self.certs.insert(key.to_string(), value.to_string());
        self
    }

    /// Canonical runtime hash accessor with backward-compatible fallback.
    pub fn runtime_hash(&self) -> &str {
        if self.runtime_hash.is_empty() {
            &self.binary_hash
        } else {
            &self.runtime_hash
        }
    }
}

fn capture_labeled_map(csv_env: &str, prefix_env: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();

    if let Ok(raw) = std::env::var(csv_env) {
        for pair in raw.split(',') {
            let trimmed = pair.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((k, v)) = trimmed.split_once('=') {
                let key = k.trim();
                let val = v.trim();
                if !key.is_empty() && !val.is_empty() {
                    out.insert(key.to_string(), val.to_string());
                }
            }
        }
    }

    for (k, v) in std::env::vars() {
        if let Some(suffix) = k.strip_prefix(prefix_env) {
            if !suffix.is_empty() && !v.trim().is_empty() {
                out.insert(suffix.to_ascii_lowercase(), v.trim().to_string());
            }
        }
    }

    out
}

/// The unified receipt — a single evolving document that grows through the pipeline.
///
/// Its JSON form follows the Universal Envelope:
/// `@type` first, `@id` second, all four anchors present.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedReceipt {
    /// Schema version
    #[serde(rename = "@type")]
    pub receipt_type: String,
    /// Receipt ID (becomes the final CID after WF)
    #[serde(rename = "@id")]
    pub id: String,
    /// Schema version
    #[serde(rename = "@ver")]
    pub ver: String,
    /// World scope
    #[serde(rename = "@world")]
    pub world: TypedWorld,

    /// Schema version number
    pub v: u32,
    /// Creation timestamp (RFC-3339 UTC)
    pub t: String,
    /// Issuer DID
    pub did: TypedDid,
    /// Subject DID (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Key ID
    pub kid: TypedKid,
    /// Anti-replay nonce
    pub nonce: TypedNonce,

    /// Append-only stage executions
    pub stages: Vec<StageExecution>,
    /// Current decision state
    pub decision: Decision,
    /// Side-effects record
    pub effects: serde_json::Value,

    /// Chain linkage to previous receipt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_receipt_cid: Option<TypedCid>,
    /// Current receipt CID (recomputed after each stage)
    pub receipt_cid: TypedCid,
    /// Ed25519 JWS detached signature (empty until finalized)
    pub sig: String,

    /// Runtime that produced this receipt (binary hash, version, env)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rt: Option<RuntimeInfo>,
}

const STAGE_SECRET_ENV: &str = "UBL_STAGE_SECRET";
const STAGE_SECRET_PREV_ENV: &str = "UBL_STAGE_SECRET_PREV";
const RECEIPT_DOMAIN_ENV: &str = "UBL_SIGN_DOMAIN_RECEIPT";

impl UnifiedReceipt {
    /// Create a new receipt at the start of pipeline processing.
    pub fn new(world: &str, did: &str, kid: &str, nonce: &str) -> Self {
        let t = chrono::Utc::now().to_rfc3339();
        Self {
            receipt_type: "ubl/receipt".to_string(),
            id: String::new(), // Set after first CID computation
            ver: "1.0".to_string(),
            world: TypedWorld::new_unchecked(world),
            v: 1,
            t,
            did: TypedDid::new_unchecked(did),
            subject: None,
            kid: TypedKid::new_unchecked(kid),
            nonce: TypedNonce::new_unchecked(nonce),
            stages: Vec::new(),
            decision: Decision::Allow, // Optimistic — changes on DENY
            effects: serde_json::Value::Object(serde_json::Map::new()),
            prev_receipt_cid: None,
            receipt_cid: TypedCid::new_unchecked(""),
            sig: String::new(),
            rt: None,
        }
    }

    /// Attach runtime info to this receipt.
    pub fn with_runtime_info(mut self, rt: RuntimeInfo) -> Self {
        self.rt = Some(rt);
        self
    }

    /// Append a stage execution and recompute the receipt CID.
    pub fn append_stage(&mut self, mut stage: StageExecution) -> Result<(), ReceiptError> {
        let current_key = load_required_stage_secret_key()?;

        // Compute auth token: HMAC-BLAKE3(secret, prev_cid || stage_name)
        let prev_cid = if self.receipt_cid.as_str().is_empty() {
            "genesis"
        } else {
            self.receipt_cid.as_str()
        };
        stage.auth_token =
            compute_auth_token_with_key(prev_cid, stage.stage.as_str(), &current_key);

        self.stages.push(stage);

        // Recompute CID
        self.recompute_cid()?;

        // Update @id to match current CID
        self.id = self.receipt_cid.as_str().to_string();

        // Enforce auth-chain integrity after every append.
        let previous_key = load_optional_stage_secret_key(STAGE_SECRET_PREV_ENV)?;
        if !self.verify_auth_chain_with_keys(&current_key, previous_key.as_ref())? {
            return Err(ReceiptError::AuthChainBroken(
                "stage auth token mismatch after append".to_string(),
            ));
        }

        Ok(())
    }

    /// Recompute the receipt CID from current state (excluding sig).
    fn recompute_cid(&mut self) -> Result<(), ReceiptError> {
        // Temporarily clear sig and receipt_cid for canonical hashing/signing payload.
        let saved_sig = std::mem::take(&mut self.sig);
        let saved_cid = std::mem::replace(&mut self.receipt_cid, TypedCid::new_unchecked(""));
        let saved_id = std::mem::take(&mut self.id);

        let json =
            serde_json::to_value(&*self).map_err(|e| ReceiptError::Serialization(e.to_string()))?;
        let new_cid = cid_of(&json).map_err(|e| ReceiptError::Signature(e.to_string()))?;

        // Restore
        self.sig = saved_sig;
        self.receipt_cid = TypedCid::new_unchecked(&new_cid);
        self.id = self.receipt_cid.as_str().to_string();

        // Suppress unused warning — saved_cid and saved_id are intentionally dropped
        let _ = saved_cid;
        let _ = saved_id;

        Ok(())
    }

    fn signature_payload_value(&self) -> Result<serde_json::Value, ReceiptError> {
        let mut tmp = self.clone();
        tmp.sig.clear();
        serde_json::to_value(tmp).map_err(|e| ReceiptError::Serialization(e.to_string()))
    }

    /// Finalize the receipt signature for WF output.
    pub fn finalize_and_sign(
        &mut self,
        sk: &ubl_kms::Ed25519SigningKey,
        mode: CryptoMode,
    ) -> Result<(), ReceiptError> {
        let payload = self.signature_payload_value()?;
        let domain = receipt_sign_domain();
        self.sig = match mode.as_canon() {
            CanonCryptoMode::CompatV1 => ubl_canon::sign_domain_v1(&payload, &domain, sk)
                .map_err(|e| ReceiptError::Signature(e.to_string()))?,
            CanonCryptoMode::HashFirstV2 => {
                ubl_canon::sign_domain_v2_hash_first(&payload, &domain, sk)
                    .map_err(|e| ReceiptError::Signature(e.to_string()))?
            }
        };
        Ok(())
    }

    /// Verify the receipt signature against `did`.
    pub fn verify_signature(&self, mode: VerifyMode) -> Result<VerifyReport, ReceiptError> {
        if self.sig.is_empty() {
            return Err(ReceiptError::Signature(
                "receipt signature is empty".to_string(),
            ));
        }

        let vk = ubl_kms::verifying_key_from_did(self.did.as_str())
            .map_err(|e| ReceiptError::Signature(e.to_string()))?;
        let payload = self.signature_payload_value()?;
        let domain = receipt_sign_domain();

        let v1_valid = ubl_canon::verify_domain_v1(&payload, &domain, &vk, &self.sig)
            .map_err(|e| ReceiptError::Signature(e.to_string()))?;
        let v2_valid = ubl_canon::verify_domain_v2_hash_first(&payload, &domain, &vk, &self.sig)
            .map_err(|e| ReceiptError::Signature(e.to_string()))?;

        let valid = match mode {
            VerifyMode::V1Only => v1_valid,
            VerifyMode::V2Only => v2_valid,
            VerifyMode::Dual => v1_valid || v2_valid,
        };

        Ok(VerifyReport {
            valid,
            v1_valid,
            v2_valid,
        })
    }

    /// Mark the receipt as denied.
    pub fn deny(&mut self, reason: &str) {
        self.decision = Decision::Deny;
        if let Some(obj) = self.effects.as_object_mut() {
            obj.insert(
                "deny_reason".to_string(),
                serde_json::Value::String(reason.to_string()),
            );
        }
        // Decision/effects are mutable across the pipeline. Rebuild prior stage
        // auth tokens against the new state so the chain remains internally
        // consistent before appending the WF stage.
        self.rebuild_auth_chain_with_current_key();
        let _ = self.recompute_cid();
        self.id = self.receipt_cid.as_str().to_string();
    }

    fn rebuild_auth_chain_with_current_key(&mut self) {
        let Ok(current_key) = load_required_stage_secret_key() else {
            return;
        };
        if self.stages.is_empty() {
            return;
        }

        let mut shadow = self.clone();
        shadow.stages.clear();
        shadow.receipt_cid = TypedCid::new_unchecked("");
        shadow.id.clear();

        let mut rebuilt = Vec::with_capacity(self.stages.len());
        for mut stage in self.stages.clone() {
            let prev_cid = if shadow.receipt_cid.as_str().is_empty() {
                "genesis"
            } else {
                shadow.receipt_cid.as_str()
            };
            stage.auth_token =
                compute_auth_token_with_key(prev_cid, stage.stage.as_str(), &current_key);
            shadow.stages.push(stage.clone());
            if shadow.recompute_cid().is_err() {
                return;
            }
            shadow.id = shadow.receipt_cid.as_str().to_string();
            rebuilt.push(stage);
        }

        self.stages = rebuilt;
    }

    /// Get the current stage count.
    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }

    /// Check if a specific stage has been executed.
    pub fn has_stage(&self, stage: PipelineStage) -> bool {
        self.stages.iter().any(|s| s.stage == stage)
    }

    /// Get the last stage's auth token (for verifying the next stage).
    pub fn last_auth_token(&self) -> Option<&str> {
        self.stages.last().map(|s| s.auth_token.as_str())
    }

    /// Verify the auth chain is intact.
    pub fn verify_auth_chain(&self) -> bool {
        let current_key = match load_required_stage_secret_key() {
            Ok(k) => k,
            Err(_) => return false,
        };
        let previous_key = match load_optional_stage_secret_key(STAGE_SECRET_PREV_ENV) {
            Ok(k) => k,
            Err(_) => return false,
        };

        self.verify_auth_chain_with_keys(&current_key, previous_key.as_ref())
            .unwrap_or(false)
    }

    fn verify_auth_chain_with_keys(
        &self,
        current_key: &[u8; 32],
        previous_key: Option<&[u8; 32]>,
    ) -> Result<bool, ReceiptError> {
        // Replay the receipt CID evolution stage by stage and verify token at each step.
        let mut shadow = self.clone();
        shadow.stages.clear();
        shadow.receipt_cid = TypedCid::new_unchecked("");
        shadow.id.clear();

        for stage in &self.stages {
            let prev_cid = if shadow.receipt_cid.as_str().is_empty() {
                "genesis"
            } else {
                shadow.receipt_cid.as_str()
            };

            let expected_current =
                compute_auth_token_with_key(prev_cid, stage.stage.as_str(), current_key);
            let expected_previous = previous_key
                .map(|k| compute_auth_token_with_key(prev_cid, stage.stage.as_str(), k));

            let token_matches = stage.auth_token == expected_current
                || expected_previous.as_deref() == Some(stage.auth_token.as_str());
            if !token_matches {
                return Ok(false);
            }

            shadow.stages.push(stage.clone());
            shadow.recompute_cid()?;
            shadow.id = shadow.receipt_cid.as_str().to_string();
        }

        Ok(shadow.receipt_cid == self.receipt_cid)
    }

    /// Serialize to Universal Envelope JSON.
    pub fn to_json(&self) -> Result<serde_json::Value, ReceiptError> {
        serde_json::to_value(self).map_err(|e| ReceiptError::Serialization(e.to_string()))
    }

    /// Deserialize from Universal Envelope JSON.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, ReceiptError> {
        serde_json::from_value(value.clone())
            .map_err(|e| ReceiptError::Serialization(e.to_string()))
    }
}

fn load_required_stage_secret_key() -> Result<[u8; 32], ReceiptError> {
    let raw = std::env::var(STAGE_SECRET_ENV).map_err(|_| {
        ReceiptError::AuthChainBroken(format!(
            "{} is not set; configure a stage secret",
            STAGE_SECRET_ENV
        ))
    })?;

    key_from_secret_str(&raw).map_err(|e| {
        ReceiptError::AuthChainBroken(format!("invalid {} value: {}", STAGE_SECRET_ENV, e))
    })
}

fn load_optional_stage_secret_key(var_name: &str) -> Result<Option<[u8; 32]>, ReceiptError> {
    match std::env::var(var_name) {
        Ok(raw) => key_from_secret_str(&raw).map(Some).map_err(|e| {
            ReceiptError::AuthChainBroken(format!("invalid {} value: {}", var_name, e))
        }),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(ReceiptError::AuthChainBroken(format!(
            "failed reading {}: {}",
            var_name, e
        ))),
    }
}

fn key_from_secret_str(raw: &str) -> Result<[u8; 32], String> {
    if raw.is_empty() {
        return Err("secret is empty".to_string());
    }

    let bytes = if let Some(hex_payload) = raw.strip_prefix("hex:") {
        hex::decode(hex_payload).map_err(|e| format!("hex decode failed: {}", e))?
    } else {
        raw.as_bytes().to_vec()
    };

    Ok(padded_key(&bytes))
}

fn receipt_sign_domain() -> String {
    std::env::var(RECEIPT_DOMAIN_ENV).unwrap_or_else(|_| ubl_canon::domains::RECEIPT.to_string())
}

/// Compute HMAC-BLAKE3 auth token for stage chain linkage.
fn compute_auth_token_with_key(prev_cid: &str, stage_name: &str, key: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(prev_cid.as_bytes());
    hasher.update(b"||");
    hasher.update(stage_name.as_bytes());
    let hash = hasher.finalize();
    format!("hmac:{}", hex::encode(&hash.as_bytes()[..16])) // Truncate to 128 bits
}

/// Pad or truncate key to exactly 32 bytes for BLAKE3 keyed mode.
fn padded_key(key: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let len = key.len().min(32);
    buf[..len].copy_from_slice(&key[..len]);
    buf
}

#[derive(Debug)]
pub enum ReceiptError {
    Serialization(String),
    InvalidStageOrder(String),
    AuthChainBroken(String),
    Signature(String),
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialization(s) => write!(f, "Serialization error: {}", s),
            Self::InvalidStageOrder(s) => write!(f, "Invalid stage order: {}", s),
            Self::AuthChainBroken(s) => write!(f, "Auth chain broken: {}", s),
            Self::Signature(s) => write!(f, "Signature error: {}", s),
        }
    }
}

impl std::error::Error for ReceiptError {}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_STAGE_SECRET_HEX: &str =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn ensure_test_stage_secret() {
        std::env::set_var(STAGE_SECRET_ENV, format!("hex:{}", TEST_STAGE_SECRET_HEX));
    }

    fn make_receipt() -> UnifiedReceipt {
        ensure_test_stage_secret();
        UnifiedReceipt::new(
            "a/acme/t/prod",
            "did:key:z123",
            "did:key:z123#v0",
            "deadbeef01020304",
        )
    }

    fn make_stage(stage: PipelineStage, input_cid: &str) -> StageExecution {
        StageExecution {
            stage,
            timestamp: chrono::Utc::now().to_rfc3339(),
            input_cid: input_cid.to_string(),
            output_cid: Some(format!("b3:output-{}", stage.as_str())),
            fuel_used: None,
            policy_trace: vec![],
            vm_sig: None,
            vm_sig_payload_cid: None,
            auth_token: String::new(), // Computed by append_stage
            duration_ms: 1,
        }
    }

    #[test]
    fn new_receipt_has_envelope_anchors() {
        let r = make_receipt();
        assert_eq!(r.receipt_type, "ubl/receipt");
        assert_eq!(r.ver, "1.0");
        assert_eq!(r.world.as_str(), "a/acme/t/prod");
        assert_eq!(r.v, 1);
    }

    #[test]
    fn append_stage_computes_cid() {
        let mut r = make_receipt();
        assert!(r.receipt_cid.as_str().is_empty());

        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:input-wa"))
            .unwrap();
        assert!(
            r.receipt_cid.as_str().starts_with("b3:"),
            "CID must be BLAKE3"
        );
        assert_eq!(r.id, r.receipt_cid.as_str(), "@id must match receipt_cid");
    }

    #[test]
    fn cid_changes_with_each_stage() {
        let mut r = make_receipt();
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa"))
            .unwrap();
        let cid_after_wa = r.receipt_cid.clone();

        r.append_stage(make_stage(PipelineStage::Check, "b3:check"))
            .unwrap();
        let cid_after_check = r.receipt_cid.clone();

        assert_ne!(
            cid_after_wa, cid_after_check,
            "CID must change after each stage"
        );
    }

    #[test]
    fn full_pipeline_stages() {
        let mut r = make_receipt();

        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa"))
            .unwrap();
        r.append_stage(make_stage(PipelineStage::Check, "b3:check"))
            .unwrap();
        r.append_stage(make_stage(PipelineStage::Transition, "b3:tr"))
            .unwrap();
        r.append_stage(make_stage(PipelineStage::WriteFinished, "b3:wf"))
            .unwrap();

        assert_eq!(r.stage_count(), 4);
        assert!(r.has_stage(PipelineStage::WriteAhead));
        assert!(r.has_stage(PipelineStage::Check));
        assert!(r.has_stage(PipelineStage::Transition));
        assert!(r.has_stage(PipelineStage::WriteFinished));
    }

    #[test]
    fn auth_tokens_are_non_empty() {
        let mut r = make_receipt();
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa"))
            .unwrap();
        r.append_stage(make_stage(PipelineStage::Check, "b3:check"))
            .unwrap();

        for stage in &r.stages {
            assert!(
                stage.auth_token.starts_with("hmac:"),
                "auth_token must be HMAC"
            );
            assert!(stage.auth_token.len() > 5);
        }
    }

    #[test]
    fn auth_tokens_differ_per_stage() {
        let mut r = make_receipt();
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa"))
            .unwrap();
        r.append_stage(make_stage(PipelineStage::Check, "b3:check"))
            .unwrap();

        assert_ne!(
            r.stages[0].auth_token, r.stages[1].auth_token,
            "Each stage must have a unique auth token"
        );
    }

    #[test]
    fn verify_auth_chain_detects_tamper() {
        let mut r = make_receipt();
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa"))
            .unwrap();
        r.append_stage(make_stage(PipelineStage::Check, "b3:check"))
            .unwrap();
        assert!(r.verify_auth_chain());

        r.stages[1].auth_token = "hmac:deadbeefdeadbeefdeadbeefdeadbeef".to_string();
        assert!(!r.verify_auth_chain());
    }

    #[test]
    fn verify_auth_chain_accepts_previous_secret_after_rotation() {
        // Build receipt with the test key.
        let mut r = make_receipt();
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa"))
            .unwrap();
        r.append_stage(make_stage(PipelineStage::Check, "b3:check"))
            .unwrap();

        let old_key = key_from_secret_str(&format!("hex:{}", TEST_STAGE_SECRET_HEX)).unwrap();
        let new_key = key_from_secret_str(
            "hex:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();

        assert!(r
            .verify_auth_chain_with_keys(&new_key, Some(&old_key))
            .unwrap());
    }

    #[test]
    fn deny_sets_decision_and_effect() {
        let mut r = make_receipt();
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa"))
            .unwrap();
        r.deny("type not allowed");

        assert_eq!(r.decision, Decision::Deny);
        assert_eq!(r.effects["deny_reason"], "type not allowed");
    }

    #[test]
    fn to_json_has_all_anchors() {
        let mut r = make_receipt();
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa"))
            .unwrap();

        let json = r.to_json().unwrap();
        assert_eq!(json["@type"], "ubl/receipt");
        assert!(json["@id"].as_str().unwrap().starts_with("b3:"));
        assert_eq!(json["@ver"], "1.0");
        assert_eq!(json["@world"], "a/acme/t/prod");
        assert!(json["stages"].is_array());
        assert!(json["nonce"].is_string());
    }

    #[test]
    fn receipt_cid_is_deterministic() {
        ensure_test_stage_secret();
        // Same inputs → same CID
        let mut r1 = UnifiedReceipt::new("a/x/t/y", "did:key:z1", "did:key:z1#v0", "aabb");
        let mut r2 = UnifiedReceipt::new("a/x/t/y", "did:key:z1", "did:key:z1#v0", "aabb");

        // Force same timestamp
        r2.t = r1.t.clone();

        let stage1 = StageExecution {
            stage: PipelineStage::WriteAhead,
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            input_cid: "b3:same".to_string(),
            output_cid: None,
            fuel_used: None,
            policy_trace: vec![],
            vm_sig: None,
            vm_sig_payload_cid: None,
            auth_token: String::new(),
            duration_ms: 0,
        };

        r1.append_stage(stage1.clone()).unwrap();
        r2.append_stage(stage1).unwrap();

        assert_eq!(
            r1.receipt_cid, r2.receipt_cid,
            "Same inputs must produce same CID"
        );
    }

    #[test]
    fn check_stage_includes_policy_trace() {
        let mut r = make_receipt();
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa"))
            .unwrap();

        let check_stage = StageExecution {
            stage: PipelineStage::Check,
            timestamp: chrono::Utc::now().to_rfc3339(),
            input_cid: "b3:check-input".to_string(),
            output_cid: None,
            fuel_used: None,
            policy_trace: vec![PolicyTraceEntry {
                level: "genesis".to_string(),
                policy_id: "ubl.genesis.v1".to_string(),
                result: Decision::Allow,
                reason: "All circuits allowed".to_string(),
                rb_results: vec![],
                duration_ms: 0,
            }],
            vm_sig: None,
            vm_sig_payload_cid: None,
            auth_token: String::new(),
            duration_ms: 1,
        };

        r.append_stage(check_stage).unwrap();
        assert_eq!(r.stages[1].policy_trace.len(), 1);
        assert_eq!(r.stages[1].policy_trace[0].policy_id, "ubl.genesis.v1");
    }

    #[test]
    fn tr_stage_records_fuel() {
        let mut r = make_receipt();
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa"))
            .unwrap();

        let tr_stage = StageExecution {
            stage: PipelineStage::Transition,
            timestamp: chrono::Utc::now().to_rfc3339(),
            input_cid: "b3:tr-input".to_string(),
            output_cid: Some("b3:tr-output".to_string()),
            fuel_used: Some(42),
            policy_trace: vec![],
            vm_sig: Some("ed25519:test".to_string()),
            vm_sig_payload_cid: Some("b3:test-payload".to_string()),
            auth_token: String::new(),
            duration_ms: 5,
        };

        r.append_stage(tr_stage).unwrap();
        assert_eq!(r.stages[1].fuel_used, Some(42));
    }

    // ── RuntimeInfo / BuildMeta / PF-01 tests ──────────────────

    #[test]
    fn runtime_info_capture_has_valid_fields() {
        let rt = RuntimeInfo::capture();
        assert!(
            rt.binary_hash.starts_with("b3:"),
            "binary_hash must be b3: prefixed"
        );
        assert_eq!(rt.runtime_hash(), rt.binary_hash);
        assert!(!rt.version.is_empty());
        assert!(!rt.build.arch.is_empty());
        assert!(!rt.build.os.is_empty());
        assert!(rt.build.profile == "debug" || rt.build.profile == "release");
    }

    #[test]
    fn runtime_info_new_sets_explicit_hash() {
        let rt = RuntimeInfo::new("b3:deadbeef", "0.1.0");
        assert_eq!(rt.binary_hash, "b3:deadbeef");
        assert_eq!(rt.runtime_hash, "b3:deadbeef");
        assert_eq!(rt.version, "0.1.0");
    }

    #[test]
    fn runtime_info_with_env_labels() {
        let rt = RuntimeInfo::new("b3:abc", "1.0.0")
            .with_env("cluster", "us-east-1")
            .with_env("deploy", "canary")
            .with_cert("slsa", "b3:slsa-cid");
        assert_eq!(rt.env.len(), 2);
        assert_eq!(rt.env["cluster"], "us-east-1");
        assert_eq!(rt.env["deploy"], "canary");
        assert_eq!(rt.certs["slsa"], "b3:slsa-cid");
    }

    #[test]
    fn receipt_with_runtime_info_includes_rt_in_json() {
        ensure_test_stage_secret();
        let rt = RuntimeInfo::new("b3:test-hash", "0.1.0");
        let mut r = UnifiedReceipt::new(
            "a/acme/t/prod",
            "did:key:z123",
            "did:key:z123#v0",
            "aabbccdd",
        )
        .with_runtime_info(rt);

        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa"))
            .unwrap();

        let json = r.to_json().unwrap();
        assert!(
            json.get("rt").is_some(),
            "receipt JSON must include rt field"
        );
        assert_eq!(json["rt"]["binary_hash"], "b3:test-hash");
        assert_eq!(json["rt"]["runtime_hash"], "b3:test-hash");
        assert_eq!(json["rt"]["version"], "0.1.0");
        assert!(json["rt"]["build"]["arch"].is_string());
        assert!(json["rt"]["build"]["os"].is_string());
    }

    #[test]
    fn receipt_without_runtime_info_omits_rt() {
        let mut r = make_receipt();
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa"))
            .unwrap();

        let json = r.to_json().unwrap();
        assert!(json.get("rt").is_none(), "rt should be omitted when None");
    }

    #[test]
    fn build_meta_capture_has_fields() {
        let bm = BuildMeta::capture();
        assert!(!bm.os.is_empty());
        assert!(!bm.arch.is_empty());
        assert!(
            !bm.rustc.is_empty(),
            "rustc must be non-empty (at least 'unknown')"
        );
        assert!(bm.profile == "debug" || bm.profile == "release");
    }

    #[test]
    fn runtime_info_changes_receipt_cid() {
        ensure_test_stage_secret();
        let mut r1 = make_receipt();
        r1.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa"))
            .unwrap();
        let cid_without_rt = r1.receipt_cid.clone();

        let rt = RuntimeInfo::new("b3:some-binary", "0.1.0");
        let mut r2 = UnifiedReceipt::new(
            "a/acme/t/prod",
            "did:key:z123",
            "did:key:z123#v0",
            "deadbeef01020304",
        )
        .with_runtime_info(rt);
        r2.t = r1.t.clone(); // same timestamp
        r2.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa"))
            .unwrap();

        assert_ne!(
            cid_without_rt, r2.receipt_cid,
            "RuntimeInfo must affect receipt CID (different content = different CID)"
        );
    }

    #[test]
    fn receipt_sign_and_verify_ok() {
        ensure_test_stage_secret();
        let sk = ubl_kms::generate_signing_key();
        let vk = sk.verifying_key();
        let did = ubl_kms::did_from_verifying_key(&vk);
        let kid = ubl_kms::kid_from_verifying_key(&vk);

        let mut r = UnifiedReceipt::new("a/acme/t/prod", &did, &kid, "deadbeef01020304");
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa"))
            .unwrap();
        r.finalize_and_sign(&sk, CryptoMode::CompatV1).unwrap();

        let report = r.verify_signature(VerifyMode::V1Only).unwrap();
        assert!(report.valid);
        assert!(report.v1_valid);
    }

    #[test]
    fn receipt_bitflip_invalidates_sig() {
        ensure_test_stage_secret();
        let sk = ubl_kms::generate_signing_key();
        let vk = sk.verifying_key();
        let did = ubl_kms::did_from_verifying_key(&vk);
        let kid = ubl_kms::kid_from_verifying_key(&vk);

        let mut r = UnifiedReceipt::new("a/acme/t/prod", &did, &kid, "deadbeef01020304");
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa"))
            .unwrap();
        r.finalize_and_sign(&sk, CryptoMode::CompatV1).unwrap();
        assert!(r.verify_signature(VerifyMode::V1Only).unwrap().valid);

        r.effects["tampered"] = serde_json::json!(true);
        let report = r.verify_signature(VerifyMode::V1Only).unwrap();
        assert!(!report.valid);
    }
}
