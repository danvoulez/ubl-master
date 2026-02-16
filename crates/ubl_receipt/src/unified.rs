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
    pub auth_token: String,
    pub duration_ms: i64,
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
    pub world: String,

    /// Schema version number
    pub v: u32,
    /// Creation timestamp (RFC-3339 UTC)
    pub t: String,
    /// Issuer DID
    pub did: String,
    /// Subject DID (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Key ID
    pub kid: String,
    /// Anti-replay nonce
    pub nonce: String,

    /// Append-only stage executions
    pub stages: Vec<StageExecution>,
    /// Current decision state
    pub decision: Decision,
    /// Side-effects record
    pub effects: serde_json::Value,

    /// Chain linkage to previous receipt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_receipt_cid: Option<String>,
    /// Current receipt CID (recomputed after each stage)
    pub receipt_cid: String,
    /// Ed25519 JWS detached signature (empty until finalized)
    pub sig: String,
}

/// Secret used for HMAC auth tokens between stages.
const STAGE_SECRET: &[u8] = b"ubl-stage-secret-v1"; // TODO: load from env

impl UnifiedReceipt {
    /// Create a new receipt at the start of pipeline processing.
    pub fn new(
        world: &str,
        did: &str,
        kid: &str,
        nonce: &str,
    ) -> Self {
        let t = chrono::Utc::now().to_rfc3339();
        Self {
            receipt_type: "ubl/receipt".to_string(),
            id: String::new(), // Set after first CID computation
            ver: "1.0".to_string(),
            world: world.to_string(),
            v: 1,
            t,
            did: did.to_string(),
            subject: None,
            kid: kid.to_string(),
            nonce: nonce.to_string(),
            stages: Vec::new(),
            decision: Decision::Allow, // Optimistic — changes on DENY
            effects: serde_json::Value::Object(serde_json::Map::new()),
            prev_receipt_cid: None,
            receipt_cid: String::new(),
            sig: String::new(),
        }
    }

    /// Append a stage execution and recompute the receipt CID.
    pub fn append_stage(&mut self, mut stage: StageExecution) -> Result<(), ReceiptError> {
        // Compute auth token: HMAC-BLAKE3(secret, prev_cid || stage_name)
        let prev_cid = if self.receipt_cid.is_empty() {
            "genesis"
        } else {
            &self.receipt_cid
        };
        stage.auth_token = compute_auth_token(prev_cid, stage.stage.as_str());

        self.stages.push(stage);

        // Recompute CID
        self.recompute_cid()?;

        // Update @id to match current CID
        self.id = self.receipt_cid.clone();

        Ok(())
    }

    /// Recompute the receipt CID from current state (excluding sig).
    fn recompute_cid(&mut self) -> Result<(), ReceiptError> {
        // Temporarily clear sig and receipt_cid for canonical hashing
        let saved_sig = std::mem::take(&mut self.sig);
        let saved_cid = std::mem::take(&mut self.receipt_cid);
        let saved_id = std::mem::take(&mut self.id);

        let json = serde_json::to_value(&*self)
            .map_err(|e| ReceiptError::Serialization(e.to_string()))?;

        let canonical = canonical_json_bytes(&json);
        let hash = blake3::hash(&canonical);
        let new_cid = format!("b3:{}", hex::encode(hash.as_bytes()));

        // Restore
        self.sig = saved_sig;
        self.receipt_cid = new_cid;
        self.id = self.receipt_cid.clone();

        // Suppress unused warning — saved_cid and saved_id are intentionally dropped
        let _ = saved_cid;
        let _ = saved_id;

        Ok(())
    }

    /// Mark the receipt as denied.
    pub fn deny(&mut self, reason: &str) {
        self.decision = Decision::Deny;
        if let Some(obj) = self.effects.as_object_mut() {
            obj.insert("deny_reason".to_string(), serde_json::Value::String(reason.to_string()));
        }
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
        let mut prev_cid = "genesis".to_string();

        for stage in &self.stages {
            let expected = compute_auth_token(&prev_cid, stage.stage.as_str());
            if stage.auth_token != expected {
                return false;
            }
            // After this stage, the receipt CID would have been recomputed.
            // For chain verification, we use the auth_token as the link.
            prev_cid = stage.auth_token.clone();
        }

        true
    }

    /// Serialize to Universal Envelope JSON.
    pub fn to_json(&self) -> Result<serde_json::Value, ReceiptError> {
        serde_json::to_value(self)
            .map_err(|e| ReceiptError::Serialization(e.to_string()))
    }
}

/// Compute HMAC-BLAKE3 auth token for stage chain linkage.
fn compute_auth_token(prev_cid: &str, stage_name: &str) -> String {
    let mut hasher = blake3::Hasher::new_keyed(&padded_key(STAGE_SECRET));
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

/// Produce canonical JSON bytes (sorted keys, no extra whitespace).
fn canonical_json_bytes(value: &serde_json::Value) -> Vec<u8> {
    fn sort(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(map) => {
                let mut sorted = serde_json::Map::new();
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for k in keys {
                    sorted.insert(k.clone(), sort(&map[k]));
                }
                serde_json::Value::Object(sorted)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(sort).collect())
            }
            other => other.clone(),
        }
    }
    let sorted = sort(value);
    serde_json::to_vec(&sorted).unwrap_or_default()
}

#[derive(Debug)]
pub enum ReceiptError {
    Serialization(String),
    InvalidStageOrder(String),
    AuthChainBroken(String),
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialization(s) => write!(f, "Serialization error: {}", s),
            Self::InvalidStageOrder(s) => write!(f, "Invalid stage order: {}", s),
            Self::AuthChainBroken(s) => write!(f, "Auth chain broken: {}", s),
        }
    }
}

impl std::error::Error for ReceiptError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_receipt() -> UnifiedReceipt {
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
            auth_token: String::new(), // Computed by append_stage
            duration_ms: 1,
        }
    }

    #[test]
    fn new_receipt_has_envelope_anchors() {
        let r = make_receipt();
        assert_eq!(r.receipt_type, "ubl/receipt");
        assert_eq!(r.ver, "1.0");
        assert_eq!(r.world, "a/acme/t/prod");
        assert_eq!(r.v, 1);
    }

    #[test]
    fn append_stage_computes_cid() {
        let mut r = make_receipt();
        assert!(r.receipt_cid.is_empty());

        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:input-wa")).unwrap();
        assert!(r.receipt_cid.starts_with("b3:"), "CID must be BLAKE3");
        assert_eq!(r.id, r.receipt_cid, "@id must match receipt_cid");
    }

    #[test]
    fn cid_changes_with_each_stage() {
        let mut r = make_receipt();
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa")).unwrap();
        let cid_after_wa = r.receipt_cid.clone();

        r.append_stage(make_stage(PipelineStage::Check, "b3:check")).unwrap();
        let cid_after_check = r.receipt_cid.clone();

        assert_ne!(cid_after_wa, cid_after_check, "CID must change after each stage");
    }

    #[test]
    fn full_pipeline_stages() {
        let mut r = make_receipt();

        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa")).unwrap();
        r.append_stage(make_stage(PipelineStage::Check, "b3:check")).unwrap();
        r.append_stage(make_stage(PipelineStage::Transition, "b3:tr")).unwrap();
        r.append_stage(make_stage(PipelineStage::WriteFinished, "b3:wf")).unwrap();

        assert_eq!(r.stage_count(), 4);
        assert!(r.has_stage(PipelineStage::WriteAhead));
        assert!(r.has_stage(PipelineStage::Check));
        assert!(r.has_stage(PipelineStage::Transition));
        assert!(r.has_stage(PipelineStage::WriteFinished));
    }

    #[test]
    fn auth_tokens_are_non_empty() {
        let mut r = make_receipt();
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa")).unwrap();
        r.append_stage(make_stage(PipelineStage::Check, "b3:check")).unwrap();

        for stage in &r.stages {
            assert!(stage.auth_token.starts_with("hmac:"), "auth_token must be HMAC");
            assert!(stage.auth_token.len() > 5);
        }
    }

    #[test]
    fn auth_tokens_differ_per_stage() {
        let mut r = make_receipt();
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa")).unwrap();
        r.append_stage(make_stage(PipelineStage::Check, "b3:check")).unwrap();

        assert_ne!(
            r.stages[0].auth_token,
            r.stages[1].auth_token,
            "Each stage must have a unique auth token"
        );
    }

    #[test]
    fn deny_sets_decision_and_effect() {
        let mut r = make_receipt();
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa")).unwrap();
        r.deny("type not allowed");

        assert_eq!(r.decision, Decision::Deny);
        assert_eq!(r.effects["deny_reason"], "type not allowed");
    }

    #[test]
    fn to_json_has_all_anchors() {
        let mut r = make_receipt();
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa")).unwrap();

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
            auth_token: String::new(),
            duration_ms: 0,
        };

        r1.append_stage(stage1.clone()).unwrap();
        r2.append_stage(stage1).unwrap();

        assert_eq!(r1.receipt_cid, r2.receipt_cid, "Same inputs must produce same CID");
    }

    #[test]
    fn check_stage_includes_policy_trace() {
        let mut r = make_receipt();
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa")).unwrap();

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
        r.append_stage(make_stage(PipelineStage::WriteAhead, "b3:wa")).unwrap();

        let tr_stage = StageExecution {
            stage: PipelineStage::Transition,
            timestamp: chrono::Utc::now().to_rfc3339(),
            input_cid: "b3:tr-input".to_string(),
            output_cid: Some("b3:tr-output".to_string()),
            fuel_used: Some(42),
            policy_trace: vec![],
            auth_token: String::new(),
            duration_ms: 5,
        };

        r.append_stage(tr_stage).unwrap();
        assert_eq!(r.stages[1].fuel_used, Some(42));
    }
}
