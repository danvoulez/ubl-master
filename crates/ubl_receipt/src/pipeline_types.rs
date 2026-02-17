//! Receipt types for the WA→TR→WF pipeline

use serde::{Deserialize, Serialize};

/// Decision result from policy evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny,
    Require,
}

/// Receipt types for the UBL MASTER pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UblReceiptType {
    #[serde(rename = "ubl/wa")]
    WriteAhead,
    #[serde(rename = "ubl/wf")]
    WriteFinished,
    #[serde(rename = "ubl/advisory")]
    Advisory,
    #[serde(rename = "ubl/knock")]
    Knock,
}

/// Write-Ahead receipt body (Stage 1: WA)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaReceiptBody {
    pub ghost: bool,
    pub chip_cid: String,
    pub policy_cid: String,
    pub frozen_time: String,
    pub caller: String,
    pub context: serde_json::Value,
    pub operation: String,
    /// Unique nonce for anti-replay (hex-encoded 16 random bytes)
    pub nonce: String,
    /// Key ID of the signer (e.g. `did:key:z...#ed25519`)
    pub kid: String,
}

/// Write-Finished receipt body (Stage 4: WF)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WfReceiptBody {
    pub decision: Decision,
    pub wa_cid: String,
    pub tr_cid: Option<String>,
    pub artifacts: std::collections::HashMap<String, String>,
    pub duration_ms: i64,
    pub policy_trace: Vec<PolicyTraceEntry>,
    pub short_circuited: bool,
}

/// Advisory receipt body (LLM advice - unsigned)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisoryBody {
    pub advisor_cid: String,
    pub advice_type: String,
    pub input_cid: String,
    pub output: serde_json::Value,
    pub confidence: f32,
    pub reasoning: String,
    pub context_used: Vec<String>,
}

/// Knock receipt body (Stage 0: ingestion)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnockBody {
    pub intent: ChipIntent,
    pub received_at: String,
    pub source_ip: String,
    pub user_agent: Option<String>,
    pub request_size: usize,
}

/// Chip creation intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChipIntent {
    pub operation: String,
    pub chip_type: String,
    pub logical_id: Option<String>,
    pub parents: Vec<String>,
    pub body_preview: serde_json::Value,
}

/// Policy trace entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTraceEntry {
    pub level: String,
    pub policy_id: String,
    pub result: Decision,
    pub reason: String,
    pub rb_results: Vec<RbResult>,
    pub duration_ms: i64,
}

/// Result from a single reasoning bit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbResult {
    pub rb_id: String,
    pub decision: Decision,
    pub reason: String,
    pub inputs_used: Vec<String>,
    pub duration_nanos: u64,
}

/// Operation result for WF receipts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationResult {
    Success { chip_cid: String },
    Failed { error: String, error_code: String },
    RequiresConsent { consent_request_id: String },
}
