//! Canonical error responses — every pipeline error becomes a `ubl/error` envelope.
//!
//! Error codes are stable and documented in ARCHITECTURE.md §12.2.
//! KNOCK failures → HTTP 400, no receipt.
//! Policy/internal failures → DENY receipt with full policy_trace.

use crate::pipeline::PipelineError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Stable error codes for the UBL pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    // KNOCK errors (400, no receipt)
    #[serde(rename = "KNOCK_BODY_TOO_LARGE")]
    KnockBodyTooLarge,
    #[serde(rename = "KNOCK_DEPTH_EXCEEDED")]
    KnockDepthExceeded,
    #[serde(rename = "KNOCK_ARRAY_TOO_LONG")]
    KnockArrayTooLong,
    #[serde(rename = "KNOCK_DUPLICATE_KEY")]
    KnockDuplicateKey,
    #[serde(rename = "KNOCK_INVALID_UTF8")]
    KnockInvalidUtf8,
    #[serde(rename = "KNOCK_MISSING_ANCHOR")]
    KnockMissingAnchor,
    #[serde(rename = "KNOCK_NOT_OBJECT")]
    KnockNotObject,
    #[serde(rename = "KNOCK_RAW_FLOAT")]
    KnockRawFloat,
    #[serde(rename = "KNOCK_MALFORMED_NUM")]
    KnockMalformedNum,
    #[serde(rename = "KNOCK_NUMERIC_LITERAL_NOT_ALLOWED")]
    KnockNumericLiteralNotAllowed,

    // Pipeline errors (produce DENY receipt)
    #[serde(rename = "POLICY_DENIED")]
    PolicyDenied,
    #[serde(rename = "INVALID_CHIP")]
    InvalidChip,
    #[serde(rename = "DEPENDENCY_MISSING")]
    DependencyMissing,

    // VM execution errors (produce DENY receipt)
    #[serde(rename = "FUEL_EXHAUSTED")]
    FuelExhausted,
    #[serde(rename = "TYPE_MISMATCH")]
    TypeMismatch,
    #[serde(rename = "STACK_UNDERFLOW")]
    StackUnderflow,
    #[serde(rename = "CAS_NOT_FOUND")]
    CasNotFound,

    // Security errors
    #[serde(rename = "REPLAY_DETECTED")]
    ReplayDetected,
    #[serde(rename = "CANON_ERROR")]
    CanonError,
    #[serde(rename = "SIGN_ERROR")]
    SignError,
    #[serde(rename = "STORAGE_ERROR")]
    StorageError,
    #[serde(rename = "invalid_signature")]
    InvalidSignature,
    #[serde(rename = "runtime_hash_mismatch")]
    RuntimeHashMismatch,
    #[serde(rename = "idempotency_conflict")]
    IdempotencyConflict,
    #[serde(rename = "durable_commit_failed")]
    DurableCommitFailed,
    #[serde(rename = "TAMPER_DETECTED")]
    TamperDetected,

    #[serde(rename = "INTERNAL_ERROR")]
    InternalError,

    // ── Unified taxonomy additions (P1.7) ──
    /// Authentication required or invalid credentials.
    #[serde(rename = "UNAUTHORIZED")]
    Unauthorized,
    /// Resource not found.
    #[serde(rename = "NOT_FOUND")]
    NotFound,
    /// Rate limit exceeded.
    #[serde(rename = "TOO_MANY_REQUESTS")]
    TooManyRequests,
    /// Service temporarily unavailable.
    #[serde(rename = "UNAVAILABLE")]
    Unavailable,
}

impl ErrorCode {
    /// HTTP status code for this error.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::KnockBodyTooLarge
            | Self::KnockDepthExceeded
            | Self::KnockArrayTooLong
            | Self::KnockDuplicateKey
            | Self::KnockInvalidUtf8
            | Self::KnockMissingAnchor
            | Self::KnockNotObject
            | Self::KnockRawFloat
            | Self::KnockMalformedNum
            | Self::KnockNumericLiteralNotAllowed => 400,

            Self::PolicyDenied => 403,
            Self::DependencyMissing => 409,
            Self::ReplayDetected => 409,
            Self::InvalidChip => 422,
            Self::FuelExhausted => 422,
            Self::TypeMismatch => 422,
            Self::StackUnderflow => 422,
            Self::CasNotFound => 422,
            Self::CanonError => 422,
            Self::SignError => 422,
            Self::StorageError => 500,
            Self::InvalidSignature => 400,
            Self::RuntimeHashMismatch => 400,
            Self::IdempotencyConflict => 409,
            Self::DurableCommitFailed => 500,
            Self::TamperDetected => 422,
            Self::InternalError => 500,
            Self::Unauthorized => 401,
            Self::NotFound => 404,
            Self::TooManyRequests => 429,
            Self::Unavailable => 503,
        }
    }

    /// Unified error category per the P1.7 taxonomy.
    ///
    /// Maps every `ErrorCode` to one of 8 categories:
    /// BadInput, Unauthorized, Forbidden, NotFound, Conflict,
    /// TooManyRequests, Internal, Unavailable.
    pub fn category(&self) -> &'static str {
        match self {
            Self::KnockBodyTooLarge
            | Self::KnockDepthExceeded
            | Self::KnockArrayTooLong
            | Self::KnockDuplicateKey
            | Self::KnockInvalidUtf8
            | Self::KnockMissingAnchor
            | Self::KnockNotObject
            | Self::KnockRawFloat
            | Self::KnockMalformedNum
            | Self::KnockNumericLiteralNotAllowed
            | Self::InvalidChip
            | Self::CanonError
            | Self::FuelExhausted
            | Self::TypeMismatch
            | Self::StackUnderflow
            | Self::CasNotFound => "BadInput",
            Self::InvalidSignature | Self::RuntimeHashMismatch => "BadInput",

            Self::Unauthorized | Self::SignError => "Unauthorized",
            Self::PolicyDenied => "Forbidden",
            Self::NotFound | Self::DependencyMissing => "NotFound",
            Self::ReplayDetected | Self::IdempotencyConflict => "Conflict",
            Self::TamperDetected => "Conflict",
            Self::TooManyRequests => "TooManyRequests",
            Self::StorageError | Self::DurableCommitFailed | Self::InternalError => "Internal",
            Self::Unavailable => "Unavailable",
        }
    }

    /// MCP error code mapping.
    ///
    /// Maps to JSON-RPC 2.0 error codes used by MCP:
    /// -32600 (Invalid Request), -32602 (Invalid Params),
    /// -32001 (Unauthorized), -32003 (Forbidden), -32004 (Not Found),
    /// -32005 (Conflict), -32006 (Too Many Requests),
    /// -32603 (Internal), -32000 (Server Error/Unavailable).
    pub fn mcp_code(&self) -> i32 {
        match self.category() {
            "BadInput" => -32602,
            "Unauthorized" => -32001,
            "Forbidden" => -32003,
            "NotFound" => -32004,
            "Conflict" => -32005,
            "TooManyRequests" => -32006,
            "Internal" => -32603,
            "Unavailable" => -32000,
            _ => -32603,
        }
    }

    /// Whether this error produces a receipt (DENY) or just an HTTP error.
    /// KNOCK errors are pre-pipeline — no receipt. Everything else gets a DENY receipt.
    pub fn produces_receipt(&self) -> bool {
        !matches!(
            self,
            Self::KnockBodyTooLarge
                | Self::KnockDepthExceeded
                | Self::KnockArrayTooLong
                | Self::KnockDuplicateKey
                | Self::KnockInvalidUtf8
                | Self::KnockMissingAnchor
                | Self::KnockNotObject
                | Self::KnockRawFloat
                | Self::KnockMalformedNum
                | Self::KnockNumericLiteralNotAllowed
                | Self::Unauthorized
                | Self::NotFound
                | Self::TooManyRequests
                | Self::TamperDetected
                | Self::Unavailable
        )
    }

    /// Whether this error is a VM execution error.
    pub fn is_vm_error(&self) -> bool {
        matches!(
            self,
            Self::FuelExhausted | Self::TypeMismatch | Self::StackUnderflow | Self::CasNotFound
        )
    }
}

/// Canonical error response in Universal Envelope format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UblError {
    #[serde(rename = "@type")]
    pub error_type: String,
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@ver")]
    pub ver: String,
    #[serde(rename = "@world")]
    pub world: String,
    pub code: ErrorCode,
    pub message: String,
    pub link: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl UblError {
    /// Create a new error response from a PipelineError.
    pub fn from_pipeline_error(err: &PipelineError) -> Self {
        let (code, message) = match err {
            PipelineError::Knock(msg) => {
                let code = classify_knock_error(msg);
                (code, msg.clone())
            }
            PipelineError::PolicyDenied(msg) => (ErrorCode::PolicyDenied, msg.clone()),
            PipelineError::InvalidChip(msg) => (ErrorCode::InvalidChip, msg.clone()),
            PipelineError::DependencyMissing(msg) => (ErrorCode::DependencyMissing, msg.clone()),
            PipelineError::FuelExhausted(msg) => (ErrorCode::FuelExhausted, msg.clone()),
            PipelineError::TypeMismatch(msg) => (ErrorCode::TypeMismatch, msg.clone()),
            PipelineError::StackUnderflow(msg) => (ErrorCode::StackUnderflow, msg.clone()),
            PipelineError::CasNotFound(msg) => (ErrorCode::CasNotFound, msg.clone()),
            PipelineError::ReplayDetected(msg) => (ErrorCode::ReplayDetected, msg.clone()),
            PipelineError::CanonError(msg) => (ErrorCode::CanonError, msg.clone()),
            PipelineError::SignError(msg) => (ErrorCode::SignError, msg.clone()),
            PipelineError::StorageError(msg) => (ErrorCode::StorageError, msg.clone()),
            PipelineError::IdempotencyConflict(msg) => {
                (ErrorCode::IdempotencyConflict, msg.clone())
            }
            PipelineError::DurableCommitFailed(msg) => {
                (ErrorCode::DurableCommitFailed, msg.clone())
            }
            PipelineError::Internal(msg) => (ErrorCode::InternalError, msg.clone()),
        };

        Self {
            error_type: "ubl/error".to_string(),
            id: format!("err-{}", uuid_v4_hex()),
            ver: "1.0".to_string(),
            world: "a/system/t/errors".to_string(),
            code,
            message,
            link: format!(
                "https://docs.ubl.agency/errors#{}",
                serde_json::to_value(code)
                    .unwrap_or(Value::Null)
                    .as_str()
                    .unwrap_or("UNKNOWN")
            ),
            details: None,
        }
    }

    /// Serialize to JSON Value (Universal Envelope format).
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(json!({
            "@type": "ubl/error",
            "code": "INTERNAL_ERROR",
            "message": "Failed to serialize error"
        }))
    }
}

/// Classify a KNOCK error message into a specific error code.
fn classify_knock_error(msg: &str) -> ErrorCode {
    if msg.contains("KNOCK-001") {
        ErrorCode::KnockBodyTooLarge
    } else if msg.contains("KNOCK-002") {
        ErrorCode::KnockDepthExceeded
    } else if msg.contains("KNOCK-003") {
        ErrorCode::KnockArrayTooLong
    } else if msg.contains("KNOCK-004") {
        ErrorCode::KnockDuplicateKey
    } else if msg.contains("KNOCK-005") {
        ErrorCode::KnockInvalidUtf8
    } else if msg.contains("KNOCK-006") {
        ErrorCode::KnockMissingAnchor
    } else if msg.contains("KNOCK-007") {
        ErrorCode::KnockNotObject
    } else if msg.contains("KNOCK-008") {
        ErrorCode::KnockRawFloat
    } else if msg.contains("KNOCK-009") {
        ErrorCode::KnockMalformedNum
    } else if msg.contains("KNOCK-010") {
        ErrorCode::KnockNumericLiteralNotAllowed
    } else {
        ErrorCode::KnockInvalidUtf8 // fallback
    }
}

/// Generate a simple hex ID (not a real UUID, but unique enough for error IDs).
fn uuid_v4_hex() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knock_error_maps_to_400() {
        let err = PipelineError::Knock(
            "KNOCK-001: body too large (2000000 bytes, max 1048576)".to_string(),
        );
        let ubl_err = UblError::from_pipeline_error(&err);
        assert_eq!(ubl_err.code, ErrorCode::KnockBodyTooLarge);
        assert_eq!(ubl_err.code.http_status(), 400);
        assert!(!ubl_err.code.produces_receipt());
    }

    #[test]
    fn policy_denied_maps_to_403() {
        let err = PipelineError::PolicyDenied("type not allowed".to_string());
        let ubl_err = UblError::from_pipeline_error(&err);
        assert_eq!(ubl_err.code, ErrorCode::PolicyDenied);
        assert_eq!(ubl_err.code.http_status(), 403);
        assert!(ubl_err.code.produces_receipt());
    }

    #[test]
    fn invalid_chip_maps_to_422() {
        let err = PipelineError::InvalidChip("@world: invalid format".to_string());
        let ubl_err = UblError::from_pipeline_error(&err);
        assert_eq!(ubl_err.code, ErrorCode::InvalidChip);
        assert_eq!(ubl_err.code.http_status(), 422);
    }

    #[test]
    fn internal_error_maps_to_500() {
        let err = PipelineError::Internal("something broke".to_string());
        let ubl_err = UblError::from_pipeline_error(&err);
        assert_eq!(ubl_err.code, ErrorCode::InternalError);
        assert_eq!(ubl_err.code.http_status(), 500);
    }

    #[test]
    fn error_json_has_envelope_anchors() {
        let err = PipelineError::Knock("KNOCK-006: missing required anchor \"@type\"".to_string());
        let ubl_err = UblError::from_pipeline_error(&err);
        let json = ubl_err.to_json();
        assert_eq!(json["@type"], "ubl/error");
        assert!(json["@id"].as_str().unwrap().starts_with("err-"));
        assert_eq!(json["@ver"], "1.0");
        assert_eq!(json["@world"], "a/system/t/errors");
        assert_eq!(json["code"], "KNOCK_MISSING_ANCHOR");
    }

    #[test]
    fn all_knock_codes_are_400() {
        let codes = [
            ErrorCode::KnockBodyTooLarge,
            ErrorCode::KnockDepthExceeded,
            ErrorCode::KnockArrayTooLong,
            ErrorCode::KnockDuplicateKey,
            ErrorCode::KnockInvalidUtf8,
            ErrorCode::KnockMissingAnchor,
            ErrorCode::KnockNotObject,
            ErrorCode::KnockRawFloat,
            ErrorCode::KnockMalformedNum,
            ErrorCode::KnockNumericLiteralNotAllowed,
        ];
        for code in &codes {
            assert_eq!(code.http_status(), 400, "{:?} should be 400", code);
            assert!(
                !code.produces_receipt(),
                "{:?} should not produce receipt",
                code
            );
        }
    }

    #[test]
    fn knock_raw_float_maps_to_400() {
        let err = PipelineError::Knock(
            "KNOCK-008: raw float in payload violates UNC-1 — use @num atoms: 12.34".to_string(),
        );
        let ubl_err = UblError::from_pipeline_error(&err);
        assert_eq!(ubl_err.code, ErrorCode::KnockRawFloat);
        assert_eq!(ubl_err.code.http_status(), 400);
        assert!(!ubl_err.code.produces_receipt());
    }

    #[test]
    fn knock_malformed_num_maps_to_400() {
        let err =
            PipelineError::Knock("KNOCK-009: malformed @num atom: $.amount missing m".to_string());
        let ubl_err = UblError::from_pipeline_error(&err);
        assert_eq!(ubl_err.code, ErrorCode::KnockMalformedNum);
        assert_eq!(ubl_err.code.http_status(), 400);
        assert!(!ubl_err.code.produces_receipt());
    }

    #[test]
    fn error_link_contains_code() {
        let err = PipelineError::Knock("KNOCK-004: duplicate key \"name\"".to_string());
        let ubl_err = UblError::from_pipeline_error(&err);
        assert!(ubl_err.link.contains("KNOCK_DUPLICATE_KEY"));
    }

    #[test]
    fn each_error_gets_unique_id() {
        let err = PipelineError::Internal("test".to_string());
        let e1 = UblError::from_pipeline_error(&err);
        let e2 = UblError::from_pipeline_error(&err);
        assert_ne!(e1.id, e2.id);
    }

    #[test]
    fn fuel_exhausted_maps_to_422() {
        let err = PipelineError::FuelExhausted("VM fuel exhausted (limit: 10000)".to_string());
        let ubl_err = UblError::from_pipeline_error(&err);
        assert_eq!(ubl_err.code, ErrorCode::FuelExhausted);
        assert_eq!(ubl_err.code.http_status(), 422);
        assert!(ubl_err.code.produces_receipt());
        assert!(ubl_err.code.is_vm_error());
    }

    #[test]
    fn type_mismatch_maps_to_422() {
        let err = PipelineError::TypeMismatch("type mismatch at AddI64".to_string());
        let ubl_err = UblError::from_pipeline_error(&err);
        assert_eq!(ubl_err.code, ErrorCode::TypeMismatch);
        assert_eq!(ubl_err.code.http_status(), 422);
        assert!(ubl_err.code.is_vm_error());
    }

    #[test]
    fn stack_underflow_maps_to_422() {
        let err = PipelineError::StackUnderflow("stack underflow at Drop".to_string());
        let ubl_err = UblError::from_pipeline_error(&err);
        assert_eq!(ubl_err.code, ErrorCode::StackUnderflow);
        assert_eq!(ubl_err.code.http_status(), 422);
        assert!(ubl_err.code.is_vm_error());
    }

    #[test]
    fn cas_not_found_maps_to_422() {
        let err = PipelineError::CasNotFound("cas_get_not_found".to_string());
        let ubl_err = UblError::from_pipeline_error(&err);
        assert_eq!(ubl_err.code, ErrorCode::CasNotFound);
        assert_eq!(ubl_err.code.http_status(), 422);
        assert!(ubl_err.code.is_vm_error());
    }

    #[test]
    fn replay_detected_maps_to_409() {
        let err = PipelineError::ReplayDetected("duplicate nonce".to_string());
        let ubl_err = UblError::from_pipeline_error(&err);
        assert_eq!(ubl_err.code, ErrorCode::ReplayDetected);
        assert_eq!(ubl_err.code.http_status(), 409);
        assert!(ubl_err.code.produces_receipt());
        assert!(!ubl_err.code.is_vm_error());
    }

    #[test]
    fn canon_error_maps_to_422() {
        let err = PipelineError::CanonError("NFC normalization failed".to_string());
        let ubl_err = UblError::from_pipeline_error(&err);
        assert_eq!(ubl_err.code, ErrorCode::CanonError);
        assert_eq!(ubl_err.code.http_status(), 422);
    }

    #[test]
    fn sign_error_maps_to_422() {
        let err = PipelineError::SignError("invalid signature".to_string());
        let ubl_err = UblError::from_pipeline_error(&err);
        assert_eq!(ubl_err.code, ErrorCode::SignError);
        assert_eq!(ubl_err.code.http_status(), 422);
    }

    #[test]
    fn storage_error_maps_to_500() {
        let err = PipelineError::StorageError("disk full".to_string());
        let ubl_err = UblError::from_pipeline_error(&err);
        assert_eq!(ubl_err.code, ErrorCode::StorageError);
        assert_eq!(ubl_err.code.http_status(), 500);
        assert!(ubl_err.code.produces_receipt());
    }

    #[test]
    fn all_vm_errors_are_422() {
        let vm_codes = [
            ErrorCode::FuelExhausted,
            ErrorCode::TypeMismatch,
            ErrorCode::StackUnderflow,
            ErrorCode::CasNotFound,
        ];
        for code in &vm_codes {
            assert_eq!(code.http_status(), 422, "{:?} should be 422", code);
            assert!(code.is_vm_error(), "{:?} should be VM error", code);
            assert!(code.produces_receipt(), "{:?} should produce receipt", code);
        }
    }

    #[test]
    fn non_vm_errors_are_not_vm_errors() {
        let non_vm = [
            ErrorCode::PolicyDenied,
            ErrorCode::InvalidChip,
            ErrorCode::InternalError,
            ErrorCode::ReplayDetected,
            ErrorCode::KnockBodyTooLarge,
        ];
        for code in &non_vm {
            assert!(!code.is_vm_error(), "{:?} should NOT be VM error", code);
        }
    }

    #[test]
    fn dependency_missing_maps_to_409() {
        let err = PipelineError::DependencyMissing("ubl/app required before ubl/user".to_string());
        let ubl_err = UblError::from_pipeline_error(&err);
        assert_eq!(ubl_err.code, ErrorCode::DependencyMissing);
        assert_eq!(ubl_err.code.http_status(), 409);
    }

    // ── Unified taxonomy tests (P1.7) ──

    #[test]
    fn new_codes_have_correct_http_status() {
        assert_eq!(ErrorCode::Unauthorized.http_status(), 401);
        assert_eq!(ErrorCode::NotFound.http_status(), 404);
        assert_eq!(ErrorCode::TooManyRequests.http_status(), 429);
        assert_eq!(ErrorCode::TamperDetected.http_status(), 422);
        assert_eq!(ErrorCode::Unavailable.http_status(), 503);
    }

    #[test]
    fn new_codes_do_not_produce_receipts() {
        assert!(!ErrorCode::Unauthorized.produces_receipt());
        assert!(!ErrorCode::NotFound.produces_receipt());
        assert!(!ErrorCode::TooManyRequests.produces_receipt());
        assert!(!ErrorCode::TamperDetected.produces_receipt());
        assert!(!ErrorCode::Unavailable.produces_receipt());
    }

    #[test]
    fn category_covers_all_8_categories() {
        let mut categories = std::collections::HashSet::new();
        let all_codes = [
            ErrorCode::KnockBodyTooLarge,
            ErrorCode::Unauthorized,
            ErrorCode::PolicyDenied,
            ErrorCode::NotFound,
            ErrorCode::ReplayDetected,
            ErrorCode::TooManyRequests,
            ErrorCode::InternalError,
            ErrorCode::Unavailable,
        ];
        for code in &all_codes {
            categories.insert(code.category());
        }
        assert_eq!(categories.len(), 8, "must cover all 8 taxonomy categories");
        assert!(categories.contains("BadInput"));
        assert!(categories.contains("Unauthorized"));
        assert!(categories.contains("Forbidden"));
        assert!(categories.contains("NotFound"));
        assert!(categories.contains("Conflict"));
        assert!(categories.contains("TooManyRequests"));
        assert!(categories.contains("Internal"));
        assert!(categories.contains("Unavailable"));
    }

    #[test]
    fn category_assignments_correct() {
        assert_eq!(ErrorCode::KnockBodyTooLarge.category(), "BadInput");
        assert_eq!(ErrorCode::InvalidChip.category(), "BadInput");
        assert_eq!(ErrorCode::FuelExhausted.category(), "BadInput");
        assert_eq!(ErrorCode::Unauthorized.category(), "Unauthorized");
        assert_eq!(ErrorCode::SignError.category(), "Unauthorized");
        assert_eq!(ErrorCode::PolicyDenied.category(), "Forbidden");
        assert_eq!(ErrorCode::DependencyMissing.category(), "NotFound");
        assert_eq!(ErrorCode::NotFound.category(), "NotFound");
        assert_eq!(ErrorCode::ReplayDetected.category(), "Conflict");
        assert_eq!(ErrorCode::TamperDetected.category(), "Conflict");
        assert_eq!(ErrorCode::TooManyRequests.category(), "TooManyRequests");
        assert_eq!(ErrorCode::InternalError.category(), "Internal");
        assert_eq!(ErrorCode::StorageError.category(), "Internal");
        assert_eq!(ErrorCode::Unavailable.category(), "Unavailable");
    }

    #[test]
    fn mcp_codes_are_negative() {
        let all_codes = [
            ErrorCode::KnockBodyTooLarge,
            ErrorCode::Unauthorized,
            ErrorCode::PolicyDenied,
            ErrorCode::NotFound,
            ErrorCode::ReplayDetected,
            ErrorCode::TooManyRequests,
            ErrorCode::InternalError,
            ErrorCode::Unavailable,
        ];
        for code in &all_codes {
            assert!(code.mcp_code() < 0, "{:?} mcp_code must be negative", code);
        }
    }

    #[test]
    fn mcp_code_mapping() {
        assert_eq!(ErrorCode::InvalidChip.mcp_code(), -32602); // BadInput
        assert_eq!(ErrorCode::Unauthorized.mcp_code(), -32001); // Unauthorized
        assert_eq!(ErrorCode::PolicyDenied.mcp_code(), -32003); // Forbidden
        assert_eq!(ErrorCode::NotFound.mcp_code(), -32004); // NotFound
        assert_eq!(ErrorCode::ReplayDetected.mcp_code(), -32005); // Conflict
        assert_eq!(ErrorCode::TamperDetected.mcp_code(), -32005); // Conflict
        assert_eq!(ErrorCode::TooManyRequests.mcp_code(), -32006); // TooManyRequests
        assert_eq!(ErrorCode::InternalError.mcp_code(), -32603); // Internal
        assert_eq!(ErrorCode::Unavailable.mcp_code(), -32000); // Unavailable
    }

    #[test]
    fn new_codes_serialize_correctly() {
        let json = serde_json::to_value(ErrorCode::Unauthorized).unwrap();
        assert_eq!(json, "UNAUTHORIZED");
        let json = serde_json::to_value(ErrorCode::NotFound).unwrap();
        assert_eq!(json, "NOT_FOUND");
        let json = serde_json::to_value(ErrorCode::TooManyRequests).unwrap();
        assert_eq!(json, "TOO_MANY_REQUESTS");
        let json = serde_json::to_value(ErrorCode::TamperDetected).unwrap();
        assert_eq!(json, "TAMPER_DETECTED");
        let json = serde_json::to_value(ErrorCode::Unavailable).unwrap();
        assert_eq!(json, "UNAVAILABLE");
    }
}
