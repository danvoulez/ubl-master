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

    // Pipeline errors (produce DENY receipt)
    #[serde(rename = "POLICY_DENIED")]
    PolicyDenied,
    #[serde(rename = "INVALID_CHIP")]
    InvalidChip,
    #[serde(rename = "INTERNAL_ERROR")]
    InternalError,
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
            | Self::KnockNotObject => 400,

            Self::PolicyDenied => 403,
            Self::InvalidChip => 422,
            Self::InternalError => 500,
        }
    }

    /// Whether this error produces a receipt (DENY) or just an HTTP error.
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
                serde_json::to_value(&code)
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
        let err = PipelineError::Knock("KNOCK-001: body too large (2000000 bytes, max 1048576)".to_string());
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
        ];
        for code in &codes {
            assert_eq!(code.http_status(), 400, "{:?} should be 400", code);
            assert!(!code.produces_receipt(), "{:?} should not produce receipt", code);
        }
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
}
