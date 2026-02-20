use chrono::Utc;
use serde_json::{json, Value};
use ubl_runtime::error_response::ErrorCode;
use ubl_runtime::manifest::GateManifest;

fn all_error_codes() -> Vec<ErrorCode> {
    vec![
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
        ErrorCode::PolicyDenied,
        ErrorCode::InvalidChip,
        ErrorCode::DependencyMissing,
        ErrorCode::FuelExhausted,
        ErrorCode::TypeMismatch,
        ErrorCode::StackUnderflow,
        ErrorCode::CasNotFound,
        ErrorCode::ReplayDetected,
        ErrorCode::CanonError,
        ErrorCode::SignError,
        ErrorCode::StorageError,
        ErrorCode::InvalidSignature,
        ErrorCode::RuntimeHashMismatch,
        ErrorCode::IdempotencyConflict,
        ErrorCode::DurableCommitFailed,
        ErrorCode::TamperDetected,
        ErrorCode::InternalError,
        ErrorCode::Unauthorized,
        ErrorCode::NotFound,
        ErrorCode::TooManyRequests,
        ErrorCode::Unavailable,
    ]
}

// Keep this exhaustive so compile fails when ErrorCode gains a new variant
// and this exporter is not updated.
fn assert_exhaustive(code: ErrorCode) {
    match code {
        ErrorCode::KnockBodyTooLarge
        | ErrorCode::KnockDepthExceeded
        | ErrorCode::KnockArrayTooLong
        | ErrorCode::KnockDuplicateKey
        | ErrorCode::KnockInvalidUtf8
        | ErrorCode::KnockMissingAnchor
        | ErrorCode::KnockNotObject
        | ErrorCode::KnockRawFloat
        | ErrorCode::KnockMalformedNum
        | ErrorCode::KnockNumericLiteralNotAllowed
        | ErrorCode::PolicyDenied
        | ErrorCode::InvalidChip
        | ErrorCode::DependencyMissing
        | ErrorCode::FuelExhausted
        | ErrorCode::TypeMismatch
        | ErrorCode::StackUnderflow
        | ErrorCode::CasNotFound
        | ErrorCode::ReplayDetected
        | ErrorCode::CanonError
        | ErrorCode::SignError
        | ErrorCode::StorageError
        | ErrorCode::InvalidSignature
        | ErrorCode::RuntimeHashMismatch
        | ErrorCode::IdempotencyConflict
        | ErrorCode::DurableCommitFailed
        | ErrorCode::TamperDetected
        | ErrorCode::InternalError
        | ErrorCode::Unauthorized
        | ErrorCode::NotFound
        | ErrorCode::TooManyRequests
        | ErrorCode::Unavailable => {}
    }
}

fn error_code_name(code: ErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|v| v.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "UNKNOWN".to_string())
}

fn export_errors() -> Vec<Value> {
    let mut out = Vec::new();
    for code in all_error_codes() {
        assert_exhaustive(code);
        out.push(json!({
            "code": error_code_name(code),
            "http_status": code.http_status(),
            "category": code.category(),
            "mcp_code": code.mcp_code(),
            "produces_receipt": code.produces_receipt(),
            "is_vm_error": code.is_vm_error(),
        }));
    }
    out.sort_by(|a, b| {
        let aa = a["code"].as_str().unwrap_or_default();
        let bb = b["code"].as_str().unwrap_or_default();
        aa.cmp(bb)
    });
    out
}

fn main() {
    let manifest = GateManifest::default();
    let payload = json!({
        "generated_at_utc": Utc::now().format("%Y-%m-%d").to_string(),
        "openapi": manifest.to_openapi(),
        "errors": export_errors(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).expect("serialize payload")
    );
}
