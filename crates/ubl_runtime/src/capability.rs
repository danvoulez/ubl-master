//! Capability-based authorization for sensitive chip operations.
//!
//! Per the "ato oficial" §P0.3 and §P0.4:
//! - `ubl/app` and first `ubl/user` require `cap.registry:init` capability.
//! - `ubl/membership`, `ubl/revoke` require a signed capability in the chip body.
//! - Capabilities have audience, scope, and expiration.
//! - Consumed capabilities are recorded in the receipt.
//!
//! A capability is a JSON object embedded in the chip body under `@cap`:
//! ```json
//! {
//!   "@cap": {
//!     "action": "registry:init",
//!     "audience": "a/acme",
//!     "issued_by": "did:key:z...",
//!     "issued_at": "2025-01-01T00:00:00Z",
//!     "expires_at": "2025-12-31T23:59:59Z",
//!     "signature": "ed25519:..."
//!   }
//! }
//! ```

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// A capability embedded in a chip body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    /// The action this capability grants (e.g. "registry:init", "membership:grant", "revoke:any").
    pub action: String,
    /// The audience scope (e.g. "a/acme", "a/acme/t/prod").
    pub audience: String,
    /// DID of the issuer.
    pub issued_by: String,
    /// RFC-3339 timestamp of issuance.
    pub issued_at: String,
    /// RFC-3339 timestamp of expiration. Empty = never expires.
    #[serde(default)]
    pub expires_at: String,
    /// Ed25519 signature over the canonical capability fields.
    #[serde(default)]
    pub signature: String,
}

/// Errors from capability validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapError {
    /// No @cap field in chip body.
    Missing,
    /// @cap field is malformed.
    Malformed(String),
    /// Capability action doesn't match required action.
    WrongAction { required: String, got: String },
    /// Capability audience doesn't match chip @world.
    WrongAudience { required: String, got: String },
    /// Capability has expired.
    Expired { expires_at: String, now: String },
    /// Signature is missing or invalid.
    InvalidSignature(String),
}

impl std::fmt::Display for CapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "missing @cap: capability required"),
            Self::Malformed(msg) => write!(f, "malformed @cap: {}", msg),
            Self::WrongAction { required, got } => write!(
                f,
                "wrong capability action: required '{}', got '{}'",
                required, got
            ),
            Self::WrongAudience { required, got } => write!(
                f,
                "wrong capability audience: required '{}', got '{}'",
                required, got
            ),
            Self::Expired { expires_at, now } => {
                write!(f, "capability expired at {} (now: {})", expires_at, now)
            }
            Self::InvalidSignature(msg) => write!(f, "invalid capability signature: {}", msg),
        }
    }
}

impl std::error::Error for CapError {}

/// Required capabilities per chip type.
pub fn required_capability(chip_type: &str) -> Option<&'static str> {
    match chip_type {
        "ubl/app" => Some("registry:init"),
        "ubl/membership" => Some("membership:grant"),
        "ubl/revoke" => Some("revoke:execute"),
        "ubl/key.rotate" => Some("key:rotate"),
        "audit/report.request.v1" => Some("audit:report"),
        "audit/ledger.snapshot.request.v1" => Some("audit:snapshot"),
        "ledger/segment.compact.v1" => Some("ledger:compact"),
        "audit/advisory.request.v1" => Some("audit:advisory"),
        _ => None,
    }
}

/// Check if a chip type requires a capability for the first instance.
/// `ubl/user` only requires cap when it's the first user for an app.
pub fn requires_cap_for_first(chip_type: &str) -> bool {
    chip_type == "ubl/user"
}

/// Extract a capability from a chip body's `@cap` field.
pub fn extract_cap(body: &Value) -> Result<Capability, CapError> {
    let cap_val = body.get("@cap").ok_or(CapError::Missing)?;

    serde_json::from_value::<Capability>(cap_val.clone())
        .map_err(|e| CapError::Malformed(e.to_string()))
}

/// Validate a capability against requirements.
///
/// Checks:
/// 1. Action matches the required action.
/// 2. Audience matches the chip's @world scope boundary.
/// 3. issued_at/expires_at (if present) are valid RFC-3339.
/// 4. Not expired (if expires_at is set).
/// 5. Signature is valid over canonical capability payload.
pub fn validate_cap(cap: &Capability, required_action: &str, world: &str) -> Result<(), CapError> {
    // 1. Action check
    if cap.action != required_action {
        return Err(CapError::WrongAction {
            required: required_action.to_string(),
            got: cap.action.clone(),
        });
    }

    // 2. Audience check with path boundary semantics.
    //    "a/acme" matches "a/acme/t/prod", but not "a/acme2".
    if !audience_matches_world(&cap.audience, world) {
        return Err(CapError::WrongAudience {
            required: world.to_string(),
            got: cap.audience.clone(),
        });
    }

    // 3. Timestamp parse/validation
    let issued_at = chrono::DateTime::parse_from_rfc3339(&cap.issued_at)
        .map_err(|e| CapError::Malformed(format!("issued_at must be RFC-3339: {}", e)))?
        .with_timezone(&chrono::Utc);

    let now = chrono::Utc::now();

    // 4. Expiration check
    if !cap.expires_at.is_empty() {
        let expires_at = chrono::DateTime::parse_from_rfc3339(&cap.expires_at)
            .map_err(|e| CapError::Malformed(format!("expires_at must be RFC-3339: {}", e)))?
            .with_timezone(&chrono::Utc);

        if expires_at <= issued_at {
            return Err(CapError::Malformed(
                "expires_at must be later than issued_at".to_string(),
            ));
        }

        if expires_at <= now {
            return Err(CapError::Expired {
                expires_at: cap.expires_at.clone(),
                now: now.to_rfc3339(),
            });
        }
    }

    // 5. Signature verification
    if cap.signature.is_empty() {
        return Err(CapError::InvalidSignature("signature is empty".to_string()));
    }

    let verifying_key = ubl_kms::verifying_key_from_did(&cap.issued_by)
        .map_err(|e| CapError::InvalidSignature(e.to_string()))?;

    let payload = cap_signing_payload(cap);
    let verified = ubl_kms::verify_canonical(
        &verifying_key,
        &payload,
        ubl_kms::domain::CAPABILITY,
        &cap.signature,
    )
    .map_err(|e| CapError::InvalidSignature(e.to_string()))?;

    if !verified {
        return Err(CapError::InvalidSignature(
            "signature verification failed".to_string(),
        ));
    }

    Ok(())
}

fn audience_matches_world(audience: &str, world: &str) -> bool {
    if world == audience {
        return true;
    }

    if let Some(rest) = world.strip_prefix(audience) {
        return rest.starts_with('/');
    }

    false
}

fn cap_signing_payload(cap: &Capability) -> Value {
    json!({
        "action": cap.action,
        "audience": cap.audience,
        "issued_by": cap.issued_by,
        "issued_at": cap.issued_at,
        "expires_at": cap.expires_at,
    })
}

/// Validate that a chip body carries the required capability.
/// Returns the validated capability on success (for receipt recording).
pub fn require_cap(
    body: &Value,
    required_action: &str,
    world: &str,
) -> Result<Capability, CapError> {
    let cap = extract_cap(body)?;
    validate_cap(&cap, required_action, world)?;
    Ok(cap)
}

/// Record of a consumed capability in a receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumedCap {
    pub action: String,
    pub audience: String,
    pub issued_by: String,
    pub consumed_at: String,
}

impl From<&Capability> for ConsumedCap {
    fn from(cap: &Capability) -> Self {
        Self {
            action: cap.action.clone(),
            audience: cap.audience.clone(),
            issued_by: cap.issued_by.clone(),
            consumed_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_signed_cap(action: &str, audience: &str, issued_at: &str, expires_at: &str) -> Value {
        let sk = ubl_kms::generate_signing_key();
        let vk = ubl_kms::verifying_key(&sk);
        let issued_by = ubl_kms::did_from_verifying_key(&vk);

        let payload = json!({
            "action": action,
            "audience": audience,
            "issued_by": issued_by,
            "issued_at": issued_at,
            "expires_at": expires_at,
        });

        let sig = ubl_kms::sign_canonical(&sk, &payload, ubl_kms::domain::CAPABILITY).unwrap();

        json!({
            "action": action,
            "audience": audience,
            "issued_by": payload["issued_by"],
            "issued_at": issued_at,
            "expires_at": expires_at,
            "signature": sig,
        })
    }

    fn make_valid_cap(action: &str, audience: &str) -> Value {
        make_signed_cap(
            action,
            audience,
            "2025-01-01T00:00:00Z",
            "2099-12-31T23:59:59Z",
        )
    }

    #[test]
    fn extract_valid_cap() {
        let body = json!({
            "@type": "ubl/app",
            "@cap": make_valid_cap("registry:init", "a/acme")
        });
        let cap = extract_cap(&body).unwrap();
        assert_eq!(cap.action, "registry:init");
        assert_eq!(cap.audience, "a/acme");
        assert!(cap.issued_by.starts_with("did:key:z"));
    }

    #[test]
    fn extract_missing_cap() {
        let body = json!({"@type": "ubl/app"});
        assert!(matches!(extract_cap(&body), Err(CapError::Missing)));
    }

    #[test]
    fn extract_malformed_cap() {
        let body = json!({"@type": "ubl/app", "@cap": "not-an-object"});
        assert!(matches!(extract_cap(&body), Err(CapError::Malformed(_))));
    }

    #[test]
    fn validate_correct_action() {
        let cap_val = make_valid_cap("registry:init", "a/acme");
        let cap: Capability = serde_json::from_value(cap_val).unwrap();
        assert!(validate_cap(&cap, "registry:init", "a/acme/t/prod").is_ok());
    }

    #[test]
    fn validate_wrong_action() {
        let cap_val = make_valid_cap("membership:grant", "a/acme");
        let cap: Capability = serde_json::from_value(cap_val).unwrap();
        let err = validate_cap(&cap, "registry:init", "a/acme").unwrap_err();
        assert!(matches!(err, CapError::WrongAction { .. }));
    }

    #[test]
    fn validate_wrong_audience() {
        let cap_val = make_valid_cap("registry:init", "a/other");
        let cap: Capability = serde_json::from_value(cap_val).unwrap();
        let err = validate_cap(&cap, "registry:init", "a/acme/t/prod").unwrap_err();
        assert!(matches!(err, CapError::WrongAudience { .. }));
    }

    #[test]
    fn validate_audience_prefix_match() {
        let cap_val = make_valid_cap("registry:init", "a/acme");
        let cap: Capability = serde_json::from_value(cap_val).unwrap();
        assert!(validate_cap(&cap, "registry:init", "a/acme/t/prod").is_ok());
    }

    #[test]
    fn validate_audience_boundary_mismatch_rejected() {
        let cap_val = make_valid_cap("registry:init", "a/ac");
        let cap: Capability = serde_json::from_value(cap_val).unwrap();
        let err = validate_cap(&cap, "registry:init", "a/acme/t/prod").unwrap_err();
        assert!(matches!(err, CapError::WrongAudience { .. }));
    }

    #[test]
    fn validate_expired_cap() {
        let body = make_signed_cap(
            "registry:init",
            "a/acme",
            "2020-01-01T00:00:00Z",
            "2020-12-31T23:59:59Z",
        );
        let cap: Capability = serde_json::from_value(body).unwrap();
        let err = validate_cap(&cap, "registry:init", "a/acme").unwrap_err();
        assert!(matches!(err, CapError::Expired { .. }));
    }

    #[test]
    fn validate_no_expiry_is_ok() {
        let body = make_signed_cap("registry:init", "a/acme", "2025-01-01T00:00:00Z", "");
        let cap: Capability = serde_json::from_value(body).unwrap();
        assert!(validate_cap(&cap, "registry:init", "a/acme").is_ok());
    }

    #[test]
    fn validate_empty_signature_rejected() {
        let mut body = make_signed_cap("registry:init", "a/acme", "2025-01-01T00:00:00Z", "");
        body["signature"] = json!("");
        let cap: Capability = serde_json::from_value(body).unwrap();
        let err = validate_cap(&cap, "registry:init", "a/acme").unwrap_err();
        assert!(matches!(err, CapError::InvalidSignature(_)));
    }

    #[test]
    fn validate_signature_tamper_rejected() {
        let mut cap_val = make_valid_cap("registry:init", "a/acme");
        cap_val["issued_at"] = json!("2025-01-02T00:00:00Z"); // invalidates signature
        let cap: Capability = serde_json::from_value(cap_val).unwrap();
        let err = validate_cap(&cap, "registry:init", "a/acme").unwrap_err();
        assert!(matches!(err, CapError::InvalidSignature(_)));
    }

    #[test]
    fn require_cap_full_flow() {
        let body = json!({
            "@type": "ubl/app",
            "@world": "a/acme",
            "@cap": make_valid_cap("registry:init", "a/acme")
        });
        let cap = require_cap(&body, "registry:init", "a/acme").unwrap();
        assert_eq!(cap.action, "registry:init");
    }

    #[test]
    fn require_cap_missing_fails() {
        let body = json!({"@type": "ubl/app", "@world": "a/acme"});
        assert!(matches!(
            require_cap(&body, "registry:init", "a/acme"),
            Err(CapError::Missing)
        ));
    }

    #[test]
    fn required_capability_for_types() {
        assert_eq!(required_capability("ubl/app"), Some("registry:init"));
        assert_eq!(
            required_capability("ubl/membership"),
            Some("membership:grant")
        );
        assert_eq!(required_capability("ubl/revoke"), Some("revoke:execute"));
        assert_eq!(required_capability("ubl/key.rotate"), Some("key:rotate"));
        assert_eq!(
            required_capability("audit/report.request.v1"),
            Some("audit:report")
        );
        assert_eq!(
            required_capability("audit/ledger.snapshot.request.v1"),
            Some("audit:snapshot")
        );
        assert_eq!(
            required_capability("ledger/segment.compact.v1"),
            Some("ledger:compact")
        );
        assert_eq!(
            required_capability("audit/advisory.request.v1"),
            Some("audit:advisory")
        );
        assert_eq!(required_capability("ubl/user"), None);
        assert_eq!(required_capability("ubl/document"), None);
    }

    #[test]
    fn consumed_cap_from_capability() {
        let cap_val = make_valid_cap("registry:init", "a/acme");
        let cap: Capability = serde_json::from_value(cap_val).unwrap();
        let consumed = ConsumedCap::from(&cap);
        assert_eq!(consumed.action, "registry:init");
        assert_eq!(consumed.audience, "a/acme");
        assert!(consumed.issued_by.starts_with("did:key:z"));
        assert!(!consumed.consumed_at.is_empty());
    }

    #[test]
    fn cap_error_display() {
        let err = CapError::Missing;
        assert!(err.to_string().contains("missing @cap"));

        let err = CapError::WrongAction {
            required: "a".into(),
            got: "b".into(),
        };
        assert!(err.to_string().contains("wrong capability action"));
    }
}
