//! Meta-chips for type registration (P2.10).
//!
//! Three meta-chip types govern the chip type registry:
//! - `ubl/meta.register` — register a new chip type with schema + mandatory KATs
//! - `ubl/meta.describe` — update description/docs for an existing type
//! - `ubl/meta.deprecate` — mark a chip type as deprecated
//!
//! Every `ubl/meta.register` MUST include at least one KAT (Known Answer Test)
//! that demonstrates a valid chip body for the type being registered.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A Known Answer Test for a chip type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Kat {
    /// Human-readable label for this test case.
    pub label: String,
    /// A valid chip body that should pass KNOCK + CHECK for this type.
    pub input: Value,
    /// Expected decision: "allow" or "deny".
    pub expected_decision: String,
    /// Optional: expected error code if decision is "deny".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_error: Option<String>,
}

/// Schema definition for a chip type (simplified JSON Schema subset).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TypeSchema {
    /// Required fields (beyond @type, @ver, @world, @id).
    pub required_fields: Vec<SchemaField>,
    /// Optional fields.
    #[serde(default)]
    pub optional_fields: Vec<SchemaField>,
    /// Required capability action (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_cap: Option<String>,
}

/// A field in a type schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SchemaField {
    pub name: String,
    pub field_type: String,
    #[serde(default)]
    pub description: String,
}

/// Parsed body of a `ubl/meta.register` chip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterChip {
    /// The chip type being registered (e.g. "acme/invoice").
    pub target_type: String,
    /// Human-readable description.
    pub description: String,
    /// Schema for the type.
    pub schema: TypeSchema,
    /// Mandatory KATs — at least one required.
    pub kats: Vec<Kat>,
    /// Semantic version of this type definition.
    pub type_version: String,
}

/// Parsed body of a `ubl/meta.describe` chip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescribeChip {
    /// The chip type being described.
    pub target_type: String,
    /// Updated description.
    pub description: String,
    /// Optional: link to external documentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs_url: Option<String>,
    /// Optional: updated KATs.
    #[serde(default)]
    pub kats: Vec<Kat>,
}

/// Parsed body of a `ubl/meta.deprecate` chip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprecateChip {
    /// The chip type being deprecated.
    pub target_type: String,
    /// Reason for deprecation.
    pub reason: String,
    /// Optional: replacement type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_type: Option<String>,
    /// RFC-3339 date when the type will be fully removed (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sunset_at: Option<String>,
}

/// Errors from meta-chip validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaChipError {
    /// Missing required field.
    MissingField(String),
    /// Invalid field value.
    InvalidField(String),
    /// No KATs provided (at least one required for register).
    NoKats,
    /// KAT is malformed.
    InvalidKat(String),
    /// Target type uses reserved prefix.
    ReservedPrefix(String),
}

impl std::fmt::Display for MetaChipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField(name) => write!(f, "missing required field: {}", name),
            Self::InvalidField(msg) => write!(f, "invalid field: {}", msg),
            Self::NoKats => write!(f, "at least one KAT is required for type registration"),
            Self::InvalidKat(msg) => write!(f, "invalid KAT: {}", msg),
            Self::ReservedPrefix(prefix) => write!(f, "type prefix '{}' is reserved", prefix),
        }
    }
}

impl std::error::Error for MetaChipError {}

/// Reserved type prefixes that cannot be registered by users.
const RESERVED_PREFIXES: &[&str] = &["ubl/", "ubl/meta."];

/// Validate and parse a `ubl/meta.register` chip body.
pub fn parse_register(body: &Value) -> Result<RegisterChip, MetaChipError> {
    let target_type = body
        .get("target_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MetaChipError::MissingField("target_type".into()))?;

    // Check reserved prefixes
    for prefix in RESERVED_PREFIXES {
        if target_type.starts_with(prefix) {
            return Err(MetaChipError::ReservedPrefix(prefix.to_string()));
        }
    }

    let description = body
        .get("description")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MetaChipError::MissingField("description".into()))?;

    let schema_val = body
        .get("schema")
        .ok_or_else(|| MetaChipError::MissingField("schema".into()))?;
    let schema: TypeSchema = serde_json::from_value(schema_val.clone())
        .map_err(|e| MetaChipError::InvalidField(format!("schema: {}", e)))?;

    let kats_val = body
        .get("kats")
        .and_then(|v| v.as_array())
        .ok_or(MetaChipError::NoKats)?;
    if kats_val.is_empty() {
        return Err(MetaChipError::NoKats);
    }

    let kats: Vec<Kat> = kats_val
        .iter()
        .enumerate()
        .map(|(i, v)| {
            serde_json::from_value::<Kat>(v.clone())
                .map_err(|e| MetaChipError::InvalidKat(format!("KAT[{}]: {}", i, e)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Validate each KAT has the correct @type
    for (i, kat) in kats.iter().enumerate() {
        let kat_type = kat
            .input
            .get("@type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if kat_type != target_type {
            return Err(MetaChipError::InvalidKat(format!(
                "KAT[{}]: @type '{}' doesn't match target_type '{}'",
                i, kat_type, target_type
            )));
        }
    }

    let type_version = body
        .get("type_version")
        .and_then(|v| v.as_str())
        .unwrap_or("1.0")
        .to_string();

    Ok(RegisterChip {
        target_type: target_type.to_string(),
        description: description.to_string(),
        schema,
        kats,
        type_version,
    })
}

/// Validate and parse a `ubl/meta.describe` chip body.
pub fn parse_describe(body: &Value) -> Result<DescribeChip, MetaChipError> {
    let target_type = body
        .get("target_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MetaChipError::MissingField("target_type".into()))?;

    let description = body
        .get("description")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MetaChipError::MissingField("description".into()))?;

    let docs_url = body
        .get("docs_url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let kats = body
        .get("kats")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| serde_json::from_value::<Kat>(v.clone()).ok())
                .collect()
        })
        .unwrap_or_default();

    Ok(DescribeChip {
        target_type: target_type.to_string(),
        description: description.to_string(),
        docs_url,
        kats,
    })
}

/// Validate and parse a `ubl/meta.deprecate` chip body.
pub fn parse_deprecate(body: &Value) -> Result<DeprecateChip, MetaChipError> {
    let target_type = body
        .get("target_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MetaChipError::MissingField("target_type".into()))?;

    let reason = body
        .get("reason")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MetaChipError::MissingField("reason".into()))?;

    let replacement_type = body
        .get("replacement_type")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let sunset_at = body
        .get("sunset_at")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(DeprecateChip {
        target_type: target_type.to_string(),
        reason: reason.to_string(),
        replacement_type,
        sunset_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_register_body() -> Value {
        json!({
            "@type": "ubl/meta.register",
            "@id": "reg-invoice",
            "@ver": "1.0",
            "@world": "a/acme",
            "target_type": "acme/invoice",
            "description": "An invoice for goods or services",
            "type_version": "1.0",
            "schema": {
                "required_fields": [
                    { "name": "amount", "field_type": "string", "description": "Invoice amount" },
                    { "name": "currency", "field_type": "string", "description": "ISO 4217 currency" }
                ],
                "optional_fields": [
                    { "name": "notes", "field_type": "string", "description": "Free-text notes" }
                ],
                "required_cap": null
            },
            "kats": [{
                "label": "valid invoice",
                "input": {
                    "@type": "acme/invoice",
                    "@id": "inv-001",
                    "@ver": "1.0",
                    "@world": "a/acme/t/billing",
                    "amount": "100.00",
                    "currency": "USD"
                },
                "expected_decision": "allow"
            }]
        })
    }

    #[test]
    fn parse_valid_register() {
        let body = valid_register_body();
        let reg = parse_register(&body).unwrap();
        assert_eq!(reg.target_type, "acme/invoice");
        assert_eq!(reg.description, "An invoice for goods or services");
        assert_eq!(reg.kats.len(), 1);
        assert_eq!(reg.kats[0].label, "valid invoice");
        assert_eq!(reg.kats[0].expected_decision, "allow");
        assert_eq!(reg.schema.required_fields.len(), 2);
        assert_eq!(reg.schema.optional_fields.len(), 1);
        assert_eq!(reg.type_version, "1.0");
    }

    #[test]
    fn register_missing_target_type() {
        let body = json!({
            "description": "test",
            "schema": { "required_fields": [] },
            "kats": [{ "label": "x", "input": {}, "expected_decision": "allow" }]
        });
        assert!(matches!(
            parse_register(&body),
            Err(MetaChipError::MissingField(_))
        ));
    }

    #[test]
    fn register_missing_description() {
        let body = json!({
            "target_type": "acme/test",
            "schema": { "required_fields": [] },
            "kats": [{ "label": "x", "input": { "@type": "acme/test" }, "expected_decision": "allow" }]
        });
        assert!(matches!(
            parse_register(&body),
            Err(MetaChipError::MissingField(_))
        ));
    }

    #[test]
    fn register_no_kats_fails() {
        let body = json!({
            "target_type": "acme/test",
            "description": "test",
            "schema": { "required_fields": [] },
            "kats": []
        });
        assert!(matches!(parse_register(&body), Err(MetaChipError::NoKats)));
    }

    #[test]
    fn register_missing_kats_field_fails() {
        let body = json!({
            "target_type": "acme/test",
            "description": "test",
            "schema": { "required_fields": [] }
        });
        assert!(matches!(parse_register(&body), Err(MetaChipError::NoKats)));
    }

    #[test]
    fn register_reserved_prefix_rejected() {
        let body = json!({
            "target_type": "ubl/custom",
            "description": "trying to register ubl/ prefix",
            "schema": { "required_fields": [] },
            "kats": [{ "label": "x", "input": { "@type": "ubl/custom" }, "expected_decision": "allow" }]
        });
        assert!(matches!(
            parse_register(&body),
            Err(MetaChipError::ReservedPrefix(_))
        ));
    }

    #[test]
    fn register_kat_type_mismatch_rejected() {
        let body = json!({
            "target_type": "acme/invoice",
            "description": "invoice",
            "schema": { "required_fields": [] },
            "kats": [{
                "label": "wrong type",
                "input": { "@type": "acme/receipt", "@id": "x", "@ver": "1.0", "@world": "a/acme" },
                "expected_decision": "allow"
            }]
        });
        let err = parse_register(&body).unwrap_err();
        assert!(matches!(err, MetaChipError::InvalidKat(_)));
        assert!(err.to_string().contains("doesn't match"));
    }

    #[test]
    fn register_multiple_kats() {
        let mut body = valid_register_body();
        body["kats"] = json!([
            {
                "label": "valid invoice",
                "input": { "@type": "acme/invoice", "@id": "inv-1", "@ver": "1.0", "@world": "a/acme", "amount": "50", "currency": "EUR" },
                "expected_decision": "allow"
            },
            {
                "label": "missing amount should deny",
                "input": { "@type": "acme/invoice", "@id": "inv-2", "@ver": "1.0", "@world": "a/acme" },
                "expected_decision": "deny",
                "expected_error": "INVALID_CHIP"
            }
        ]);
        let reg = parse_register(&body).unwrap();
        assert_eq!(reg.kats.len(), 2);
        assert_eq!(reg.kats[1].expected_decision, "deny");
        assert_eq!(reg.kats[1].expected_error.as_deref(), Some("INVALID_CHIP"));
    }

    #[test]
    fn parse_valid_describe() {
        let body = json!({
            "target_type": "acme/invoice",
            "description": "Updated description for invoices",
            "docs_url": "https://docs.acme.com/invoice"
        });
        let desc = parse_describe(&body).unwrap();
        assert_eq!(desc.target_type, "acme/invoice");
        assert_eq!(
            desc.docs_url.as_deref(),
            Some("https://docs.acme.com/invoice")
        );
        assert!(desc.kats.is_empty());
    }

    #[test]
    fn describe_missing_target_type() {
        let body = json!({ "description": "test" });
        assert!(matches!(
            parse_describe(&body),
            Err(MetaChipError::MissingField(_))
        ));
    }

    #[test]
    fn parse_valid_deprecate() {
        let body = json!({
            "target_type": "acme/invoice",
            "reason": "Replaced by acme/invoice.v2",
            "replacement_type": "acme/invoice.v2",
            "sunset_at": "2026-06-01T00:00:00Z"
        });
        let dep = parse_deprecate(&body).unwrap();
        assert_eq!(dep.target_type, "acme/invoice");
        assert_eq!(dep.reason, "Replaced by acme/invoice.v2");
        assert_eq!(dep.replacement_type.as_deref(), Some("acme/invoice.v2"));
        assert_eq!(dep.sunset_at.as_deref(), Some("2026-06-01T00:00:00Z"));
    }

    #[test]
    fn deprecate_missing_reason() {
        let body = json!({ "target_type": "acme/invoice" });
        assert!(matches!(
            parse_deprecate(&body),
            Err(MetaChipError::MissingField(_))
        ));
    }

    #[test]
    fn deprecate_minimal() {
        let body = json!({
            "target_type": "acme/old",
            "reason": "No longer supported"
        });
        let dep = parse_deprecate(&body).unwrap();
        assert!(dep.replacement_type.is_none());
        assert!(dep.sunset_at.is_none());
    }

    #[test]
    fn meta_chip_error_display() {
        assert!(MetaChipError::NoKats
            .to_string()
            .contains("at least one KAT"));
        assert!(MetaChipError::ReservedPrefix("ubl/".into())
            .to_string()
            .contains("reserved"));
        assert!(MetaChipError::MissingField("x".into())
            .to_string()
            .contains("missing"));
    }

    #[test]
    fn kat_roundtrip_serialization() {
        let kat = Kat {
            label: "test".into(),
            input: json!({"@type": "acme/test"}),
            expected_decision: "allow".into(),
            expected_error: None,
        };
        let json = serde_json::to_value(&kat).unwrap();
        let kat2: Kat = serde_json::from_value(json).unwrap();
        assert_eq!(kat, kat2);
    }

    #[test]
    fn register_default_type_version() {
        let body = json!({
            "target_type": "acme/simple",
            "description": "simple type",
            "schema": { "required_fields": [] },
            "kats": [{
                "label": "basic",
                "input": { "@type": "acme/simple" },
                "expected_decision": "allow"
            }]
        });
        let reg = parse_register(&body).unwrap();
        assert_eq!(reg.type_version, "1.0");
    }
}
