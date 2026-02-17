//! AI Passport — LLM identity, rights, and duties as a chip.
//!
//! An AI Passport (`ubl/ai.passport`) is the first-class identity for any LLM
//! operating within UBL. It enters the system through the same gate as everything
//! else — POST /v1/chips. The passport defines what the LLM can do (rights),
//! what it must do (duties), and its scope of operation.
//!
//! See ARCHITECTURE.md §11.3.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// An AI Passport chip — the identity of an LLM within UBL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiPassport {
    /// Model identifier (e.g. "gpt-4", "claude-sonnet-4")
    pub model: String,
    /// Provider (e.g. "openai", "anthropic")
    pub provider: String,
    /// What the LLM is allowed to do
    pub rights: Vec<String>,
    /// What the LLM must do
    pub duties: Vec<String>,
    /// Scope of operation (chip types, worlds, etc.)
    pub scope: Vec<String>,
    /// Fuel limit per advisory action
    pub fuel_limit: u64,
    /// DID key for signing advisory receipts
    pub signing_key: String,
}

/// Errors specific to AI Passport operations
#[derive(Debug, Clone)]
pub enum PassportError {
    /// Passport chip missing required fields
    MissingField(String),
    /// Passport not found in ChipStore
    NotFound(String),
    /// Action not permitted by passport rights
    RightDenied { action: String, passport_id: String },
}

impl std::fmt::Display for PassportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PassportError::MissingField(field) => write!(f, "Passport missing field: {}", field),
            PassportError::NotFound(cid) => write!(f, "Passport not found: {}", cid),
            PassportError::RightDenied {
                action,
                passport_id,
            } => write!(
                f,
                "Action '{}' not permitted for passport '{}'",
                action, passport_id
            ),
        }
    }
}

impl std::error::Error for PassportError {}

impl AiPassport {
    /// Parse an AiPassport from a chip body (serde_json::Value).
    pub fn from_chip_body(body: &Value) -> Result<Self, PassportError> {
        let model = body
            .get("model")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PassportError::MissingField("model".into()))?
            .to_string();

        let provider = body
            .get("provider")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PassportError::MissingField("provider".into()))?
            .to_string();

        let rights = extract_string_array(body, "rights")
            .ok_or_else(|| PassportError::MissingField("rights".into()))?;

        let duties = extract_string_array(body, "duties")
            .ok_or_else(|| PassportError::MissingField("duties".into()))?;

        let scope = extract_string_array(body, "scope").unwrap_or_default();

        let fuel_limit = body
            .get("fuel_limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(100_000);

        let signing_key = body
            .get("signing_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PassportError::MissingField("signing_key".into()))?
            .to_string();

        Ok(Self {
            model,
            provider,
            rights,
            duties,
            scope,
            fuel_limit,
            signing_key,
        })
    }

    /// Check whether this passport grants a specific right.
    pub fn has_right(&self, action: &str) -> bool {
        self.rights.iter().any(|r| r == action || r == "*")
    }

    /// Validate that the passport can perform the given action, returning an error if not.
    pub fn authorize(&self, action: &str) -> Result<(), PassportError> {
        if self.has_right(action) {
            Ok(())
        } else {
            Err(PassportError::RightDenied {
                action: action.to_string(),
                passport_id: self.signing_key.clone(),
            })
        }
    }

    /// Produce the canonical chip body for this passport.
    pub fn to_chip_body(&self, id: &str, world: &str) -> Value {
        json!({
            "@type": "ubl/ai.passport",
            "@id": id,
            "@ver": "1.0",
            "@world": world,
            "model": self.model,
            "provider": self.provider,
            "rights": self.rights,
            "duties": self.duties,
            "scope": self.scope,
            "fuel_limit": self.fuel_limit,
            "signing_key": self.signing_key,
        })
    }
}

/// Extract a Vec<String> from a JSON array field.
fn extract_string_array(body: &Value, key: &str) -> Option<Vec<String>> {
    body.get(key)?
        .as_array()?
        .iter()
        .map(|v| v.as_str().map(|s| s.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_passport_body() -> Value {
        json!({
            "@type": "ubl/ai.passport",
            "@id": "claude-v1",
            "@ver": "1.0",
            "@world": "a/acme/t/prod",
            "model": "claude-sonnet-4",
            "provider": "anthropic",
            "rights": ["advise", "classify", "narrate"],
            "duties": ["sign", "trace", "account"],
            "scope": ["a/acme/*"],
            "fuel_limit": 100000,
            "signing_key": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        })
    }

    #[test]
    fn parse_passport_from_chip_body() {
        let body = sample_passport_body();
        let passport = AiPassport::from_chip_body(&body).unwrap();
        assert_eq!(passport.model, "claude-sonnet-4");
        assert_eq!(passport.provider, "anthropic");
        assert_eq!(passport.rights.len(), 3);
        assert_eq!(passport.duties.len(), 3);
        assert_eq!(passport.fuel_limit, 100_000);
        assert!(passport.signing_key.starts_with("did:key:"));
    }

    #[test]
    fn passport_has_right_checks() {
        let body = sample_passport_body();
        let passport = AiPassport::from_chip_body(&body).unwrap();
        assert!(passport.has_right("advise"));
        assert!(passport.has_right("classify"));
        assert!(!passport.has_right("delete"));
    }

    #[test]
    fn passport_authorize_denies_missing_right() {
        let body = sample_passport_body();
        let passport = AiPassport::from_chip_body(&body).unwrap();
        assert!(passport.authorize("advise").is_ok());
        assert!(passport.authorize("delete").is_err());
    }

    #[test]
    fn passport_missing_model_fails() {
        let body = json!({
            "provider": "openai",
            "rights": ["advise"],
            "duties": ["sign"],
            "signing_key": "did:key:z123"
        });
        let err = AiPassport::from_chip_body(&body).unwrap_err();
        assert!(matches!(err, PassportError::MissingField(_)));
    }

    #[test]
    fn passport_to_chip_body_roundtrip() {
        let body = sample_passport_body();
        let passport = AiPassport::from_chip_body(&body).unwrap();
        let out = passport.to_chip_body("claude-v1", "a/acme/t/prod");
        assert_eq!(out["@type"], "ubl/ai.passport");
        assert_eq!(out["model"], "claude-sonnet-4");
        assert_eq!(
            out["signing_key"],
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
    }
}
