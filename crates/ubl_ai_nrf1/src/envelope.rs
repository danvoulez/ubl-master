//! Universal Envelope — the four mandatory anchors on every UBL artifact.
//!
//! Rule: `@type` is always the first key, `@id` is always the second key.
//! Every chip, receipt, event, and error in the system carries these four fields.
//! Additional fields are added on top but never fewer than these four.

use serde_json::{Map, Value};
use std::fmt;

/// The four mandatory anchor fields present on every UBL JSON artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UblEnvelope {
    /// Always the first key. Determines how the artifact is processed.
    pub r#type: String,
    /// Always the second key. Globally unique identifier.
    pub id: String,
    /// Schema version for this artifact type.
    pub ver: String,
    /// Scope anchor: `a/{app}/t/{tenant}`.
    pub world: String,
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("missing required anchor: {0}")]
    MissingAnchor(&'static str),
    #[error("@type must not be empty")]
    EmptyType,
    #[error("@id must not be empty")]
    EmptyId,
    #[error("@ver must not be empty")]
    EmptyVer,
    #[error("@world must not be empty")]
    EmptyWorld,
    #[error("@world must match a/{{app}}/t/{{tenant}}, got {0:?}")]
    InvalidWorld(String),
    #[error("@type must be first key in JSON object, found {0:?}")]
    TypeNotFirst(String),
    #[error("@id must be second key in JSON object, found {0:?}")]
    IdNotSecond(String),
}

impl UblEnvelope {
    /// Create a new envelope with all four anchors.
    pub fn new(
        r#type: impl Into<String>,
        id: impl Into<String>,
        ver: impl Into<String>,
        world: impl Into<String>,
    ) -> Result<Self, EnvelopeError> {
        let envelope = Self {
            r#type: r#type.into(),
            id: id.into(),
            ver: ver.into(),
            world: world.into(),
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validate that all four anchors are non-empty and @world has correct format.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.r#type.is_empty() {
            return Err(EnvelopeError::EmptyType);
        }
        if self.id.is_empty() {
            return Err(EnvelopeError::EmptyId);
        }
        if self.ver.is_empty() {
            return Err(EnvelopeError::EmptyVer);
        }
        if self.world.is_empty() {
            return Err(EnvelopeError::EmptyWorld);
        }
        Self::validate_world(&self.world)?;
        Ok(())
    }

    /// Validate @world format: `a/{app}` or `a/{app}/t/{tenant}` where segments are non-empty.
    pub fn validate_world(world: &str) -> Result<(), EnvelopeError> {
        let parts: Vec<&str> = world.split('/').collect();
        match parts.len() {
            // a/{app}
            2 if parts[0] == "a" && !parts[1].is_empty() => Ok(()),
            // a/{app}/t/{tenant}
            4 if parts[0] == "a"
                && parts[2] == "t"
                && !parts[1].is_empty()
                && !parts[3].is_empty() =>
            {
                Ok(())
            }
            _ => Err(EnvelopeError::InvalidWorld(world.to_string())),
        }
    }

    /// Extract (app, tenant) from a valid @world string.
    pub fn parse_world(world: &str) -> Option<(&str, &str)> {
        let parts: Vec<&str> = world.split('/').collect();
        if parts.len() == 4 && parts[0] == "a" && parts[2] == "t" {
            Some((parts[1], parts[3]))
        } else {
            None
        }
    }

    /// Extract an envelope from a JSON object, validating anchor presence and key order.
    pub fn from_json(value: &Value) -> Result<Self, EnvelopeError> {
        let obj = value
            .as_object()
            .ok_or(EnvelopeError::MissingAnchor("@type"))?;

        // Validate key ordering: @type must be first, @id must be second
        let keys: Vec<&String> = obj.keys().collect();
        if keys.is_empty() || keys[0] != "@type" {
            let found = keys.first().map(|s| s.to_string()).unwrap_or_default();
            return Err(EnvelopeError::TypeNotFirst(found));
        }
        if keys.len() < 2 || keys[1] != "@id" {
            let found = keys.get(1).map(|s| s.to_string()).unwrap_or_default();
            return Err(EnvelopeError::IdNotSecond(found));
        }

        let r#type = obj
            .get("@type")
            .and_then(|v| v.as_str())
            .ok_or(EnvelopeError::MissingAnchor("@type"))?
            .to_string();
        let id = obj
            .get("@id")
            .and_then(|v| v.as_str())
            .ok_or(EnvelopeError::MissingAnchor("@id"))?
            .to_string();
        let ver = obj
            .get("@ver")
            .and_then(|v| v.as_str())
            .ok_or(EnvelopeError::MissingAnchor("@ver"))?
            .to_string();
        let world = obj
            .get("@world")
            .and_then(|v| v.as_str())
            .ok_or(EnvelopeError::MissingAnchor("@world"))?
            .to_string();

        let envelope = Self {
            r#type,
            id,
            ver,
            world,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Serialize the envelope anchors into a JSON Map with guaranteed key order:
    /// `@type` first, `@id` second, then `@ver`, `@world`.
    ///
    /// Uses `serde_json::Map` which preserves insertion order.
    pub fn to_ordered_map(&self) -> Map<String, Value> {
        let mut map = Map::with_capacity(4);
        map.insert("@type".to_string(), Value::String(self.r#type.clone()));
        map.insert("@id".to_string(), Value::String(self.id.clone()));
        map.insert("@ver".to_string(), Value::String(self.ver.clone()));
        map.insert("@world".to_string(), Value::String(self.world.clone()));
        map
    }

    /// Build a full JSON object: envelope anchors first, then additional fields.
    /// Additional fields must not collide with anchor keys.
    pub fn to_json_with(&self, extra: &Map<String, Value>) -> Value {
        let mut map = self.to_ordered_map();
        for (k, v) in extra {
            if k != "@type" && k != "@id" && k != "@ver" && k != "@world" {
                map.insert(k.clone(), v.clone());
            }
        }
        Value::Object(map)
    }

    /// Build a JSON Value with just the four anchors.
    pub fn to_json(&self) -> Value {
        Value::Object(self.to_ordered_map())
    }
}

impl fmt::Display for UblEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} (ver={}, world={})",
            self.r#type, self.id, self.ver, self.world
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn create_valid_envelope() {
        let env = UblEnvelope::new("ubl/chip", "chip-001", "1.0", "a/myapp/t/default").unwrap();
        assert_eq!(env.r#type, "ubl/chip");
        assert_eq!(env.id, "chip-001");
        assert_eq!(env.ver, "1.0");
        assert_eq!(env.world, "a/myapp/t/default");
    }

    #[test]
    fn reject_empty_type() {
        let err = UblEnvelope::new("", "id", "1.0", "a/x/t/y").unwrap_err();
        assert!(matches!(err, EnvelopeError::EmptyType));
    }

    #[test]
    fn reject_empty_id() {
        let err = UblEnvelope::new("ubl/chip", "", "1.0", "a/x/t/y").unwrap_err();
        assert!(matches!(err, EnvelopeError::EmptyId));
    }

    #[test]
    fn reject_empty_ver() {
        let err = UblEnvelope::new("ubl/chip", "id", "", "a/x/t/y").unwrap_err();
        assert!(matches!(err, EnvelopeError::EmptyVer));
    }

    #[test]
    fn reject_empty_world() {
        let err = UblEnvelope::new("ubl/chip", "id", "1.0", "").unwrap_err();
        assert!(matches!(err, EnvelopeError::EmptyWorld));
    }

    #[test]
    fn to_json_key_order() {
        let env = UblEnvelope::new("ubl/receipt", "rc-001", "1.0", "a/demo/t/main").unwrap();
        let json = env.to_json();
        let obj = json.as_object().unwrap();
        let keys: Vec<&String> = obj.keys().collect();
        assert_eq!(keys, vec!["@type", "@id", "@ver", "@world"]);
    }

    #[test]
    fn to_json_with_extra_fields() {
        let env = UblEnvelope::new("ubl/chip", "c-1", "1.0", "a/app/t/ten").unwrap();
        let mut extra = Map::new();
        extra.insert("email".to_string(), json!("alice@acme.com"));
        extra.insert("role".to_string(), json!("admin"));
        let json = env.to_json_with(&extra);
        let obj = json.as_object().unwrap();
        let keys: Vec<&String> = obj.keys().collect();
        // Anchors first, then extra in insertion order
        assert_eq!(keys[0], "@type");
        assert_eq!(keys[1], "@id");
        assert_eq!(keys[2], "@ver");
        assert_eq!(keys[3], "@world");
        assert_eq!(obj.get("email").unwrap(), "alice@acme.com");
    }

    #[test]
    fn extra_fields_cannot_overwrite_anchors() {
        let env = UblEnvelope::new("ubl/chip", "c-1", "1.0", "a/app/t/ten").unwrap();
        let mut extra = Map::new();
        extra.insert("@type".to_string(), json!("HACKED"));
        let json = env.to_json_with(&extra);
        assert_eq!(json["@type"], "ubl/chip", "anchor must not be overwritten");
    }

    #[test]
    fn from_json_valid() {
        let j = json!({
            "@type": "ubl/event",
            "@id": "evt-42",
            "@ver": "1.0",
            "@world": "a/demo/t/main",
            "payload": "data"
        });
        let env = UblEnvelope::from_json(&j).unwrap();
        assert_eq!(env.r#type, "ubl/event");
        assert_eq!(env.id, "evt-42");
    }

    #[test]
    fn from_json_missing_type() {
        let j = json!({"@id": "x", "@ver": "1.0", "@world": "a/x/t/y"});
        let err = UblEnvelope::from_json(&j).unwrap_err();
        assert!(err.to_string().contains("@type"));
    }

    #[test]
    fn from_json_missing_world() {
        let j = json!({"@type": "ubl/chip", "@id": "x", "@ver": "1.0"});
        let err = UblEnvelope::from_json(&j).unwrap_err();
        assert!(err.to_string().contains("@world"));
    }

    #[test]
    fn from_json_wrong_key_order_type_not_first() {
        // serde_json::json! with preserve_order feature respects insertion order
        let mut map = Map::new();
        map.insert("@id".to_string(), json!("x"));
        map.insert("@type".to_string(), json!("ubl/chip"));
        map.insert("@ver".to_string(), json!("1.0"));
        map.insert("@world".to_string(), json!("a/x/t/y"));
        let j = Value::Object(map);
        let err = UblEnvelope::from_json(&j).unwrap_err();
        assert!(matches!(err, EnvelopeError::TypeNotFirst(_)));
    }

    #[test]
    fn from_json_wrong_key_order_id_not_second() {
        let mut map = Map::new();
        map.insert("@type".to_string(), json!("ubl/chip"));
        map.insert("@ver".to_string(), json!("1.0"));
        map.insert("@id".to_string(), json!("x"));
        map.insert("@world".to_string(), json!("a/x/t/y"));
        let j = Value::Object(map);
        let err = UblEnvelope::from_json(&j).unwrap_err();
        assert!(matches!(err, EnvelopeError::IdNotSecond(_)));
    }

    #[test]
    fn roundtrip_envelope() {
        let env = UblEnvelope::new("ubl/receipt", "rc-99", "2.0", "a/prod/t/acme").unwrap();
        let json = env.to_json();
        let env2 = UblEnvelope::from_json(&json).unwrap();
        assert_eq!(env, env2);
    }

    #[test]
    fn display_format() {
        let env = UblEnvelope::new("ubl/chip", "c-1", "1.0", "a/app/t/ten").unwrap();
        let s = format!("{}", env);
        assert_eq!(s, "ubl/chip:c-1 (ver=1.0, world=a/app/t/ten)");
    }

    // ── @world format validation ─────────────────────────────────

    #[test]
    fn world_valid_format() {
        assert!(UblEnvelope::validate_world("a/myapp/t/default").is_ok());
        assert!(UblEnvelope::validate_world("a/lab512/t/dev").is_ok());
        assert!(UblEnvelope::validate_world("a/prod/t/acme-corp").is_ok());
    }

    #[test]
    fn world_valid_app_level() {
        assert!(UblEnvelope::validate_world("a/myapp").is_ok());
        assert!(UblEnvelope::validate_world("a/lab512").is_ok());
    }

    #[test]
    fn world_rejects_missing_prefix() {
        let err = UblEnvelope::validate_world("myapp/t/default").unwrap_err();
        assert!(matches!(err, EnvelopeError::InvalidWorld(_)));
    }

    #[test]
    fn world_rejects_missing_tenant_prefix() {
        let err = UblEnvelope::validate_world("a/myapp/default").unwrap_err();
        assert!(matches!(err, EnvelopeError::InvalidWorld(_)));
    }

    #[test]
    fn world_rejects_empty_app() {
        let err = UblEnvelope::validate_world("a//t/default").unwrap_err();
        assert!(matches!(err, EnvelopeError::InvalidWorld(_)));
    }

    #[test]
    fn world_rejects_empty_tenant() {
        let err = UblEnvelope::validate_world("a/myapp/t/").unwrap_err();
        assert!(matches!(err, EnvelopeError::InvalidWorld(_)));
    }

    #[test]
    fn world_rejects_extra_segments() {
        let err = UblEnvelope::validate_world("a/myapp/t/default/extra").unwrap_err();
        assert!(matches!(err, EnvelopeError::InvalidWorld(_)));
    }

    #[test]
    fn world_rejects_bare_string() {
        let err = UblEnvelope::validate_world("just-a-string").unwrap_err();
        assert!(matches!(err, EnvelopeError::InvalidWorld(_)));
    }

    #[test]
    fn parse_world_extracts_app_tenant() {
        let (app, tenant) = UblEnvelope::parse_world("a/lab512/t/dev").unwrap();
        assert_eq!(app, "lab512");
        assert_eq!(tenant, "dev");
    }

    #[test]
    fn parse_world_returns_none_for_invalid() {
        assert!(UblEnvelope::parse_world("invalid").is_none());
    }

    #[test]
    fn new_envelope_rejects_invalid_world() {
        let err = UblEnvelope::new("ubl/chip", "c-1", "1.0", "bad-world").unwrap_err();
        assert!(matches!(err, EnvelopeError::InvalidWorld(_)));
    }
}
