//! Advisory chips — LLM actions signed by an AI Passport.
//!
//! Every LLM action produces a `ubl/advisory` chip signed by the LLM's
//! AI Passport key, following the Universal Envelope. Advisory chips are
//! stored and indexed but **never block the pipeline**.
//!
//! See ARCHITECTURE.md §11.2.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// An advisory chip — the output of an LLM action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    /// CID of the AI Passport that produced this advisory
    pub passport_cid: String,
    /// Action performed (e.g. "classify", "narrate", "explain")
    pub action: String,
    /// CID of the input chip/receipt that triggered this advisory
    pub input_cid: String,
    /// The LLM's output
    pub output: Value,
    /// Confidence score (0–100 integer scale, NRF-1 compatible)
    pub confidence: i64,
    /// Model used (copied from passport for traceability)
    pub model: String,
    /// Hook point that triggered this advisory
    pub hook: AdvisoryHook,
}

/// Where in the pipeline the advisory was triggered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AdvisoryHook {
    /// After CHECK stage — explain denial or narrate policy evaluation
    PostCheck,
    /// After WF stage — classify, summarize, route
    PostWf,
    /// Manual / on-demand advisory request
    OnDemand,
}

impl std::fmt::Display for AdvisoryHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdvisoryHook::PostCheck => write!(f, "post_check"),
            AdvisoryHook::PostWf => write!(f, "post_wf"),
            AdvisoryHook::OnDemand => write!(f, "on_demand"),
        }
    }
}

impl Advisory {
    /// Create a new advisory from LLM analysis output.
    pub fn new(
        passport_cid: String,
        action: String,
        input_cid: String,
        output: Value,
        confidence: i64,
        model: String,
        hook: AdvisoryHook,
    ) -> Self {
        Self {
            passport_cid,
            action,
            input_cid,
            output,
            confidence,
            model,
            hook,
        }
    }

    /// Produce the canonical chip body for this advisory.
    pub fn to_chip_body(&self, id: &str, world: &str) -> Value {
        json!({
            "@type": "ubl/advisory",
            "@id": id,
            "@ver": "1.0",
            "@world": world,
            "passport_cid": self.passport_cid,
            "action": self.action,
            "input_cid": self.input_cid,
            "output": self.output,
            "confidence": self.confidence,
            "model": self.model,
            "hook": self.hook.to_string(),
        })
    }

    /// Parse an Advisory from a chip body.
    pub fn from_chip_body(body: &Value) -> Result<Self, AdvisoryError> {
        let passport_cid = body
            .get("passport_cid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AdvisoryError::MissingField("passport_cid".into()))?
            .to_string();

        let action = body
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AdvisoryError::MissingField("action".into()))?
            .to_string();

        let input_cid = body
            .get("input_cid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AdvisoryError::MissingField("input_cid".into()))?
            .to_string();

        let output = body.get("output").cloned().unwrap_or(Value::Null);

        let confidence = body.get("confidence").and_then(|v| v.as_i64()).unwrap_or(0);

        let model = body
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let hook = match body.get("hook").and_then(|v| v.as_str()) {
            Some("post_check") => AdvisoryHook::PostCheck,
            Some("post_wf") => AdvisoryHook::PostWf,
            _ => AdvisoryHook::OnDemand,
        };

        Ok(Self {
            passport_cid,
            action,
            input_cid,
            output,
            confidence,
            model,
            hook,
        })
    }
}

/// Errors specific to advisory operations.
#[derive(Debug, Clone)]
pub enum AdvisoryError {
    MissingField(String),
    InvalidPassport(String),
}

impl std::fmt::Display for AdvisoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdvisoryError::MissingField(field) => write!(f, "Advisory missing field: {}", field),
            AdvisoryError::InvalidPassport(msg) => write!(f, "Invalid passport: {}", msg),
        }
    }
}

impl std::error::Error for AdvisoryError {}

/// The AdvisoryEngine produces advisory chips from pipeline events.
/// It holds a reference to the active AI Passport and emits advisories
/// as non-blocking background tasks.
pub struct AdvisoryEngine {
    /// CID of the active AI Passport
    pub passport_cid: String,
    /// Model name (from passport)
    pub model: String,
    /// World scope for emitted advisories
    pub world: String,
    /// Counter for generating advisory IDs
    counter: std::sync::atomic::AtomicU64,
}

impl AdvisoryEngine {
    /// Create a new AdvisoryEngine bound to a specific passport.
    pub fn new(passport_cid: String, model: String, world: String) -> Self {
        Self {
            passport_cid,
            model,
            world,
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Generate a unique advisory ID.
    fn next_id(&self) -> String {
        let n = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("advisory-{}", n)
    }

    /// Produce a post-CHECK advisory (e.g. explain denial).
    pub fn post_check_advisory(
        &self,
        input_cid: &str,
        decision: &str,
        reason: &str,
        policy_trace: &[Value],
    ) -> Advisory {
        let output = json!({
            "decision": decision,
            "reason": reason,
            "policy_count": policy_trace.len(),
            "narration": format!(
                "Policy evaluation resulted in {}. {}",
                decision.to_uppercase(),
                reason
            ),
        });

        let confidence: i64 = if decision == "deny" { 95 } else { 85 };

        Advisory::new(
            self.passport_cid.clone(),
            "explain_check".to_string(),
            input_cid.to_string(),
            output,
            confidence,
            self.model.clone(),
            AdvisoryHook::PostCheck,
        )
    }

    /// Produce a post-WF advisory (e.g. classify, summarize).
    pub fn post_wf_advisory(
        &self,
        input_cid: &str,
        chip_type: &str,
        decision: &str,
        duration_ms: i64,
    ) -> Advisory {
        let category = classify_chip_type(chip_type);
        let output = json!({
            "category": category,
            "chip_type": chip_type,
            "decision": decision,
            "duration_ms": duration_ms,
            "summary": format!(
                "{} chip processed in {}ms → {}",
                chip_type, duration_ms, decision.to_uppercase()
            ),
        });

        Advisory::new(
            self.passport_cid.clone(),
            "classify".to_string(),
            input_cid.to_string(),
            output,
            90,
            self.model.clone(),
            AdvisoryHook::PostWf,
        )
    }

    /// Convert an advisory into a chip body ready for pipeline submission.
    pub fn advisory_to_chip_body(&self, advisory: &Advisory) -> Value {
        advisory.to_chip_body(&self.next_id(), &self.world)
    }
}

/// Simple chip type classifier (will be replaced by real LLM in production).
fn classify_chip_type(chip_type: &str) -> &str {
    match chip_type {
        t if t.starts_with("ubl/user") => "identity",
        t if t.starts_with("ubl/token") => "auth",
        t if t.starts_with("ubl/policy") => "governance",
        t if t.starts_with("ubl/ai.passport") => "ai_identity",
        t if t.starts_with("ubl/advisory") => "ai_advisory",
        t if t.starts_with("ubl/app") => "application",
        t if t.starts_with("ubl/tenant") => "tenant",
        _ => "general",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisory_to_chip_body_has_envelope() {
        let adv = Advisory::new(
            "b3:passport123".into(),
            "classify".into(),
            "b3:input456".into(),
            json!({"category": "identity"}),
            92,
            "claude-sonnet-4".into(),
            AdvisoryHook::PostWf,
        );

        let body = adv.to_chip_body("adv-1", "a/acme/t/prod");
        assert_eq!(body["@type"], "ubl/advisory");
        assert_eq!(body["@id"], "adv-1");
        assert_eq!(body["@ver"], "1.0");
        assert_eq!(body["@world"], "a/acme/t/prod");
        assert_eq!(body["passport_cid"], "b3:passport123");
        assert_eq!(body["action"], "classify");
        assert_eq!(body["confidence"], 92);
    }

    #[test]
    fn advisory_roundtrip() {
        let adv = Advisory::new(
            "b3:pass".into(),
            "explain_check".into(),
            "b3:in".into(),
            json!({"reason": "denied"}),
            95,
            "gpt-4".into(),
            AdvisoryHook::PostCheck,
        );

        let body = adv.to_chip_body("adv-rt", "a/x/t/y");
        let parsed = Advisory::from_chip_body(&body).unwrap();
        assert_eq!(parsed.passport_cid, "b3:pass");
        assert_eq!(parsed.action, "explain_check");
        assert_eq!(parsed.hook, AdvisoryHook::PostCheck);
        assert_eq!(parsed.confidence, 95);
    }

    #[test]
    fn advisory_missing_passport_cid_fails() {
        let body = json!({"action": "classify", "input_cid": "b3:x"});
        assert!(Advisory::from_chip_body(&body).is_err());
    }

    #[test]
    fn engine_post_check_advisory() {
        let engine = AdvisoryEngine::new(
            "b3:passport".into(),
            "claude-sonnet-4".into(),
            "a/acme/t/prod".into(),
        );

        let adv = engine.post_check_advisory("b3:input", "deny", "Type not allowed", &[]);
        assert_eq!(adv.action, "explain_check");
        assert_eq!(adv.hook, AdvisoryHook::PostCheck);
        assert!(adv.confidence > 90);
        assert!(adv.output["narration"].as_str().unwrap().contains("DENY"));
    }

    #[test]
    fn engine_post_wf_advisory() {
        let engine = AdvisoryEngine::new(
            "b3:passport".into(),
            "claude-sonnet-4".into(),
            "a/acme/t/prod".into(),
        );

        let adv = engine.post_wf_advisory("b3:wf", "ubl/user", "allow", 42);
        assert_eq!(adv.action, "classify");
        assert_eq!(adv.hook, AdvisoryHook::PostWf);
        assert_eq!(adv.output["category"], "identity");
        assert!(adv.output["summary"].as_str().unwrap().contains("42ms"));
    }

    #[test]
    fn engine_generates_unique_ids() {
        let engine = AdvisoryEngine::new("b3:p".into(), "m".into(), "a/x/t/y".into());
        let a1 = engine.next_id();
        let a2 = engine.next_id();
        assert_ne!(a1, a2);
    }

    #[test]
    fn classify_chip_type_works() {
        assert_eq!(classify_chip_type("ubl/user"), "identity");
        assert_eq!(classify_chip_type("ubl/token"), "auth");
        assert_eq!(classify_chip_type("ubl/ai.passport"), "ai_identity");
        assert_eq!(classify_chip_type("ubl/advisory"), "ai_advisory");
        assert_eq!(classify_chip_type("custom/thing"), "general");
    }
}
