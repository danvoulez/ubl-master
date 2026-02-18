//! Genesis chip creation and management
//!
//! The genesis chip is the root of all policy in the UBL system.
//! It's self-signed and defines the fundamental rules.

use crate::circuit::{AggregationMode, Circuit, CompositionMode};
use crate::policy_bit::{PolicyBit, PolicyScope};
use crate::reasoning_bit::{Decision, Expression, ReasoningBit};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Genesis chip body containing the root policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisChipBody {
    #[serde(rename = "@type")]
    pub chip_type: String,
    pub id: String,
    pub version: String,
    pub circuits: Vec<Circuit>,
    pub scope: PolicyScope,
    pub description: String,
    pub created_at: String,
}

/// Create the genesis policy chip
pub fn create_genesis_policy() -> PolicyBit {
    PolicyBit {
        id: "ubl.genesis.v1".to_string(),
        name: "UBL Genesis Policy".to_string(),
        circuits: vec![create_genesis_circuit()],
        scope: PolicyScope {
            chip_types: vec!["*".to_string()],
            operations: vec!["create".to_string(), "update".to_string()],
            level: "genesis".to_string(),
        },
    }
}

/// Create the core genesis circuit
fn create_genesis_circuit() -> Circuit {
    Circuit {
        id: "genesis_validation".to_string(),
        name: "Genesis Validation Circuit".to_string(),
        reasoning_bits: vec![
            create_type_validation_rb(),
            create_id_required_rb(),
            create_size_limit_rb(),
            create_no_malicious_content_rb(),
        ],
        composition: CompositionMode::Sequential,
        aggregator: AggregationMode::All,
    }
}

/// RB: Valid chip type check
fn create_type_validation_rb() -> ReasoningBit {
    ReasoningBit {
        id: "type_validation".to_string(),
        name: "Valid Chip Type".to_string(),
        condition: Expression::Or(vec![
            Expression::TypeEquals("ubl/app".to_string()),
            Expression::TypeEquals("ubl/tenant".to_string()),
            Expression::TypeEquals("ubl/user".to_string()),
            Expression::TypeEquals("ubl/policy".to_string()),
            Expression::TypeEquals("ubl/token".to_string()),
            Expression::TypeEquals("ubl/invite".to_string()),
            Expression::TypeEquals("ubl/ai.passport".to_string()),
            Expression::TypeEquals("ubl/wasm.module".to_string()),
            Expression::TypeEquals("ubl/verification".to_string()),
            Expression::TypeEquals("ubl/advisory".to_string()),
            Expression::TypeEquals("ubl/adapter".to_string()),
            Expression::TypeEquals("ubl/membership".to_string()),
            Expression::TypeEquals("ubl/revoke".to_string()),
            Expression::TypeEquals("ubl/key.rotate".to_string()),
            Expression::TypeEquals("ubl/document".to_string()),
            Expression::TypeEquals("audit/report.request.v1".to_string()),
            Expression::TypeEquals("audit/ledger.snapshot.request.v1".to_string()),
            Expression::TypeEquals("ledger/segment.compact.v1".to_string()),
            Expression::TypeEquals("audit/advisory.request.v1".to_string()),
        ]),
        on_true: Decision::Allow,
        on_false: Decision::Deny,
        requires_context: vec!["chip.@type".to_string()],
    }
}

/// RB: Must have logical ID
fn create_id_required_rb() -> ReasoningBit {
    ReasoningBit {
        id: "has_logical_id".to_string(),
        name: "Has ID Field".to_string(),
        condition: Expression::ContextHas("chip.id".to_string()),
        on_true: Decision::Allow,
        on_false: Decision::Deny,
        requires_context: vec!["chip.id".to_string()],
    }
}

/// RB: Size limit (1MB)
fn create_size_limit_rb() -> ReasoningBit {
    ReasoningBit {
        id: "size_limit".to_string(),
        name: "Body Size Limit".to_string(),
        condition: Expression::BodySizeLte(1_048_576), // 1MB
        on_true: Decision::Allow,
        on_false: Decision::Deny,
        requires_context: vec![],
    }
}

/// RB: No obviously malicious content
fn create_no_malicious_content_rb() -> ReasoningBit {
    ReasoningBit {
        id: "no_malicious_content".to_string(),
        name: "No Malicious Content".to_string(),
        condition: Expression::And(vec![
            // No script tags
            Expression::Not(Box::new(Expression::ContextEquals(
                "body.script".to_string(),
                json!("*"),
            ))),
            // No obvious SQL injection attempts
            Expression::Not(Box::new(Expression::ContextEquals(
                "body.query".to_string(),
                json!("DROP TABLE*"),
            ))),
        ]),
        on_true: Decision::Allow,
        on_false: Decision::Deny,
        requires_context: vec![],
    }
}

/// Create the genesis chip body as JSON
pub fn create_genesis_chip_body() -> serde_json::Value {
    let genesis_policy = create_genesis_policy();

    json!({
        "@type": "ubl/policy.genesis",
        "id": "ubl.genesis.v1",
        "version": "1.0",
        "description": "Genesis Policy - Root of all UBL policies",
        "created_at": "2025-02-15T00:00:00Z",
        "circuits": genesis_policy.circuits,
        "scope": genesis_policy.scope
    })
}

/// Genesis chip CID - this is computed deterministically
pub fn genesis_chip_cid() -> String {
    use ubl_ai_nrf1::{compute_cid, to_nrf1_bytes};

    let genesis_body = create_genesis_chip_body();
    let nrf1_bytes = to_nrf1_bytes(&genesis_body).expect("Genesis chip must compile");
    compute_cid(&nrf1_bytes).expect("Genesis CID must compute")
}

/// Check if a CID is the genesis chip
pub fn is_genesis_chip(cid: &str) -> bool {
    cid == genesis_chip_cid()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_policy_creates_successfully() {
        let policy = create_genesis_policy();
        assert_eq!(policy.id, "ubl.genesis.v1");
        assert_eq!(policy.circuits.len(), 1);
        assert_eq!(policy.scope.level, "genesis");
    }

    #[test]
    fn genesis_circuit_has_required_rbs() {
        let circuit = create_genesis_circuit();
        assert_eq!(circuit.reasoning_bits.len(), 4);

        let rb_ids: Vec<&String> = circuit.reasoning_bits.iter().map(|rb| &rb.id).collect();

        assert!(rb_ids.contains(&&"type_validation".to_string()));
        assert!(rb_ids.contains(&&"has_logical_id".to_string()));
        assert!(rb_ids.contains(&&"size_limit".to_string()));
        assert!(rb_ids.contains(&&"no_malicious_content".to_string()));
    }

    #[test]
    fn genesis_cid_is_deterministic() {
        let cid1 = genesis_chip_cid();
        let cid2 = genesis_chip_cid();
        assert_eq!(cid1, cid2);
        assert!(cid1.starts_with("b3:"));
    }

    #[test]
    fn genesis_body_serializes_correctly() {
        let body = create_genesis_chip_body();
        assert_eq!(body["@type"], "ubl/policy.genesis");
        assert_eq!(body["id"], "ubl.genesis.v1");
        assert!(body["circuits"].is_array());
        assert!(body["scope"].is_object());
    }

    #[test]
    fn type_validation_rb_accepts_valid_types() {
        use crate::reasoning_bit::EvalContext;
        use std::collections::HashMap;

        let rb = create_type_validation_rb();
        let variables = HashMap::new();

        let context = EvalContext {
            chip: json!({"@type": "ubl/user", "id": "test"}),
            body_size: 1000,
            variables,
        };

        let result = rb.evaluate(&context);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn type_validation_rb_rejects_invalid_types() {
        use crate::reasoning_bit::EvalContext;
        use std::collections::HashMap;

        let rb = create_type_validation_rb();

        let context = EvalContext {
            chip: json!({"@type": "evil/malware", "id": "test"}),
            body_size: 1000,
            variables: HashMap::new(),
        };

        let result = rb.evaluate(&context);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn type_validation_rb_accepts_key_rotate() {
        use crate::reasoning_bit::EvalContext;
        use std::collections::HashMap;

        let rb = create_type_validation_rb();
        let context = EvalContext {
            chip: json!({"@type": "ubl/key.rotate", "id": "rot"}),
            body_size: 1000,
            variables: HashMap::new(),
        };
        let result = rb.evaluate(&context);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn size_limit_rb_enforces_1mb_limit() {
        use crate::reasoning_bit::EvalContext;
        use std::collections::HashMap;

        let rb = create_size_limit_rb();

        // Within limit
        let context = EvalContext {
            chip: json!({"@type": "ubl/user", "id": "test"}),
            body_size: 1000,
            variables: HashMap::new(),
        };
        assert_eq!(rb.evaluate(&context).decision, Decision::Allow);

        // Over limit
        let context = EvalContext {
            chip: json!({"@type": "ubl/user", "id": "test"}),
            body_size: 2_000_000, // 2MB
            variables: HashMap::new(),
        };
        assert_eq!(rb.evaluate(&context).decision, Decision::Deny);
    }
}
