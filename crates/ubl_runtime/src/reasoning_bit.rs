//! Reasoning Bit implementation - the atomic unit of decision making

use serde::{Deserialize, Serialize};

// Single Decision enum — lives in ubl_receipt, re-exported here.
pub use ubl_receipt::Decision;

/// Expression language for reasoning bit conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Expression {
    Always(bool),
    ContextHas(String),
    ContextEquals(String, serde_json::Value),
    BodySizeLte(usize),
    TypeEquals(String),
    And(Vec<Expression>),
    Or(Vec<Expression>),
    Not(Box<Expression>),
}

/// The atomic unit of decision making
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningBit {
    pub id: String,
    pub name: String,
    pub condition: Expression,
    pub on_true: Decision,
    pub on_false: Decision,
    pub requires_context: Vec<String>,
}

/// Context for evaluating reasoning bits
#[derive(Debug, Clone)]
pub struct EvalContext {
    pub chip: serde_json::Value,
    pub body_size: usize,
    pub variables: std::collections::HashMap<String, serde_json::Value>,
}

/// Result of evaluating a reasoning bit
#[derive(Debug, Clone)]
pub struct RbResult {
    pub rb_id: String,
    pub decision: Decision,
    pub reason: String,
    pub inputs_used: Vec<String>,
    pub duration_nanos: u64,
}

impl ReasoningBit {
    /// Evaluate this reasoning bit against the given context
    pub fn evaluate(&self, context: &EvalContext) -> RbResult {
        let start = std::time::Instant::now();

        let condition_result = self.condition.evaluate(context);
        let decision = if condition_result {
            self.on_true.clone()
        } else {
            self.on_false.clone()
        };

        let reason = format!(
            "{} evaluated to {} → {:?}",
            self.name, condition_result, decision
        );

        let inputs_used = self.condition.inputs_used();
        let duration_nanos = start.elapsed().as_nanos() as u64;

        RbResult {
            rb_id: self.id.clone(),
            decision,
            reason,
            inputs_used,
            duration_nanos,
        }
    }
}

impl Expression {
    /// Evaluate this expression against the context
    pub fn evaluate(&self, context: &EvalContext) -> bool {
        match self {
            Expression::Always(value) => *value,
            Expression::ContextHas(key) => context.variables.contains_key(key),
            Expression::ContextEquals(key, expected) => context
                .variables
                .get(key)
                .map(|v| v == expected)
                .unwrap_or(false),
            Expression::BodySizeLte(limit) => context.body_size <= *limit,
            Expression::TypeEquals(expected_type) => context
                .chip
                .get("@type")
                .and_then(|v| v.as_str())
                .map(|t| t == expected_type)
                .unwrap_or(false),
            Expression::And(expressions) => expressions.iter().all(|e| e.evaluate(context)),
            Expression::Or(expressions) => expressions.iter().any(|e| e.evaluate(context)),
            Expression::Not(expr) => !expr.evaluate(context),
        }
    }

    /// Get list of context keys this expression uses
    pub fn inputs_used(&self) -> Vec<String> {
        let mut inputs = Vec::new();
        self.collect_inputs(&mut inputs);
        inputs.sort();
        inputs.dedup();
        inputs
    }

    fn collect_inputs(&self, inputs: &mut Vec<String>) {
        match self {
            Expression::ContextHas(key) | Expression::ContextEquals(key, _) => {
                inputs.push(key.clone());
            }
            Expression::TypeEquals(_) => {
                inputs.push("@type".to_string());
            }
            Expression::And(exprs) | Expression::Or(exprs) => {
                for expr in exprs {
                    expr.collect_inputs(inputs);
                }
            }
            Expression::Not(expr) => {
                expr.collect_inputs(inputs);
            }
            Expression::Always(_) | Expression::BodySizeLte(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_context() -> EvalContext {
        let mut variables = HashMap::new();
        variables.insert(
            "body.email".to_string(),
            serde_json::Value::String("alice@acme.com".to_string()),
        );
        variables.insert(
            "body.role".to_string(),
            serde_json::Value::String("admin".to_string()),
        );

        EvalContext {
            chip: serde_json::json!({"@type": "ubl/user", "id": "alice"}),
            body_size: 1024,
            variables,
        }
    }

    #[test]
    fn reasoning_bit_allow() {
        let rb = ReasoningBit {
            id: "test_admin".to_string(),
            name: "Is Admin".to_string(),
            condition: Expression::ContextEquals(
                "body.role".to_string(),
                serde_json::Value::String("admin".to_string()),
            ),
            on_true: Decision::Allow,
            on_false: Decision::Deny,
            requires_context: vec!["body.role".to_string()],
        };

        let result = rb.evaluate(&test_context());
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.inputs_used.contains(&"body.role".to_string()));
    }

    #[test]
    fn expression_and() {
        let expr = Expression::And(vec![
            Expression::TypeEquals("ubl/user".to_string()),
            Expression::ContextHas("body.email".to_string()),
        ]);

        assert!(expr.evaluate(&test_context()));

        let inputs = expr.inputs_used();
        assert!(inputs.contains(&"@type".to_string()));
        assert!(inputs.contains(&"body.email".to_string()));
    }

    #[test]
    fn expression_size_limit() {
        let expr = Expression::BodySizeLte(2048);
        assert!(expr.evaluate(&test_context()));

        let expr = Expression::BodySizeLte(512);
        assert!(!expr.evaluate(&test_context()));
    }
}
