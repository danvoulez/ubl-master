//! Circuit composition - combining reasoning bits into logic units

use crate::reasoning_bit::{Decision, EvalContext, RbResult, ReasoningBit};
use serde::{Deserialize, Serialize};

/// How to compose multiple reasoning bits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompositionMode {
    /// Evaluate in order, stop on first DENY
    Sequential,
    /// Evaluate all in parallel
    Parallel,
    /// Conditional branching
    Conditional(Vec<ConditionalBranch>),
}

/// How to aggregate multiple decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AggregationMode {
    /// All must ALLOW
    All,
    /// At least one must ALLOW
    Any,
    /// Majority must ALLOW
    Majority,
    /// At least K out of N must ALLOW
    KofN { k: usize, n: usize },
    /// First non-REQUIRE decision wins
    FirstDecisive,
}

/// A conditional branch in circuit evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionalBranch {
    pub condition: crate::reasoning_bit::Expression,
    pub then_circuit: Box<Circuit>,
    pub else_circuit: Option<Box<Circuit>>,
}

/// A circuit of reasoning bits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Circuit {
    pub id: String,
    pub name: String,
    pub reasoning_bits: Vec<ReasoningBit>,
    pub composition: CompositionMode,
    pub aggregator: AggregationMode,
}

/// Result of evaluating a circuit
#[derive(Debug, Clone)]
pub struct CircuitResult {
    pub circuit_id: String,
    pub decision: Decision,
    pub reason: String,
    pub rb_results: Vec<RbResult>,
    pub total_duration_nanos: u64,
    pub short_circuited: bool,
}

impl Circuit {
    /// Evaluate this circuit against the given context
    pub fn evaluate(&self, context: &EvalContext) -> CircuitResult {
        let start = std::time::Instant::now();

        let result = match &self.composition {
            CompositionMode::Sequential => self.evaluate_sequential(context),
            CompositionMode::Parallel => self.evaluate_parallel(context),
            CompositionMode::Conditional(branches) => self.evaluate_conditional(context, branches),
        };

        CircuitResult {
            circuit_id: self.id.clone(),
            decision: result.decision,
            reason: result.reason,
            rb_results: result.rb_results,
            total_duration_nanos: start.elapsed().as_nanos() as u64,
            short_circuited: result.short_circuited,
        }
    }

    fn evaluate_sequential(&self, context: &EvalContext) -> CircuitResult {
        let mut rb_results = Vec::new();

        for rb in &self.reasoning_bits {
            let result = rb.evaluate(context);
            rb_results.push(result.clone());

            // Short-circuit on DENY
            if matches!(result.decision, Decision::Deny) {
                return CircuitResult {
                    circuit_id: self.id.clone(),
                    decision: Decision::Deny,
                    reason: format!("Denied by {}: {}", result.rb_id, result.reason),
                    rb_results,
                    total_duration_nanos: 0, // Will be filled by caller
                    short_circuited: true,
                };
            }
        }

        // All passed - aggregate according to strategy
        self.aggregate_results(rb_results)
    }

    fn evaluate_parallel(&self, context: &EvalContext) -> CircuitResult {
        let mut rb_results = Vec::new();

        // Evaluate all reasoning bits
        for rb in &self.reasoning_bits {
            let result = rb.evaluate(context);
            rb_results.push(result);
        }

        // Aggregate results
        self.aggregate_results(rb_results)
    }

    fn evaluate_conditional(
        &self,
        context: &EvalContext,
        branches: &[ConditionalBranch],
    ) -> CircuitResult {
        for branch in branches {
            if branch.condition.evaluate(context) {
                return branch.then_circuit.evaluate(context);
            }
        }

        // No condition matched - use else circuit if available
        if let Some(branch) = branches.first() {
            if let Some(ref else_circuit) = branch.else_circuit {
                return else_circuit.evaluate(context);
            }
        }

        // No matching condition and no else - default to DENY
        CircuitResult {
            circuit_id: self.id.clone(),
            decision: Decision::Deny,
            reason: "No matching condition in conditional circuit".to_string(),
            rb_results: vec![],
            total_duration_nanos: 0,
            short_circuited: false,
        }
    }

    fn aggregate_results(&self, rb_results: Vec<RbResult>) -> CircuitResult {
        if rb_results.is_empty() {
            return CircuitResult {
                circuit_id: self.id.clone(),
                decision: Decision::Allow,
                reason: "No reasoning bits to evaluate".to_string(),
                rb_results: vec![],
                total_duration_nanos: 0,
                short_circuited: false,
            };
        }

        let (decision, reason) = match &self.aggregator {
            AggregationMode::All => {
                let denies: Vec<_> = rb_results
                    .iter()
                    .filter(|r| matches!(r.decision, Decision::Deny))
                    .collect();

                if !denies.is_empty() {
                    (
                        Decision::Deny,
                        format!(
                            "Denied by: {}",
                            denies
                                .iter()
                                .map(|r| r.rb_id.clone())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    )
                } else {
                    let requires: Vec<_> = rb_results
                        .iter()
                        .filter(|r| matches!(r.decision, Decision::Require))
                        .collect();

                    if !requires.is_empty() {
                        (
                            Decision::Require,
                            format!(
                                "Requires consent from: {}",
                                requires
                                    .iter()
                                    .map(|r| r.rb_id.clone())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                        )
                    } else {
                        (Decision::Allow, "All reasoning bits allowed".to_string())
                    }
                }
            }

            AggregationMode::Any => {
                let allows: Vec<_> = rb_results
                    .iter()
                    .filter(|r| matches!(r.decision, Decision::Allow))
                    .collect();

                if !allows.is_empty() {
                    (
                        Decision::Allow,
                        format!(
                            "Allowed by: {}",
                            allows
                                .iter()
                                .map(|r| r.rb_id.clone())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    )
                } else {
                    (Decision::Deny, "No reasoning bit allowed".to_string())
                }
            }

            AggregationMode::Majority => {
                let allows = rb_results
                    .iter()
                    .filter(|r| matches!(r.decision, Decision::Allow))
                    .count();
                let total = rb_results.len();

                if allows > total / 2 {
                    (
                        Decision::Allow,
                        format!("Majority allowed ({}/{})", allows, total),
                    )
                } else {
                    (
                        Decision::Deny,
                        format!("Majority denied ({}/{})", total - allows, total),
                    )
                }
            }

            AggregationMode::KofN { k, n } => {
                let allows = rb_results
                    .iter()
                    .filter(|r| matches!(r.decision, Decision::Allow))
                    .count();

                if allows >= *k {
                    (
                        Decision::Allow,
                        format!("K-of-N satisfied ({}/{})", allows, n),
                    )
                } else {
                    (
                        Decision::Deny,
                        format!("K-of-N not satisfied ({}/{}, need {})", allows, n, k),
                    )
                }
            }

            AggregationMode::FirstDecisive => {
                for result in &rb_results {
                    if !matches!(result.decision, Decision::Require) {
                        return CircuitResult {
                            circuit_id: self.id.clone(),
                            decision: result.decision.clone(),
                            reason: format!("First decisive: {}", result.reason),
                            rb_results,
                            total_duration_nanos: 0,
                            short_circuited: false,
                        };
                    }
                }

                // All were REQUIRE
                (
                    Decision::Require,
                    "All reasoning bits require consent".to_string(),
                )
            }
        };

        CircuitResult {
            circuit_id: self.id.clone(),
            decision,
            reason,
            rb_results,
            total_duration_nanos: 0,
            short_circuited: false,
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
    fn circuit_sequential_all_allow() {
        let circuit = Circuit {
            id: "test_circuit".to_string(),
            name: "Test Circuit".to_string(),
            reasoning_bits: vec![
                ReasoningBit {
                    id: "always_allow".to_string(),
                    name: "Always Allow".to_string(),
                    condition: crate::reasoning_bit::Expression::Always(true),
                    on_true: Decision::Allow,
                    on_false: Decision::Deny,
                    requires_context: vec![],
                },
                ReasoningBit {
                    id: "check_type".to_string(),
                    name: "Check Type".to_string(),
                    condition: crate::reasoning_bit::Expression::TypeEquals("ubl/user".to_string()),
                    on_true: Decision::Allow,
                    on_false: Decision::Deny,
                    requires_context: vec!["@type".to_string()],
                },
            ],
            composition: CompositionMode::Sequential,
            aggregator: AggregationMode::All,
        };

        let result = circuit.evaluate(&test_context());
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.rb_results.len(), 2);
        assert!(!result.short_circuited);
    }

    #[test]
    fn circuit_sequential_short_circuit() {
        let circuit = Circuit {
            id: "test_circuit".to_string(),
            name: "Test Circuit".to_string(),
            reasoning_bits: vec![
                ReasoningBit {
                    id: "always_deny".to_string(),
                    name: "Always Deny".to_string(),
                    condition: crate::reasoning_bit::Expression::Always(false),
                    on_true: Decision::Allow,
                    on_false: Decision::Deny,
                    requires_context: vec![],
                },
                ReasoningBit {
                    id: "never_reached".to_string(),
                    name: "Never Reached".to_string(),
                    condition: crate::reasoning_bit::Expression::Always(true),
                    on_true: Decision::Allow,
                    on_false: Decision::Deny,
                    requires_context: vec![],
                },
            ],
            composition: CompositionMode::Sequential,
            aggregator: AggregationMode::All,
        };

        let result = circuit.evaluate(&test_context());
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.rb_results.len(), 1); // Short-circuited
        assert!(result.short_circuited);
    }
}
