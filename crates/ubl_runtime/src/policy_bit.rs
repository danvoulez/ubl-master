//! Policy Bit - composition of circuits into governance

use crate::circuit::{Circuit, CircuitResult};
use crate::reasoning_bit::{Decision, EvalContext};
use serde::{Deserialize, Serialize};

/// Scope where a policy applies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyScope {
    pub chip_types: Vec<String>,
    pub operations: Vec<String>,
    pub level: String,
}

/// A policy bit - composition of circuits into governance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBit {
    pub id: String,
    pub name: String,
    pub circuits: Vec<Circuit>,
    pub scope: PolicyScope,
}

impl PolicyBit {
    /// Evaluate this policy bit against context
    pub fn evaluate(&self, context: &EvalContext) -> PolicyResult {
        let mut circuit_results = Vec::new();

        for circuit in &self.circuits {
            let result = circuit.evaluate(context);
            circuit_results.push(result.clone());

            // Stop on first DENY
            if matches!(result.decision, Decision::Deny) {
                return PolicyResult {
                    policy_id: self.id.clone(),
                    decision: Decision::Deny,
                    reason: result.reason,
                    circuit_results,
                    short_circuited: true,
                };
            }
        }

        // All circuits passed - final decision is ALLOW
        PolicyResult {
            policy_id: self.id.clone(),
            decision: Decision::Allow,
            reason: "All circuits allowed".to_string(),
            circuit_results,
            short_circuited: false,
        }
    }
}

/// Result of evaluating a policy bit
#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub policy_id: String,
    pub decision: Decision,
    pub reason: String,
    pub circuit_results: Vec<CircuitResult>,
    pub short_circuited: bool,
}
