use super::super::*;

impl UblPipeline {
    /// Stage 2: CHECK - Onboarding validation + Policy evaluation with full trace
    pub(in crate::pipeline) async fn stage_check(
        &self,
        request: &ChipRequest,
    ) -> Result<CheckResult, PipelineError> {
        let _check_start = std::time::Instant::now();

        // ── Onboarding pre-check: validate body + dependency chain ──
        if crate::auth::is_onboarding_type(&request.chip_type) {
            // 1. Parse chip body into typed onboarding payload
            let onboarding = crate::auth::parse_onboarding_chip(&request.body)
                .map_err(|e| PipelineError::InvalidChip(format!("Onboarding validation: {}", e)))?;
            let onboarding = onboarding.ok_or_else(|| {
                PipelineError::InvalidChip(format!(
                    "Onboarding type '{}' not recognized",
                    request.chip_type
                ))
            })?;

            // 2. Validate @world format
            let world_str = request
                .body
                .get("@world")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    PipelineError::InvalidChip("Onboarding chip missing @world".into())
                })?;

            // 3. Check dependency chain against ChipStore
            if let Some(ref store) = self.chip_store {
                let auth = crate::auth::AuthEngine::new();
                auth.validate_onboarding_dependencies(&onboarding, &request.body, world_str, store)
                    .await
                    .map_err(|e| match e {
                        crate::auth::AuthValidationError::InvalidChip(msg) => {
                            PipelineError::InvalidChip(msg)
                        }
                        crate::auth::AuthValidationError::DependencyMissing(msg) => {
                            PipelineError::DependencyMissing(msg)
                        }
                        crate::auth::AuthValidationError::Internal(msg) => {
                            PipelineError::Internal(msg)
                        }
                    })?;
            }
        }

        // ── Key rotation pre-check: typed parse + capability + duplicate guard ──
        if request.chip_type == "ubl/key.rotate" {
            let parsed = KeyRotateRequest::parse(&request.body)
                .map_err(|e| PipelineError::InvalidChip(format!("Key rotation: {}", e)))?;
            let world_str = request
                .body
                .get("@world")
                .and_then(|v| v.as_str())
                .ok_or_else(|| PipelineError::InvalidChip("Key rotation missing @world".into()))?;

            crate::capability::require_cap(&request.body, "key:rotate", world_str).map_err(
                |e| PipelineError::InvalidChip(format!("ubl/key.rotate capability: {}", e)),
            )?;

            if let Some(ref store) = self.chip_store {
                let existing = store
                    .query(&ubl_chipstore::ChipQuery {
                        chip_type: Some("ubl/key.map".to_string()),
                        tags: vec![format!("old_kid:{}", parsed.old_kid)],
                        created_after: None,
                        created_before: None,
                        executor_did: None,
                        limit: Some(1),
                        offset: None,
                    })
                    .await
                    .map_err(|e| PipelineError::Internal(format!("ChipStore query: {}", e)))?;
                if !existing.chips.is_empty() {
                    return Err(PipelineError::InvalidChip(format!(
                        "old_kid '{}' already rotated",
                        parsed.old_kid
                    )));
                }
            }
        }

        // Convert to policy request
        let policy_request = PolicyChipRequest {
            chip_type: request.chip_type.clone(),
            body: request.body.clone(),
            parents: request.parents.clone(),
            operation: request
                .operation
                .clone()
                .unwrap_or_else(|| "create".to_string()),
        };

        // Load policy chain
        let policies = self
            .policy_loader
            .load_policy_chain(&policy_request)
            .await
            .map_err(|e| PipelineError::Internal(format!("Policy loading: {}", e)))?;

        // Create evaluation context
        let body_bytes = serde_json::to_vec(&request.body)
            .map_err(|e| PipelineError::Internal(format!("Body serialization: {}", e)))?;

        let mut variables = HashMap::new();
        if let Some(chip_type) = request.body.get("@type") {
            variables.insert("chip.@type".to_string(), chip_type.clone());
        }
        if let Some(chip_id) = request.body.get("@id").or_else(|| request.body.get("id")) {
            variables.insert("chip.id".to_string(), chip_id.clone());
        }

        let context = EvalContext {
            chip: request.body.clone(),
            body_size: body_bytes.len(),
            variables,
        };

        // Evaluate each policy, collecting trace entries
        let mut trace = Vec::new();
        for policy in &policies {
            let policy_start = std::time::Instant::now();
            let result = policy.evaluate(&context);
            let policy_ms = policy_start.elapsed().as_millis() as i64;

            trace.push(Self::policy_result_to_trace(&result, policy_ms));

            // Stop on first DENY
            if matches!(result.decision, Decision::Deny) {
                return Ok(CheckResult {
                    decision: Decision::Deny,
                    reason: result.reason,
                    short_circuited: true,
                    trace,
                });
            }
        }

        Ok(CheckResult {
            decision: Decision::Allow,
            reason: "All policies allowed".to_string(),
            short_circuited: false,
            trace,
        })
    }
}
