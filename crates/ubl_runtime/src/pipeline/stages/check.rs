use super::super::*;

impl UblPipeline {
    /// Stage 2: CHECK - Onboarding validation + Policy evaluation with full trace
    pub(in crate::pipeline) async fn stage_check(
        &self,
        request: &ParsedChipRequest<'_>,
    ) -> Result<CheckResult, PipelineError> {
        let _check_start = std::time::Instant::now();

        // ── Onboarding pre-check: validate body + dependency chain ──
        if crate::auth::is_onboarding_type(request.chip_type) {
            // 1. Parse chip body into typed onboarding payload
            let onboarding = crate::auth::parse_onboarding_chip(request.body())
                .map_err(|e| PipelineError::InvalidChip(format!("Onboarding validation: {}", e)))?;
            let onboarding = onboarding.ok_or_else(|| {
                PipelineError::InvalidChip(format!(
                    "Onboarding type '{}' not recognized",
                    request.chip_type
                ))
            })?;

            // 2. Validate @world format
            let world_str = request.world;

            // 3. Check dependency chain against ChipStore
            if let Some(ref store) = self.chip_store {
                let auth = crate::auth::AuthEngine::new();
                auth.validate_onboarding_dependencies(
                    &onboarding,
                    request.body(),
                    world_str,
                    store,
                )
                .await
                .map_err(|e| match e {
                    crate::auth::AuthValidationError::InvalidChip(msg) => {
                        PipelineError::InvalidChip(msg)
                    }
                    crate::auth::AuthValidationError::DependencyMissing(msg) => {
                        PipelineError::DependencyMissing(msg)
                    }
                    crate::auth::AuthValidationError::Internal(msg) => PipelineError::Internal(msg),
                })?;
            }
        }

        // ── Key rotation pre-check: typed parse + capability + duplicate guard ──
        if request.chip_type == "ubl/key.rotate" {
            let parsed = KeyRotateRequest::parse(request.body())
                .map_err(|e| PipelineError::InvalidChip(format!("Key rotation: {}", e)))?;
            let world_str = request.world;

            crate::capability::require_cap(request.body(), "key:rotate", world_str).map_err(
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

        // ── Audit pre-checks: typed contract + capability + range/link constraints ──
        if crate::audit_chip::is_audit_request_type(request.chip_type) {
            crate::audit_chip::validate_request_for_check(
                request.chip_type,
                request.body(),
                request.world,
                self.chip_store.as_deref(),
            )
            .await
            .map_err(|e| match e {
                crate::audit_chip::AuditError::ChipStore(_) => {
                    PipelineError::Internal(format!("Audit validation store: {}", e))
                }
                _ => PipelineError::InvalidChip(format!("Audit validation: {}", e)),
            })?;
        }

        // ── Silicon chips: bit / circuit / chip / compile ────────────────────────
        if crate::silicon_chip::is_silicon_type(request.chip_type) {
            crate::silicon_chip::validate_for_check(
                request.chip_type,
                request.body(),
                self.chip_store.as_deref(),
            )
            .await
            .map_err(|e| match e {
                crate::silicon_chip::SiliconError::ChipStore(_) => {
                    PipelineError::Internal(format!("Silicon validation store: {}", e))
                }
                _ => PipelineError::InvalidChip(format!("Silicon validation: {}", e)),
            })?;
        }

        // ── @silicon_gate: live silicon enforcement ───────────────────────────────
        // Any chip body may declare "@silicon_gate": "<ubl/silicon.chip CID>".
        // The gate's compiled bytecode runs (ghost mode) against the incoming
        // chip body.  ExecError::Deny → reject here before any TR execution.
        if let Some(gate_cid) = request.body().get("@silicon_gate").and_then(|v| v.as_str()) {
            if let Some(ref store) = self.chip_store {
                let gate_start = std::time::Instant::now();

                let bytecode = crate::silicon_chip::gate_compile(gate_cid, store)
                    .await
                    .map_err(|e| {
                        PipelineError::InvalidChip(format!("@silicon_gate compile: {}", e))
                    })?;

                let instructions = tlv::decode_stream(&bytecode)
                    .map_err(|e| PipelineError::Internal(format!("@silicon_gate decode: {}", e)))?;

                // NRF-encode the incoming chip body as the VM's input #0.
                let chip_nrf = ubl_ai_nrf1::to_nrf1_bytes(request.body())
                    .map_err(|e| PipelineError::Internal(format!("@silicon_gate nrf: {}", e)))?;

                let mut cas = PipelineCas::new();
                let input_cid = cas.put(&chip_nrf);
                let signer = PipelineSigner {
                    signing_key: self.signing_key.clone(),
                    kid: self.kid.clone(),
                };
                let cfg = VmConfig {
                    fuel_limit: self.fuel_limit,
                    ghost: true,
                    trace: false,
                };
                let mut vm = Vm::new(cfg, cas, &signer, PipelineCanon, vec![input_cid])
                    .with_body_size(chip_nrf.len());

                if let Err(ExecError::Deny(reason)) = vm.run(&instructions) {
                    let gate_ms = gate_start.elapsed().as_millis() as i64;
                    return Ok(CheckResult {
                        decision: Decision::Deny,
                        reason: format!("@silicon_gate '{}' denied: {}", gate_cid, reason),
                        short_circuited: true,
                        trace: vec![PolicyTraceEntry {
                            level: "silicon_gate".to_string(),
                            policy_id: format!("silicon_gate:{}", gate_cid),
                            result: Decision::Deny,
                            reason: format!("silicon gate denied: {}", reason),
                            rb_results: vec![],
                            duration_ms: gate_ms,
                        }],
                    });
                }
            }
        }

        // Convert to policy request
        let policy_request = PolicyChipRequest {
            chip_type: request.chip_type.to_string(),
            body: request.body().clone(),
            parents: request.parents().to_vec(),
            operation: request.operation().to_string(),
        };

        // Load policy chain
        let policies = self
            .policy_loader
            .load_policy_chain(&policy_request)
            .await
            .map_err(|e| PipelineError::Internal(format!("Policy loading: {}", e)))?;

        // Create evaluation context
        let body_bytes = serde_json::to_vec(request.body())
            .map_err(|e| PipelineError::Internal(format!("Body serialization: {}", e)))?;

        let mut variables = HashMap::new();
        variables.insert(
            "chip.@type".to_string(),
            serde_json::json!(request.chip_type),
        );
        if let Some(chip_id) = request.chip_id {
            variables.insert("chip.id".to_string(), serde_json::json!(chip_id));
        }

        let context = EvalContext {
            chip: request.body().clone(),
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
