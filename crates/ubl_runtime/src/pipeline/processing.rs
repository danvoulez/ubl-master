use super::*;

impl UblPipeline {
    /// Process raw bytes through the full KNOCK→WA→CHECK→TR→WF pipeline.
    /// Use this when you have raw HTTP body bytes (e.g. from the gate).
    pub async fn process_raw(&self, bytes: &[u8]) -> Result<PipelineResult, PipelineError> {
        // Stage 0: KNOCK
        let value = crate::knock::knock(bytes).map_err(|e| PipelineError::Knock(e.to_string()))?;

        let chip_type = value["@type"].as_str().unwrap_or("").to_string();
        let request = ChipRequest {
            chip_type,
            body: value,
            parents: vec![],
            operation: Some("create".to_string()),
        };

        self.process_chip(request).await
    }

    /// Process a chip request through the WA→TR→WF pipeline.
    /// Assumes KNOCK already passed (use `process_raw` for full pipeline).
    ///
    /// **Idempotency:** If the chip has key `(@type, @ver, @world, @id)` and
    /// that key was already processed, returns the cached result immediately.
    pub async fn process_chip(
        &self,
        request: ChipRequest,
    ) -> Result<PipelineResult, PipelineError> {
        let pipeline_start = std::time::Instant::now();
        let parsed_request = ParsedChipRequest::parse(&request)?;
        let chip_id = parsed_request.chip_id.unwrap_or("-");
        info!(
            chip_type = %parsed_request.chip_type,
            world = %parsed_request.world,
            chip_id = %chip_id,
            "pipeline request accepted"
        );

        // ── Idempotency check: replay returns cached result (no re-execution) ──
        let idem_key = IdempotencyKey::from_chip_body(parsed_request.body()).ok_or_else(|| {
            PipelineError::InvalidChip(
                "missing strict idempotency anchors: @type, @ver, @world, @id".to_string(),
            )
        })?;
        let durable_idem_key = idem_key.to_durable_key();
        let cached = if let Some(durable) = &self.durable_store {
            durable
                .get_idempotent(&durable_idem_key)
                .map_err(|e| PipelineError::StorageError(format!("Idempotency lookup: {}", e)))?
        } else {
            self.idempotency_store.get(&idem_key).await
        };

        if let Some(cached) = cached {
            let decision = if cached.decision.eq_ignore_ascii_case("allow")
                || cached.decision.contains("Allow")
            {
                Decision::Allow
            } else {
                Decision::Deny
            };
            let receipt = UnifiedReceipt::from_json(&cached.response_json)
                .unwrap_or_else(|_| UnifiedReceipt::new("", "", "", ""));
            info!(
                chip_type = %parsed_request.chip_type,
                world = %parsed_request.world,
                receipt_cid = %cached.receipt_cid,
                "pipeline idempotency replay"
            );
            return Ok(PipelineResult {
                final_receipt: PipelineReceipt {
                    body_cid: ubl_types::Cid::new_unchecked(&cached.receipt_cid),
                    receipt_type: "ubl/wf".to_string(),
                    body: cached.response_json.clone(),
                },
                chain: cached.chain.clone(),
                decision,
                receipt,
                replayed: true,
            });
        }

        // `@world` and `@type` already parsed/validated above.
        let world = parsed_request.world;
        let nonce = Self::generate_nonce();

        // Create the unified receipt — it evolves through each stage
        let mut receipt = UnifiedReceipt::new(world, &self.did, &self.kid, &nonce)
            .with_runtime_info((*self.runtime_info).clone());

        // Stage 1: WA (Write-Ahead)
        let wa_start = std::time::Instant::now();
        let wa_receipt = self.stage_write_ahead(&parsed_request).await?;
        let wa_ms = wa_start.elapsed().as_millis() as i64;
        debug!(chip_type = %parsed_request.chip_type, duration_ms = wa_ms, "stage wa completed");

        receipt
            .append_stage(StageExecution {
                stage: PipelineStage::WriteAhead,
                timestamp: chrono::Utc::now().to_rfc3339(),
                input_cid: wa_receipt.body_cid.as_str().to_string(),
                output_cid: Some(wa_receipt.body_cid.as_str().to_string()),
                fuel_used: None,
                policy_trace: vec![],
                vm_sig: None,
                vm_sig_payload_cid: None,
                auth_token: String::new(),
                duration_ms: wa_ms,
            })
            .map_err(|e| PipelineError::Internal(format!("Receipt WA: {}", e)))?;

        // Publish WA event
        if let Err(e) = self
            .event_bus
            .publish_stage_event(crate::event_bus::ReceiptEvent::from_stage_receipt(
                wa_receipt.body_cid.as_str(),
                &wa_receipt.receipt_type,
                wa_receipt.body.clone(),
                "wa",
                StageEventContext {
                    decision: None,
                    duration_ms: Some(wa_ms),
                    world: Some(world.to_string()),
                    input_cid: None,
                    binary_hash: Some(self.runtime_info.binary_hash.clone()),
                    build_meta: serde_json::to_value(&self.runtime_info.build).ok(),
                    actor: Some(self.did.clone()),
                },
            ))
            .await
        {
            warn!(error = %e, "Failed to publish receipt event");
        }

        // Stage 2: CHECK (Policy Evaluation)
        let check_start = std::time::Instant::now();
        let check = self.stage_check(&parsed_request).await?;
        let check_ms = check_start.elapsed().as_millis() as i64;
        debug!(
            chip_type = %parsed_request.chip_type,
            duration_ms = check_ms,
            decision = ?check.decision,
            "stage check completed"
        );

        receipt
            .append_stage(StageExecution {
                stage: PipelineStage::Check,
                timestamp: chrono::Utc::now().to_rfc3339(),
                input_cid: wa_receipt.body_cid.as_str().to_string(),
                output_cid: None,
                fuel_used: None,
                policy_trace: check.trace.clone(),
                vm_sig: None,
                vm_sig_payload_cid: None,
                auth_token: String::new(),
                duration_ms: check_ms,
            })
            .map_err(|e| PipelineError::Internal(format!("Receipt CHECK: {}", e)))?;

        // Post-CHECK advisory hook (non-blocking) — explain denial
        if let (Some(ref engine), Some(ref store)) = (&self.advisory_engine, &self.chip_store) {
            let adv = engine.post_check_advisory(
                wa_receipt.body_cid.as_str(),
                if matches!(check.decision, Decision::Deny) {
                    "deny"
                } else {
                    "allow"
                },
                &check.reason,
                &check
                    .trace
                    .iter()
                    .map(|t| serde_json::to_value(t).unwrap_or_default())
                    .collect::<Vec<_>>(),
            );
            let body = engine.advisory_to_chip_body(&adv);
            let store = store.clone();
            tokio::spawn(async move {
                let metadata = ExecutionMetadata {
                    runtime_version: "advisory/post-check".to_string(),
                    execution_time_ms: 0,
                    fuel_consumed: 0,
                    policies_applied: vec![],
                    executor_did: ubl_types::Did::new_unchecked("did:key:advisory"),
                    reproducible: false,
                };
                if let Err(e) = store
                    .store_executed_chip(body, "self".to_string(), metadata)
                    .await
                {
                    warn!(error = %e, "advisory post-CHECK store failed (non-fatal)");
                }
            });
        }

        // Short-circuit if denied
        if matches!(check.decision, Decision::Deny) {
            receipt.deny(&check.reason);

            let wf_receipt = self.create_deny_receipt(&wa_receipt, &check).await?;
            let deny_ms = pipeline_start.elapsed().as_millis() as i64;

            receipt
                .append_stage(StageExecution {
                    stage: PipelineStage::WriteFinished,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    input_cid: wa_receipt.body_cid.as_str().to_string(),
                    output_cid: Some(wf_receipt.body_cid.as_str().to_string()),
                    fuel_used: None,
                    policy_trace: check.trace.clone(),
                    vm_sig: None,
                    vm_sig_payload_cid: None,
                    auth_token: String::new(),
                    duration_ms: deny_ms,
                })
                .map_err(|e| PipelineError::Internal(format!("Receipt WF(DENY): {}", e)))?;
            receipt
                .finalize_and_sign(&self.signing_key, CryptoMode::from_env())
                .map_err(|e| PipelineError::SignError(format!("WF(DENY) sign failed: {}", e)))?;

            if let Err(e) = self
                .event_bus
                .publish_stage_event(crate::event_bus::ReceiptEvent::from_stage_receipt(
                    wf_receipt.body_cid.as_str(),
                    &wf_receipt.receipt_type,
                    wf_receipt.body.clone(),
                    "wf",
                    StageEventContext {
                        decision: Some("deny".to_string()),
                        duration_ms: Some(deny_ms),
                        world: Some(world.to_string()),
                        input_cid: Some(wa_receipt.body_cid.as_str().to_string()),
                        binary_hash: Some(self.runtime_info.binary_hash.clone()),
                        build_meta: serde_json::to_value(&self.runtime_info.build).ok(),
                        actor: Some(self.did.clone()),
                    },
                ))
                .await
            {
                warn!(error = %e, "Failed to publish receipt event");
            }

            let result = PipelineResult {
                final_receipt: wf_receipt.clone(),
                chain: vec![
                    wa_receipt.body_cid.as_str().to_string(),
                    "no-tr".to_string(),
                    wf_receipt.body_cid.as_str().to_string(),
                ],
                decision: Decision::Deny,
                receipt,
                replayed: false,
            };
            info!(
                chip_type = %parsed_request.chip_type,
                world = %parsed_request.world,
                decision = "deny",
                duration_ms = deny_ms,
                "pipeline completed"
            );

            self.persist_final_result(Some(&idem_key), world, &result)
                .await?;
            return Ok(result);
        }

        // Stage 3: TR (Transition - RB-VM execution)
        let tr_start = std::time::Instant::now();
        let tr_receipt = self.stage_transition(&parsed_request, &check).await?;
        let tr_ms = tr_start.elapsed().as_millis() as i64;
        debug!(chip_type = %parsed_request.chip_type, duration_ms = tr_ms, "stage tr completed");

        let fuel_used = tr_receipt
            .body
            .get("vm_state")
            .and_then(|v| v.get("fuel_used"))
            .and_then(|v| v.as_u64());

        receipt
            .append_stage(StageExecution {
                stage: PipelineStage::Transition,
                timestamp: chrono::Utc::now().to_rfc3339(),
                input_cid: wa_receipt.body_cid.as_str().to_string(),
                output_cid: Some(tr_receipt.body_cid.as_str().to_string()),
                fuel_used,
                policy_trace: vec![],
                vm_sig: tr_receipt
                    .body
                    .get("vm_sig")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                vm_sig_payload_cid: tr_receipt
                    .body
                    .get("vm_sig_payload_cid")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                auth_token: String::new(),
                duration_ms: tr_ms,
            })
            .map_err(|e| PipelineError::Internal(format!("Receipt TR: {}", e)))?;

        // Publish TR event
        if let Err(e) = self
            .event_bus
            .publish_stage_event(crate::event_bus::ReceiptEvent::from_stage_receipt(
                tr_receipt.body_cid.as_str(),
                &tr_receipt.receipt_type,
                tr_receipt.body.clone(),
                "tr",
                StageEventContext {
                    decision: None,
                    duration_ms: Some(tr_ms),
                    world: Some(world.to_string()),
                    input_cid: Some(wa_receipt.body_cid.as_str().to_string()),
                    binary_hash: Some(self.runtime_info.binary_hash.clone()),
                    build_meta: serde_json::to_value(&self.runtime_info.build).ok(),
                    actor: Some(self.did.clone()),
                },
            ))
            .await
        {
            warn!(error = %e, "Failed to publish receipt event");
        }

        // Stage 4: WF (Write-Finished)
        let wf_start = std::time::Instant::now();
        let wf_receipt = self
            .stage_write_finished(&parsed_request, &wa_receipt, &tr_receipt, &check)
            .await?;
        let wf_ms = wf_start.elapsed().as_millis() as i64;
        debug!(chip_type = %parsed_request.chip_type, duration_ms = wf_ms, "stage wf completed");

        receipt
            .append_stage(StageExecution {
                stage: PipelineStage::WriteFinished,
                timestamp: chrono::Utc::now().to_rfc3339(),
                input_cid: tr_receipt.body_cid.as_str().to_string(),
                output_cid: Some(wf_receipt.body_cid.as_str().to_string()),
                fuel_used: None,
                policy_trace: vec![],
                vm_sig: None,
                vm_sig_payload_cid: None,
                auth_token: String::new(),
                duration_ms: wf_ms,
            })
            .map_err(|e| PipelineError::Internal(format!("Receipt WF: {}", e)))?;

        let crypto_mode = CryptoMode::from_env();
        receipt
            .finalize_and_sign(&self.signing_key, crypto_mode)
            .map_err(|e| PipelineError::SignError(format!("WF finalize/sign failed: {}", e)))?;
        let unified_receipt_cid = receipt.receipt_cid.as_str().to_string();

        let total_ms = pipeline_start.elapsed().as_millis() as i64;

        // Publish successful WF event
        if let Err(e) = self
            .event_bus
            .publish_stage_event(crate::event_bus::ReceiptEvent::from_stage_receipt(
                wf_receipt.body_cid.as_str(),
                &wf_receipt.receipt_type,
                wf_receipt.body.clone(),
                "wf",
                StageEventContext {
                    decision: Some("allow".to_string()),
                    duration_ms: Some(total_ms),
                    world: Some(world.to_string()),
                    input_cid: Some(tr_receipt.body_cid.as_str().to_string()),
                    binary_hash: Some(self.runtime_info.binary_hash.clone()),
                    build_meta: serde_json::to_value(&self.runtime_info.build).ok(),
                    actor: Some(self.did.clone()),
                },
            ))
            .await
        {
            warn!(error = %e, "Failed to publish receipt event");
        }

        // Persist chip to ChipStore.
        // For `ubl/key.rotate`, mapping persistence is fail-closed.
        if let Some(ref store) = self.chip_store {
            let metadata = ExecutionMetadata {
                runtime_version: "rb_vm/0.1".to_string(),
                execution_time_ms: total_ms,
                fuel_consumed: self.fuel_limit,
                policies_applied: check.trace.iter().map(|t| t.policy_id.clone()).collect(),
                executor_did: ubl_types::Did::new_unchecked(&self.did),
                reproducible: true,
            };
            let stored_chip_res = store
                .store_executed_chip(
                    parsed_request.body().clone(),
                    unified_receipt_cid.clone(),
                    metadata,
                )
                .await;

            if parsed_request.chip_type == "ubl/key.rotate" {
                let rotation_chip_cid = stored_chip_res
                    .map_err(|e| PipelineError::StorageError(format!("key.rotate store: {}", e)))?;

                let rotate_req = KeyRotateRequest::parse(parsed_request.body())
                    .map_err(|e| PipelineError::InvalidChip(format!("Key rotation: {}", e)))?;
                let signing_seed = self.signing_key.to_bytes();
                let material =
                    derive_material(&rotate_req, parsed_request.body(), &signing_seed)
                        .map_err(|e| PipelineError::Internal(format!("Key rotation: {}", e)))?;

                let mapping = mapping_chip(
                    world,
                    &rotation_chip_cid,
                    &unified_receipt_cid,
                    rotate_req.reason.as_deref(),
                    &material,
                );
                let mapping_meta = ExecutionMetadata {
                    runtime_version: "key_rotation/0.1".to_string(),
                    execution_time_ms: total_ms,
                    fuel_consumed: self.fuel_limit,
                    policies_applied: check.trace.iter().map(|t| t.policy_id.clone()).collect(),
                    executor_did: ubl_types::Did::new_unchecked(&self.did),
                    reproducible: true,
                };
                store
                    .store_executed_chip(mapping, unified_receipt_cid.clone(), mapping_meta)
                    .await
                    .map_err(|e| {
                        PipelineError::StorageError(format!("key.rotate mapping store: {}", e))
                    })?;
            } else if let Err(e) = stored_chip_res {
                warn!(error = %e, "ChipStore persist failed (non-fatal)");
            }
        } else if parsed_request.chip_type == "ubl/key.rotate" {
            return Err(PipelineError::StorageError(
                "ubl/key.rotate requires ChipStore persistence".to_string(),
            ));
        }

        // Append to audit ledger (best-effort — never blocks pipeline)
        {
            let (app, tenant) = ubl_ai_nrf1::UblEnvelope::parse_world(world)
                .map(|(a, t)| (a.to_string(), t.to_string()))
                .unwrap_or_else(|| ("unknown".to_string(), "unknown".to_string()));
            let entry = crate::ledger::LedgerEntry {
                ts: chrono::Utc::now().to_rfc3339(),
                event: crate::ledger::LedgerEvent::ReceiptCreated,
                app,
                tenant,
                chip_cid: wf_receipt.body_cid.as_str().to_string(),
                receipt_cid: unified_receipt_cid.clone(),
                decision: "Allow".to_string(),
                did: Some(self.did.clone()),
                kid: Some(self.kid.clone()),
            };
            if let Err(e) = self.ledger.append(&entry).await {
                warn!(error = %e, "Ledger append failed (non-fatal)");
            }
        }

        // Post-WF advisory hook (non-blocking) — classify and summarize
        if let (Some(ref engine), Some(ref store)) = (&self.advisory_engine, &self.chip_store) {
            let adv = engine.post_wf_advisory(
                wf_receipt.body_cid.as_str(),
                parsed_request.chip_type,
                "allow",
                total_ms,
            );
            let body = engine.advisory_to_chip_body(&adv);
            let store = store.clone();
            tokio::spawn(async move {
                let metadata = ExecutionMetadata {
                    runtime_version: "advisory/post-wf".to_string(),
                    execution_time_ms: 0,
                    fuel_consumed: 0,
                    policies_applied: vec![],
                    executor_did: ubl_types::Did::new_unchecked("did:key:advisory"),
                    reproducible: false,
                };
                if let Err(e) = store
                    .store_executed_chip(body, "self".to_string(), metadata)
                    .await
                {
                    warn!(error = %e, "advisory post-WF store failed (non-fatal)");
                }
            });
        }

        let result = PipelineResult {
            final_receipt: wf_receipt.clone(),
            chain: vec![
                wa_receipt.body_cid.as_str().to_string(),
                tr_receipt.body_cid.as_str().to_string(),
                wf_receipt.body_cid.as_str().to_string(),
            ],
            decision: check.decision,
            receipt,
            replayed: false,
        };

        self.persist_final_result(Some(&idem_key), world, &result)
            .await?;

        info!(
            chip_type = %parsed_request.chip_type,
            world = %parsed_request.world,
            decision = "allow",
            duration_ms = total_ms,
            receipt_cid = %unified_receipt_cid,
            "pipeline completed"
        );

        Ok(result)
    }

    async fn persist_final_result(
        &self,
        idem_key: Option<&IdempotencyKey>,
        world: &str,
        result: &PipelineResult,
    ) -> Result<(), PipelineError> {
        if let Some(ref durable) = self.durable_store {
            let receipt_json = result
                .receipt
                .to_json()
                .map_err(|e| PipelineError::DurableCommitFailed(e.to_string()))?;
            let rt_hash = result
                .receipt
                .rt
                .as_ref()
                .map(|rt| rt.binary_hash.clone())
                .unwrap_or_else(|| self.runtime_info.binary_hash.clone());
            let created_at = chrono::Utc::now().timestamp();
            let event = NewOutboxEvent {
                event_type: "emit_receipt".to_string(),
                payload_json: serde_json::json!({
                    "receipt_cid": result.receipt.receipt_cid.as_str(),
                    "decision": decision_to_wire(&result.decision),
                    "world": world,
                }),
            };

            let input = CommitInput {
                receipt_cid: result.receipt.receipt_cid.as_str().to_string(),
                receipt_json,
                did: self.did.clone(),
                kid: self.kid.clone(),
                rt_hash,
                decision: decision_to_wire(&result.decision).to_string(),
                idem_key: idem_key.map(|k| k.to_durable_key()),
                chain: result.chain.clone(),
                outbox_events: vec![event],
                created_at,
                fail_after_receipt_write: false,
            };

            match durable.commit_wf_atomically(&input) {
                Ok(_) => Ok(()),
                Err(DurableError::IdempotencyConflict(e)) => {
                    Err(PipelineError::IdempotencyConflict(e))
                }
                Err(e) => Err(PipelineError::DurableCommitFailed(e.to_string())),
            }
        } else {
            if let Some(key) = idem_key.cloned() {
                self.idempotency_store
                    .put(
                        key,
                        CachedResult {
                            receipt_cid: result.receipt.receipt_cid.as_str().to_string(),
                            response_json: result.receipt.to_json().unwrap_or_default(),
                            decision: decision_to_wire(&result.decision).to_string(),
                            chain: result.chain.clone(),
                            created_at: chrono::Utc::now().to_rfc3339(),
                        },
                    )
                    .await;
            }
            Ok(())
        }
    }
}
