use super::super::*;
use crate::wasm_adapter::{SandboxConfig, WasmError, WasmExecutor, WasmInput, WasmtimeExecutor};
use base64::Engine as _;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone)]
struct AdapterExecutionOutcome {
    output_cid: String,
    fuel_used: u64,
    effects: Vec<String>,
    module_source: String,
}

#[derive(Debug, Clone)]
struct AuditReportOutcome {
    dataset_cid: String,
    line_count: usize,
    format: String,
    artifact_payload_cid: String,
    type_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Clone)]
struct AuditSnapshotOutcome {
    dataset_cid: String,
    histograms_cid: String,
    sketches_cid: String,
    manifest_cid: String,
    line_count: usize,
    covered_segments: usize,
}

#[derive(Debug, Clone)]
struct LedgerCompactOutcome {
    parent_snapshot_ref: String,
    rollup_index_cid: String,
    tombstones: bool,
    freed_bytes: u64,
    archived_files: usize,
    deleted_files: usize,
}

#[derive(Debug, Clone)]
struct AuditAdvisoryOutcome {
    parent_receipt_cid: String,
    advisory_markdown_cid: String,
    advisory_json_cid: String,
    input_count: usize,
}

#[derive(Debug, Clone)]
enum AuditTransitionOutcome {
    Report(AuditReportOutcome),
    Snapshot(AuditSnapshotOutcome),
    Compact(LedgerCompactOutcome),
    Advisory(AuditAdvisoryOutcome),
}

#[derive(Debug, Clone)]
struct SiliconCompileOutcome {
    chip_cid: String,
    target: String,
    circuit_count: usize,
    bit_count: usize,
    bytecode_len: usize,
    bytecode_cid: String,
}

impl UblPipeline {
    /// Stage 3: TR - Transition (RB-VM execution)
    pub(in crate::pipeline) async fn stage_transition(
        &self,
        request: &ParsedChipRequest<'_>,
        check: &CheckResult,
    ) -> Result<PipelineReceipt, PipelineError> {
        // Encode chip body to NRF bytes and store as CAS input
        let chip_nrf = ubl_ai_nrf1::to_nrf1_bytes(request.body())
            .map_err(|e| PipelineError::Internal(format!("TR input NRF: {}", e)))?;

        let mut cas = PipelineCas::new();
        let input_cid = cas.put(&chip_nrf);
        let input_cid_str = input_cid.0.clone();

        let signer = PipelineSigner {
            signing_key: self.signing_key.clone(),
            kid: self.kid.clone(),
        };
        let canon = PipelineCanon;
        let cfg = VmConfig {
            fuel_limit: self.fuel_limit,
            ghost: false,
            trace: true,
        };

        let adapter_info = AdapterRuntimeInfo::parse_optional(request.body())?;
        let adapter_outcome = if let Some(info) = adapter_info.as_ref() {
            Some(
                self.execute_wasm_adapter(info, &chip_nrf, &input_cid_str)
                    .await?,
            )
        } else {
            None
        };

        // Resolve bytecode by chip type / chip override / env override.
        let resolution = self
            .transition_registry
            .resolve(request.chip_type, request.body())
            .map_err(|e| PipelineError::InvalidChip(format!("TR bytecode resolution: {}", e)))?;
        let bytecode_hash = format!(
            "b3:{}",
            hex::encode(blake3::hash(&resolution.bytecode).as_bytes())
        );
        let instructions = tlv::decode_stream(&resolution.bytecode)
            .map_err(|e| PipelineError::Internal(format!("TR bytecode decode: {}", e)))?;

        // Execute VM
        let mut vm = Vm::new(cfg, cas, &signer, canon, vec![input_cid.clone()])
            .with_body_size(chip_nrf.len());
        let outcome = vm.run(&instructions).map_err(|e| match e {
            ExecError::FuelExhausted => PipelineError::FuelExhausted(format!(
                "VM fuel exhausted (limit: {})",
                self.fuel_limit
            )),
            ExecError::StackUnderflow(op) => {
                PipelineError::StackUnderflow(format!("stack underflow at {:?}", op))
            }
            ExecError::TypeMismatch(op) => {
                PipelineError::TypeMismatch(format!("type mismatch at {:?}", op))
            }
            ExecError::InvalidPayload(op) => {
                PipelineError::TypeMismatch(format!("invalid payload for {:?}", op))
            }
            ExecError::Deny(reason) => PipelineError::PolicyDenied(reason),
        })?;

        if outcome.rc_sig.as_deref().unwrap_or("").is_empty() {
            return Err(PipelineError::SignError(
                "TR EmitRc did not return a persisted signature".to_string(),
            ));
        }

        let audit_transition = match request.chip_type {
            crate::audit_chip::TYPE_AUDIT_REPORT_REQUEST_V1 => {
                Some(AuditTransitionOutcome::Report(
                    self.execute_audit_report_transition(
                        request,
                        &input_cid_str,
                        outcome.fuel_used,
                        &check.trace,
                    )
                    .await?,
                ))
            }
            crate::audit_chip::TYPE_AUDIT_LEDGER_SNAPSHOT_REQUEST_V1 => {
                Some(AuditTransitionOutcome::Snapshot(
                    self.execute_audit_snapshot_transition(
                        request,
                        &input_cid_str,
                        outcome.fuel_used,
                        &check.trace,
                    )
                    .await?,
                ))
            }
            crate::audit_chip::TYPE_LEDGER_SEGMENT_COMPACT_V1 => {
                Some(AuditTransitionOutcome::Compact(
                    self.execute_ledger_compact_transition(
                        request,
                        &input_cid_str,
                        outcome.fuel_used,
                        &check.trace,
                    )
                    .await?,
                ))
            }
            crate::audit_chip::TYPE_AUDIT_ADVISORY_REQUEST_V1 => {
                Some(AuditTransitionOutcome::Advisory(
                    self.execute_audit_advisory_transition(
                        request,
                        &input_cid_str,
                        outcome.fuel_used,
                        &check.trace,
                    )
                    .await?,
                ))
            }
            _ => None,
        };

        let key_rotation = if request.chip_type == "ubl/key.rotate" {
            let rotate_req = KeyRotateRequest::parse(request.body())
                .map_err(|e| PipelineError::InvalidChip(format!("Key rotation: {}", e)))?;
            let signing_seed = self.signing_key.to_bytes();
            Some(
                derive_material(&rotate_req, request.body(), &signing_seed)
                    .map_err(|e| PipelineError::Internal(format!("Key rotation: {}", e)))?,
            )
        } else {
            None
        };

        let silicon_compile = if request.chip_type == crate::silicon_chip::TYPE_SILICON_COMPILE {
            Some(
                self.execute_silicon_compile_transition(
                    request,
                    &input_cid_str,
                    outcome.fuel_used,
                    &check.trace,
                )
                .await?,
            )
        } else {
            None
        };

        let mut vm_state = serde_json::Map::new();
        vm_state.insert(
            "fuel_used".to_string(),
            serde_json::json!(outcome.fuel_used),
        );
        vm_state.insert("steps".to_string(), serde_json::json!(outcome.steps));
        vm_state.insert(
            "result".to_string(),
            serde_json::json!(if outcome.rc_cid.is_some() {
                "receipt_emitted"
            } else {
                "completed"
            }),
        );
        vm_state.insert(
            "trace_len".to_string(),
            serde_json::json!(outcome.trace.len()),
        );
        vm_state.insert(
            "bytecode_source".to_string(),
            serde_json::json!(resolution.source),
        );
        vm_state.insert(
            "bytecode_hash".to_string(),
            serde_json::json!(bytecode_hash),
        );
        vm_state.insert(
            "bytecode_len".to_string(),
            serde_json::json!(resolution.bytecode.len()),
        );
        vm_state.insert(
            "bytecode_profile".to_string(),
            serde_json::json!(resolution.profile.as_str()),
        );
        if let Some(info) = adapter_info.as_ref() {
            vm_state.insert(
                "adapter_wasm_sha256".to_string(),
                serde_json::json!(info.wasm_sha256),
            );
            vm_state.insert(
                "adapter_abi_version".to_string(),
                serde_json::json!(info.abi_version),
            );
            if let Some(cid) = info.wasm_cid.as_ref() {
                vm_state.insert("adapter_wasm_cid".to_string(), serde_json::json!(cid));
            }
        }
        if let Some(adapter) = adapter_outcome.as_ref() {
            vm_state.insert("adapter_executed".to_string(), serde_json::json!(true));
            vm_state.insert(
                "adapter_module_source".to_string(),
                serde_json::json!(adapter.module_source),
            );
            vm_state.insert(
                "adapter_output_cid".to_string(),
                serde_json::json!(adapter.output_cid),
            );
            vm_state.insert(
                "adapter_fuel_used".to_string(),
                serde_json::json!(adapter.fuel_used),
            );
            vm_state.insert(
                "adapter_effects".to_string(),
                serde_json::json!(adapter.effects),
            );
        }
        if let Some(audit) = audit_transition.as_ref() {
            match audit {
                AuditTransitionOutcome::Report(report) => {
                    vm_state.insert(
                        "audit_report_generated".to_string(),
                        serde_json::json!(true),
                    );
                    vm_state.insert(
                        "audit_report_dataset_cid".to_string(),
                        serde_json::json!(report.dataset_cid),
                    );
                    vm_state.insert(
                        "audit_report_line_count".to_string(),
                        serde_json::json!(report.line_count),
                    );
                }
                AuditTransitionOutcome::Snapshot(snapshot) => {
                    vm_state.insert(
                        "audit_snapshot_generated".to_string(),
                        serde_json::json!(true),
                    );
                    vm_state.insert(
                        "audit_snapshot_manifest_cid".to_string(),
                        serde_json::json!(snapshot.manifest_cid),
                    );
                    vm_state.insert(
                        "audit_snapshot_line_count".to_string(),
                        serde_json::json!(snapshot.line_count),
                    );
                }
                AuditTransitionOutcome::Compact(compact) => {
                    vm_state.insert(
                        "ledger_compact_generated".to_string(),
                        serde_json::json!(true),
                    );
                    vm_state.insert(
                        "ledger_compact_rollup_cid".to_string(),
                        serde_json::json!(compact.rollup_index_cid),
                    );
                    vm_state.insert(
                        "ledger_compact_freed_bytes".to_string(),
                        serde_json::json!(compact.freed_bytes),
                    );
                    vm_state.insert(
                        "ledger_compact_archived_files".to_string(),
                        serde_json::json!(compact.archived_files),
                    );
                    vm_state.insert(
                        "ledger_compact_deleted_files".to_string(),
                        serde_json::json!(compact.deleted_files),
                    );
                }
                AuditTransitionOutcome::Advisory(advisory) => {
                    vm_state.insert(
                        "audit_advisory_generated".to_string(),
                        serde_json::json!(true),
                    );
                    vm_state.insert(
                        "audit_advisory_json_cid".to_string(),
                        serde_json::json!(advisory.advisory_json_cid),
                    );
                    vm_state.insert(
                        "audit_advisory_input_count".to_string(),
                        serde_json::json!(advisory.input_count),
                    );
                }
            }
        }

        let tr_body = serde_json::json!({
            "@type": "ubl/transition",
            "input_cid": input_cid_str,
            "output_cid": outcome.rc_cid.as_ref().map(|c| c.0.clone()).unwrap_or_default(),
            "vm_sig": outcome.rc_sig.as_deref().unwrap_or_default(),
            "vm_sig_payload_cid": outcome.rc_payload_cid.as_ref().map(|c| c.0.clone()).unwrap_or_default(),
            "vm_state": vm_state
        });
        let mut tr_body = tr_body;
        if let Some(audit) = audit_transition {
            match audit {
                AuditTransitionOutcome::Report(report) => {
                    tr_body["artifacts"] = serde_json::json!({
                        "dataset": report.dataset_cid,
                    });
                    tr_body["audit_report"] = serde_json::json!({
                        "dataset_cid": report.dataset_cid,
                        "line_count": report.line_count,
                        "format": report.format,
                        "type_counts": report.type_counts,
                        "artifact_payload_cid": report.artifact_payload_cid,
                    });
                }
                AuditTransitionOutcome::Snapshot(snapshot) => {
                    tr_body["artifacts"] = serde_json::json!({
                        "dataset": snapshot.dataset_cid,
                        "histograms": snapshot.histograms_cid,
                        "sketches": snapshot.sketches_cid,
                        "manifest": snapshot.manifest_cid,
                    });
                    tr_body["audit_snapshot"] = serde_json::json!({
                        "dataset_cid": snapshot.dataset_cid,
                        "histograms_cid": snapshot.histograms_cid,
                        "sketches_cid": snapshot.sketches_cid,
                        "manifest_cid": snapshot.manifest_cid,
                        "line_count": snapshot.line_count,
                        "covered_segments": snapshot.covered_segments,
                    });
                }
                AuditTransitionOutcome::Compact(compact) => {
                    tr_body["artifacts"] = serde_json::json!({
                        "rollup_index": compact.rollup_index_cid,
                    });
                    tr_body["ledger_compact"] = serde_json::json!({
                        "parent_snapshot_ref": compact.parent_snapshot_ref,
                        "rollup_index_cid": compact.rollup_index_cid,
                        "tombstones": compact.tombstones,
                        "freed_bytes": compact.freed_bytes,
                        "archived_files": compact.archived_files,
                        "deleted_files": compact.deleted_files,
                    });
                }
                AuditTransitionOutcome::Advisory(advisory) => {
                    tr_body["artifacts"] = serde_json::json!({
                        "advisory_markdown": advisory.advisory_markdown_cid,
                        "advisory_json": advisory.advisory_json_cid,
                    });
                    tr_body["audit_advisory"] = serde_json::json!({
                        "parent_receipt_cid": advisory.parent_receipt_cid,
                        "advisory_markdown_cid": advisory.advisory_markdown_cid,
                        "advisory_json_cid": advisory.advisory_json_cid,
                        "input_count": advisory.input_count,
                    });
                }
            }
        }
        if let Some(rotation) = key_rotation {
            tr_body["key_rotation"] = serde_json::json!({
                "old_did": rotation.old_did,
                "old_kid": rotation.old_kid,
                "new_did": rotation.new_did,
                "new_kid": rotation.new_kid,
                "new_key_cid": rotation.new_key_cid,
            });
        }
        if let Some(ref compile) = silicon_compile {
            tr_body["artifacts"] = serde_json::json!({
                "bytecode": compile.bytecode_cid,
            });
            tr_body["silicon_compile"] = serde_json::json!({
                "chip_cid": compile.chip_cid,
                "target": compile.target,
                "circuit_count": compile.circuit_count,
                "bit_count": compile.bit_count,
                "bytecode_len": compile.bytecode_len,
                "bytecode_cid": compile.bytecode_cid,
            });
        }

        let nrf1_bytes = ubl_ai_nrf1::to_nrf1_bytes(&tr_body)
            .map_err(|e| PipelineError::Internal(format!("TR CID: {}", e)))?;
        let cid = ubl_ai_nrf1::compute_cid(&nrf1_bytes)
            .map_err(|e| PipelineError::Internal(format!("TR CID: {}", e)))?;

        Ok(PipelineReceipt {
            body_cid: ubl_types::Cid::new_unchecked(&cid),
            receipt_type: "ubl/transition".to_string(),
            body: tr_body,
        })
    }

    async fn execute_wasm_adapter(
        &self,
        adapter_info: &AdapterRuntimeInfo,
        chip_nrf: &[u8],
        input_cid: &str,
    ) -> Result<AdapterExecutionOutcome, PipelineError> {
        let (module_bytes, module_source) = self.resolve_adapter_module_bytes(adapter_info).await?;
        let actual_sha256 = Self::sha256_hex(&module_bytes);
        if !actual_sha256.eq_ignore_ascii_case(&adapter_info.wasm_sha256) {
            return Err(PipelineError::InvalidChip(format!(
                "adapter.wasm_sha256 mismatch: expected {}, got {}",
                adapter_info.wasm_sha256, actual_sha256
            )));
        }

        let fuel_limit = adapter_info
            .fuel_budget
            .unwrap_or(self.fuel_limit)
            .min(self.fuel_limit);
        let input = WasmInput {
            nrf1_bytes: chip_nrf.to_vec(),
            chip_cid: input_cid.to_string(),
            frozen_timestamp: chrono::Utc::now().to_rfc3339(),
            fuel_limit,
        };
        let sandbox = SandboxConfig {
            fuel_limit,
            ..Default::default()
        };
        let exec = WasmtimeExecutor;
        let out = exec
            .execute(&module_bytes, &input, &sandbox)
            .map_err(Self::map_wasm_error)?;

        Ok(AdapterExecutionOutcome {
            output_cid: out.output_cid,
            fuel_used: out.fuel_consumed,
            effects: out.effects,
            module_source,
        })
    }

    async fn resolve_adapter_module_bytes(
        &self,
        adapter_info: &AdapterRuntimeInfo,
    ) -> Result<(Vec<u8>, String), PipelineError> {
        if let Some(inline_b64) = adapter_info.wasm_b64.as_deref() {
            let bytes = Self::decode_base64_bytes(inline_b64)?;
            return Ok((bytes, "inline:adapter.wasm_b64".to_string()));
        }

        let wasm_cid = adapter_info.wasm_cid.as_deref().ok_or_else(|| {
            PipelineError::InvalidChip(
                "adapter requires one of adapter.wasm_b64 or adapter.wasm_cid".to_string(),
            )
        })?;

        let store = self.chip_store.as_ref().ok_or_else(|| {
            PipelineError::StorageError("adapter.wasm_cid requires ChipStore".to_string())
        })?;
        let stored = store
            .get_chip(wasm_cid)
            .await
            .map_err(|e| PipelineError::StorageError(format!("WASM module lookup: {}", e)))?
            .ok_or_else(|| {
                PipelineError::InvalidChip(format!("adapter.wasm_cid not found: {}", wasm_cid))
            })?;
        let bytes = Self::extract_module_bytes(&stored.chip_data)?;
        Ok((bytes, format!("chipstore:{}", wasm_cid)))
    }

    fn extract_module_bytes(chip_data: &serde_json::Value) -> Result<Vec<u8>, PipelineError> {
        fn from_obj(obj: &serde_json::Map<String, serde_json::Value>) -> Option<&str> {
            [
                "wasm_b64",
                "module_b64",
                "wasm_base64",
                "module_base64",
                "bytes_b64",
            ]
            .iter()
            .find_map(|key| obj.get(*key).and_then(|v| v.as_str()))
        }

        fn from_obj_hex(obj: &serde_json::Map<String, serde_json::Value>) -> Option<&str> {
            ["wasm_hex", "module_hex"]
                .iter()
                .find_map(|key| obj.get(*key).and_then(|v| v.as_str()))
        }

        let mut sources: Vec<&serde_json::Map<String, serde_json::Value>> = Vec::new();
        if let Some(obj) = chip_data.as_object() {
            sources.push(obj);
            if let Some(body) = obj.get("body").and_then(|v| v.as_object()) {
                sources.push(body);
            }
        }

        for source in sources {
            if let Some(raw) = from_obj(source) {
                return Self::decode_base64_bytes(raw);
            }
            if let Some(raw_hex) = from_obj_hex(source) {
                let bytes = hex::decode(raw_hex).map_err(|e| {
                    PipelineError::InvalidChip(format!("invalid adapter module hex bytes: {}", e))
                })?;
                if bytes.is_empty() {
                    return Err(PipelineError::InvalidChip(
                        "adapter module bytes cannot be empty".to_string(),
                    ));
                }
                return Ok(bytes);
            }
        }

        Err(PipelineError::InvalidChip(
            "wasm module chip missing bytes field (expected wasm_b64/module_b64/wasm_hex)"
                .to_string(),
        ))
    }

    fn decode_base64_bytes(raw: &str) -> Result<Vec<u8>, PipelineError> {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(raw)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(raw))
            .map_err(|e| {
                PipelineError::InvalidChip(format!("invalid adapter module base64: {}", e))
            })?;
        if decoded.is_empty() {
            return Err(PipelineError::InvalidChip(
                "adapter module bytes cannot be empty".to_string(),
            ));
        }
        Ok(decoded)
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use ring::digest;
        let hash = digest::digest(&digest::SHA256, bytes);
        hex::encode(hash.as_ref())
    }

    fn map_wasm_error(error: WasmError) -> PipelineError {
        match error {
            WasmError::FuelExhausted { limit, consumed } => PipelineError::FuelExhausted(format!(
                "WASM fuel exhausted (limit: {}, consumed: {})",
                limit, consumed
            )),
            WasmError::MemoryExceeded { limit } => {
                PipelineError::FuelExhausted(format!("WASM memory exceeded (limit: {})", limit))
            }
            other => {
                PipelineError::InvalidChip(format!("WASM adapter execution failed: {}", other))
            }
        }
    }

    async fn execute_audit_report_transition(
        &self,
        request: &ParsedChipRequest<'_>,
        input_cid: &str,
        fuel_used: u64,
        policy_trace: &[PolicyTraceEntry],
    ) -> Result<AuditReportOutcome, PipelineError> {
        let parsed = crate::audit_chip::parse_request(request.chip_type, request.body())
            .map_err(|e| PipelineError::InvalidChip(format!("audit/report parse: {}", e)))?;
        let report = match parsed {
            crate::audit_chip::AuditRequest::Report(report) => report,
            _ => {
                return Err(PipelineError::InvalidChip(
                    "audit/report transition received non-report request".to_string(),
                ));
            }
        };

        let store = self.chip_store.as_ref().ok_or_else(|| {
            PipelineError::StorageError("audit/report.request.v1 requires ChipStore".to_string())
        })?;

        let limit = request
            .body()
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(1_000)
            .clamp(1, 10_000) as usize;

        let query = ubl_chipstore::ChipQuery {
            chip_type: None,
            tags: vec![format!("world:{}", request.world)],
            created_after: None,
            created_before: None,
            executor_did: None,
            limit: Some(limit),
            offset: None,
        };
        let result = store
            .query(&query)
            .await
            .map_err(|e| PipelineError::StorageError(format!("audit/report query: {}", e)))?;

        let report_range = report.range.as_ref().map(|r| (r.start, r.end));
        let mut rows: Vec<serde_json::Value> = result
            .chips
            .iter()
            .filter(|chip| {
                if let Some((start, end)) = report_range {
                    let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&chip.created_at) else {
                        return false;
                    };
                    let ts = ts.with_timezone(&chrono::Utc);
                    ts >= start && ts <= end
                } else {
                    true
                }
            })
            .map(|chip| {
                serde_json::json!({
                    "cid": chip.cid.as_str(),
                    "receipt_cid": chip.receipt_cid.as_str(),
                    "chip_type": chip.chip_type,
                    "created_at": chip.created_at,
                })
            })
            .collect();

        rows.sort_by(|a, b| {
            let a_cid = a.get("cid").and_then(|v| v.as_str()).unwrap_or("");
            let b_cid = b.get("cid").and_then(|v| v.as_str()).unwrap_or("");
            a_cid.cmp(b_cid)
        });

        let mut type_counts: BTreeMap<String, usize> = BTreeMap::new();
        for row in &rows {
            if let Some(chip_type) = row.get("chip_type").and_then(|v| v.as_str()) {
                *type_counts.entry(chip_type.to_string()).or_insert(0) += 1;
            }
        }

        let output_format = report.format.unwrap_or_else(|| "ndjson".to_string());
        let mut ndjson_lines = Vec::with_capacity(rows.len());
        for row in &rows {
            let line = serde_json::to_string(row)
                .map_err(|e| PipelineError::Internal(format!("audit/report ndjson: {}", e)))?;
            ndjson_lines.push(line);
        }
        let ndjson = ndjson_lines.join("\n");
        let ndjson_hash = format!(
            "b3:{}",
            hex::encode(blake3::hash(ndjson.as_bytes()).as_bytes())
        );

        let artifact_payload = serde_json::json!({
            "@type": "ubl/audit.dataset.v1",
            "@id": format!(
                "{}:dataset",
                request.chip_id.unwrap_or(input_cid.trim_start_matches("b3:"))
            ),
            "@ver": "1.0.0",
            "@world": request.world,
            "request_type": request.chip_type,
            "request_id": request.chip_id,
            "input_cid": input_cid,
            "format": output_format,
            "window": report.window,
            "range": report_range.map(|(start, end)| serde_json::json!({
                "start": start.to_rfc3339(),
                "end": end.to_rfc3339()
            })),
            "line_count": rows.len(),
            "type_counts": type_counts,
            "dataset_ndjson_b3": ndjson_hash,
            "rows": rows,
            "fuel_used_at_tr": fuel_used,
            "policy_trace_len": policy_trace.len(),
        });
        let artifact_cid = ubl_ai_nrf1::compute_cid(
            &ubl_ai_nrf1::to_nrf1_bytes(&artifact_payload)
                .map_err(|e| PipelineError::Internal(format!("audit/report NRF: {}", e)))?,
        )
        .map_err(|e| PipelineError::Internal(format!("audit/report CID: {}", e)))?;

        let metadata = ubl_chipstore::ExecutionMetadata {
            runtime_version: "audit/report-tr/0.1".to_string(),
            execution_time_ms: 0,
            fuel_consumed: fuel_used,
            policies_applied: policy_trace.iter().map(|p| p.policy_id.clone()).collect(),
            executor_did: ubl_types::Did::new_unchecked(&self.did),
            reproducible: true,
        };
        let stored_artifact_cid = store
            .store_executed_chip(artifact_payload.clone(), "self".to_string(), metadata)
            .await
            .map_err(|e| {
                PipelineError::StorageError(format!("audit/report artifact store: {}", e))
            })?;
        if stored_artifact_cid != artifact_cid {
            return Err(PipelineError::Internal(format!(
                "audit/report artifact CID mismatch: expected {}, got {}",
                artifact_cid, stored_artifact_cid
            )));
        }

        Ok(AuditReportOutcome {
            dataset_cid: artifact_cid,
            line_count: ndjson_lines.len(),
            format: output_format,
            artifact_payload_cid: stored_artifact_cid,
            type_counts,
        })
    }

    async fn execute_audit_snapshot_transition(
        &self,
        request: &ParsedChipRequest<'_>,
        input_cid: &str,
        fuel_used: u64,
        policy_trace: &[PolicyTraceEntry],
    ) -> Result<AuditSnapshotOutcome, PipelineError> {
        let parsed = crate::audit_chip::parse_request(request.chip_type, request.body())
            .map_err(|e| PipelineError::InvalidChip(format!("audit/snapshot parse: {}", e)))?;
        let snapshot = match parsed {
            crate::audit_chip::AuditRequest::Snapshot(snapshot) => snapshot,
            _ => {
                return Err(PipelineError::InvalidChip(
                    "audit/snapshot transition received non-snapshot request".to_string(),
                ));
            }
        };
        let store = self.chip_store.as_ref().ok_or_else(|| {
            PipelineError::StorageError(
                "audit/ledger.snapshot.request.v1 requires ChipStore".into(),
            )
        })?;

        let limit = request
            .body()
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(5_000)
            .clamp(1, 20_000) as usize;

        let query = ubl_chipstore::ChipQuery {
            chip_type: None,
            tags: vec![format!("world:{}", request.world)],
            created_after: None,
            created_before: None,
            executor_did: None,
            limit: Some(limit),
            offset: None,
        };
        let result = store
            .query(&query)
            .await
            .map_err(|e| PipelineError::StorageError(format!("audit/snapshot query: {}", e)))?;

        let mut chips_in_range: Vec<&ubl_chipstore::StoredChip> = result
            .chips
            .iter()
            .filter(|chip| {
                let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&chip.created_at) else {
                    return false;
                };
                let ts = ts.with_timezone(&chrono::Utc);
                ts >= snapshot.range.start && ts <= snapshot.range.end
            })
            .collect();
        chips_in_range.sort_by(|a, b| a.cid.as_str().cmp(b.cid.as_str()));

        let rows: Vec<serde_json::Value> = chips_in_range
            .iter()
            .map(|chip| {
                serde_json::json!({
                    "cid": chip.cid.as_str(),
                    "receipt_cid": chip.receipt_cid.as_str(),
                    "chip_type": chip.chip_type,
                    "created_at": chip.created_at,
                })
            })
            .collect();

        let mut latencies: Vec<i64> = chips_in_range
            .iter()
            .map(|chip| chip.execution_metadata.execution_time_ms)
            .collect();
        latencies.sort_unstable();
        let p50 = Self::percentile_i64(&latencies, 0.50);
        let p95 = Self::percentile_i64(&latencies, 0.95);
        let p99 = Self::percentile_i64(&latencies, 0.99);

        let mut distinct_types = BTreeMap::<String, usize>::new();
        for chip in &chips_in_range {
            *distinct_types.entry(chip.chip_type.clone()).or_insert(0) += 1;
        }

        let dataset_payload = serde_json::json!({
            "@type": "ubl/audit.snapshot.dataset.v1",
            "@id": format!("{}:snapshot-dataset", request.chip_id.unwrap_or(input_cid.trim_start_matches("b3:"))),
            "@ver": "1.0.0",
            "@world": request.world,
            "input_cid": input_cid,
            "range": {
                "start": snapshot.range.start.to_rfc3339(),
                "end": snapshot.range.end.to_rfc3339()
            },
            "line_count": rows.len(),
            "rows": rows,
        });
        let dataset_cid = self
            .store_audit_artifact(
                store,
                dataset_payload,
                fuel_used,
                policy_trace,
                "audit/snapshot-dataset-tr/0.1",
            )
            .await?;

        let histograms_payload = serde_json::json!({
            "@type": "ubl/audit.snapshot.histograms.v1",
            "@id": format!("{}:snapshot-histograms", request.chip_id.unwrap_or(input_cid.trim_start_matches("b3:"))),
            "@ver": "1.0.0",
            "@world": request.world,
            "input_cid": input_cid,
            "count": latencies.len(),
            "latency_ms": {
                "p50": p50,
                "p95": p95,
                "p99": p99,
                "min": latencies.first().copied().unwrap_or(0),
                "max": latencies.last().copied().unwrap_or(0)
            }
        });
        let histograms_cid = self
            .store_audit_artifact(
                store,
                histograms_payload,
                fuel_used,
                policy_trace,
                "audit/snapshot-histograms-tr/0.1",
            )
            .await?;

        let sketches_payload = serde_json::json!({
            "@type": "ubl/audit.snapshot.sketches.v1",
            "@id": format!("{}:snapshot-sketches", request.chip_id.unwrap_or(input_cid.trim_start_matches("b3:"))),
            "@ver": "1.0.0",
            "@world": request.world,
            "input_cid": input_cid,
            "cardinality_exact": {
                "chips": chips_in_range.len(),
                "types": distinct_types.len(),
            },
            "type_counts": distinct_types,
        });
        let sketches_cid = self
            .store_audit_artifact(
                store,
                sketches_payload,
                fuel_used,
                policy_trace,
                "audit/snapshot-sketches-tr/0.1",
            )
            .await?;

        let manifest_payload = serde_json::json!({
            "@type": "ubl/audit.snapshot.manifest.v1",
            "@id": format!("{}:snapshot-manifest", request.chip_id.unwrap_or(input_cid.trim_start_matches("b3:"))),
            "@ver": "1.0.0",
            "@world": request.world,
            "input_cid": input_cid,
            "range": {
                "start": snapshot.range.start.to_rfc3339(),
                "end": snapshot.range.end.to_rfc3339()
            },
            "artifacts": {
                "dataset": dataset_cid,
                "histograms": histograms_cid,
                "sketches": sketches_cid,
            },
            "coverage": {
                "segments": chips_in_range.len(),
                "lines": chips_in_range.len(),
                "bytes_estimate": chips_in_range.len() as u64 * 128,
            }
        });
        let manifest_cid = self
            .store_audit_artifact(
                store,
                manifest_payload,
                fuel_used,
                policy_trace,
                "audit/snapshot-manifest-tr/0.1",
            )
            .await?;

        Ok(AuditSnapshotOutcome {
            dataset_cid,
            histograms_cid,
            sketches_cid,
            manifest_cid,
            line_count: chips_in_range.len(),
            covered_segments: chips_in_range.len(),
        })
    }

    async fn execute_ledger_compact_transition(
        &self,
        request: &ParsedChipRequest<'_>,
        input_cid: &str,
        fuel_used: u64,
        policy_trace: &[PolicyTraceEntry],
    ) -> Result<LedgerCompactOutcome, PipelineError> {
        let parsed = crate::audit_chip::parse_request(request.chip_type, request.body())
            .map_err(|e| PipelineError::InvalidChip(format!("ledger/compact parse: {}", e)))?;
        let compact = match parsed {
            crate::audit_chip::AuditRequest::Compact(compact) => compact,
            _ => {
                return Err(PipelineError::InvalidChip(
                    "ledger/compact transition received non-compact request".to_string(),
                ));
            }
        };
        let store = self.chip_store.as_ref().ok_or_else(|| {
            PipelineError::StorageError("ledger/segment.compact.v1 requires ChipStore".to_string())
        })?;

        let snapshot_chip = if let Some(chip) = store
            .get_chip(&compact.snapshot_ref)
            .await
            .map_err(|e| PipelineError::StorageError(format!("compact snapshot lookup: {}", e)))?
        {
            chip
        } else {
            store
                .get_chip_by_receipt_cid(&compact.snapshot_ref)
                .await
                .map_err(|e| {
                    PipelineError::StorageError(format!("compact snapshot receipt lookup: {}", e))
                })?
                .ok_or_else(|| {
                    PipelineError::InvalidChip(format!(
                        "compact snapshot_ref not found: {}",
                        compact.snapshot_ref
                    ))
                })?
        };

        let compact_result =
            Self::execute_filesystem_compaction(&compact.mode, &compact.source_segments)?;
        let rollup_payload = serde_json::json!({
            "@type": "ubl/ledger.compaction.rollup.v1",
            "@id": format!("{}:compact-rollup", request.chip_id.unwrap_or(input_cid.trim_start_matches("b3:"))),
            "@ver": "1.0.0",
            "@world": request.world,
            "input_cid": input_cid,
            "parent_snapshot_ref": compact.snapshot_ref,
            "parent_snapshot_cid": snapshot_chip.cid.as_str(),
            "mode": compact.mode,
            "range": {
                "start": compact.range.start.to_rfc3339(),
                "end": compact.range.end.to_rfc3339(),
            },
            "source_segments": compact.source_segments,
            "tombstones": true,
            "freed_bytes": compact_result.freed_bytes,
            "archived_files": compact_result.archived_files,
            "deleted_files": compact_result.deleted_files,
        });
        let rollup_index_cid = self
            .store_audit_artifact(
                store,
                rollup_payload,
                fuel_used,
                policy_trace,
                "ledger/compact-tr/0.1",
            )
            .await?;

        Ok(LedgerCompactOutcome {
            parent_snapshot_ref: compact.snapshot_ref,
            rollup_index_cid,
            tombstones: true,
            freed_bytes: compact_result.freed_bytes,
            archived_files: compact_result.archived_files,
            deleted_files: compact_result.deleted_files,
        })
    }

    async fn execute_audit_advisory_transition(
        &self,
        request: &ParsedChipRequest<'_>,
        input_cid: &str,
        fuel_used: u64,
        policy_trace: &[PolicyTraceEntry],
    ) -> Result<AuditAdvisoryOutcome, PipelineError> {
        let parsed = crate::audit_chip::parse_request(request.chip_type, request.body())
            .map_err(|e| PipelineError::InvalidChip(format!("audit/advisory parse: {}", e)))?;
        let advisory = match parsed {
            crate::audit_chip::AuditRequest::Advisory(advisory) => advisory,
            _ => {
                return Err(PipelineError::InvalidChip(
                    "audit/advisory transition received non-advisory request".to_string(),
                ));
            }
        };
        let store = self.chip_store.as_ref().ok_or_else(|| {
            PipelineError::StorageError("audit/advisory.request.v1 requires ChipStore".to_string())
        })?;

        let subject = store
            .get_chip_by_receipt_cid(&advisory.subject_receipt_cid)
            .await
            .map_err(|e| PipelineError::StorageError(format!("audit/advisory subject: {}", e)))?
            .ok_or_else(|| {
                PipelineError::InvalidChip(format!(
                    "subject receipt not found: {}",
                    advisory.subject_receipt_cid
                ))
            })?;

        let inputs = request
            .body()
            .get("inputs")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        let input_count = inputs.len();

        let mut findings = Vec::new();
        findings.push(serde_json::json!({
            "severity": if input_count == 0 { "warn" } else { "info" },
            "code": "advisory.inputs.count",
            "message": format!("{} aggregate input(s) provided", input_count),
        }));
        findings.push(serde_json::json!({
            "severity": "info",
            "code": "advisory.subject.type",
            "message": format!("subject type {}", subject.chip_type),
        }));

        let policy_cid = request
            .body()
            .get("policy_cid")
            .and_then(|v| v.as_str())
            .unwrap_or("b3:policy-missing");
        let style = request
            .body()
            .get("style")
            .and_then(|v| v.as_str())
            .unwrap_or("concise");
        let lang = request
            .body()
            .get("lang")
            .and_then(|v| v.as_str())
            .unwrap_or("en");

        let advisory_json_payload = serde_json::json!({
            "@type": "ubl/audit.advisory.result.v1",
            "@id": format!("{}:advisory-json", request.chip_id.unwrap_or(input_cid.trim_start_matches("b3:"))),
            "@ver": "1.0.0",
            "@world": request.world,
            "input_cid": input_cid,
            "subject": {
                "kind": advisory.subject_kind,
                "receipt_cid": advisory.subject_receipt_cid,
                "chip_type": subject.chip_type,
            },
            "policy_cid": policy_cid,
            "style": style,
            "lang": lang,
            "inputs": inputs,
            "findings": findings,
        });
        let advisory_json_cid = self
            .store_audit_artifact(
                store,
                advisory_json_payload.clone(),
                fuel_used,
                policy_trace,
                "audit/advisory-json-tr/0.1",
            )
            .await?;

        let markdown_lines = vec![
            "# Advisory".to_string(),
            format!(
                "- Subject: `{}` (`{}`)",
                advisory.subject_receipt_cid, subject.chip_type
            ),
            format!("- Inputs: `{}`", input_count),
            format!("- Policy: `{}`", policy_cid),
            format!("- Style: `{}`", style),
            format!("- Lang: `{}`", lang),
        ];
        let advisory_markdown_payload = serde_json::json!({
            "@type": "ubl/audit.advisory.markdown.v1",
            "@id": format!("{}:advisory-md", request.chip_id.unwrap_or(input_cid.trim_start_matches("b3:"))),
            "@ver": "1.0.0",
            "@world": request.world,
            "input_cid": input_cid,
            "markdown_text": markdown_lines.join(" | "),
            "markdown_lines": markdown_lines,
            "advisory_json_cid": advisory_json_cid,
        });
        let advisory_markdown_cid = self
            .store_audit_artifact(
                store,
                advisory_markdown_payload,
                fuel_used,
                policy_trace,
                "audit/advisory-markdown-tr/0.1",
            )
            .await?;

        Ok(AuditAdvisoryOutcome {
            parent_receipt_cid: advisory.subject_receipt_cid,
            advisory_markdown_cid,
            advisory_json_cid,
            input_count,
        })
    }

    async fn execute_silicon_compile_transition(
        &self,
        request: &ParsedChipRequest<'_>,
        _input_cid: &str,
        fuel_used: u64,
        policy_trace: &[PolicyTraceEntry],
    ) -> Result<SiliconCompileOutcome, PipelineError> {
        use crate::silicon_chip::{
            compile_chip_to_rb_vm, parse_silicon, resolve_chip_graph, SiliconRequest,
        };

        let compile = match parse_silicon(request.chip_type, request.body())
            .map_err(|e| PipelineError::InvalidChip(format!("silicon.compile parse: {}", e)))?
        {
            SiliconRequest::Compile(c) => c,
            _ => {
                return Err(PipelineError::InvalidChip(
                    "silicon.compile transition received non-compile request".to_string(),
                ));
            }
        };

        let store = self.chip_store.as_ref().ok_or_else(|| {
            PipelineError::StorageError("ubl/silicon.compile requires ChipStore".to_string())
        })?;

        // Load the silicon.chip from ChipStore.
        let chip_stored = store
            .get_chip(&compile.chip_cid)
            .await
            .map_err(|e| {
                PipelineError::StorageError(format!("silicon.compile chip lookup: {}", e))
            })?
            .ok_or_else(|| {
                PipelineError::InvalidChip(format!(
                    "silicon.compile chip_cid not found: {}",
                    compile.chip_cid
                ))
            })?;

        let chip_body = crate::silicon_chip::parse_silicon(
            crate::silicon_chip::TYPE_SILICON_CHIP,
            &chip_stored.chip_data,
        )
        .map_err(|e| PipelineError::InvalidChip(format!("silicon.compile chip parse: {}", e)))?;
        let chip_body = match chip_body {
            SiliconRequest::Chip(c) => c,
            _ => {
                return Err(PipelineError::InvalidChip(
                    "chip_cid does not point to a ubl/silicon.chip".to_string(),
                ));
            }
        };

        // Resolve full circuit graph (chip → circuits → bits).
        let circuits = resolve_chip_graph(&chip_body, store).await.map_err(|e| {
            PipelineError::Internal(format!("silicon.compile graph resolve: {}", e))
        })?;

        let circuit_count = circuits.len();
        let bit_count: usize = circuits.iter().map(|c| c.nodes.len()).sum();

        // Compile to TLV bytecode.
        let bytecode = compile_chip_to_rb_vm(&circuits)
            .map_err(|e| PipelineError::InvalidChip(format!("silicon.compile: {}", e)))?;
        let bytecode_len = bytecode.len();

        // Store bytecode artifact in ChipStore.
        let bytecode_b3 = format!("b3:{}", hex::encode(blake3::hash(&bytecode).as_bytes()));
        let bytecode_artifact = serde_json::json!({
            "@type": "ubl/silicon.bytecode.v1",
            "@world": request.world,
            "chip_cid": compile.chip_cid,
            "target": compile.target.as_str(),
            "bytecode_hex": hex::encode(&bytecode),
            "bytecode_len": bytecode_len,
            "bytecode_b3": bytecode_b3,
            "circuit_count": circuit_count,
            "bit_count": bit_count,
        });
        let bytecode_cid = self
            .store_audit_artifact(
                store,
                bytecode_artifact,
                fuel_used,
                policy_trace,
                "silicon/compile-tr/0.1",
            )
            .await?;

        Ok(SiliconCompileOutcome {
            chip_cid: compile.chip_cid,
            target: compile.target.as_str().to_string(),
            circuit_count,
            bit_count,
            bytecode_len,
            bytecode_cid,
        })
    }

    async fn store_audit_artifact(
        &self,
        store: &ubl_chipstore::ChipStore,
        payload: serde_json::Value,
        fuel_used: u64,
        policy_trace: &[PolicyTraceEntry],
        runtime_version: &str,
    ) -> Result<String, PipelineError> {
        let expected_cid = ubl_ai_nrf1::compute_cid(
            &ubl_ai_nrf1::to_nrf1_bytes(&payload)
                .map_err(|e| PipelineError::Internal(format!("artifact NRF: {}", e)))?,
        )
        .map_err(|e| PipelineError::Internal(format!("artifact CID: {}", e)))?;

        let metadata = ubl_chipstore::ExecutionMetadata {
            runtime_version: runtime_version.to_string(),
            execution_time_ms: 0,
            fuel_consumed: fuel_used,
            policies_applied: policy_trace.iter().map(|p| p.policy_id.clone()).collect(),
            executor_did: ubl_types::Did::new_unchecked(&self.did),
            reproducible: true,
        };
        let stored_cid = store
            .store_executed_chip(payload, "self".to_string(), metadata)
            .await
            .map_err(|e| PipelineError::StorageError(format!("artifact store: {}", e)))?;

        if stored_cid != expected_cid {
            return Err(PipelineError::Internal(format!(
                "artifact CID mismatch: expected {}, got {}",
                expected_cid, stored_cid
            )));
        }
        Ok(stored_cid)
    }

    fn execute_filesystem_compaction(
        mode: &str,
        segments: &[crate::audit_chip::SegmentSource],
    ) -> Result<CompactFsResult, PipelineError> {
        let base_dir =
            std::env::var("UBL_LEDGER_BASE_DIR").unwrap_or_else(|_| "./data/ledger".to_string());
        let base_dir = PathBuf::from(base_dir);
        std::fs::create_dir_all(&base_dir).map_err(|e| {
            PipelineError::StorageError(format!("compact base dir create failed: {}", e))
        })?;

        let archive_root = if mode == "archive_then_delete" {
            let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
            let root = base_dir.join("archive").join(ts);
            std::fs::create_dir_all(&root).map_err(|e| {
                PipelineError::StorageError(format!("compact archive dir create failed: {}", e))
            })?;
            Some(root)
        } else {
            None
        };

        let mut freed_bytes = 0u64;
        let mut archived_files = 0usize;
        let mut deleted_files = 0usize;

        for segment in segments {
            let resolved = Self::resolve_compact_segment_path(&base_dir, &segment.path)?;
            let metadata = std::fs::metadata(&resolved).map_err(|e| {
                PipelineError::StorageError(format!(
                    "compact segment metadata failed '{}': {}",
                    resolved.display(),
                    e
                ))
            })?;
            if !metadata.is_file() {
                return Err(PipelineError::InvalidChip(format!(
                    "compact segment is not a file: {}",
                    resolved.display()
                )));
            }

            let content = std::fs::read(&resolved).map_err(|e| {
                PipelineError::StorageError(format!(
                    "compact segment read failed '{}': {}",
                    resolved.display(),
                    e
                ))
            })?;
            let actual_sha = Self::sha256_hex(&content);
            if !actual_sha.eq_ignore_ascii_case(&segment.sha256) {
                return Err(PipelineError::InvalidChip(format!(
                    "compact segment sha256 mismatch for '{}': expected {}, got {}",
                    segment.path, segment.sha256, actual_sha
                )));
            }
            let actual_lines = Self::count_non_empty_lines(&content) as u64;
            if actual_lines != segment.lines {
                return Err(PipelineError::InvalidChip(format!(
                    "compact segment lines mismatch for '{}': expected {}, got {}",
                    segment.path, segment.lines, actual_lines
                )));
            }

            freed_bytes = freed_bytes.saturating_add(metadata.len());

            if let Some(root) = archive_root.as_ref() {
                let rel = Self::segment_rel_path(&segment.path)?;
                let target = root.join(rel);
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        PipelineError::StorageError(format!(
                            "compact archive parent create failed '{}': {}",
                            parent.display(),
                            e
                        ))
                    })?;
                }
                std::fs::rename(&resolved, &target)
                    .or_else(|_| {
                        std::fs::copy(&resolved, &target)?;
                        std::fs::remove_file(&resolved)
                    })
                    .map_err(|e| {
                        PipelineError::StorageError(format!(
                            "compact archive move failed '{}' -> '{}': {}",
                            resolved.display(),
                            target.display(),
                            e
                        ))
                    })?;
                archived_files += 1;
            } else {
                std::fs::remove_file(&resolved).map_err(|e| {
                    PipelineError::StorageError(format!(
                        "compact delete failed '{}': {}",
                        resolved.display(),
                        e
                    ))
                })?;
                deleted_files += 1;
            }
        }

        Ok(CompactFsResult {
            freed_bytes,
            archived_files,
            deleted_files,
        })
    }

    fn count_non_empty_lines(content: &[u8]) -> usize {
        content
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .count()
    }

    fn segment_rel_path(raw: &str) -> Result<PathBuf, PipelineError> {
        let path = Path::new(raw);
        if path.is_absolute() {
            return Err(PipelineError::InvalidChip(format!(
                "segment path must be relative: {}",
                raw
            )));
        }
        let mut clean = PathBuf::new();
        for comp in path.components() {
            match comp {
                Component::Normal(s) => clean.push(s),
                Component::CurDir => {}
                _ => {
                    return Err(PipelineError::InvalidChip(format!(
                        "segment path contains invalid component: {}",
                        raw
                    )));
                }
            }
        }
        if clean.as_os_str().is_empty() {
            return Err(PipelineError::InvalidChip(
                "segment path cannot be empty".to_string(),
            ));
        }
        Ok(clean)
    }

    fn resolve_compact_segment_path(base_dir: &Path, raw: &str) -> Result<PathBuf, PipelineError> {
        let rel = Self::segment_rel_path(raw)?;
        Ok(base_dir.join(rel))
    }

    fn percentile_i64(values: &[i64], q: f64) -> i64 {
        if values.is_empty() {
            return 0;
        }
        let idx = ((values.len() as f64 - 1.0) * q.clamp(0.0, 1.0)).round() as usize;
        values[idx]
    }
}

struct CompactFsResult {
    freed_bytes: u64,
    archived_files: usize,
    deleted_files: usize,
}
