use super::super::*;
use crate::wasm_adapter::{SandboxConfig, WasmError, WasmExecutor, WasmInput, WasmtimeExecutor};
use base64::Engine as _;

#[derive(Debug, Clone)]
struct AdapterExecutionOutcome {
    output_cid: String,
    fuel_used: u64,
    effects: Vec<String>,
    module_source: String,
}

impl UblPipeline {
    /// Stage 3: TR - Transition (RB-VM execution)
    pub(in crate::pipeline) async fn stage_transition(
        &self,
        request: &ChipRequest,
        _check: &CheckResult,
    ) -> Result<PipelineReceipt, PipelineError> {
        // Encode chip body to NRF bytes and store as CAS input
        let chip_nrf = ubl_ai_nrf1::to_nrf1_bytes(&request.body)
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

        let adapter_info = AdapterRuntimeInfo::parse_optional(&request.body)?;
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
            .resolve(&request.chip_type, &request.body)
            .map_err(|e| PipelineError::InvalidChip(format!("TR bytecode resolution: {}", e)))?;
        let bytecode_hash = format!(
            "b3:{}",
            hex::encode(blake3::hash(&resolution.bytecode).as_bytes())
        );
        let instructions = tlv::decode_stream(&resolution.bytecode)
            .map_err(|e| PipelineError::Internal(format!("TR bytecode decode: {}", e)))?;

        // Execute VM
        let mut vm = Vm::new(cfg, cas, &signer, canon, vec![input_cid.clone()]);
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

        let key_rotation = if request.chip_type == "ubl/key.rotate" {
            let rotate_req = KeyRotateRequest::parse(&request.body)
                .map_err(|e| PipelineError::InvalidChip(format!("Key rotation: {}", e)))?;
            let signing_seed = self.signing_key.to_bytes();
            Some(
                derive_material(&rotate_req, &request.body, &signing_seed)
                    .map_err(|e| PipelineError::Internal(format!("Key rotation: {}", e)))?,
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

        let tr_body = serde_json::json!({
            "@type": "ubl/transition",
            "input_cid": input_cid_str,
            "output_cid": outcome.rc_cid.as_ref().map(|c| c.0.clone()).unwrap_or_default(),
            "vm_sig": outcome.rc_sig.as_deref().unwrap_or_default(),
            "vm_sig_payload_cid": outcome.rc_payload_cid.as_ref().map(|c| c.0.clone()).unwrap_or_default(),
            "vm_state": vm_state
        });
        let mut tr_body = tr_body;
        if let Some(rotation) = key_rotation {
            tr_body["key_rotation"] = serde_json::json!({
                "old_did": rotation.old_did,
                "old_kid": rotation.old_kid,
                "new_did": rotation.new_did,
                "new_kid": rotation.new_kid,
                "new_key_cid": rotation.new_key_cid,
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
}
