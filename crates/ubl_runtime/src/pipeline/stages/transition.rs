use super::super::*;

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
        if let Some(info) = adapter_info {
            vm_state.insert(
                "adapter_wasm_sha256".to_string(),
                serde_json::json!(info.wasm_sha256),
            );
            vm_state.insert(
                "adapter_abi_version".to_string(),
                serde_json::json!(info.abi_version),
            );
        }

        let tr_body = serde_json::json!({
            "@type": "ubl/transition",
            "input_cid": input_cid.0,
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
}
