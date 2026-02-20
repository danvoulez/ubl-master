use super::super::*;

impl UblPipeline {
    /// Stage 4: WF - Write Finished
    pub(in crate::pipeline) async fn stage_write_finished(
        &self,
        request: &ParsedChipRequest<'_>,
        wa_receipt: &PipelineReceipt,
        tr_receipt: &PipelineReceipt,
        check: &CheckResult,
        pipeline_duration_ms: i64,
    ) -> Result<PipelineReceipt, PipelineError> {
        // Compute the final chip CID
        let chip_nrf1 = ubl_ai_nrf1::to_nrf1_bytes(request.body())
            .map_err(|e| PipelineError::Internal(format!("Chip CID: {}", e)))?;
        let chip_cid = ubl_ai_nrf1::compute_cid(&chip_nrf1)
            .map_err(|e| PipelineError::Internal(format!("Chip CID: {}", e)))?;

        let mut artifacts = HashMap::new();
        artifacts.insert("chip".to_string(), chip_cid.clone());
        if let Some(tr_artifacts) = tr_receipt.body.get("artifacts").and_then(|v| v.as_object()) {
            for (key, value) in tr_artifacts {
                if let Some(cid) = value.as_str() {
                    artifacts.insert(key.clone(), cid.to_string());
                }
            }
        }

        let wf_body = WfReceiptBody {
            decision: check.decision.clone(),
            wa_cid: wa_receipt.body_cid.as_str().to_string(),
            tr_cid: Some(tr_receipt.body_cid.as_str().to_string()),
            artifacts,
            duration_ms: pipeline_duration_ms,
            policy_trace: check.trace.clone(),
            short_circuited: check.short_circuited,
        };

        let body_json = serde_json::to_value(&wf_body)
            .map_err(|e| PipelineError::Internal(format!("WF serialization: {}", e)))?;

        let nrf1_bytes = ubl_ai_nrf1::to_nrf1_bytes(&body_json)
            .map_err(|e| PipelineError::Internal(format!("WF CID: {}", e)))?;
        let cid = ubl_ai_nrf1::compute_cid(&nrf1_bytes)
            .map_err(|e| PipelineError::Internal(format!("WF CID: {}", e)))?;

        Ok(PipelineReceipt {
            body_cid: ubl_types::Cid::new_unchecked(&cid),
            receipt_type: "ubl/wf".to_string(),
            body: body_json,
        })
    }

    /// Create a DENY receipt when policy fails
    pub(in crate::pipeline) async fn create_deny_receipt(
        &self,
        wa_receipt: &PipelineReceipt,
        check: &CheckResult,
        pipeline_duration_ms: i64,
    ) -> Result<PipelineReceipt, PipelineError> {
        let wf_body = WfReceiptBody {
            decision: Decision::Deny,
            wa_cid: wa_receipt.body_cid.as_str().to_string(),
            tr_cid: None, // No transition executed
            artifacts: HashMap::new(),
            duration_ms: pipeline_duration_ms,
            policy_trace: check.trace.clone(),
            short_circuited: true,
        };

        let body_json = serde_json::to_value(&wf_body)
            .map_err(|e| PipelineError::Internal(format!("WF DENY serialization: {}", e)))?;

        let nrf1_bytes = ubl_ai_nrf1::to_nrf1_bytes(&body_json)
            .map_err(|e| PipelineError::Internal(format!("WF DENY CID: {}", e)))?;
        let cid = ubl_ai_nrf1::compute_cid(&nrf1_bytes)
            .map_err(|e| PipelineError::Internal(format!("WF DENY CID: {}", e)))?;

        Ok(PipelineReceipt {
            body_cid: ubl_types::Cid::new_unchecked(&cid),
            receipt_type: "ubl/wf".to_string(),
            body: body_json,
        })
    }
}
