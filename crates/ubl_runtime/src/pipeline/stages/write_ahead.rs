use super::super::*;

impl UblPipeline {
    /// Stage 1: Write-Ahead - create ghost record, freeze @world
    pub(in crate::pipeline) async fn stage_write_ahead(
        &self,
        request: &ChipRequest,
    ) -> Result<PipelineReceipt, PipelineError> {
        // Validate @world format before freezing
        if let Some(world) = request.body.get("@world").and_then(|v| v.as_str()) {
            ubl_ai_nrf1::UblEnvelope::validate_world(world)
                .map_err(|e| PipelineError::InvalidChip(format!("@world: {}", e)))?;
        } else {
            return Err(PipelineError::InvalidChip(
                "missing @world anchor".to_string(),
            ));
        }

        // Generate nonce and check for replay
        let nonce = Self::generate_nonce();
        {
            let mut seen = self.seen_nonces.write().await;
            if !seen.insert(nonce.clone()) {
                return Err(PipelineError::ReplayDetected("duplicate nonce".to_string()));
            }
        }

        let wa_body = WaReceiptBody {
            ghost: true,
            chip_cid: "pending".to_string(), // Will be computed later
            policy_cid: genesis_chip_cid(),  // For now, just genesis
            frozen_time: chrono::Utc::now().to_rfc3339(),
            caller: self.did.clone(),
            context: request.body.clone(),
            operation: request
                .operation
                .clone()
                .unwrap_or_else(|| "create".to_string()),
            nonce,
            kid: self.kid.clone(),
        };

        let body_json = serde_json::to_value(&wa_body)
            .map_err(|e| PipelineError::Internal(format!("WA serialization: {}", e)))?;

        // Compute CID
        let nrf1_bytes = ubl_ai_nrf1::to_nrf1_bytes(&body_json)
            .map_err(|e| PipelineError::Internal(format!("WA CID: {}", e)))?;
        let cid = ubl_ai_nrf1::compute_cid(&nrf1_bytes)
            .map_err(|e| PipelineError::Internal(format!("WA CID: {}", e)))?;

        Ok(PipelineReceipt {
            body_cid: ubl_types::Cid::new_unchecked(&cid),
            receipt_type: "ubl/wa".to_string(),
            body: body_json,
        })
    }
}
