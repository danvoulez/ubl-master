use super::*;

#[derive(Debug, Clone)]
pub(super) struct AdapterRuntimeInfo {
    pub(super) wasm_sha256: String,
    pub(super) abi_version: String,
    pub(super) wasm_cid: Option<String>,
    pub(super) wasm_b64: Option<String>,
    pub(super) fuel_budget: Option<u64>,
}

impl AdapterRuntimeInfo {
    pub(super) fn parse_optional(body: &serde_json::Value) -> Result<Option<Self>, PipelineError> {
        let Some(adapter) = body.get("adapter") else {
            return Ok(None);
        };
        let adapter = adapter
            .as_object()
            .ok_or_else(|| PipelineError::InvalidChip("adapter must be object".to_string()))?;

        let wasm_sha256 = adapter
            .get("wasm_sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PipelineError::InvalidChip("adapter.wasm_sha256 missing".to_string()))?;
        let abi_version = adapter
            .get("abi_version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PipelineError::InvalidChip("adapter.abi_version missing".to_string()))?;
        let wasm_cid = adapter
            .get("wasm_cid")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string());
        let wasm_b64 = adapter
            .get("wasm_b64")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string());
        let fuel_budget = adapter.get("fuel_budget").and_then(|v| v.as_u64());

        let is_hex = wasm_sha256.len() == 64 && wasm_sha256.chars().all(|c| c.is_ascii_hexdigit());
        if !is_hex {
            return Err(PipelineError::InvalidChip(
                "adapter.wasm_sha256 must be 64 hex chars".to_string(),
            ));
        }
        if abi_version != "1.0" {
            return Err(PipelineError::InvalidChip(format!(
                "adapter.abi_version unsupported: {}",
                abi_version
            )));
        }

        Ok(Some(Self {
            wasm_sha256: wasm_sha256.to_string(),
            abi_version: abi_version.to_string(),
            wasm_cid,
            wasm_b64,
            fuel_budget,
        }))
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ParsedChipRequest<'a> {
    request: &'a ChipRequest,
    pub(super) chip_type: &'a str,
    pub(super) chip_id: Option<&'a str>,
    pub(super) world: &'a str,
}

impl<'a> ParsedChipRequest<'a> {
    pub(super) fn parse(request: &'a ChipRequest) -> Result<Self, PipelineError> {
        let body = request
            .body
            .as_object()
            .ok_or_else(|| PipelineError::InvalidChip("chip body must be object".to_string()))?;

        let chip_type = body
            .get("@type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PipelineError::InvalidChip("missing @type".to_string()))?;
        if chip_type != request.chip_type {
            return Err(PipelineError::InvalidChip(format!(
                "request.chip_type '{}' != body.@type '{}'",
                request.chip_type, chip_type
            )));
        }

        let world = body
            .get("@world")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PipelineError::InvalidChip("missing @world".to_string()))?;
        ubl_ai_nrf1::UblEnvelope::validate_world(world)
            .map_err(|e| PipelineError::InvalidChip(format!("@world: {}", e)))?;

        let chip_id = body
            .get("@id")
            .and_then(|v| v.as_str())
            .or_else(|| body.get("id").and_then(|v| v.as_str()));

        Ok(Self {
            request,
            chip_type,
            chip_id,
            world,
        })
    }

    pub(super) fn body(&self) -> &'a serde_json::Value {
        &self.request.body
    }

    pub(super) fn parents(&self) -> &'a [String] {
        &self.request.parents
    }

    pub(super) fn operation(&self) -> &'a str {
        self.request.operation.as_deref().unwrap_or("create")
    }
}

/// Result of the CHECK stage — decision + full policy trace.
pub(super) struct CheckResult {
    pub(super) decision: Decision,
    pub(super) reason: String,
    pub(super) short_circuited: bool,
    pub(super) trace: Vec<PolicyTraceEntry>,
}

pub(super) fn decision_to_wire(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
        Decision::Require => "require",
    }
}
