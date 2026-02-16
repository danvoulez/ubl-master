//! UBL Gate — the single HTTP entry point for the UBL pipeline.
//!
//! Every mutation is a chip. Every chip goes through KNOCK→WA→CHECK→TR→WF.
//! Every output is a receipt. Nothing bypasses the gate.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use ubl_chipstore::{ChipStore, InMemoryBackend};
use ubl_runtime::advisory::AdvisoryEngine;
use ubl_runtime::error_response::UblError;
use ubl_runtime::event_bus::EventBus;
use ubl_runtime::policy_loader::InMemoryPolicyStorage;
use ubl_runtime::UblPipeline;

/// Shared application state.
#[derive(Clone)]
struct AppState {
    pipeline: Arc<UblPipeline>,
    chip_store: Arc<ChipStore>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting UBL MASTER Gate");

    // Initialize shared components
    let _event_bus = Arc::new(EventBus::new());
    let backend = Arc::new(InMemoryBackend::new());
    let chip_store = Arc::new(ChipStore::new(backend));

    let storage = InMemoryPolicyStorage::new();
    let mut pipeline = UblPipeline::with_chip_store(Box::new(storage), chip_store.clone());

    // Wire AdvisoryEngine for post-CHECK / post-WF advisory chips
    let advisory_engine = Arc::new(AdvisoryEngine::new(
        "b3:gate-passport".to_string(),
        "ubl-gate/0.1".to_string(),
        "a/system/t/gate".to_string(),
    ));
    pipeline.set_advisory_engine(advisory_engine);

    let pipeline = Arc::new(pipeline);

    // Bootstrap genesis chip — self-signed root of all policy
    match pipeline.bootstrap_genesis().await {
        Ok(cid) => println!("Genesis chip bootstrapped: {}", cid),
        Err(e) => eprintln!("FATAL: Genesis bootstrap failed: {}", e),
    }

    let state = AppState {
        pipeline,
        chip_store,
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/chips", post(create_chip))
        .route("/v1/chips/:cid", get(get_chip))
        .route("/v1/receipts/:cid/trace", get(get_receipt_trace))
        .route("/v1/passports", post(register_passport))
        .route("/v1/passports/:cid/advisories", get(get_passport_advisories))
        .route("/v1/advisories/:cid/verify", get(verify_advisory))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:4000").await?;
    println!("Gate listening on http://0.0.0.0:4000");

    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> Json<Value> {
    Json(json!({"status": "ok", "system": "ubl-master", "pipeline": "KNOCK->WA->CHECK->TR->WF"}))
}

/// POST /v1/chips — process raw bytes through the full KNOCK→WA→CHECK→TR→WF pipeline.
async fn create_chip(
    State(state): State<AppState>,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    match state.pipeline.process_raw(&body).await {
        Ok(result) => {
            let receipt_json = result.receipt.to_json().unwrap_or(json!({}));
            (
                StatusCode::OK,
                Json(json!({
                    "@type": "ubl/response",
                    "status": "success",
                    "decision": format!("{:?}", result.decision),
                    "receipt_cid": result.receipt.receipt_cid,
                    "chain": result.chain,
                    "receipt": receipt_json,
                })),
            )
        }
        Err(e) => {
            let ubl_err = UblError::from_pipeline_error(&e);
            let status = StatusCode::from_u16(ubl_err.code.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status, Json(ubl_err.to_json()))
        }
    }
}

/// GET /v1/chips/:cid — retrieve a stored chip by CID.
async fn get_chip(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> (StatusCode, Json<Value>) {
    if !cid.starts_with("b3:") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"@type": "ubl/error", "code": "INVALID_CID", "message": "CID must start with b3:"})),
        );
    }

    match state.chip_store.get_chip(&cid).await {
        Ok(Some(chip)) => (
            StatusCode::OK,
            Json(json!({
                "@type": "ubl/chip",
                "cid": chip.cid,
                "chip_type": chip.chip_type,
                "chip_data": chip.chip_data,
                "receipt_cid": chip.receipt_cid,
                "created_at": chip.created_at,
                "tags": chip.tags,
            })),
        ),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"@type": "ubl/error", "code": "NOT_FOUND", "message": format!("Chip {} not found", cid)})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"@type": "ubl/error", "code": "INTERNAL_ERROR", "message": e.to_string()})),
        ),
    }
}

/// POST /v1/passports — register an AI Passport identity through the pipeline.
async fn register_passport(
    State(state): State<AppState>,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    // Parse the incoming JSON and ensure it's an ai.passport chip
    let chip_json: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            Json(json!({"@type": "ubl/error", "code": "INVALID_JSON", "message": e.to_string()})),
        ),
    };

    // Validate it's an ai.passport type
    let chip_type = chip_json.get("@type").and_then(|v| v.as_str()).unwrap_or("");
    if chip_type != "ubl/ai.passport" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"@type": "ubl/error", "code": "INVALID_TYPE", "message": "Expected @type: ubl/ai.passport"})),
        );
    }

    // Validate the passport fields
    if let Err(e) = ubl_runtime::ai_passport::AiPassport::from_chip_body(&chip_json) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"@type": "ubl/error", "code": "INVALID_PASSPORT", "message": e.to_string()})),
        );
    }

    // Process through the full pipeline
    match state.pipeline.process_raw(&body).await {
        Ok(result) => {
            let receipt_json = result.receipt.to_json().unwrap_or(json!({}));
            (
                StatusCode::CREATED,
                Json(json!({
                    "@type": "ubl/passport.registered",
                    "status": "success",
                    "decision": format!("{:?}", result.decision),
                    "passport_cid": result.chain.first().unwrap_or(&String::new()),
                    "receipt_cid": result.receipt.receipt_cid,
                    "chain": result.chain,
                    "receipt": receipt_json,
                })),
            )
        }
        Err(e) => {
            let ubl_err = UblError::from_pipeline_error(&e);
            let status = StatusCode::from_u16(ubl_err.code.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status, Json(ubl_err.to_json()))
        }
    }
}

/// GET /v1/passports/:cid/advisories — query advisory history for a passport.
async fn get_passport_advisories(
    State(state): State<AppState>,
    Path(passport_cid): Path<String>,
) -> (StatusCode, Json<Value>) {
    // Query ChipStore for advisory chips that reference this passport
    let query = ubl_chipstore::ChipQuery {
        chip_type: Some("ubl/advisory".to_string()),
        tags: vec![],
        created_after: None,
        created_before: None,
        executor_did: None,
        limit: Some(100),
        offset: None,
    };

    match state.chip_store.query(&query).await {
        Ok(result) => {
            // Filter by passport_cid in chip_data
            let advisories: Vec<Value> = result.chips.iter()
                .filter(|c| c.chip_data.get("passport_cid")
                    .and_then(|v| v.as_str()) == Some(passport_cid.as_str()))
                .map(|c| json!({
                    "cid": c.cid,
                    "action": c.chip_data.get("action").unwrap_or(&json!("unknown")),
                    "hook": c.chip_data.get("hook").unwrap_or(&json!("unknown")),
                    "confidence": c.chip_data.get("confidence").unwrap_or(&json!(0)),
                    "model": c.chip_data.get("model").unwrap_or(&json!("unknown")),
                    "input_cid": c.chip_data.get("input_cid").unwrap_or(&json!("")),
                    "created_at": c.created_at,
                }))
                .collect();

            (
                StatusCode::OK,
                Json(json!({
                    "@type": "ubl/advisory.list",
                    "passport_cid": passport_cid,
                    "count": advisories.len(),
                    "advisories": advisories,
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"@type": "ubl/error", "code": "INTERNAL_ERROR", "message": e.to_string()})),
        ),
    }
}

/// GET /v1/advisories/:cid/verify — verify an advisory chip's integrity.
async fn verify_advisory(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> (StatusCode, Json<Value>) {
    // Fetch the advisory chip
    let chip = match state.chip_store.get_chip(&cid).await {
        Ok(Some(c)) => c,
        Ok(None) => return (
            StatusCode::NOT_FOUND,
            Json(json!({"@type": "ubl/error", "code": "NOT_FOUND", "message": format!("Advisory {} not found", cid)})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"@type": "ubl/error", "code": "INTERNAL_ERROR", "message": e.to_string()})),
        ),
    };

    if chip.chip_type != "ubl/advisory" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"@type": "ubl/error", "code": "INVALID_TYPE", "message": "Chip is not an advisory"})),
        );
    }

    // Parse the advisory
    let advisory = match ubl_runtime::advisory::Advisory::from_chip_body(&chip.chip_data) {
        Ok(a) => a,
        Err(e) => return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"@type": "ubl/error", "code": "INVALID_ADVISORY", "message": e.to_string()})),
        ),
    };

    // Recompute CID to verify integrity
    let nrf_bytes = match ubl_ai_nrf1::to_nrf1_bytes(&chip.chip_data) {
        Ok(b) => b,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"@type": "ubl/error", "code": "ENCODING_ERROR", "message": e.to_string()})),
        ),
    };
    let computed_cid = match ubl_ai_nrf1::compute_cid(&nrf_bytes) {
        Ok(c) => c,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"@type": "ubl/error", "code": "CID_ERROR", "message": e.to_string()})),
        ),
    };

    let cid_valid = computed_cid == cid;

    // Check if the passport exists
    let passport_exists = state.chip_store.get_chip(&advisory.passport_cid).await
        .map(|r| r.is_some()).unwrap_or(false);

    // Check if the input chip exists
    let input_exists = state.chip_store.get_chip(&advisory.input_cid).await
        .map(|r| r.is_some()).unwrap_or(false);

    let verified = cid_valid;

    (
        StatusCode::OK,
        Json(json!({
            "@type": "ubl/advisory.verification",
            "advisory_cid": cid,
            "verified": verified,
            "cid_valid": cid_valid,
            "computed_cid": computed_cid,
            "passport_cid": advisory.passport_cid,
            "passport_exists": passport_exists,
            "input_cid": advisory.input_cid,
            "input_exists": input_exists,
            "action": advisory.action,
            "model": advisory.model,
            "hook": format!("{:?}", advisory.hook),
            "confidence": advisory.confidence,
        })),
    )
}

/// GET /v1/receipts/:cid/trace — retrieve the policy trace for a receipt.
async fn get_receipt_trace(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> (StatusCode, Json<Value>) {
    // Look up the chip by its receipt_cid
    // For now, scan by querying all chips and matching receipt_cid
    // In production, this would be an indexed lookup
    let query = ubl_chipstore::ChipQuery {
        chip_type: None,
        tags: vec![],
        created_after: None,
        created_before: None,
        executor_did: None,
        limit: Some(1000),
        offset: None,
    };

    match state.chip_store.query(&query).await {
        Ok(result) => {
            if let Some(chip) = result.chips.iter().find(|c| c.receipt_cid == cid) {
                (
                    StatusCode::OK,
                    Json(json!({
                        "@type": "ubl/trace",
                        "receipt_cid": cid,
                        "chip_cid": chip.cid,
                        "chip_type": chip.chip_type,
                        "execution_metadata": {
                            "runtime_version": chip.execution_metadata.runtime_version,
                            "execution_time_ms": chip.execution_metadata.execution_time_ms,
                            "fuel_consumed": chip.execution_metadata.fuel_consumed,
                            "policies_applied": chip.execution_metadata.policies_applied,
                            "reproducible": chip.execution_metadata.reproducible,
                        },
                    })),
                )
            } else {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({"@type": "ubl/error", "code": "NOT_FOUND", "message": format!("Receipt {} not found", cid)})),
                )
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"@type": "ubl/error", "code": "INTERNAL_ERROR", "message": e.to_string()})),
        ),
    }
}