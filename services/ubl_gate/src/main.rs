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
    let pipeline = UblPipeline::with_chip_store(Box::new(storage), chip_store.clone());
    // Attach event bus (rebuild with both)
    // For now, use the with_chip_store constructor which doesn't take event_bus.
    // The event bus is set separately if needed.
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