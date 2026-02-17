//! UBL Gate — the single HTTP entry point for the UBL pipeline.
//!
//! Every mutation is a chip. Every chip goes through KNOCK→WA→CHECK→TR→WF.
//! Every output is a receipt. Nothing bypasses the gate.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use ubl_chipstore::{ChipStore, SledBackend};
use ubl_runtime::advisory::AdvisoryEngine;
use ubl_runtime::error_response::UblError;
use ubl_runtime::event_bus::EventBus;
use ubl_runtime::manifest::GateManifest;
use ubl_runtime::policy_loader::InMemoryPolicyStorage;
use ubl_runtime::UblPipeline;

mod metrics;

/// Shared application state.
#[derive(Clone)]
struct AppState {
    pipeline: Arc<UblPipeline>,
    chip_store: Arc<ChipStore>,
    manifest: Arc<GateManifest>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting UBL MASTER Gate");

    // Initialize shared components
    let _event_bus = Arc::new(EventBus::new());
    let backend = Arc::new(SledBackend::new("./data/chips")?);
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

    // Wire NDJSON audit ledger — append-only log alongside Sled CAS
    let ledger = Arc::new(ubl_runtime::ledger::NdjsonLedger::new("./data/ledger"));
    pipeline.set_ledger(ledger);

    let pipeline = Arc::new(pipeline);

    // Bootstrap genesis chip — self-signed root of all policy
    match pipeline.bootstrap_genesis().await {
        Ok(cid) => println!("Genesis chip bootstrapped: {}", cid),
        Err(e) => eprintln!("FATAL: Genesis bootstrap failed: {}", e),
    }

    let manifest = Arc::new(GateManifest::default());

    let state = AppState {
        pipeline,
        chip_store,
        manifest,
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/chips", post(create_chip))
        .route("/v1/chips/:cid", get(get_chip))
        .route("/v1/receipts/:cid/trace", get(get_receipt_trace))
        .route("/v1/passports/:cid/advisories", get(get_passport_advisories))
        .route("/v1/advisories/:cid/verify", get(verify_advisory))
        .route("/v1/chips/:cid/verify", get(verify_chip))
        .route("/metrics", get(metrics_handler))
        .route("/openapi.json", get(openapi_spec))
        .route("/mcp/manifest", get(mcp_manifest))
        .route("/.well-known/webmcp.json", get(webmcp_manifest))
        .route("/mcp/rpc", post(mcp_rpc))
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
///
/// Idempotent: if the chip was already processed (same @type/@ver/@world/@id),
/// returns the cached result with `X-UBL-Replay: true` header and `"replayed": true`
/// in the response body. No re-execution occurs.
async fn create_chip(
    State(state): State<AppState>,
    body: Bytes,
) -> impl IntoResponse {
    metrics::inc_chips_total();
    let t0 = std::time::Instant::now();

    match state.pipeline.process_raw(&body).await {
        Ok(result) => {
            metrics::observe_pipeline_seconds(t0.elapsed().as_secs_f64());
            let decision_str = format!("{:?}", result.decision);
            if decision_str.contains("Allow") {
                metrics::inc_allow();
            } else {
                metrics::inc_deny();
            }
            let receipt_json = result.receipt.to_json().unwrap_or(json!({}));
            let mut headers = HeaderMap::new();
            if result.replayed {
                headers.insert("X-UBL-Replay", "true".parse().unwrap());
            }
            (
                StatusCode::OK,
                headers,
                Json(json!({
                    "@type": "ubl/response",
                    "status": "success",
                    "decision": decision_str,
                    "receipt_cid": result.receipt.receipt_cid,
                    "chain": result.chain,
                    "receipt": receipt_json,
                    "replayed": result.replayed,
                })),
            )
        }
        Err(e) => {
            metrics::observe_pipeline_seconds(t0.elapsed().as_secs_f64());
            let ubl_err = UblError::from_pipeline_error(&e);
            let code_str = format!("{:?}", ubl_err.code);
            if code_str.contains("Knock") {
                metrics::inc_knock_reject();
            }
            metrics::inc_error(&code_str);
            let status = StatusCode::from_u16(ubl_err.code.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status, HeaderMap::new(), Json(ubl_err.to_json()))
        }
    }
}

async fn metrics_handler() -> String {
    metrics::encode_metrics()
}

/// GET /v1/chips/:cid/verify — recompute CID from stored chip content and verify integrity.
async fn verify_chip(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> (StatusCode, Json<Value>) {
    if !cid.starts_with("b3:") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"@type": "ubl/error", "code": "INVALID_CID", "message": "CID must start with b3:"})),
        );
    }

    let chip = match state.chip_store.get_chip(&cid).await {
        Ok(Some(c)) => c,
        Ok(None) => return (
            StatusCode::NOT_FOUND,
            Json(json!({"@type": "ubl/error", "code": "NOT_FOUND", "message": format!("Chip {} not found", cid)})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"@type": "ubl/error", "code": "INTERNAL_ERROR", "message": e.to_string()})),
        ),
    };

    // Recompute CID from chip_data via NRF-1 canonical encoding → BLAKE3
    let (computed_cid, encoding_ok) = match ubl_ai_nrf1::to_nrf1_bytes(&chip.chip_data) {
        Ok(nrf_bytes) => match ubl_ai_nrf1::compute_cid(&nrf_bytes) {
            Ok(c) => (c, true),
            Err(_) => (String::new(), false),
        },
        Err(_) => (String::new(), false),
    };

    let cid_matches = encoding_ok && computed_cid == cid;

    // Check receipt exists
    let receipt_cid = &chip.receipt_cid;
    let receipt_exists = if receipt_cid.is_empty() {
        false
    } else {
        // Scan for receipt (same pattern as get_receipt_trace)
        let query = ubl_chipstore::ChipQuery {
            chip_type: None, tags: vec![], created_after: None,
            created_before: None, executor_did: None, limit: Some(1000), offset: None,
        };
        state.chip_store.query(&query).await
            .map(|r| r.chips.iter().any(|c| c.receipt_cid == *receipt_cid))
            .unwrap_or(false)
    };

    (
        StatusCode::OK,
        Json(json!({
            "@type": "ubl/chip.verification",
            "cid": cid,
            "verified": cid_matches,
            "cid_matches": cid_matches,
            "computed_cid": computed_cid,
            "encoding_ok": encoding_ok,
            "chip_type": chip.chip_type,
            "receipt_cid": chip.receipt_cid,
            "receipt_exists": receipt_exists,
            "created_at": chip.created_at,
        })),
    )
}

/// GET /v1/chips/:cid — retrieve a stored chip by CID.
///
/// ETag support (P1.6): The chip CID is the ETag (content-addressed).
/// If `If-None-Match` header matches the CID, returns 304 Not Modified.
async fn get_chip(
    State(state): State<AppState>,
    Path(cid): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !cid.starts_with("b3:") {
        return (
            StatusCode::BAD_REQUEST,
            HeaderMap::new(),
            Json(json!({"@type": "ubl/error", "code": "INVALID_CID", "message": "CID must start with b3:"})),
        );
    }

    // ETag: If-None-Match → 304 (P1.6)
    if let Some(inm) = headers.get(header::IF_NONE_MATCH) {
        if let Ok(inm_str) = inm.to_str() {
            let etag = format!("\"{}\"" , cid);
            if inm_str == etag || inm_str.trim_matches('"') == cid {
                let mut h = HeaderMap::new();
                h.insert(header::ETAG, etag.parse().unwrap());
                return (StatusCode::NOT_MODIFIED, h, Json(json!(null)));
            }
        }
    }

    match state.chip_store.get_chip(&cid).await {
        Ok(Some(chip)) => {
            let mut h = HeaderMap::new();
            let etag = format!("\"{}\"" , chip.cid);
            h.insert(header::ETAG, etag.parse().unwrap());
            h.insert(header::CACHE_CONTROL, "public, max-age=31536000, immutable".parse().unwrap());
            (
                StatusCode::OK,
                h,
                Json(json!({
                    "@type": "ubl/chip",
                    "cid": chip.cid,
                    "chip_type": chip.chip_type,
                    "chip_data": chip.chip_data,
                    "receipt_cid": chip.receipt_cid,
                    "created_at": chip.created_at,
                    "tags": chip.tags,
                })),
            )
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            HeaderMap::new(),
            Json(json!({"@type": "ubl/error", "code": "NOT_FOUND", "message": format!("Chip {} not found", cid)})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            HeaderMap::new(),
            Json(json!({"@type": "ubl/error", "code": "INTERNAL_ERROR", "message": e.to_string()})),
        ),
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

// ── Manifest endpoints (P2.8 + P2.9) ──

/// GET /openapi.json — OpenAPI 3.1 specification.
async fn openapi_spec(State(state): State<AppState>) -> Json<Value> {
    Json(state.manifest.to_openapi())
}

/// GET /mcp/manifest — MCP tool manifest for AI agents.
async fn mcp_manifest(State(state): State<AppState>) -> Json<Value> {
    Json(state.manifest.to_mcp_manifest())
}

/// GET /.well-known/webmcp.json — WebMCP discovery manifest.
async fn webmcp_manifest(State(state): State<AppState>) -> Json<Value> {
    Json(state.manifest.to_webmcp_manifest())
}

/// POST /mcp/rpc — MCP JSON-RPC 2.0 proxy (P2.9).
///
/// Dispatches MCP tool calls to the same pipeline:
/// - ubl.deliver → process_raw
/// - ubl.query → ChipStore get
/// - ubl.verify → CID recomputation
/// - registry.listTypes → manifest chip types
async fn mcp_rpc(
    State(state): State<AppState>,
    Json(rpc): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let id = rpc.get("id").cloned().unwrap_or(json!(null));
    let method = rpc.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let params = rpc.get("params").cloned().unwrap_or(json!({}));

    if rpc.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return (StatusCode::BAD_REQUEST, Json(json!({
            "jsonrpc": "2.0", "id": id,
            "error": { "code": -32600, "message": "Invalid Request: missing jsonrpc 2.0" }
        })));
    }

    match method {
        "tools/list" => {
            let manifest = state.manifest.to_mcp_manifest();
            (StatusCode::OK, Json(json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "tools": manifest["tools"] }
            })))
        }

        "tools/call" => {
            let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            dispatch_tool_call(&state, tool_name, &arguments, id).await
        }

        _ => (StatusCode::OK, Json(json!({
            "jsonrpc": "2.0", "id": id,
            "error": { "code": -32601, "message": format!("Method not found: {}", method) }
        }))),
    }
}

/// Dispatch an MCP tools/call to the appropriate handler.
async fn dispatch_tool_call(
    state: &AppState,
    tool_name: &str,
    arguments: &Value,
    id: Value,
) -> (StatusCode, Json<Value>) {
    match tool_name {
        "ubl.deliver" => {
            let chip = arguments.get("chip").cloned().unwrap_or(json!({}));
            let bytes = serde_json::to_vec(&chip).unwrap_or_default();
            match state.pipeline.process_raw(&bytes).await {
                Ok(result) => {
                    let receipt_json = result.receipt.to_json().unwrap_or(json!({}));
                    (StatusCode::OK, Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": { "content": [{ "type": "text", "text": serde_json::to_string(&json!({
                            "decision": format!("{:?}", result.decision),
                            "receipt_cid": result.receipt.receipt_cid,
                            "chain": result.chain,
                            "receipt": receipt_json,
                        })).unwrap_or_default() }] }
                    })))
                }
                Err(e) => {
                    let ubl_err = UblError::from_pipeline_error(&e);
                    (StatusCode::OK, Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": ubl_err.code.mcp_code(), "message": ubl_err.message, "data": ubl_err.to_json() }
                    })))
                }
            }
        }

        "ubl.query" => {
            let cid = arguments.get("cid").and_then(|v| v.as_str()).unwrap_or("");
            match state.chip_store.get_chip(cid).await {
                Ok(Some(chip)) => (StatusCode::OK, Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "content": [{ "type": "text", "text": serde_json::to_string(&json!({
                        "cid": chip.cid, "chip_type": chip.chip_type,
                        "chip_data": chip.chip_data, "receipt_cid": chip.receipt_cid,
                    })).unwrap_or_default() }] }
                }))),
                Ok(None) => (StatusCode::OK, Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32004, "message": format!("Chip {} not found", cid) }
                }))),
                Err(e) => (StatusCode::OK, Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32603, "message": e.to_string() }
                }))),
            }
        }

        "ubl.verify" => {
            let cid = arguments.get("cid").and_then(|v| v.as_str()).unwrap_or("");
            match state.chip_store.get_chip(cid).await {
                Ok(Some(chip)) => {
                    let verified = match ubl_ai_nrf1::to_nrf1_bytes(&chip.chip_data) {
                        Ok(nrf) => ubl_ai_nrf1::compute_cid(&nrf).map(|c| c == cid).unwrap_or(false),
                        Err(_) => false,
                    };
                    (StatusCode::OK, Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": { "content": [{ "type": "text", "text": serde_json::to_string(&json!({
                            "cid": cid, "verified": verified
                        })).unwrap_or_default() }] }
                    })))
                }
                Ok(None) => (StatusCode::OK, Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32004, "message": format!("Chip {} not found", cid) }
                }))),
                Err(e) => (StatusCode::OK, Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32603, "message": e.to_string() }
                }))),
            }
        }

        "registry.listTypes" => {
            let types: Vec<Value> = state.manifest.chip_types.iter().map(|ct| json!({
                "type": ct.chip_type, "description": ct.description, "required_cap": ct.required_cap,
            })).collect();
            (StatusCode::OK, Json(json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "content": [{ "type": "text", "text": serde_json::to_string(&types).unwrap_or_default() }] }
            })))
        }

        _ => (StatusCode::OK, Json(json!({
            "jsonrpc": "2.0", "id": id,
            "error": { "code": -32601, "message": format!("Tool not found: {}", tool_name) }
        }))),
    }
}