//! UBL Gate — the single HTTP entry point for the UBL pipeline.
//!
//! Every mutation is a chip. Every chip goes through KNOCK→WA→CHECK→TR→WF.
//! Every output is a receipt. Nothing bypasses the gate.

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use ubl_chipstore::{ChipStore, SledBackend};
use ubl_runtime::advisory::{Advisory, AdvisoryEngine, AdvisoryHook};
use ubl_runtime::durable_store::DurableStore;
use ubl_runtime::error_response::{ErrorCode, UblError};
use ubl_runtime::event_bus::EventBus;
use ubl_runtime::manifest::GateManifest;
use ubl_runtime::outbox_dispatcher::OutboxDispatcher;
use ubl_runtime::policy_loader::InMemoryPolicyStorage;
use ubl_runtime::rate_limit::{CanonRateLimiter, RateLimitConfig, RateLimitResult};
use ubl_runtime::UblPipeline;

mod metrics;

/// Shared application state.
#[derive(Clone)]
struct AppState {
    pipeline: Arc<UblPipeline>,
    chip_store: Arc<ChipStore>,
    manifest: Arc<GateManifest>,
    advisory_engine: Arc<AdvisoryEngine>,
    canon_rate_limiter: Option<Arc<CanonRateLimiter>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    info!("starting UBL MASTER Gate");

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
    pipeline.set_advisory_engine(advisory_engine.clone());

    // Wire NDJSON audit ledger — append-only log alongside Sled CAS
    let ledger = Arc::new(ubl_runtime::ledger::NdjsonLedger::new("./data/ledger"));
    pipeline.set_ledger(ledger);

    let pipeline = Arc::new(pipeline);

    // Bootstrap genesis chip — self-signed root of all policy
    match pipeline.bootstrap_genesis().await {
        Ok(cid) => info!(%cid, "genesis chip bootstrapped"),
        Err(e) => error!(error = %e, "FATAL: genesis bootstrap failed"),
    }

    // Start outbox dispatcher workers when SQLite durability is enabled.
    if let Ok(Some(store)) = DurableStore::from_env() {
        let workers: usize = std::env::var("UBL_OUTBOX_WORKERS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1)
            .max(1);
        metrics::set_outbox_pending(store.outbox_pending().unwrap_or(0));

        for worker_id in 0..workers {
            let dispatcher = OutboxDispatcher::new(store.clone()).with_backoff(2, 300);
            let store_for_metrics = store.clone();
            tokio::spawn(async move {
                loop {
                    let processed =
                        dispatcher.run_once(64, |event| match event.event_type.as_str() {
                            // Placeholder delivery path; real publisher can be wired here.
                            "emit_receipt" => Ok(()),
                            _ => {
                                metrics::inc_outbox_retry();
                                Err(format!("unknown outbox event type: {}", event.event_type))
                            }
                        });

                    match processed {
                        Ok(processed_count) => {
                            metrics::set_outbox_pending(
                                store_for_metrics.outbox_pending().unwrap_or_default(),
                            );
                            if processed_count == 0 {
                                tokio::time::sleep(Duration::from_millis(500)).await;
                            }
                        }
                        Err(e) => {
                            metrics::inc_outbox_retry();
                            warn!(worker_id, error = %e, "outbox worker error");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            });
        }
        info!(workers, "outbox dispatcher started");
    }

    let manifest = Arc::new(GateManifest::default());

    let state = AppState {
        pipeline,
        chip_store,
        manifest,
        advisory_engine,
        canon_rate_limiter: load_canon_rate_limiter(),
    };

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:4000").await?;
    info!("gate listening on http://0.0.0.0:4000");

    axum::serve(listener, app).await?;
    Ok(())
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,ubl_runtime=debug,ubl_gate=debug"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .try_init();
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "on"))
        .unwrap_or(default)
}

fn load_canon_rate_limiter() -> Option<Arc<CanonRateLimiter>> {
    if !env_bool("UBL_CANON_RATE_LIMIT_ENABLED", true) {
        return None;
    }
    let per_min = std::env::var("UBL_CANON_RATE_LIMIT_PER_MIN")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(120)
        .max(1);
    Some(Arc::new(CanonRateLimiter::new(
        RateLimitConfig::per_minute(per_min),
    )))
}

fn too_many_requests_error(message: String, details: Value) -> UblError {
    UblError {
        error_type: "ubl/error".to_string(),
        id: format!("err-rate-{}", chrono::Utc::now().timestamp_micros()),
        ver: "1.0".to_string(),
        world: "a/system/t/errors".to_string(),
        code: ErrorCode::TooManyRequests,
        message,
        link: "https://docs.ubl.agency/errors#TOO_MANY_REQUESTS".to_string(),
        details: Some(details),
    }
}

async fn submit_chip_bytes(state: &AppState, body: &[u8]) -> (StatusCode, HeaderMap, Value) {
    metrics::inc_chips_total();
    let t0 = std::time::Instant::now();

    let value = match ubl_runtime::knock::knock(body) {
        Ok(v) => v,
        Err(e) => {
            metrics::observe_pipeline_seconds(t0.elapsed().as_secs_f64());
            let ubl_err = UblError::from_pipeline_error(
                &ubl_runtime::pipeline::PipelineError::Knock(e.to_string()),
            );
            let code_str = format!("{:?}", ubl_err.code);
            metrics::inc_knock_reject();
            metrics::inc_error(&code_str);
            let status =
                StatusCode::from_u16(ubl_err.code.http_status()).unwrap_or(StatusCode::BAD_REQUEST);
            return (status, HeaderMap::new(), ubl_err.to_json());
        }
    };

    if let Some(ref limiter) = state.canon_rate_limiter {
        if let Some((fp, RateLimitResult::Limited { retry_after, .. })) =
            limiter.check_body(&value).await
        {
            metrics::observe_pipeline_seconds(t0.elapsed().as_secs_f64());
            metrics::inc_error("TooManyRequests");
            let mut headers = HeaderMap::new();
            let retry_secs = retry_after.as_secs().saturating_add(1);
            if let Ok(v) = retry_secs.to_string().parse() {
                headers.insert(header::RETRY_AFTER, v);
            }
            let err = too_many_requests_error(
                format!(
                    "Rate limit exceeded for canonical payload {}",
                    fp.rate_key()
                ),
                json!({
                    "limited_by": "canon_fingerprint",
                    "fingerprint": fp.hash,
                    "at_type": fp.at_type,
                    "at_ver": fp.at_ver,
                    "at_world": fp.at_world,
                    "retry_after_seconds": retry_secs,
                }),
            );
            return (StatusCode::TOO_MANY_REQUESTS, headers, err.to_json());
        }
    }

    let chip_type = value["@type"].as_str().unwrap_or("").to_string();
    let request = ubl_runtime::pipeline::ChipRequest {
        chip_type,
        body: value,
        parents: vec![],
        operation: Some("create".to_string()),
    };

    match state.pipeline.process_chip(request).await {
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
                metrics::inc_idempotency_hit();
                metrics::inc_idempotency_replay_block();
                headers.insert("X-UBL-Replay", "true".parse().unwrap());
            }
            (
                StatusCode::OK,
                headers,
                json!({
                    "@type": "ubl/response",
                    "status": "success",
                    "decision": decision_str,
                    "receipt_cid": result.receipt.receipt_cid,
                    "chain": result.chain,
                    "receipt": receipt_json,
                    "replayed": result.replayed,
                }),
            )
        }
        Err(e) => {
            metrics::observe_pipeline_seconds(t0.elapsed().as_secs_f64());
            let ubl_err = UblError::from_pipeline_error(&e);
            match ubl_err.code {
                ErrorCode::SignError | ErrorCode::InvalidSignature => {
                    let mode = std::env::var("UBL_CRYPTO_MODE")
                        .unwrap_or_else(|_| "compat_v1".to_string());
                    metrics::inc_crypto_verify_fail("pipeline", &mode);
                }
                ErrorCode::CanonError => metrics::inc_canon_divergence("pipeline"),
                _ => {}
            }
            let code_str = format!("{:?}", ubl_err.code);
            if code_str.contains("Knock") {
                metrics::inc_knock_reject();
            }
            metrics::inc_error(&code_str);
            let status = StatusCode::from_u16(ubl_err.code.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status, HeaderMap::new(), ubl_err.to_json())
        }
    }
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/runtime/attestation", get(get_runtime_attestation))
        .route("/v1/chips", post(create_chip))
        .route("/v1/chips/:cid", get(get_chip))
        .route("/v1/receipts/:cid/trace", get(get_receipt_trace))
        .route("/v1/receipts/:cid/narrate", get(narrate_receipt))
        .route(
            "/v1/passports/:cid/advisories",
            get(get_passport_advisories),
        )
        .route("/v1/advisories/:cid/verify", get(verify_advisory))
        .route("/v1/chips/:cid/verify", get(verify_chip))
        .route("/metrics", get(metrics_handler))
        .route("/openapi.json", get(openapi_spec))
        .route("/mcp/manifest", get(mcp_manifest))
        .route("/.well-known/webmcp.json", get(webmcp_manifest))
        .route("/mcp/rpc", post(mcp_rpc))
        .with_state(state)
}

async fn healthz() -> Json<Value> {
    Json(json!({"status": "ok", "system": "ubl-master", "pipeline": "KNOCK->WA->CHECK->TR->WF"}))
}

/// GET /v1/runtime/attestation — signed runtime self-attestation (PS3/F1).
async fn get_runtime_attestation(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    match state.pipeline.runtime_self_attestation() {
        Ok(attestation) => {
            let verified = attestation.verify().unwrap_or(false);
            (
                StatusCode::OK,
                Json(json!({
                    "@type": "ubl/runtime.attestation.response",
                    "verified": verified,
                    "attestation": attestation,
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "@type": "ubl/error",
                "code": "INTERNAL_ERROR",
                "message": e.to_string(),
            })),
        ),
    }
}

/// POST /v1/chips — process raw bytes through the full KNOCK→WA→CHECK→TR→WF pipeline.
///
/// Idempotent: if the chip was already processed (same @type/@ver/@world/@id),
/// returns the cached result with `X-UBL-Replay: true` header and `"replayed": true`
/// in the response body. No re-execution occurs.
async fn create_chip(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    let (status, headers, payload) = submit_chip_bytes(&state, &body).await;
    (status, headers, Json(payload))
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
            Json(
                json!({"@type": "ubl/error", "code": "INVALID_CID", "message": "CID must start with b3:"}),
            ),
        );
    }

    let chip = match state.chip_store.get_chip(&cid).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(
                    json!({"@type": "ubl/error", "code": "NOT_FOUND", "message": format!("Chip {} not found", cid)}),
                ),
            )
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({"@type": "ubl/error", "code": "INTERNAL_ERROR", "message": e.to_string()}),
                ),
            )
        }
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
    let receipt_exists = if receipt_cid.as_str().is_empty() {
        false
    } else {
        state
            .chip_store
            .get_chip_by_receipt_cid(receipt_cid.as_str())
            .await
            .map(|c| c.is_some())
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
            Json(
                json!({"@type": "ubl/error", "code": "INVALID_CID", "message": "CID must start with b3:"}),
            ),
        );
    }

    // ETag: If-None-Match → 304 (P1.6)
    if let Some(inm) = headers.get(header::IF_NONE_MATCH) {
        if let Ok(inm_str) = inm.to_str() {
            let etag = format!("\"{}\"", cid);
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
            let etag = format!("\"{}\"", chip.cid);
            h.insert(header::ETAG, etag.parse().unwrap());
            h.insert(
                header::CACHE_CONTROL,
                "public, max-age=31536000, immutable".parse().unwrap(),
            );
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
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            HeaderMap::new(),
            Json(
                json!({"@type": "ubl/error", "code": "NOT_FOUND", "message": format!("Chip {} not found", cid)}),
            ),
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
        tags: vec![format!("passport_cid:{}", passport_cid)],
        created_after: None,
        created_before: None,
        executor_did: None,
        limit: Some(100),
        offset: None,
    };

    match state.chip_store.query(&query).await {
        Ok(result) => {
            let advisories: Vec<Value> = result
                .chips
                .iter()
                .map(|c| {
                    json!({
                        "cid": c.cid,
                        "action": c.chip_data.get("action").unwrap_or(&json!("unknown")),
                        "hook": c.chip_data.get("hook").unwrap_or(&json!("unknown")),
                        "confidence": c.chip_data.get("confidence").unwrap_or(&json!(0)),
                        "model": c.chip_data.get("model").unwrap_or(&json!("unknown")),
                        "input_cid": c.chip_data.get("input_cid").unwrap_or(&json!("")),
                        "created_at": c.created_at,
                    })
                })
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
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(
                    json!({"@type": "ubl/error", "code": "NOT_FOUND", "message": format!("Advisory {} not found", cid)}),
                ),
            )
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({"@type": "ubl/error", "code": "INTERNAL_ERROR", "message": e.to_string()}),
                ),
            )
        }
    };

    if chip.chip_type != "ubl/advisory" {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({"@type": "ubl/error", "code": "INVALID_TYPE", "message": "Chip is not an advisory"}),
            ),
        );
    }

    // Parse the advisory
    let advisory = match ubl_runtime::advisory::Advisory::from_chip_body(&chip.chip_data) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(
                    json!({"@type": "ubl/error", "code": "INVALID_ADVISORY", "message": e.to_string()}),
                ),
            )
        }
    };

    // Recompute CID to verify integrity
    let nrf_bytes = match ubl_ai_nrf1::to_nrf1_bytes(&chip.chip_data) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({"@type": "ubl/error", "code": "ENCODING_ERROR", "message": e.to_string()}),
                ),
            )
        }
    };
    let computed_cid = match ubl_ai_nrf1::compute_cid(&nrf_bytes) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"@type": "ubl/error", "code": "CID_ERROR", "message": e.to_string()})),
            )
        }
    };

    let cid_valid = computed_cid == cid;

    // Check if the passport exists
    let passport_exists = state
        .chip_store
        .get_chip(&advisory.passport_cid)
        .await
        .map(|r| r.is_some())
        .unwrap_or(false);

    // Check if the input chip exists
    let input_exists = state
        .chip_store
        .get_chip(&advisory.input_cid)
        .await
        .map(|r| r.is_some())
        .unwrap_or(false);

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
    match state.chip_store.get_chip_by_receipt_cid(&cid).await {
        Ok(Some(chip)) => (
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
        ),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(
                json!({"@type": "ubl/error", "code": "NOT_FOUND", "message": format!("Receipt {} not found", cid)}),
            ),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"@type": "ubl/error", "code": "INTERNAL_ERROR", "message": e.to_string()})),
        ),
    }
}

#[derive(Debug, Deserialize)]
struct NarrateQuery {
    persist: Option<bool>,
}

/// GET /v1/receipts/:cid/narrate — deterministic on-demand narration for a receipt.
/// Optional `?persist=true` stores a `ubl/advisory` chip with hook `on_demand`.
async fn narrate_receipt(
    State(state): State<AppState>,
    Path(cid): Path<String>,
    Query(query): Query<NarrateQuery>,
) -> (StatusCode, Json<Value>) {
    let chip = match state.chip_store.get_chip_by_receipt_cid(&cid).await {
        Ok(Some(chip)) => chip,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "@type": "ubl/error",
                    "code": "NOT_FOUND",
                    "message": format!("Receipt {} not found", cid)
                })),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "@type": "ubl/error",
                    "code": "INTERNAL_ERROR",
                    "message": e.to_string()
                })),
            );
        }
    };

    let world = chip
        .chip_data
        .get("@world")
        .and_then(|v| v.as_str())
        .unwrap_or("a/system/t/unknown");
    let policy_count = chip.execution_metadata.policies_applied.len();
    let latency_ms = chip.execution_metadata.execution_time_ms;
    let fuel = chip.execution_metadata.fuel_consumed;
    let decision = "allow";

    let summary = format!(
        "{} processed as {} in {}ms (fuel {}, policies {}).",
        chip.chip_type, decision, latency_ms, fuel, policy_count
    );
    let narration = json!({
        "@type": "ubl/advisory.narration",
        "receipt_cid": cid,
        "chip_cid": chip.cid,
        "chip_type": chip.chip_type,
        "decision": decision,
        "world": world,
        "policy_count": policy_count,
        "latency_ms": latency_ms,
        "fuel_consumed": fuel,
        "summary": summary,
        "generated_at": chrono::Utc::now().to_rfc3339(),
    });

    let mut persisted_advisory_cid: Option<String> = None;
    if query.persist.unwrap_or(false) {
        let adv = Advisory::new(
            state.advisory_engine.passport_cid.clone(),
            "narrate".to_string(),
            cid.clone(),
            narration.clone(),
            90,
            state.advisory_engine.model.clone(),
            AdvisoryHook::OnDemand,
        );
        let body = state.advisory_engine.advisory_to_chip_body(&adv);
        let metadata = ubl_chipstore::ExecutionMetadata {
            runtime_version: "advisory/on-demand".to_string(),
            execution_time_ms: 0,
            fuel_consumed: 0,
            policies_applied: vec![],
            executor_did: chip.execution_metadata.executor_did.clone(),
            reproducible: true,
        };
        match state
            .chip_store
            .store_executed_chip(body, cid.clone(), metadata)
            .await
        {
            Ok(adv_cid) => persisted_advisory_cid = Some(adv_cid),
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "@type":"ubl/error",
                        "code":"INTERNAL_ERROR",
                        "message": format!("narration persist failed: {}", e),
                    })),
                );
            }
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "@type":"ubl/advisory.narration.response",
            "receipt_cid": cid,
            "narration": narration,
            "persisted_advisory_cid": persisted_advisory_cid,
        })),
    )
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
/// - ubl.deliver → same submission path as POST /v1/chips
/// - ubl.query → ChipStore get
/// - ubl.verify → CID recomputation
/// - ubl.narrate → receipt narration
/// - registry.listTypes → manifest chip types
async fn mcp_rpc(
    State(state): State<AppState>,
    Json(rpc): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let id = rpc.get("id").cloned().unwrap_or(json!(null));
    let method = rpc.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let params = rpc.get("params").cloned().unwrap_or(json!({}));

    if rpc.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -32600, "message": "Invalid Request: missing jsonrpc 2.0" }
            })),
        );
    }

    match method {
        "tools/list" => {
            let manifest = state.manifest.to_mcp_manifest();
            (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "tools": manifest["tools"] }
                })),
            )
        }

        "tools/call" => {
            let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            dispatch_tool_call(&state, tool_name, &arguments, id).await
        }

        _ => (
            StatusCode::OK,
            Json(json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -32601, "message": format!("Method not found: {}", method) }
            })),
        ),
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
            let (status, _headers, payload) = submit_chip_bytes(state, &bytes).await;
            if status.is_success() {
                (
                    StatusCode::OK,
                    Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": { "content": [{ "type": "text", "text": serde_json::to_string(&payload).unwrap_or_default() }] }
                    })),
                )
            } else {
                let (mcp_code, message) = serde_json::from_value::<UblError>(payload.clone())
                    .map(|e| (e.code.mcp_code(), e.message))
                    .unwrap_or_else(|_| {
                        let code = if status == StatusCode::TOO_MANY_REQUESTS {
                            -32006
                        } else if status == StatusCode::BAD_REQUEST
                            || status == StatusCode::UNPROCESSABLE_ENTITY
                        {
                            -32602
                        } else if status == StatusCode::UNAUTHORIZED {
                            -32001
                        } else if status == StatusCode::FORBIDDEN {
                            -32003
                        } else if status == StatusCode::NOT_FOUND {
                            -32004
                        } else if status == StatusCode::CONFLICT {
                            -32005
                        } else if status == StatusCode::SERVICE_UNAVAILABLE {
                            -32000
                        } else {
                            -32603
                        };
                        (code, format!("HTTP {}", status.as_u16()))
                    });
                (
                    StatusCode::OK,
                    Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": mcp_code, "message": message, "data": payload }
                    })),
                )
            }
        }

        "ubl.query" => {
            let cid = arguments.get("cid").and_then(|v| v.as_str()).unwrap_or("");
            match state.chip_store.get_chip(cid).await {
                Ok(Some(chip)) => (
                    StatusCode::OK,
                    Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": { "content": [{ "type": "text", "text": serde_json::to_string(&json!({
                            "cid": chip.cid, "chip_type": chip.chip_type,
                            "chip_data": chip.chip_data, "receipt_cid": chip.receipt_cid,
                        })).unwrap_or_default() }] }
                    })),
                ),
                Ok(None) => (
                    StatusCode::OK,
                    Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32004, "message": format!("Chip {} not found", cid) }
                    })),
                ),
                Err(e) => (
                    StatusCode::OK,
                    Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32603, "message": e.to_string() }
                    })),
                ),
            }
        }

        "ubl.verify" => {
            let cid = arguments.get("cid").and_then(|v| v.as_str()).unwrap_or("");
            match state.chip_store.get_chip(cid).await {
                Ok(Some(chip)) => {
                    let verified = match ubl_ai_nrf1::to_nrf1_bytes(&chip.chip_data) {
                        Ok(nrf) => ubl_ai_nrf1::compute_cid(&nrf)
                            .map(|c| c == cid)
                            .unwrap_or(false),
                        Err(_) => false,
                    };
                    (
                        StatusCode::OK,
                        Json(json!({
                            "jsonrpc": "2.0", "id": id,
                            "result": { "content": [{ "type": "text", "text": serde_json::to_string(&json!({
                                "cid": cid, "verified": verified
                            })).unwrap_or_default() }] }
                        })),
                    )
                }
                Ok(None) => (
                    StatusCode::OK,
                    Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32004, "message": format!("Chip {} not found", cid) }
                    })),
                ),
                Err(e) => (
                    StatusCode::OK,
                    Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32603, "message": e.to_string() }
                    })),
                ),
            }
        }

        "ubl.narrate" => {
            let receipt_cid = arguments.get("cid").and_then(|v| v.as_str()).unwrap_or("");
            let persist = arguments
                .get("persist")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if receipt_cid.is_empty() {
                return (
                    StatusCode::OK,
                    Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32602, "message": "missing required argument: cid" }
                    })),
                );
            }

            let chip = match state.chip_store.get_chip_by_receipt_cid(receipt_cid).await {
                Ok(Some(chip)) => chip,
                Ok(None) => {
                    return (
                        StatusCode::OK,
                        Json(json!({
                            "jsonrpc": "2.0", "id": id,
                            "error": { "code": -32004, "message": format!("Receipt {} not found", receipt_cid) }
                        })),
                    );
                }
                Err(e) => {
                    return (
                        StatusCode::OK,
                        Json(json!({
                            "jsonrpc": "2.0", "id": id,
                            "error": { "code": -32603, "message": e.to_string() }
                        })),
                    );
                }
            };

            let world = chip
                .chip_data
                .get("@world")
                .and_then(|v| v.as_str())
                .unwrap_or("a/system/t/unknown");
            let policy_count = chip.execution_metadata.policies_applied.len();
            let latency_ms = chip.execution_metadata.execution_time_ms;
            let fuel = chip.execution_metadata.fuel_consumed;
            let summary = format!(
                "{} processed as allow in {}ms (fuel {}, policies {}).",
                chip.chip_type, latency_ms, fuel, policy_count
            );
            let narration = json!({
                "@type": "ubl/advisory.narration",
                "receipt_cid": receipt_cid,
                "chip_cid": chip.cid,
                "chip_type": chip.chip_type,
                "decision": "allow",
                "world": world,
                "policy_count": policy_count,
                "latency_ms": latency_ms,
                "fuel_consumed": fuel,
                "summary": summary,
                "generated_at": chrono::Utc::now().to_rfc3339(),
            });

            let mut persisted_advisory_cid: Option<String> = None;
            if persist {
                let adv = Advisory::new(
                    state.advisory_engine.passport_cid.clone(),
                    "narrate".to_string(),
                    receipt_cid.to_string(),
                    narration.clone(),
                    90,
                    state.advisory_engine.model.clone(),
                    AdvisoryHook::OnDemand,
                );
                let body = state.advisory_engine.advisory_to_chip_body(&adv);
                let metadata = ubl_chipstore::ExecutionMetadata {
                    runtime_version: "advisory/on-demand".to_string(),
                    execution_time_ms: 0,
                    fuel_consumed: 0,
                    policies_applied: vec![],
                    executor_did: chip.execution_metadata.executor_did.clone(),
                    reproducible: true,
                };
                match state
                    .chip_store
                    .store_executed_chip(body, receipt_cid.to_string(), metadata)
                    .await
                {
                    Ok(adv_cid) => persisted_advisory_cid = Some(adv_cid),
                    Err(e) => {
                        return (
                            StatusCode::OK,
                            Json(json!({
                                "jsonrpc": "2.0", "id": id,
                                "error": { "code": -32603, "message": format!("narration persist failed: {}", e) }
                            })),
                        );
                    }
                }
            }

            (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "content": [{ "type": "text", "text": serde_json::to_string(&json!({
                        "receipt_cid": receipt_cid,
                        "narration": narration,
                        "persisted_advisory_cid": persisted_advisory_cid,
                    })).unwrap_or_default() }] }
                })),
            )
        }

        "registry.listTypes" => {
            let types: Vec<Value> = state.manifest.chip_types.iter().map(|ct| json!({
                "type": ct.chip_type, "description": ct.description, "required_cap": ct.required_cap,
            })).collect();
            (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "content": [{ "type": "text", "text": serde_json::to_string(&types).unwrap_or_default() }] }
                })),
            )
        }

        _ => (
            StatusCode::OK,
            Json(json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -32601, "message": format!("Tool not found: {}", tool_name) }
            })),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Method, Request};
    use tower::ServiceExt;
    use ubl_chipstore::InMemoryBackend;

    fn test_state(canon_limiter: Option<Arc<CanonRateLimiter>>) -> AppState {
        let backend = Arc::new(InMemoryBackend::new());
        let chip_store = Arc::new(ChipStore::new(backend));
        let mut pipeline = UblPipeline::with_chip_store(
            Box::new(InMemoryPolicyStorage::new()),
            chip_store.clone(),
        );
        let advisory_engine = Arc::new(AdvisoryEngine::new(
            "b3:test-passport".to_string(),
            "ubl-gate/test".to_string(),
            "a/system/t/test".to_string(),
        ));
        pipeline.set_advisory_engine(advisory_engine.clone());
        AppState {
            pipeline: Arc::new(pipeline),
            chip_store,
            manifest: Arc::new(GateManifest::default()),
            advisory_engine,
            canon_rate_limiter: canon_limiter,
        }
    }

    #[tokio::test]
    async fn chips_endpoint_accepts_post_and_rejects_other_write_verbs() {
        let app = build_router(test_state(None));
        let req = Request::builder()
            .method(Method::PUT)
            .uri("/v1/chips")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn chips_endpoint_idempotent_replay_sets_header_and_same_receipt() {
        let app = build_router(test_state(None));
        let chip = json!({
            "@type": "ubl/document",
            "@id": "gate-idem-1",
            "@ver": "1.0",
            "@world": "a/test/t/main",
            "title": "hello"
        });

        let req1 = Request::builder()
            .method(Method::POST)
            .uri("/v1/chips")
            .header("content-type", "application/json")
            .body(Body::from(chip.to_string()))
            .unwrap();
        let res1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(res1.status(), StatusCode::OK);
        assert!(res1.headers().get("X-UBL-Replay").is_none());
        let body1 = to_bytes(res1.into_body(), usize::MAX).await.unwrap();
        let v1: Value = serde_json::from_slice(&body1).unwrap();
        assert_eq!(v1["replayed"], Value::Bool(false));
        let cid1 = v1["receipt_cid"].as_str().unwrap().to_string();

        let req2 = Request::builder()
            .method(Method::POST)
            .uri("/v1/chips")
            .header("content-type", "application/json")
            .body(Body::from(chip.to_string()))
            .unwrap();
        let res2 = app.clone().oneshot(req2).await.unwrap();
        assert_eq!(res2.status(), StatusCode::OK);
        assert_eq!(
            res2.headers()
                .get("X-UBL-Replay")
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );
        let body2 = to_bytes(res2.into_body(), usize::MAX).await.unwrap();
        let v2: Value = serde_json::from_slice(&body2).unwrap();
        assert_eq!(v2["replayed"], Value::Bool(true));
        let cid2 = v2["receipt_cid"].as_str().unwrap().to_string();
        assert_eq!(cid1, cid2);
    }

    #[tokio::test]
    async fn chips_endpoint_canon_rate_limit_blocks_identical_payload_spam() {
        let limiter = Arc::new(CanonRateLimiter::new(RateLimitConfig::per_minute(1)));
        let app = build_router(test_state(Some(limiter)));
        let chip = json!({
            "@type": "ubl/document",
            "@id": "gate-rate-1",
            "@ver": "1.0",
            "@world": "a/test/t/main",
            "title": "same"
        });

        let req1 = Request::builder()
            .method(Method::POST)
            .uri("/v1/chips")
            .header("content-type", "application/json")
            .body(Body::from(chip.to_string()))
            .unwrap();
        let res1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(res1.status(), StatusCode::OK);

        let req2 = Request::builder()
            .method(Method::POST)
            .uri("/v1/chips")
            .header("content-type", "application/json")
            .body(Body::from(chip.to_string()))
            .unwrap();
        let res2 = app.oneshot(req2).await.unwrap();
        assert_eq!(res2.status(), StatusCode::TOO_MANY_REQUESTS);
        let body2 = to_bytes(res2.into_body(), usize::MAX).await.unwrap();
        let v2: Value = serde_json::from_slice(&body2).unwrap();
        assert_eq!(v2["code"], Value::String("TOO_MANY_REQUESTS".to_string()));
    }
}
