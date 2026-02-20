//! UBL Gate — the single HTTP entry point for the UBL pipeline.
//!
//! Every mutation is a chip. Every chip goes through KNOCK→WA→CHECK→TR→WF.
//! Every output is a receipt. Nothing bypasses the gate.

use askama::Template;
use async_stream::stream;
use axum::{
    body::Bytes,
    extract::{Form, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::sse::{Event as SseEvent, KeepAlive, Sse},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use ubl_chipstore::{ChipStore, SledBackend};
use ubl_eventstore::{EventQuery, EventStore};
use ubl_receipt::UnifiedReceipt;
use ubl_runtime::advisory::{Advisory, AdvisoryEngine, AdvisoryHook};
use ubl_runtime::durable_store::{DurableStore, OutboxEvent};
use ubl_runtime::error_response::{ErrorCode, UblError};
use ubl_runtime::event_bus::{EventBus, ReceiptEvent};
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
    http_client: reqwest::Client,
    canon_rate_limiter: Option<Arc<CanonRateLimiter>>,
    durable_store: Option<Arc<DurableStore>>,
    event_store: Option<Arc<EventStore>>,
}

fn outbox_endpoint_from_env() -> Option<String> {
    std::env::var("UBL_OUTBOX_ENDPOINT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

async fn deliver_emit_receipt_event(
    client: &reqwest::Client,
    endpoint: Option<&str>,
    event: OutboxEvent,
) -> Result<(), String> {
    let Some(endpoint) = endpoint else {
        warn!(
            event_id = event.id,
            "outbox: no endpoint configured, emit_receipt dropped"
        );
        return Ok(());
    };

    let payload = json!({
        "event_id": event.id,
        "event_type": event.event_type,
        "attempt": event.attempts.saturating_add(1),
        "payload": event.payload_json,
    });

    let response = client
        .post(endpoint)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("outbox http send failed: {}", e))?;

    let status = response.status();
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable body>".to_string());
        let body_snippet: String = body.chars().take(240).collect();
        return Err(format!(
            "outbox endpoint returned {} body={}",
            status, body_snippet
        ));
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    info!("starting UBL MASTER Gate");

    // Initialize shared components
    let _event_bus = Arc::new(EventBus::new());
    let backend = Arc::new(SledBackend::new("./data/chips")?);
    let chip_store = Arc::new(ChipStore::new_with_rebuild(backend).await?);

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
    let durable_store = match DurableStore::from_env() {
        Ok(Some(store)) => {
            let store = Arc::new(store);
            let workers: usize = std::env::var("UBL_OUTBOX_WORKERS")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1)
                .max(1);
            let outbox_endpoint = outbox_endpoint_from_env();
            if let Some(ref endpoint) = outbox_endpoint {
                info!(workers, endpoint = %endpoint, "outbox dispatcher started");
            } else {
                warn!(
                    workers,
                    "UBL_OUTBOX_ENDPOINT not set; emit_receipt outbox events will be dropped"
                );
            }
            let outbox_http_client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?;
            metrics::set_outbox_pending(store.outbox_pending().unwrap_or(0));

            for worker_id in 0..workers {
                let dispatcher = OutboxDispatcher::new((*store).clone()).with_backoff(2, 300);
                let store_for_metrics = store.clone();
                let outbox_endpoint_for_worker = outbox_endpoint.clone();
                let outbox_http_client_for_worker = outbox_http_client.clone();
                tokio::spawn(async move {
                    loop {
                        let processed = dispatcher
                            .run_once_async(64, |event| {
                                let outbox_endpoint = outbox_endpoint_for_worker.clone();
                                let outbox_http_client = outbox_http_client_for_worker.clone();
                                async move {
                                    if event.event_type == "emit_receipt" {
                                        return deliver_emit_receipt_event(
                                            &outbox_http_client,
                                            outbox_endpoint.as_deref(),
                                            event,
                                        )
                                        .await;
                                    }
                                    metrics::inc_outbox_retry();
                                    Err(format!("unknown outbox event type: {}", event.event_type))
                                }
                            })
                            .await;

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
            Some(store)
        }
        Ok(None) => None,
        Err(e) => {
            warn!(error = %e, "durable store init failed for gate");
            None
        }
    };

    let event_store = match EventStore::from_env() {
        Ok(Some(store)) => Some(Arc::new(store)),
        Ok(None) => None,
        Err(e) => {
            warn!(error = %e, "event store init failed for gate");
            None
        }
    };

    if let Some(store) = event_store.clone() {
        let mut rx = pipeline.event_bus.subscribe();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let hub = to_hub_event(&event);
                        let stage = hub
                            .get("stage")
                            .and_then(|v| v.as_str())
                            .unwrap_or("UNKNOWN")
                            .to_string();
                        let world = hub
                            .get("@world")
                            .and_then(|v| v.as_str())
                            .unwrap_or("a/system")
                            .to_string();
                        metrics::inc_events_ingested(&stage, &world);
                        if let Err(e) = store.append_event_json(&hub) {
                            warn!(error = %e, "event store append failed");
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        metrics::inc_events_stream_dropped("hub_lagged");
                        warn!(skipped, "event hub ingestion lagged");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        info!("event hub ingestion task started");
    }

    let manifest = Arc::new(GateManifest::default());

    let state = AppState {
        pipeline,
        chip_store,
        manifest,
        advisory_engine,
        http_client: reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?,
        canon_rate_limiter: load_canon_rate_limiter(),
        durable_store,
        event_store,
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

fn tamper_detected_error(message: String, details: Value) -> UblError {
    UblError {
        error_type: "ubl/error".to_string(),
        id: format!("err-tamper-{}", chrono::Utc::now().timestamp_micros()),
        ver: "1.0".to_string(),
        world: "a/system/t/errors".to_string(),
        code: ErrorCode::TamperDetected,
        message,
        link: "https://docs.ubl.agency/errors#TAMPER_DETECTED".to_string(),
        details: Some(details),
    }
}

fn verify_receipt_auth_chain(receipt_cid: &str, receipt_json: &Value) -> Result<(), UblError> {
    let receipt = UnifiedReceipt::from_json(receipt_json).map_err(|e| {
        tamper_detected_error(
            format!("receipt {} parse failed: {}", receipt_cid, e),
            json!({
                "receipt_cid": receipt_cid,
                "reason": "receipt_parse_failed"
            }),
        )
    })?;

    if !receipt.verify_auth_chain() {
        return Err(tamper_detected_error(
            format!("receipt {} auth chain broken", receipt_cid),
            json!({
                "receipt_cid": receipt_cid,
                "reason": "auth_chain_broken"
            }),
        ));
    }

    Ok(())
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

#[derive(Debug, Deserialize, Clone, Default)]
struct EventStreamQuery {
    world: Option<String>,
    stage: Option<String>,
    decision: Option<String>,
    code: Option<String>,
    #[serde(rename = "type")]
    chip_type: Option<String>,
    actor: Option<String>,
    since: Option<String>,
    limit: Option<usize>,
}

async fn stream_events(
    State(state): State<AppState>,
    Query(query): Query<EventStreamQuery>,
) -> Response {
    let Some(store) = state.event_store.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "@type": "ubl/error",
                "code": "UNAVAILABLE",
                "message": "Event hub unavailable: enable EventStore",
            })),
        )
            .into_response();
    };

    let world_label = query.world.clone().unwrap_or_else(|| "*".to_string());
    let db_query = EventQuery {
        world: query.world.clone(),
        stage: query.stage.clone(),
        decision: query.decision.clone(),
        code: query.code.clone(),
        chip_type: query.chip_type.clone(),
        actor: query.actor.clone(),
        since: query.since.clone(),
        limit: query.limit,
    };

    let historical = match store.query(&db_query) {
        Ok(events) => events,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "@type": "ubl/error",
                    "code": "INTERNAL_ERROR",
                    "message": format!("event query failed: {}", e),
                })),
            )
                .into_response();
        }
    };

    struct StreamClientGuard {
        world: String,
    }
    impl Drop for StreamClientGuard {
        fn drop(&mut self) {
            metrics::dec_events_stream_clients(&self.world);
        }
    }

    metrics::inc_events_stream_clients(&world_label);
    let mut rx = state.pipeline.event_bus.subscribe();
    let stream_world = world_label.clone();
    let live_filters = query.clone();
    let sse_stream = stream! {
        let _guard = StreamClientGuard { world: stream_world };

        for event in historical {
            let payload = match serde_json::to_string(&event) {
                Ok(p) => p,
                Err(_) => {
                    metrics::inc_events_stream_dropped("serialize_error");
                    continue;
                }
            };
            let id = event.get("@id").and_then(|v| v.as_str()).unwrap_or("evt");
            yield Ok::<SseEvent, Infallible>(SseEvent::default().id(id).event("ubl.event").data(payload));
        }

        loop {
            match rx.recv().await {
                Ok(receipt_event) => {
                    let hub = to_hub_event(&receipt_event);
                    if !hub_matches_query(&hub, &live_filters) {
                        continue;
                    }
                    let payload = match serde_json::to_string(&hub) {
                        Ok(p) => p,
                        Err(_) => {
                            metrics::inc_events_stream_dropped("serialize_error");
                            continue;
                        }
                    };
                    let id = hub.get("@id").and_then(|v| v.as_str()).unwrap_or("evt");
                    yield Ok::<SseEvent, Infallible>(SseEvent::default().id(id).event("ubl.event").data(payload));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    metrics::inc_events_stream_dropped("client_lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Sse::new(sse_stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(10))
                .text("heartbeat"),
        )
        .into_response()
}

#[derive(Debug, Deserialize, Clone, Default)]
struct EventSearchQuery {
    world: Option<String>,
    stage: Option<String>,
    decision: Option<String>,
    code: Option<String>,
    #[serde(rename = "type")]
    chip_type: Option<String>,
    actor: Option<String>,
    from: Option<String>,
    to: Option<String>,
    page_key: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct AdvisorQuery {
    world: Option<String>,
    window: Option<String>,
    interval_ms: Option<u64>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct Mock24hQuery {
    world: Option<String>,
    profile: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct LlmPanelQuery {
    page: Option<String>,
    tab: Option<String>,
    world: Option<String>,
    kind: Option<String>,
    profile: Option<String>,
    cid: Option<String>,
    #[serde(rename = "type")]
    chip_type: Option<String>,
}

async fn search_events(
    State(state): State<AppState>,
    Query(query): Query<EventSearchQuery>,
) -> Response {
    let Some(store) = state.event_store.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "@type": "ubl/error",
                "code": "UNAVAILABLE",
                "message": "Event hub unavailable: enable EventStore",
            })),
        )
            .into_response();
    };

    let since = query
        .page_key
        .clone()
        .or_else(|| query.from.clone())
        .or_else(|| Some("0".to_string()));

    let db_query = EventQuery {
        world: query.world.clone(),
        stage: query.stage.clone(),
        decision: query.decision.clone(),
        code: query.code.clone(),
        chip_type: query.chip_type.clone(),
        actor: query.actor.clone(),
        since,
        limit: query.limit,
    };

    let mut events = match store.query(&db_query) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "@type": "ubl/error",
                    "code": "INTERNAL_ERROR",
                    "message": format!("event search failed: {}", e),
                })),
            )
                .into_response();
        }
    };

    if let Some(to) = query.to.as_deref().and_then(parse_when_to_ms) {
        events.retain(|e| {
            let when = e
                .get("when")
                .and_then(|v| v.as_str())
                .or_else(|| e.get("timestamp").and_then(|v| v.as_str()));
            when.and_then(parse_when_to_ms).is_some_and(|ms| ms <= to)
        });
    }

    let next_page_key = events
        .last()
        .and_then(|e| {
            e.get("when")
                .and_then(|v| v.as_str())
                .or_else(|| e.get("timestamp").and_then(|v| v.as_str()))
        })
        .map(ToString::to_string);

    (
        StatusCode::OK,
        Json(json!({
            "@type": "ubl/events.search.response",
            "count": events.len(),
            "next_page_key": next_page_key,
            "events": events,
        })),
    )
        .into_response()
}

async fn advisor_snapshots(
    State(state): State<AppState>,
    Query(query): Query<AdvisorQuery>,
) -> Response {
    let Some(store) = state.event_store.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "@type": "ubl/error",
                "code": "UNAVAILABLE",
                "message": "Advisor snapshot unavailable: enable EventStore",
            })),
        )
            .into_response();
    };

    let window = parse_window_duration(query.window.as_deref()).unwrap_or(Duration::from_secs(300));
    let limit = query.limit.unwrap_or(10_000).clamp(100, 50_000);
    match build_advisor_snapshot(&state, store, query.world.as_deref(), window, limit) {
        Ok(frame) => (
            StatusCode::OK,
            Json(json!({
                "@type": "ubl/advisor.snapshot",
                "window_ms": window.as_millis() as u64,
                "snapshot": frame,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "@type": "ubl/error",
                "code": "INTERNAL_ERROR",
                "message": format!("advisor snapshot failed: {}", e),
            })),
        )
            .into_response(),
    }
}

async fn advisor_tap(State(state): State<AppState>, Query(query): Query<AdvisorQuery>) -> Response {
    let Some(store) = state.event_store.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "@type": "ubl/error",
                "code": "UNAVAILABLE",
                "message": "Advisor tap unavailable: enable EventStore",
            })),
        )
            .into_response();
    };

    let window = parse_window_duration(query.window.as_deref()).unwrap_or(Duration::from_secs(300));
    let interval = Duration::from_millis(query.interval_ms.unwrap_or(2_000).clamp(1_000, 5_000));
    let limit = query.limit.unwrap_or(10_000).clamp(100, 50_000);
    let world_filter = query.world.clone();
    let state_for_stream = state.clone();

    let sse_stream = stream! {
        loop {
            match build_advisor_snapshot(&state_for_stream, &store, world_filter.as_deref(), window, limit) {
                Ok(frame) => {
                    let payload = match serde_json::to_string(&frame) {
                        Ok(v) => v,
                        Err(_) => {
                            metrics::inc_events_stream_dropped("advisor_tap_serialize_error");
                            tokio::time::sleep(interval).await;
                            continue;
                        }
                    };
                    let id = frame.get("@id").and_then(|v| v.as_str()).unwrap_or("adv");
                    yield Ok::<SseEvent, Infallible>(SseEvent::default().id(id).event("ubl.advisor.frame").data(payload));
                }
                Err(_) => {
                    metrics::inc_events_stream_dropped("advisor_tap_query_error");
                }
            }
            tokio::time::sleep(interval).await;
        }
    };

    Sse::new(sse_stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(10))
                .text("heartbeat"),
        )
        .into_response()
}

fn parse_when_to_ms(input: &str) -> Option<i64> {
    if let Ok(ms) = input.parse::<i64>() {
        return Some(ms);
    }
    chrono::DateTime::parse_from_rfc3339(input)
        .ok()
        .map(|dt| dt.timestamp_millis())
}

fn parse_window_duration(input: Option<&str>) -> Option<Duration> {
    let raw = input?.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(ms) = raw.parse::<u64>() {
        return Some(Duration::from_millis(ms));
    }
    let (num, unit) = raw.split_at(raw.len().saturating_sub(1));
    let value = num.parse::<u64>().ok()?;
    match unit {
        "s" | "S" => Some(Duration::from_secs(value)),
        "m" | "M" => Some(Duration::from_secs(value.saturating_mul(60))),
        "h" | "H" => Some(Duration::from_secs(value.saturating_mul(3600))),
        _ => None,
    }
}

fn build_advisor_snapshot(
    state: &AppState,
    store: &EventStore,
    world: Option<&str>,
    window: Duration,
    limit: usize,
) -> Result<Value, String> {
    let now = chrono::Utc::now();
    let since = now
        .checked_sub_signed(chrono::Duration::from_std(window).map_err(|e| e.to_string())?)
        .ok_or_else(|| "window underflow".to_string())?;

    let query = EventQuery {
        world: world.map(ToString::to_string),
        since: Some(since.timestamp_millis().to_string()),
        limit: Some(limit),
        ..Default::default()
    };
    let events = store.query(&query).map_err(|e| e.to_string())?;

    let mut by_stage = std::collections::BTreeMap::<String, u64>::new();
    let mut by_decision = std::collections::BTreeMap::<String, u64>::new();
    let mut by_code = std::collections::BTreeMap::<String, u64>::new();
    let mut lat_stage = std::collections::BTreeMap::<String, Vec<f64>>::new();
    let mut outliers: Vec<(f64, Value)> = Vec::new();

    for event in &events {
        if let Some(stage) = event.get("stage").and_then(|v| v.as_str()) {
            *by_stage.entry(stage.to_string()).or_default() += 1;
        }
        if let Some(decision) = event
            .get("receipt")
            .and_then(|v| v.get("decision"))
            .and_then(|v| v.as_str())
        {
            *by_decision.entry(decision.to_string()).or_default() += 1;
        }
        if let Some(code) = event
            .get("receipt")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str())
        {
            *by_code.entry(code.to_string()).or_default() += 1;
        }
        if let Some(lat) = event
            .get("perf")
            .and_then(|v| v.get("latency_ms"))
            .and_then(|v| v.as_f64())
        {
            let stage = event
                .get("stage")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();
            lat_stage.entry(stage).or_default().push(lat);
            outliers.push((
                lat,
                json!({
                    "receipt_cid": event.get("receipt").and_then(|v| v.get("cid")).cloned().unwrap_or(Value::Null),
                    "stage": event.get("stage").cloned().unwrap_or(Value::Null),
                    "chip_type": event.get("chip").and_then(|v| v.get("type")).cloned().unwrap_or(Value::Null),
                    "latency_ms": lat,
                }),
            ));
        }
    }

    let mut p95_by_stage = serde_json::Map::new();
    for (stage, mut vals) in lat_stage {
        vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let idx = ((vals.len() - 1) as f64 * 0.95).round() as usize;
        p95_by_stage.insert(stage, json!(vals[idx]));
    }

    outliers.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let top_outliers: Vec<Value> = outliers.into_iter().take(5).map(|(_, v)| v).collect();

    let samples: Vec<Value> = events
        .iter()
        .rev()
        .take(5)
        .map(|event| {
            json!({
                "event_id": event.get("@id").cloned().unwrap_or(Value::Null),
                "when": event.get("when").cloned().unwrap_or(Value::Null),
                "stage": event.get("stage").cloned().unwrap_or(Value::Null),
                "chip_type": event.get("chip").and_then(|v| v.get("type")).cloned().unwrap_or(Value::Null),
                "receipt_cid": event.get("receipt").and_then(|v| v.get("cid")).cloned().unwrap_or(Value::Null),
                "decision": event.get("receipt").and_then(|v| v.get("decision")).cloned().unwrap_or(Value::Null),
                "code": event.get("receipt").and_then(|v| v.get("code")).cloned().unwrap_or(Value::Null),
            })
        })
        .collect();

    let outbox_pending = state
        .durable_store
        .as_ref()
        .and_then(|store| store.outbox_pending().ok());

    Ok(json!({
        "@type": "ubl/advisor.tap.frame",
        "@ver": "1.0.0",
        "@id": format!("adv-{}", now.timestamp_millis()),
        "@world": world.unwrap_or("*"),
        "generated_at": now.to_rfc3339(),
        "window_ms": window.as_millis() as u64,
        "counts": {
            "stage": by_stage,
            "decision": by_decision,
            "code": by_code,
        },
        "latency_ms_p95_by_stage": Value::Object(p95_by_stage),
        "top_outliers": top_outliers,
        "samples": samples,
        "outbox": {
            "pending": outbox_pending,
            "retries": Value::Null,
        },
    }))
}

#[derive(Debug, Clone, serde::Serialize)]
struct RegistryView {
    types: std::collections::BTreeMap<String, RegistryTypeView>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RegistryTypeView {
    chip_type: String,
    latest_version: Option<String>,
    deprecated: bool,
    has_kats: bool,
    required_cap: Option<String>,
    description: Option<String>,
    docs_url: Option<String>,
    deprecation: Option<Value>,
    last_cid: Option<String>,
    last_updated_at: Option<String>,
    versions: std::collections::BTreeMap<String, RegistryVersionView>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RegistryVersionView {
    version: String,
    schema: Option<Value>,
    kats: Vec<Value>,
    required_cap: Option<String>,
    register_cid: Option<String>,
    updated_at: Option<String>,
}

#[derive(Template)]
#[template(path = "console.html")]
struct ConsoleTemplate {
    world: String,
    tab: String,
    is_stats: bool,
    profile: String,
}

#[derive(Template)]
#[template(path = "console_kpis.html")]
struct ConsoleKpisTemplate {
    available: bool,
    message: String,
    generated_at: String,
    total_events: u64,
    allow_count: u64,
    deny_count: u64,
    outbox_pending: String,
    visible_p95_rows: Vec<StageP95Row>,
    hidden_p95_rows: Vec<StageP95Row>,
}

#[derive(Clone)]
struct StageP95Row {
    stage: String,
    p95_ms: String,
}

#[derive(Template)]
#[template(path = "console_events.html")]
struct ConsoleEventsTemplate {
    available: bool,
    message: String,
    visible_rows: Vec<ConsoleEventRow>,
    hidden_rows: Vec<ConsoleEventRow>,
}

#[derive(Clone)]
struct ConsoleEventRow {
    when: String,
    stage: String,
    decision: String,
    chip_type: String,
    code: String,
    receipt_cid: String,
}

#[derive(Template)]
#[template(path = "registry.html")]
struct RegistryTemplate {
    world: String,
}

#[derive(Template)]
#[template(path = "registry_table.html")]
struct RegistryTableTemplate {
    visible_rows: Vec<RegistryRow>,
    hidden_rows: Vec<RegistryRow>,
}

#[derive(Clone)]
struct RegistryRow {
    chip_type: String,
    latest_version: String,
    deprecated: bool,
    has_kats: bool,
    required_cap: String,
    last_updated_at: String,
}

#[derive(Template)]
#[template(path = "registry_type.html")]
struct RegistryTypeTemplate {
    chip_type: String,
    latest_version: String,
    deprecated: bool,
    description: String,
    docs_url: Option<String>,
    deprecation_json: String,
    versions: Vec<RegistryTypeVersionRow>,
}

#[derive(Clone)]
struct RegistryTypeVersionRow {
    version: String,
    required_cap: String,
    kats_count: usize,
    register_cid: String,
    updated_at: String,
    kats: Vec<RegistryKatRow>,
}

#[derive(Clone)]
struct RegistryKatRow {
    index: usize,
    label: String,
    expected_decision: String,
    expected_error: String,
    input_json_preview: String,
}

#[derive(Template)]
#[template(path = "registry_kat_result.html")]
struct RegistryKatResultTemplate {
    status_code: u16,
    kat_label: String,
    expected_decision: String,
    expected_error: String,
    actual_decision: String,
    actual_error: String,
    receipt_cid: String,
    pass: bool,
    response_json: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct RegistryKatTestForm {
    chip_type: String,
    version: String,
    kat_index: usize,
}

#[derive(Template)]
#[template(path = "console_receipt.html")]
struct ConsoleReceiptTemplate {
    cid: String,
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditTemplate {
    world: String,
    kind: String,
}

#[derive(Template)]
#[template(path = "audit_table.html")]
struct AuditTableTemplate {
    kind: String,
    visible_rows: Vec<AuditRow>,
    hidden_rows: Vec<AuditRow>,
}

#[derive(Clone)]
struct AuditRow {
    cid: String,
    chip_type: String,
    world: String,
    created_at: String,
    summary: String,
}

#[derive(Template)]
#[template(path = "console_mock24h.html")]
struct ConsoleMock24hTemplate {
    profile: String,
    generated_at: String,
    visible_rows: Vec<MockHourRow>,
    hidden_rows: Vec<MockHourRow>,
}

#[derive(Clone, serde::Serialize)]
struct MockHourRow {
    hour_label: String,
    events: u64,
    allow_pct: String,
    deny_pct: String,
    p95_ms: String,
    outbox_pending: u64,
    error_pct: String,
}

#[derive(Template)]
#[template(path = "llm_panel.html")]
struct LlmPanelTemplate {
    title: String,
    severity: String,
    source: String,
    generated_at: String,
    summary: String,
    bullets: Vec<String>,
}

fn render_html<T: Template>(template: &T) -> Response {
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "@type":"ubl/error",
                "code":"INTERNAL_ERROR",
                "message": format!("template render failed: {}", e),
            })),
        )
            .into_response(),
    }
}

fn split_rows<T: Clone>(rows: Vec<T>, keep: usize) -> (Vec<T>, Vec<T>) {
    let split = rows.len().min(keep);
    let (visible, hidden) = rows.split_at(split);
    (visible.to_vec(), hidden.to_vec())
}

fn normalize_console_tab(raw: &str) -> String {
    match raw.to_ascii_lowercase().as_str() {
        "stats" | "stat" | "estatisticas" => "stats".to_string(),
        _ => "live".to_string(),
    }
}

fn normalize_mock_profile(raw: &str) -> String {
    match raw.to_ascii_lowercase().as_str() {
        "spiky" => "spiky".to_string(),
        "degraded" => "degraded".to_string(),
        "chaos" => "chaos".to_string(),
        _ => "normal".to_string(),
    }
}

async fn console_page(Query(query): Query<std::collections::BTreeMap<String, String>>) -> Response {
    let world = query
        .get("world")
        .cloned()
        .unwrap_or_else(|| "*".to_string());
    let tab = query
        .get("tab")
        .map(|v| normalize_console_tab(v))
        .unwrap_or_else(|| "live".to_string());
    let profile =
        normalize_mock_profile(query.get("profile").map(String::as_str).unwrap_or("normal"));
    let is_stats = tab == "stats";
    render_html(&ConsoleTemplate {
        world,
        tab,
        is_stats,
        profile,
    })
}

async fn console_kpis_partial(
    State(state): State<AppState>,
    Query(query): Query<std::collections::BTreeMap<String, String>>,
) -> Response {
    let world = query
        .get("world")
        .map(|w| w.as_str())
        .filter(|w| !w.trim().is_empty() && *w != "*");
    let Some(store) = state.event_store.as_ref() else {
        return render_html(&ConsoleKpisTemplate {
            available: false,
            message: "EventStore unavailable".to_string(),
            generated_at: "-".to_string(),
            total_events: 0,
            allow_count: 0,
            deny_count: 0,
            outbox_pending: "-".to_string(),
            visible_p95_rows: Vec::new(),
            hidden_p95_rows: Vec::new(),
        });
    };
    let snapshot =
        match build_advisor_snapshot(&state, store, world, Duration::from_secs(300), 5000) {
            Ok(s) => s,
            Err(e) => {
                return render_html(&ConsoleKpisTemplate {
                    available: false,
                    message: format!("Snapshot error: {}", e),
                    generated_at: "-".to_string(),
                    total_events: 0,
                    allow_count: 0,
                    deny_count: 0,
                    outbox_pending: "-".to_string(),
                    visible_p95_rows: Vec::new(),
                    hidden_p95_rows: Vec::new(),
                });
            }
        };

    let mut total_events = 0u64;
    if let Some(map) = snapshot
        .get("counts")
        .and_then(|c| c.get("stage"))
        .and_then(|v| v.as_object())
    {
        for value in map.values() {
            total_events = total_events.saturating_add(value.as_u64().unwrap_or(0));
        }
    }

    let allow_count = snapshot
        .get("counts")
        .and_then(|c| c.get("decision"))
        .and_then(|d| d.get("ALLOW"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let deny_count = snapshot
        .get("counts")
        .and_then(|c| c.get("decision"))
        .and_then(|d| d.get("DENY"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let outbox_pending = snapshot
        .get("outbox")
        .and_then(|o| o.get("pending"))
        .and_then(|v| v.as_i64())
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());

    let generated_at = snapshot
        .get("generated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string();

    let mut p95_rows = Vec::new();
    if let Some(map) = snapshot
        .get("latency_ms_p95_by_stage")
        .and_then(|v| v.as_object())
    {
        for (stage, value) in map {
            let p95_ms = value
                .as_f64()
                .map(|v| format!("{:.2}", v))
                .unwrap_or_else(|| "-".to_string());
            p95_rows.push(StageP95Row {
                stage: stage.clone(),
                p95_ms,
            });
        }
    }
    p95_rows.sort_by(|a, b| a.stage.cmp(&b.stage));
    let (visible_p95_rows, hidden_p95_rows) = split_rows(p95_rows, 6);

    render_html(&ConsoleKpisTemplate {
        available: true,
        message: String::new(),
        generated_at,
        total_events,
        allow_count,
        deny_count,
        outbox_pending,
        visible_p95_rows,
        hidden_p95_rows,
    })
}

async fn console_events_partial(
    State(state): State<AppState>,
    Query(query): Query<std::collections::BTreeMap<String, String>>,
) -> Response {
    let world = query
        .get("world")
        .map(|w| w.as_str())
        .filter(|w| !w.trim().is_empty() && *w != "*");
    let Some(store) = state.event_store.as_ref() else {
        return render_html(&ConsoleEventsTemplate {
            available: false,
            message: "EventStore unavailable".to_string(),
            visible_rows: Vec::new(),
            hidden_rows: Vec::new(),
        });
    };
    let events = match store.query(&EventQuery {
        world: world.map(ToString::to_string),
        limit: Some(20),
        ..Default::default()
    }) {
        Ok(v) => v,
        Err(e) => {
            return render_html(&ConsoleEventsTemplate {
                available: false,
                message: format!("Events query error: {}", e),
                visible_rows: Vec::new(),
                hidden_rows: Vec::new(),
            });
        }
    };

    let rows: Vec<ConsoleEventRow> = events
        .iter()
        .rev()
        .map(|event| ConsoleEventRow {
            when: event
                .get("when")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_string(),
            stage: event
                .get("stage")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_string(),
            decision: event
                .get("receipt")
                .and_then(|v| v.get("decision"))
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_string(),
            chip_type: event
                .get("chip")
                .and_then(|v| v.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_string(),
            code: event
                .get("receipt")
                .and_then(|v| v.get("code"))
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_string(),
            receipt_cid: event
                .get("receipt")
                .and_then(|v| v.get("cid"))
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_string(),
        })
        .collect();

    let (visible_rows, hidden_rows) = split_rows(rows, 6);

    render_html(&ConsoleEventsTemplate {
        available: true,
        message: String::new(),
        visible_rows,
        hidden_rows,
    })
}

async fn console_mock24h_partial(
    Query(query): Query<std::collections::BTreeMap<String, String>>,
) -> Response {
    let world = query
        .get("world")
        .cloned()
        .unwrap_or_else(|| "*".to_string());
    let profile =
        normalize_mock_profile(query.get("profile").map(String::as_str).unwrap_or("normal"));
    let rows = build_mock_24h_rows(&profile, &world);
    let (visible_rows, hidden_rows) = split_rows(rows, 6);
    render_html(&ConsoleMock24hTemplate {
        profile,
        generated_at: chrono::Utc::now().to_rfc3339(),
        visible_rows,
        hidden_rows,
    })
}

async fn mock24h_api(Query(query): Query<Mock24hQuery>) -> (StatusCode, Json<Value>) {
    let world = query.world.unwrap_or_else(|| "*".to_string());
    let profile = normalize_mock_profile(query.profile.as_deref().unwrap_or("normal"));
    let rows = build_mock_24h_rows(&profile, &world);
    (
        StatusCode::OK,
        Json(json!({
            "@type": "ubl/mock.system24h",
            "world": world,
            "profile": profile,
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "rows": rows,
        })),
    )
}

fn build_mock_24h_rows(profile: &str, world: &str) -> Vec<MockHourRow> {
    let profile = normalize_mock_profile(profile);
    let seed = stable_seed(&format!("{}|{}", profile, world));
    let now = chrono::Utc::now();
    let mut rows = Vec::with_capacity(24);

    for hour_back in 0..24u64 {
        let ts = now - chrono::Duration::hours(hour_back as i64);
        let slot = 23 - hour_back;
        let n1 = mix64(seed ^ slot.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let n2 = mix64(seed ^ slot.wrapping_mul(0xBF58_476D_1CE4_E5B9));
        let wave = ((slot as f64 / 24.0) * std::f64::consts::TAU).sin();

        let base_events = match profile.as_str() {
            "spiky" => 820i64,
            "degraded" => 700i64,
            "chaos" => 620i64,
            _ => 900i64,
        };
        let mut events = base_events + (wave * 140.0) as i64 + ((n1 % 220) as i64 - 110);
        let mut deny_pct = 1.6 + ((n2 % 60) as f64 / 20.0);
        let mut p95_ms = 38.0 + ((n1 % 65) as f64);
        let mut outbox_pending = (n2 % 18) as i64;
        let mut error_pct = 0.20 + ((n1 % 30) as f64 / 120.0);

        if profile == "spiky" && slot % 7 == 0 {
            events += 820;
            p95_ms += 130.0;
            deny_pct += 3.4;
            outbox_pending += 45;
            error_pct += 1.2;
        }
        if profile == "degraded" {
            events -= 130;
            p95_ms += 95.0;
            deny_pct += 4.8;
            outbox_pending += 38;
            error_pct += 1.4;
        }
        if profile == "chaos" {
            let flip = (n2 % 3) as i64 - 1;
            events += flip * 350;
            p95_ms += ((n1 % 180) as f64) * 0.9;
            deny_pct += ((n2 % 90) as f64) / 12.0;
            outbox_pending += (n1 % 90) as i64;
            error_pct += ((n2 % 70) as f64) / 20.0;
        }

        events = events.max(80);
        outbox_pending = outbox_pending.max(0);
        deny_pct = deny_pct.clamp(0.2, 48.0);
        error_pct = error_pct.clamp(0.05, 22.0);
        let allow_pct = (100.0 - deny_pct - (error_pct * 0.25)).clamp(40.0, 99.5);

        rows.push(MockHourRow {
            hour_label: ts.format("%m-%d %H:00").to_string(),
            events: events as u64,
            allow_pct: format!("{:.2}", allow_pct),
            deny_pct: format!("{:.2}", deny_pct),
            p95_ms: format!("{:.1}", p95_ms),
            outbox_pending: outbox_pending as u64,
            error_pct: format!("{:.2}", error_pct),
        });
    }

    rows
}

fn stable_seed(input: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    input.hash(&mut hasher);
    hasher.finish()
}

fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

async fn ui_llm_panel(
    State(state): State<AppState>,
    Query(query): Query<LlmPanelQuery>,
) -> Response {
    let page = query.page.unwrap_or_else(|| "console".to_string());
    let tab = normalize_console_tab(query.tab.as_deref().unwrap_or("live"));
    let world = query.world.unwrap_or_else(|| "*".to_string());
    let profile = normalize_mock_profile(query.profile.as_deref().unwrap_or("normal"));
    let kind = query.kind.unwrap_or_else(|| "reports".to_string());
    let chip_type = query.chip_type.unwrap_or_default();
    let cid = query.cid.unwrap_or_default();

    let context = build_llm_context(
        &state, &page, &tab, &world, &profile, &kind, &chip_type, &cid,
    )
    .await;

    let (mut severity, mut summary, mut bullets) = heuristic_analysis(&page, &context);
    let mut source = "heuristic local mock".to_string();

    if env_bool("UBL_ENABLE_REAL_LLM", false) {
        if let Ok(text) = call_real_llm(&state.http_client, &page, &context).await {
            let (llm_summary, llm_bullets) = parse_llm_text(&text);
            summary = llm_summary;
            if !llm_bullets.is_empty() {
                bullets = llm_bullets;
            }
            severity = "LLM opinion".to_string();
            source = "real llm (openai responses api)".to_string();
        }
    }

    let title = match page.as_str() {
        "registry" => "Registry".to_string(),
        "registry_type" => format!("Registry Type {}", chip_type),
        "audit" => format!("Audit {}", kind),
        "receipt" => format!("Receipt {}", cid),
        _ => format!("Console {}", tab),
    };

    render_html(&LlmPanelTemplate {
        title,
        severity,
        source,
        generated_at: chrono::Utc::now().to_rfc3339(),
        summary,
        bullets,
    })
}

async fn build_llm_context(
    state: &AppState,
    page: &str,
    tab: &str,
    world: &str,
    profile: &str,
    kind: &str,
    chip_type: &str,
    cid: &str,
) -> Value {
    let world_filter = if world.trim().is_empty() || world == "*" {
        None
    } else {
        Some(world)
    };

    match page {
        "registry" => match materialize_registry(state, world_filter).await {
            Ok(registry) => {
                let total = registry.types.len();
                let deprecated = registry.types.values().filter(|v| v.deprecated).count();
                let without_kats = registry.types.values().filter(|v| !v.has_kats).count();
                json!({
                    "page": "registry",
                    "world": world,
                    "types_total": total,
                    "deprecated_total": deprecated,
                    "without_kats_total": without_kats,
                })
            }
            Err(e) => json!({
                "page": "registry",
                "world": world,
                "error": e
            }),
        },
        "registry_type" => match materialize_registry(state, None).await {
            Ok(registry) => {
                let view = registry.types.get(chip_type);
                json!({
                    "page": "registry_type",
                    "chip_type": chip_type,
                    "exists": view.is_some(),
                    "deprecated": view.map(|v| v.deprecated).unwrap_or(false),
                    "versions_total": view.map(|v| v.versions.len()).unwrap_or(0),
                    "has_kats": view.map(|v| v.has_kats).unwrap_or(false),
                })
            }
            Err(e) => json!({
                "page": "registry_type",
                "chip_type": chip_type,
                "error": e
            }),
        },
        "audit" => match query_audit_rows(state, kind, world_filter, 100).await {
            Ok(rows) => {
                let count = rows.len();
                json!({
                    "page": "audit",
                    "kind": kind,
                    "world": world,
                    "rows": count,
                    "latest_cid": rows.first().map(|r| r.cid.clone()).unwrap_or_else(|| "-".to_string())
                })
            }
            Err(e) => json!({
                "page": "audit",
                "kind": kind,
                "world": world,
                "error": e
            }),
        },
        "receipt" => {
            let exists = if cid.is_empty() {
                false
            } else {
                state
                    .chip_store
                    .get_chip(cid)
                    .await
                    .ok()
                    .flatten()
                    .is_some()
            };
            json!({
                "page": "receipt",
                "cid": cid,
                "exists": exists,
            })
        }
        _ => {
            let mock_rows = build_mock_24h_rows(profile, world);
            let sample = mock_rows.iter().take(6).collect::<Vec<_>>();
            let deny_avg = sample
                .iter()
                .filter_map(|r| r.deny_pct.parse::<f64>().ok())
                .sum::<f64>()
                / sample.len().max(1) as f64;
            let p95_max = sample
                .iter()
                .filter_map(|r| r.p95_ms.parse::<f64>().ok())
                .fold(0.0f64, f64::max);
            let outbox_max = sample.iter().map(|r| r.outbox_pending).max().unwrap_or(0);
            let events_sum: u64 = sample.iter().map(|r| r.events).sum();

            let mut base = json!({
                "page": "console",
                "tab": tab,
                "world": world,
                "profile": profile,
                "mock_rollup": {
                    "sample_hours": sample.len(),
                    "events_sum": events_sum,
                    "deny_avg_pct": deny_avg,
                    "p95_max_ms": p95_max,
                    "outbox_max": outbox_max
                }
            });

            if let Some(store) = state.event_store.as_ref() {
                if let Ok(snapshot) = build_advisor_snapshot(
                    state,
                    store,
                    world_filter,
                    Duration::from_secs(300),
                    5000,
                ) {
                    if let Some(obj) = base.as_object_mut() {
                        obj.insert("live_snapshot".to_string(), snapshot);
                    }
                }
            }
            base
        }
    }
}

fn heuristic_analysis(page: &str, context: &Value) -> (String, String, Vec<String>) {
    let mut severity = "green".to_string();
    let summary: String;
    let mut bullets = Vec::new();

    match page {
        "registry" => {
            let total = context
                .get("types_total")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let deprecated = context
                .get("deprecated_total")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let no_kats = context
                .get("without_kats_total")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            summary = format!(
                "Registry possui {} tipos. {} deprecated e {} sem KAT.",
                total, deprecated, no_kats
            );
            if no_kats > 0 {
                severity = "yellow".to_string();
                bullets.push("Priorizar KAT para tipos sem cobertura.".to_string());
            }
            if deprecated > 0 {
                bullets.push("Revisar plano de sunset dos tipos deprecated.".to_string());
            }
        }
        "registry_type" => {
            let exists = context
                .get("exists")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let versions = context
                .get("versions_total")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let has_kats = context
                .get("has_kats")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !exists {
                severity = "yellow".to_string();
                summary = "Tipo nao encontrado no registry materializado.".to_string();
            } else {
                summary = format!("Tipo ativo com {} versoes registradas.", versions);
                if !has_kats {
                    severity = "yellow".to_string();
                    bullets.push("Adicionar KATs para validar regressao de politica.".to_string());
                }
            }
        }
        "audit" => {
            let rows = context.get("rows").and_then(|v| v.as_u64()).unwrap_or(0);
            let kind = context
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("reports");
            summary = format!("Audit {} retornou {} artefatos.", kind, rows);
            if rows == 0 {
                severity = "yellow".to_string();
                bullets.push("Sem artefatos recentes: revisar emissao de auditoria.".to_string());
            }
        }
        "receipt" => {
            let exists = context
                .get("exists")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if exists {
                summary = "Receipt localizado; trilha de trace e narrate disponivel.".to_string();
            } else {
                severity = "yellow".to_string();
                summary = "Receipt nao localizado no store local.".to_string();
            }
        }
        _ => {
            let deny_avg = context
                .get("mock_rollup")
                .and_then(|v| v.get("deny_avg_pct"))
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let p95_max = context
                .get("mock_rollup")
                .and_then(|v| v.get("p95_max_ms"))
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let outbox_max = context
                .get("mock_rollup")
                .and_then(|v| v.get("outbox_max"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let events_sum = context
                .get("mock_rollup")
                .and_then(|v| v.get("events_sum"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let profile = context
                .get("profile")
                .and_then(|v| v.as_str())
                .unwrap_or("normal");
            let tab = context
                .get("tab")
                .and_then(|v| v.as_str())
                .unwrap_or("live");

            summary = format!(
                "Console {} com perfil {}: {} eventos no recorte recente; deny medio {:.2}%, p95 max {:.1}ms.",
                tab, profile, events_sum, deny_avg, p95_max
            );

            if deny_avg >= 7.0 || p95_max >= 240.0 || outbox_max >= 80 {
                severity = "red".to_string();
                bullets.push(
                    "Sinal de degradacao: validar pipeline CHECK/TR e fila outbox.".to_string(),
                );
            } else if deny_avg >= 4.0 || p95_max >= 170.0 || outbox_max >= 35 {
                severity = "yellow".to_string();
                bullets.push(
                    "Tendencia de risco moderado: aumentar observabilidade por stage.".to_string(),
                );
            }

            if profile == "chaos" || profile == "degraded" {
                bullets.push(
                    "Perfil mock agressivo ativo; usar para testar auto-remediacao.".to_string(),
                );
            }
        }
    }

    if bullets.is_empty() {
        bullets.push("Continuar monitorando variacao de latencia e deny rate.".to_string());
    }
    (severity, summary, bullets)
}

async fn call_real_llm(
    client: &reqwest::Client,
    page: &str,
    context: &Value,
) -> Result<String, String> {
    let api_key =
        std::env::var("OPENAI_API_KEY").map_err(|_| "OPENAI_API_KEY not configured".to_string())?;
    let model = std::env::var("UBL_LLM_MODEL").unwrap_or_else(|_| "gpt-4.1-mini".to_string());
    let payload = json!({
        "model": model,
        "input": [
            {
                "role": "system",
                "content": "Voce e um analista SRE. Responda em portugues: 1 resumo curto + ate 3 bullets acionaveis."
            },
            {
                "role": "user",
                "content": format!("Analise a pagina {} com este contexto JSON:\\n{}", page, context)
            }
        ],
        "max_output_tokens": 220
    });

    let res = client
        .post("https://api.openai.com/v1/responses")
        .bearer_auth(api_key)
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = res.status();
    let body: Value = res.json().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("openai status {}: {}", status, body));
    }

    if let Some(text) = body.get("output_text").and_then(|v| v.as_str()) {
        if !text.trim().is_empty() {
            return Ok(text.trim().to_string());
        }
    }

    if let Some(outputs) = body.get("output").and_then(|v| v.as_array()) {
        for item in outputs {
            if let Some(parts) = item.get("content").and_then(|v| v.as_array()) {
                for part in parts {
                    if let Some(text) = part.get("text").and_then(|v| v.as_str()) {
                        if !text.trim().is_empty() {
                            return Ok(text.trim().to_string());
                        }
                    }
                }
            }
        }
    }

    Err("empty LLM output".to_string())
}

fn parse_llm_text(text: &str) -> (String, Vec<String>) {
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return (
            "LLM respondeu sem conteudo, mantendo analise local.".to_string(),
            Vec::new(),
        );
    }

    let summary = lines.remove(0).to_string();
    let bullets = lines
        .into_iter()
        .take(3)
        .map(|line| {
            line.trim_start_matches('-')
                .trim_start_matches('*')
                .trim()
                .to_string()
        })
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    (summary, bullets)
}

async fn console_receipt_page(Path(cid): Path<String>) -> Response {
    render_html(&ConsoleReceiptTemplate { cid })
}

async fn audit_page(
    Path(kind): Path<String>,
    Query(query): Query<std::collections::BTreeMap<String, String>>,
) -> Response {
    let kind = normalize_audit_kind(&kind);
    let world = query
        .get("world")
        .cloned()
        .unwrap_or_else(|| "*".to_string());
    render_html(&AuditTemplate { world, kind })
}

async fn audit_table_partial(
    State(state): State<AppState>,
    Query(query): Query<std::collections::BTreeMap<String, String>>,
) -> Response {
    let world = query
        .get("world")
        .map(|w| w.as_str())
        .filter(|w| !w.trim().is_empty() && *w != "*");
    let kind = normalize_audit_kind(query.get("kind").map(String::as_str).unwrap_or("reports"));
    let rows = match query_audit_rows(&state, &kind, world, 100).await {
        Ok(rows) => rows,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "@type":"ubl/error",
                    "code":"INTERNAL_ERROR",
                    "message": format!("audit table query failed: {}", e),
                })),
            )
                .into_response();
        }
    };
    let (visible_rows, hidden_rows) = split_rows(rows, 6);
    render_html(&AuditTableTemplate {
        kind,
        visible_rows,
        hidden_rows,
    })
}

#[derive(Debug, Deserialize)]
struct AuditListQuery {
    world: Option<String>,
    limit: Option<usize>,
}

async fn list_audit_reports(
    State(state): State<AppState>,
    Query(query): Query<AuditListQuery>,
) -> (StatusCode, Json<Value>) {
    list_audit_kind_json(state, "reports", query).await
}

async fn list_audit_snapshots(
    State(state): State<AppState>,
    Query(query): Query<AuditListQuery>,
) -> (StatusCode, Json<Value>) {
    list_audit_kind_json(state, "snapshots", query).await
}

async fn list_audit_compactions(
    State(state): State<AppState>,
    Query(query): Query<AuditListQuery>,
) -> (StatusCode, Json<Value>) {
    list_audit_kind_json(state, "compactions", query).await
}

async fn list_audit_kind_json(
    state: AppState,
    kind: &str,
    query: AuditListQuery,
) -> (StatusCode, Json<Value>) {
    let world = query
        .world
        .as_deref()
        .filter(|w| !w.trim().is_empty() && *w != "*");
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    match query_audit_rows(&state, kind, world, limit).await {
        Ok(rows) => (
            StatusCode::OK,
            Json(json!({
                "@type": "ubl/audit.list",
                "kind": normalize_audit_kind(kind),
                "count": rows.len(),
                "rows": rows.iter().map(|r| json!({
                    "cid": r.cid,
                    "chip_type": r.chip_type,
                    "world": r.world,
                    "created_at": r.created_at,
                    "summary": r.summary,
                })).collect::<Vec<_>>()
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "@type": "ubl/error",
                "code": "INTERNAL_ERROR",
                "message": format!("audit list failed: {}", e),
            })),
        ),
    }
}

fn normalize_audit_kind(kind: &str) -> String {
    match kind {
        "reports" => "reports".to_string(),
        "snapshots" => "snapshots".to_string(),
        "compactions" => "compactions".to_string(),
        _ => "reports".to_string(),
    }
}

fn audit_chip_type_for_kind(kind: &str) -> &'static str {
    match kind {
        "reports" => "ubl/audit.dataset.v1",
        "snapshots" => "ubl/audit.snapshot.manifest.v1",
        "compactions" => "ubl/ledger.compaction.rollup.v1",
        _ => "ubl/audit.dataset.v1",
    }
}

async fn query_audit_rows(
    state: &AppState,
    kind: &str,
    world: Option<&str>,
    limit: usize,
) -> Result<Vec<AuditRow>, String> {
    let chip_type = audit_chip_type_for_kind(kind);
    let mut tags = Vec::new();
    if let Some(world) = world {
        tags.push(format!("world:{}", world));
    }
    let result = state
        .chip_store
        .query(&ubl_chipstore::ChipQuery {
            chip_type: Some(chip_type.to_string()),
            tags,
            created_after: None,
            created_before: None,
            executor_did: None,
            limit: Some(limit),
            offset: None,
        })
        .await
        .map_err(|e| e.to_string())?;

    let rows = result
        .chips
        .into_iter()
        .map(|chip| AuditRow {
            cid: chip.cid.as_str().to_string(),
            chip_type: chip.chip_type.clone(),
            world: chip
                .chip_data
                .get("@world")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_string(),
            created_at: chip.created_at.clone(),
            summary: audit_summary(&chip.chip_data, kind),
        })
        .collect();
    Ok(rows)
}

fn audit_summary(chip_data: &Value, kind: &str) -> String {
    match kind {
        "reports" => format!(
            "lines={} format={}",
            chip_data
                .get("line_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            chip_data
                .get("format")
                .and_then(|v| v.as_str())
                .unwrap_or("ndjson")
        ),
        "snapshots" => format!(
            "segments={} dataset={}",
            chip_data
                .get("coverage")
                .and_then(|c| c.get("segments"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            chip_data
                .get("artifacts")
                .and_then(|a| a.get("dataset"))
                .and_then(|v| v.as_str())
                .unwrap_or("-")
        ),
        "compactions" => format!(
            "freed_bytes={} mode={}",
            chip_data
                .get("freed_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            chip_data
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
        ),
        _ => "-".to_string(),
    }
}

async fn registry_page(
    Query(query): Query<std::collections::BTreeMap<String, String>>,
) -> Response {
    let world = query
        .get("world")
        .cloned()
        .unwrap_or_else(|| "*".to_string());
    render_html(&RegistryTemplate { world })
}

async fn registry_table_partial(
    State(state): State<AppState>,
    Query(query): Query<std::collections::BTreeMap<String, String>>,
) -> Response {
    let world = query
        .get("world")
        .map(|w| w.as_str())
        .filter(|w| !w.trim().is_empty() && *w != "*");
    let registry = match materialize_registry(&state, world).await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "@type":"ubl/error",
                    "code":"INTERNAL_ERROR",
                    "message": format!("registry materialization failed: {}", e),
                })),
            )
                .into_response();
        }
    };
    let rows: Vec<RegistryRow> = registry
        .types
        .values()
        .map(|view| RegistryRow {
            chip_type: view.chip_type.clone(),
            latest_version: view
                .latest_version
                .clone()
                .unwrap_or_else(|| "-".to_string()),
            deprecated: view.deprecated,
            has_kats: view.has_kats,
            required_cap: view.required_cap.clone().unwrap_or_else(|| "-".to_string()),
            last_updated_at: view
                .last_updated_at
                .clone()
                .unwrap_or_else(|| "-".to_string()),
        })
        .collect();
    let (visible_rows, hidden_rows) = split_rows(rows, 6);
    render_html(&RegistryTableTemplate {
        visible_rows,
        hidden_rows,
    })
}

async fn registry_type_page(
    State(state): State<AppState>,
    Path(chip_type): Path<String>,
) -> Response {
    let normalized_type = chip_type.trim_start_matches('/').to_string();
    let registry = match materialize_registry(&state, None).await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "@type":"ubl/error",
                    "code":"INTERNAL_ERROR",
                    "message": format!("registry materialization failed: {}", e),
                })),
            )
                .into_response();
        }
    };
    let Some(view) = registry.types.get(&normalized_type) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "@type":"ubl/error",
                "code":"NOT_FOUND",
                "message": format!("Registry type '{}' not found", normalized_type),
            })),
        )
            .into_response();
    };

    let versions: Vec<RegistryTypeVersionRow> = view
        .versions
        .values()
        .map(|ver| {
            let kats = ver
                .kats
                .iter()
                .enumerate()
                .map(|(index, kat)| {
                    let label = kat
                        .get("label")
                        .and_then(|v| v.as_str())
                        .unwrap_or("kat")
                        .to_string();
                    let expected_decision = kat
                        .get("expected_decision")
                        .and_then(|v| v.as_str())
                        .unwrap_or("-")
                        .to_string();
                    let expected_error = kat
                        .get("expected_error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("-")
                        .to_string();
                    let input_json_preview = kat
                        .get("input")
                        .map(Value::to_string)
                        .map(|s| {
                            if s.len() > 240 {
                                format!("{}...", &s[..240])
                            } else {
                                s
                            }
                        })
                        .unwrap_or_else(|| "-".to_string());
                    RegistryKatRow {
                        index,
                        label,
                        expected_decision,
                        expected_error,
                        input_json_preview,
                    }
                })
                .collect();
            RegistryTypeVersionRow {
                version: ver.version.clone(),
                required_cap: ver.required_cap.clone().unwrap_or_else(|| "-".to_string()),
                kats_count: ver.kats.len(),
                register_cid: ver.register_cid.clone().unwrap_or_else(|| "-".to_string()),
                updated_at: ver.updated_at.clone().unwrap_or_else(|| "-".to_string()),
                kats,
            }
        })
        .collect();
    let deprecation_json = view
        .deprecation
        .as_ref()
        .map(Value::to_string)
        .unwrap_or_else(|| "-".to_string());

    render_html(&RegistryTypeTemplate {
        chip_type: view.chip_type.clone(),
        latest_version: view
            .latest_version
            .clone()
            .unwrap_or_else(|| "-".to_string()),
        deprecated: view.deprecated,
        description: view.description.clone().unwrap_or_else(|| "-".to_string()),
        docs_url: view.docs_url.clone(),
        deprecation_json,
        versions,
    })
}

async fn registry_kat_test(
    State(state): State<AppState>,
    Form(form): Form<RegistryKatTestForm>,
) -> Response {
    let registry = match materialize_registry(&state, None).await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "@type":"ubl/error",
                    "code":"INTERNAL_ERROR",
                    "message": format!("registry materialization failed: {}", e),
                })),
            )
                .into_response();
        }
    };
    let Some(type_view) = registry.types.get(&form.chip_type) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "@type":"ubl/error",
                "code":"NOT_FOUND",
                "message": format!("Registry type '{}' not found", form.chip_type),
            })),
        )
            .into_response();
    };
    let Some(version_view) = type_view.versions.get(&form.version) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "@type":"ubl/error",
                "code":"NOT_FOUND",
                "message": format!(
                    "Registry version '{}' not found for type '{}'",
                    form.version, form.chip_type
                ),
            })),
        )
            .into_response();
    };
    let Some(kat) = version_view.kats.get(form.kat_index) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "@type":"ubl/error",
                "code":"NOT_FOUND",
                "message": format!(
                    "KAT index '{}' not found for type '{}' version '{}'",
                    form.kat_index, form.chip_type, form.version
                ),
            })),
        )
            .into_response();
    };

    let kat_label = kat
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("kat")
        .to_string();
    let expected_decision = kat
        .get("expected_decision")
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string();
    let expected_error = kat
        .get("expected_error")
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string();
    let Some(input_chip) = kat.get("input") else {
        return render_html(&RegistryKatResultTemplate {
            status_code: 400,
            kat_label,
            expected_decision,
            expected_error,
            actual_decision: "-".to_string(),
            actual_error: "missing_kat_input".to_string(),
            receipt_cid: "-".to_string(),
            pass: false,
            response_json: "{}".to_string(),
            message: "KAT input missing".to_string(),
        });
    };
    let body = match serde_json::to_vec(input_chip) {
        Ok(v) => v,
        Err(e) => {
            return render_html(&RegistryKatResultTemplate {
                status_code: 500,
                kat_label,
                expected_decision,
                expected_error,
                actual_decision: "-".to_string(),
                actual_error: "kat_input_serialize_error".to_string(),
                receipt_cid: "-".to_string(),
                pass: false,
                response_json: "{}".to_string(),
                message: format!("KAT input serialization failed: {}", e),
            });
        }
    };

    let (status, _headers, payload) = submit_chip_bytes(&state, &body).await;
    let actual_decision = payload
        .get("decision")
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string();
    let actual_error = payload
        .get("code")
        .and_then(|v| v.as_str())
        .or_else(|| {
            payload
                .get("receipt")
                .and_then(|v| v.get("code"))
                .and_then(|v| v.as_str())
        })
        .unwrap_or("-")
        .to_string();
    let receipt_cid = payload
        .get("receipt_cid")
        .and_then(|v| v.as_str())
        .or_else(|| {
            payload
                .get("receipt")
                .and_then(|v| v.get("receipt_cid"))
                .and_then(|v| v.as_str())
        })
        .unwrap_or("-")
        .to_string();

    let decision_match = expected_decision == "-"
        || actual_decision
            .to_ascii_lowercase()
            .contains(&expected_decision.to_ascii_lowercase());
    let error_match = expected_error == "-" || actual_error == expected_error;
    let pass = status.is_success() && decision_match && error_match;
    let response_json = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string());
    let message = if pass {
        "KAT passed".to_string()
    } else {
        "KAT failed".to_string()
    };

    render_html(&RegistryKatResultTemplate {
        status_code: status.as_u16(),
        kat_label,
        expected_decision,
        expected_error,
        actual_decision,
        actual_error,
        receipt_cid,
        pass,
        response_json,
        message,
    })
}

async fn registry_types(
    State(state): State<AppState>,
    Query(query): Query<std::collections::BTreeMap<String, String>>,
) -> Response {
    let world = query.get("world").map(|s| s.as_str());
    let registry = match materialize_registry(&state, world).await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "@type":"ubl/error",
                    "code":"INTERNAL_ERROR",
                    "message": format!("registry materialization failed: {}", e),
                })),
            )
                .into_response();
        }
    };

    let mut types: Vec<Value> = Vec::with_capacity(registry.types.len());
    for view in registry.types.values() {
        types.push(json!({
            "type": view.chip_type,
            "latest_version": view.latest_version,
            "deprecated": view.deprecated,
            "has_kats": view.has_kats,
            "required_cap": view.required_cap,
            "last_cid": view.last_cid,
            "last_updated_at": view.last_updated_at,
            "versions_count": view.versions.len(),
        }));
    }

    (
        StatusCode::OK,
        Json(json!({
            "@type": "ubl/registry.types",
            "count": types.len(),
            "types": types,
        })),
    )
        .into_response()
}

async fn registry_type_detail(
    State(state): State<AppState>,
    Path(chip_type): Path<String>,
) -> Response {
    let registry = match materialize_registry(&state, None).await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "@type":"ubl/error",
                    "code":"INTERNAL_ERROR",
                    "message": format!("registry materialization failed: {}", e),
                })),
            )
                .into_response();
        }
    };
    let Some(view) = registry.types.get(&chip_type) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "@type":"ubl/error",
                "code":"NOT_FOUND",
                "message": format!("Registry type '{}' not found", chip_type),
            })),
        )
            .into_response();
    };

    let versions: Vec<Value> = view
        .versions
        .values()
        .map(|ver| {
            json!({
                "version": ver.version,
                "schema": ver.schema,
                "kats": ver.kats,
                "required_cap": ver.required_cap,
                "register_cid": ver.register_cid,
                "updated_at": ver.updated_at,
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "@type": "ubl/registry.type",
            "type": view.chip_type,
            "latest_version": view.latest_version,
            "deprecated": view.deprecated,
            "description": view.description,
            "docs_url": view.docs_url,
            "deprecation": view.deprecation,
            "has_kats": view.has_kats,
            "required_cap": view.required_cap,
            "last_cid": view.last_cid,
            "last_updated_at": view.last_updated_at,
            "versions": versions,
        })),
    )
        .into_response()
}

async fn registry_type_version(
    State(state): State<AppState>,
    Path((chip_type, ver)): Path<(String, String)>,
) -> Response {
    let registry = match materialize_registry(&state, None).await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "@type":"ubl/error",
                    "code":"INTERNAL_ERROR",
                    "message": format!("registry materialization failed: {}", e),
                })),
            )
                .into_response();
        }
    };
    let Some(view) = registry.types.get(&chip_type) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "@type":"ubl/error",
                "code":"NOT_FOUND",
                "message": format!("Registry type '{}' not found", chip_type),
            })),
        )
            .into_response();
    };
    let Some(version) = view.versions.get(&ver) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "@type":"ubl/error",
                "code":"NOT_FOUND",
                "message": format!("Registry version '{}' not found for type '{}'", ver, chip_type),
            })),
        )
            .into_response();
    };

    (
        StatusCode::OK,
        Json(json!({
            "@type": "ubl/registry.version",
            "type": chip_type,
            "version": version.version,
            "schema": version.schema,
            "kats": version.kats,
            "required_cap": version.required_cap,
            "register_cid": version.register_cid,
            "updated_at": version.updated_at,
            "deprecated": view.deprecated,
            "deprecation": view.deprecation,
        })),
    )
        .into_response()
}

async fn materialize_registry(
    state: &AppState,
    world_filter: Option<&str>,
) -> Result<RegistryView, String> {
    fn world_matches(chip: &ubl_chipstore::StoredChip, world_filter: Option<&str>) -> bool {
        let Some(expected) = world_filter else {
            return true;
        };
        chip.chip_data
            .get("@world")
            .and_then(|v| v.as_str())
            .map(|w| w == expected)
            .unwrap_or(false)
    }

    fn type_entry<'a>(
        map: &'a mut std::collections::BTreeMap<String, RegistryTypeView>,
        chip_type: &str,
    ) -> &'a mut RegistryTypeView {
        map.entry(chip_type.to_string())
            .or_insert_with(|| RegistryTypeView {
                chip_type: chip_type.to_string(),
                latest_version: None,
                deprecated: false,
                has_kats: false,
                required_cap: None,
                description: None,
                docs_url: None,
                deprecation: None,
                last_cid: None,
                last_updated_at: None,
                versions: std::collections::BTreeMap::new(),
            })
    }

    let mut types = std::collections::BTreeMap::<String, RegistryTypeView>::new();

    let mut registers = state
        .chip_store
        .get_chips_by_type("ubl/meta.register")
        .await
        .map_err(|e| e.to_string())?;
    registers.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    for chip in registers {
        if !world_matches(&chip, world_filter) {
            continue;
        }
        let Ok(parsed) = ubl_runtime::meta_chip::parse_register(&chip.chip_data) else {
            continue;
        };
        let entry = type_entry(&mut types, &parsed.target_type);
        entry.latest_version = Some(parsed.type_version.clone());
        entry.description = Some(parsed.description.clone());
        entry.has_kats = entry.has_kats || !parsed.kats.is_empty();
        entry.required_cap = parsed.schema.required_cap.clone();
        entry.last_cid = Some(chip.cid.to_string());
        entry.last_updated_at = Some(chip.created_at.clone());
        entry.versions.insert(
            parsed.type_version.clone(),
            RegistryVersionView {
                version: parsed.type_version,
                schema: serde_json::to_value(parsed.schema.clone()).ok(),
                kats: parsed
                    .kats
                    .iter()
                    .filter_map(|k| serde_json::to_value(k).ok())
                    .collect(),
                required_cap: parsed.schema.required_cap.clone(),
                register_cid: Some(chip.cid.to_string()),
                updated_at: Some(chip.created_at.clone()),
            },
        );
    }

    let mut describes = state
        .chip_store
        .get_chips_by_type("ubl/meta.describe")
        .await
        .map_err(|e| e.to_string())?;
    describes.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    for chip in describes {
        if !world_matches(&chip, world_filter) {
            continue;
        }
        let Ok(parsed) = ubl_runtime::meta_chip::parse_describe(&chip.chip_data) else {
            continue;
        };
        let entry = type_entry(&mut types, &parsed.target_type);
        entry.description = Some(parsed.description);
        entry.docs_url = parsed.docs_url;
        entry.last_cid = Some(chip.cid.to_string());
        entry.last_updated_at = Some(chip.created_at.clone());
        if !parsed.kats.is_empty() {
            entry.has_kats = true;
            if let Some(ver) = entry.latest_version.clone() {
                if let Some(version_entry) = entry.versions.get_mut(&ver) {
                    version_entry.kats = parsed
                        .kats
                        .iter()
                        .filter_map(|k| serde_json::to_value(k).ok())
                        .collect();
                    version_entry.updated_at = Some(chip.created_at.clone());
                }
            }
        }
    }

    let mut deprecates = state
        .chip_store
        .get_chips_by_type("ubl/meta.deprecate")
        .await
        .map_err(|e| e.to_string())?;
    deprecates.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    for chip in deprecates {
        if !world_matches(&chip, world_filter) {
            continue;
        }
        let Ok(parsed) = ubl_runtime::meta_chip::parse_deprecate(&chip.chip_data) else {
            continue;
        };
        let entry = type_entry(&mut types, &parsed.target_type);
        entry.deprecated = true;
        entry.deprecation = Some(json!({
            "reason": parsed.reason,
            "replacement_type": parsed.replacement_type,
            "sunset_at": parsed.sunset_at,
            "cid": chip.cid.to_string(),
        }));
        entry.last_cid = Some(chip.cid.to_string());
        entry.last_updated_at = Some(chip.created_at.clone());
    }

    Ok(RegistryView { types })
}

fn to_hub_event(event: &ReceiptEvent) -> Value {
    let stage = normalize_stage(&event.pipeline_stage);
    let event_id = deterministic_event_id(event, &stage);
    let world = event
        .world
        .clone()
        .unwrap_or_else(|| "a/system".to_string());
    let chip_id = event
        .metadata
        .get("@id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let chip_ver = event
        .metadata
        .get("@ver")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let code = event
        .metadata
        .get("code")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let cap = event
        .metadata
        .get("cap")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);

    let decision = event.decision.as_ref().map(|d| d.to_ascii_uppercase());
    let mut receipt = json!({
        "cid": event.receipt_cid.clone(),
        "decision": decision,
        "code": code,
    });
    if receipt.get("code").is_some_and(Value::is_null) {
        if let Some(obj) = receipt.as_object_mut() {
            obj.remove("code");
        }
    }

    json!({
        "@type": "ubl/event",
        "@ver": "1.0.0",
        "@id": event_id,
        "@world": world,
        "source": "pipeline",
        "stage": stage,
        "when": event.timestamp.clone(),
        "chip": {
            "type": event.receipt_type.clone(),
            "id": chip_id,
            "ver": chip_ver,
        },
        "receipt": receipt,
        "perf": {
            "latency_ms": event.latency_ms.or(event.duration_ms),
            "fuel": event.fuel_used,
            "mem_kb": Value::Null,
        },
        "actor": {
            "kid": event.actor.clone(),
            "cap": cap,
        },
        "artifacts": event.artifact_cids.clone(),
        "runtime": {
            "binary_hash": event.binary_hash.clone(),
            "build": event.build_meta.clone(),
        },
        "labels": Value::Object(Default::default()),
    })
}

fn normalize_stage(stage: &str) -> String {
    match stage.to_ascii_lowercase().as_str() {
        "knock" => "KNOCK".to_string(),
        "wa" | "write_ahead" => "WA".to_string(),
        "check" => "CHECK".to_string(),
        "tr" | "transition" => "TR".to_string(),
        "wf" | "write_finished" => "WF".to_string(),
        "registry" => "REGISTRY".to_string(),
        other => other.to_ascii_uppercase(),
    }
}

fn deterministic_event_id(event: &ReceiptEvent, stage: &str) -> String {
    format!(
        "evt:{}:{}:{}:{}",
        event.receipt_cid,
        stage,
        event.input_cid.as_deref().unwrap_or(""),
        event.output_cid.as_deref().unwrap_or("")
    )
}

fn hub_matches_query(event: &Value, query: &EventStreamQuery) -> bool {
    if let Some(world) = &query.world {
        if event.get("@world").and_then(|v| v.as_str()) != Some(world.as_str()) {
            return false;
        }
    }
    if let Some(stage) = &query.stage {
        let actual = event.get("stage").and_then(|v| v.as_str()).unwrap_or("");
        if actual != stage && !actual.eq_ignore_ascii_case(stage) {
            return false;
        }
    }
    if let Some(decision) = &query.decision {
        let actual = event
            .get("receipt")
            .and_then(|v| v.get("decision"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if actual != decision && !actual.eq_ignore_ascii_case(decision) {
            return false;
        }
    }
    if let Some(code) = &query.code {
        if event
            .get("receipt")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str())
            != Some(code.as_str())
        {
            return false;
        }
    }
    if let Some(chip_type) = &query.chip_type {
        let actual = event
            .get("chip")
            .and_then(|v| v.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if chip_type != "*" && actual != chip_type {
            return false;
        }
    }
    if let Some(actor) = &query.actor {
        if event
            .get("actor")
            .and_then(|v| v.get("kid"))
            .and_then(|v| v.as_str())
            != Some(actor.as_str())
        {
            return false;
        }
    }
    true
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/console", get(console_page))
        .route("/console/_kpis", get(console_kpis_partial))
        .route("/console/_events", get(console_events_partial))
        .route("/console/_mock24h", get(console_mock24h_partial))
        .route("/console/receipt/:cid", get(console_receipt_page))
        .route("/ui/_llm", get(ui_llm_panel))
        .route("/audit/_table", get(audit_table_partial))
        .route("/audit/:kind", get(audit_page))
        .route("/registry", get(registry_page))
        .route("/registry/_table", get(registry_table_partial))
        .route("/registry/_kat_test", post(registry_kat_test))
        .route("/registry/*chip_type", get(registry_type_page))
        .route("/v1/audit/reports", get(list_audit_reports))
        .route("/v1/audit/snapshots", get(list_audit_snapshots))
        .route("/v1/audit/compactions", get(list_audit_compactions))
        .route("/v1/events", get(stream_events))
        .route("/v1/events/search", get(search_events))
        .route("/v1/mock/system24h", get(mock24h_api))
        .route("/v1/advisor/tap", get(advisor_tap))
        .route("/v1/advisor/snapshots", get(advisor_snapshots))
        .route("/v1/registry/types", get(registry_types))
        .route("/v1/registry/types/:chip_type", get(registry_type_detail))
        .route(
            "/v1/registry/types/:chip_type/versions/:ver",
            get(registry_type_version),
        )
        .route("/v1/runtime/attestation", get(get_runtime_attestation))
        .route("/v1/chips", post(create_chip))
        .route("/v1/chips/:cid", get(get_chip))
        .route("/v1/cas/:cid", get(get_chip))
        .route("/v1/receipts/:cid", get(get_receipt))
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

    let receipt_cid = &chip.receipt_cid;
    let mut auth_chain_verified: Option<bool> = None;
    let receipt_exists = if receipt_cid.as_str().is_empty() {
        false
    } else {
        match state.durable_store.as_ref() {
            Some(store) => match store.get_receipt(receipt_cid.as_str()) {
                Ok(Some(receipt_json)) => {
                    if let Err(ubl_err) =
                        verify_receipt_auth_chain(receipt_cid.as_str(), &receipt_json)
                    {
                        return (
                            StatusCode::from_u16(ubl_err.code.http_status())
                                .unwrap_or(StatusCode::UNPROCESSABLE_ENTITY),
                            Json(ubl_err.to_json()),
                        );
                    }
                    auth_chain_verified = Some(true);
                    true
                }
                Ok(None) => false,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({
                            "@type": "ubl/error",
                            "code": "INTERNAL_ERROR",
                            "message": format!("Receipt fetch failed: {}", e)
                        })),
                    );
                }
            },
            None => state
                .chip_store
                .get_chip_by_receipt_cid(receipt_cid.as_str())
                .await
                .map(|c| c.is_some())
                .unwrap_or(false),
        }
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
            "auth_chain_verified": auth_chain_verified,
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

/// GET /v1/receipts/:cid — retrieve persisted WF receipt JSON by receipt CID.
///
/// ETag support: receipt CID is immutable content address.
async fn get_receipt(
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

    let Some(store) = state.durable_store.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            HeaderMap::new(),
            Json(json!({
                "@type": "ubl/error",
                "code": "UNAVAILABLE",
                "message": "Receipt store unavailable: enable SQLite durable store",
            })),
        );
    };

    match store.get_receipt(&cid) {
        Ok(Some(receipt)) => {
            if let Err(ubl_err) = verify_receipt_auth_chain(&cid, &receipt) {
                return (
                    StatusCode::from_u16(ubl_err.code.http_status())
                        .unwrap_or(StatusCode::UNPROCESSABLE_ENTITY),
                    HeaderMap::new(),
                    Json(ubl_err.to_json()),
                );
            }
            let mut h = HeaderMap::new();
            let etag = format!("\"{}\"", cid);
            h.insert(header::ETAG, etag.parse().unwrap());
            h.insert(
                header::CACHE_CONTROL,
                "public, max-age=31536000, immutable".parse().unwrap(),
            );
            (StatusCode::OK, h, Json(receipt))
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            HeaderMap::new(),
            Json(
                json!({"@type": "ubl/error", "code": "NOT_FOUND", "message": format!("Receipt {} not found", cid)}),
            ),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            HeaderMap::new(),
            Json(json!({
                "@type": "ubl/error",
                "code": "INTERNAL_ERROR",
                "message": format!("Receipt fetch failed: {}", e),
            })),
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
    if let Some(store) = state.durable_store.as_ref() {
        match store.get_receipt(&cid) {
            Ok(Some(receipt_json)) => {
                if let Err(ubl_err) = verify_receipt_auth_chain(&cid, &receipt_json) {
                    return (
                        StatusCode::from_u16(ubl_err.code.http_status())
                            .unwrap_or(StatusCode::UNPROCESSABLE_ENTITY),
                        Json(ubl_err.to_json()),
                    );
                }
            }
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({
                        "@type":"ubl/error",
                        "code":"NOT_FOUND",
                        "message": format!("Receipt {} not found", cid)
                    })),
                );
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "@type":"ubl/error",
                        "code":"INTERNAL_ERROR",
                        "message": format!("Receipt fetch failed: {}", e)
                    })),
                );
            }
        }
    }

    match state.chip_store.get_chip_by_receipt_cid(&cid).await {
        Ok(Some(chip)) => (
            StatusCode::OK,
            Json(json!({
                "@type": "ubl/trace",
                "receipt_cid": cid,
                "chip_cid": chip.cid,
                "chip_type": chip.chip_type,
                "auth_chain_verified": state.durable_store.is_some(),
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
/// - ubl.receipt → durable receipt get
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

        "ubl.receipt" => {
            let cid = arguments.get("cid").and_then(|v| v.as_str()).unwrap_or("");
            if cid.is_empty() {
                return (
                    StatusCode::OK,
                    Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32602, "message": "missing required argument: cid" }
                    })),
                );
            }
            let Some(store) = state.durable_store.as_ref() else {
                return (
                    StatusCode::OK,
                    Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32000, "message": "receipt store unavailable" }
                    })),
                );
            };
            match store.get_receipt(cid) {
                Ok(Some(receipt)) => (
                    StatusCode::OK,
                    Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": { "content": [{ "type": "text", "text": serde_json::to_string(&receipt).unwrap_or_default() }] }
                    })),
                ),
                Ok(None) => (
                    StatusCode::OK,
                    Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32004, "message": format!("Receipt {} not found", cid) }
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
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;
    use ubl_chipstore::InMemoryBackend;
    use ubl_receipt::{PipelineStage, StageExecution, UnifiedReceipt};
    use ubl_runtime::durable_store::{CommitInput, NewOutboxEvent};
    use ubl_runtime::event_bus::ReceiptEvent;

    const TEST_STAGE_SECRET_HEX: &str =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

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
            http_client: reqwest::Client::new(),
            canon_rate_limiter: canon_limiter,
            durable_store: None,
            event_store: None,
        }
    }

    fn test_state_with_receipt_store(receipt_cid: &str, receipt_json: Value) -> AppState {
        let mut state = test_state(None);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ubl_gate_receipts_{}.db", ts));
        let dsn = format!("file:{}?mode=rwc&_journal_mode=WAL", path.display());
        let store = DurableStore::new(dsn).unwrap();
        let input = CommitInput {
            receipt_cid: receipt_cid.to_string(),
            receipt_json,
            did: "did:key:ztest".to_string(),
            kid: "did:key:ztest#ed25519".to_string(),
            rt_hash: "b3:runtime-test".to_string(),
            decision: "allow".to_string(),
            idem_key: None,
            chain: vec![
                "b3:wa".to_string(),
                "b3:tr".to_string(),
                "b3:wf".to_string(),
            ],
            outbox_events: vec![NewOutboxEvent {
                event_type: "emit_receipt".to_string(),
                payload_json: json!({"receipt_cid": receipt_cid}),
            }],
            created_at: chrono::Utc::now().timestamp(),
            fail_after_receipt_write: false,
        };
        store.commit_wf_atomically(&input).unwrap();
        state.durable_store = Some(Arc::new(store));
        state
    }

    fn test_state_with_event_store(events: Vec<Value>) -> AppState {
        let mut state = test_state(None);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ubl_gate_events_{}", ts));
        let store = EventStore::open(path).unwrap();
        for event in events {
            store.append_event_json(&event).unwrap();
        }
        state.event_store = Some(Arc::new(store));
        state
    }

    fn make_unified_receipt_json(tampered: bool) -> (String, Value) {
        std::env::set_var("UBL_STAGE_SECRET", format!("hex:{}", TEST_STAGE_SECRET_HEX));

        let mut receipt = UnifiedReceipt::new(
            "a/test/t/main",
            "did:key:ztest",
            "did:key:ztest#ed25519",
            "0011223344556677",
        );
        receipt
            .append_stage(StageExecution {
                stage: PipelineStage::WriteAhead,
                timestamp: chrono::Utc::now().to_rfc3339(),
                input_cid: "b3:wa-input".to_string(),
                output_cid: Some("b3:wa-output".to_string()),
                fuel_used: None,
                policy_trace: vec![],
                vm_sig: None,
                vm_sig_payload_cid: None,
                auth_token: String::new(),
                duration_ms: 1,
            })
            .unwrap();
        let receipt_cid = receipt.receipt_cid.as_str().to_string();
        let mut receipt_json = receipt.to_json().unwrap();
        if tampered {
            if let Some(stage) = receipt_json
                .get_mut("stages")
                .and_then(|v| v.as_array_mut())
                .and_then(|arr| arr.first_mut())
            {
                stage["auth_token"] =
                    Value::String("hmac:00000000000000000000000000000000".to_string());
            }
        }

        (receipt_cid, receipt_json)
    }

    async fn seed_meta_chip(state: &AppState, body: Value, receipt_cid: &str) {
        let metadata: ubl_chipstore::ExecutionMetadata = serde_json::from_value(json!({
            "runtime_version": "test-runtime",
            "execution_time_ms": 1,
            "fuel_consumed": 0,
            "policies_applied": [],
            "executor_did": "did:key:ztest",
            "reproducible": true
        }))
        .unwrap();
        state
            .chip_store
            .store_executed_chip(body, receipt_cid.to_string(), metadata)
            .await
            .unwrap();
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
    async fn cas_alias_route_is_read_only_and_reachable() {
        let app = build_router(test_state(None));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/v1/cas/b3:missing")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
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

    #[tokio::test]
    async fn receipts_endpoint_returns_raw_persisted_receipt() {
        let (receipt_cid, receipt_json) = make_unified_receipt_json(false);
        let app = build_router(test_state_with_receipt_store(&receipt_cid, receipt_json));

        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/receipts/{}", receipt_cid))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["@type"], "ubl/receipt");
        assert_eq!(v["receipt_cid"], receipt_cid);
    }

    #[tokio::test]
    async fn chip_verify_returns_422_when_receipt_auth_chain_is_tampered() {
        let (receipt_cid, tampered_receipt_json) = make_unified_receipt_json(true);
        let state = test_state_with_receipt_store(&receipt_cid, tampered_receipt_json);

        let metadata: ubl_chipstore::ExecutionMetadata = serde_json::from_value(json!({
            "runtime_version": "test-runtime",
            "execution_time_ms": 1,
            "fuel_consumed": 0,
            "policies_applied": [],
            "executor_did": "did:key:ztest",
            "reproducible": true
        }))
        .unwrap();
        let chip_cid = state
            .chip_store
            .store_executed_chip(
                json!({
                    "@type": "ubl/document",
                    "@id": "tamper-test",
                    "@ver": "1.0",
                    "@world": "a/test/t/main",
                    "title": "tamper"
                }),
                receipt_cid.clone(),
                metadata,
            )
            .await
            .unwrap();

        let app = build_router(state);
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/chips/{}/verify", chip_cid))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["code"], "TAMPER_DETECTED");
    }

    #[tokio::test]
    async fn receipt_trace_returns_422_when_auth_chain_is_tampered() {
        let (receipt_cid, tampered_receipt_json) = make_unified_receipt_json(true);
        let state = test_state_with_receipt_store(&receipt_cid, tampered_receipt_json);

        let metadata: ubl_chipstore::ExecutionMetadata = serde_json::from_value(json!({
            "runtime_version": "test-runtime",
            "execution_time_ms": 1,
            "fuel_consumed": 0,
            "policies_applied": [],
            "executor_did": "did:key:ztest",
            "reproducible": true
        }))
        .unwrap();
        state
            .chip_store
            .store_executed_chip(
                json!({
                    "@type": "ubl/document",
                    "@id": "tamper-trace-test",
                    "@ver": "1.0",
                    "@world": "a/test/t/main",
                    "title": "tamper trace"
                }),
                receipt_cid.clone(),
                metadata,
            )
            .await
            .unwrap();

        let app = build_router(state);
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/receipts/{}/trace", receipt_cid))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["code"], "TAMPER_DETECTED");
    }

    #[tokio::test]
    async fn receipts_endpoint_unavailable_without_durable_store() {
        let app = build_router(test_state(None));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/v1/receipts/b3:any")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn events_search_unavailable_without_event_store() {
        let app = build_router(test_state(None));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/v1/events/search?world=a/acme")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn events_search_filters_world_and_decision() {
        let app = build_router(test_state_with_event_store(vec![
            json!({
                "@type": "ubl/event",
                "@ver": "1.0.0",
                "@id": "evt-allow-1",
                "@world": "a/acme/t/prod",
                "source": "pipeline",
                "stage": "WF",
                "when": "2026-02-18T12:00:00.000Z",
                "chip": {"type": "ubl/user", "id": "u1", "ver": "1.0"},
                "receipt": {"cid": "b3:r1", "decision": "ALLOW", "code": "ok"},
                "actor": {"kid": "did:key:z1#k1"},
            }),
            json!({
                "@type": "ubl/event",
                "@ver": "1.0.0",
                "@id": "evt-deny-1",
                "@world": "a/acme/t/prod",
                "source": "pipeline",
                "stage": "CHECK",
                "when": "2026-02-18T12:00:01.000Z",
                "chip": {"type": "ubl/user", "id": "u2", "ver": "1.0"},
                "receipt": {"cid": "b3:r2", "decision": "DENY", "code": "check.policy.deny"},
                "actor": {"kid": "did:key:z1#k1"},
            }),
            json!({
                "@type": "ubl/event",
                "@ver": "1.0.0",
                "@id": "evt-deny-2",
                "@world": "a/other/t/dev",
                "source": "pipeline",
                "stage": "CHECK",
                "when": "2026-02-18T12:00:02.000Z",
                "chip": {"type": "ubl/user", "id": "u3", "ver": "1.0"},
                "receipt": {"cid": "b3:r3", "decision": "DENY", "code": "check.policy.deny"},
                "actor": {"kid": "did:key:z1#k1"},
            }),
        ]));

        let req = Request::builder()
            .method(Method::GET)
            .uri("/v1/events/search?world=a/acme/t/prod&decision=deny")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["@type"], "ubl/events.search.response");
        assert_eq!(v["count"], 1);
        assert_eq!(v["events"][0]["@id"], "evt-deny-1");
    }

    #[tokio::test]
    async fn advisor_snapshots_unavailable_without_event_store() {
        let app = build_router(test_state(None));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/v1/advisor/snapshots?window=5m")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn advisor_snapshots_returns_aggregates() {
        let now = chrono::Utc::now();
        let app = build_router(test_state_with_event_store(vec![
            json!({
                "@type": "ubl/event",
                "@ver": "1.0.0",
                "@id": "evt-adv-1",
                "@world": "a/acme/t/prod",
                "source": "pipeline",
                "stage": "CHECK",
                "when": now.to_rfc3339(),
                "chip": {"type": "ubl/user", "id": "u1", "ver": "1.0"},
                "receipt": {"cid": "b3:ra1", "decision": "DENY", "code": "check.policy.deny"},
                "perf": {"latency_ms": 10.0},
                "actor": {"kid": "did:key:z1#k1"},
            }),
            json!({
                "@type": "ubl/event",
                "@ver": "1.0.0",
                "@id": "evt-adv-2",
                "@world": "a/acme/t/prod",
                "source": "pipeline",
                "stage": "WF",
                "when": now.to_rfc3339(),
                "chip": {"type": "ubl/user", "id": "u2", "ver": "1.0"},
                "receipt": {"cid": "b3:ra2", "decision": "ALLOW", "code": "ok"},
                "perf": {"latency_ms": 20.0},
                "actor": {"kid": "did:key:z1#k1"},
            }),
        ]));

        let req = Request::builder()
            .method(Method::GET)
            .uri("/v1/advisor/snapshots?world=a/acme/t/prod&window=5m")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["@type"], "ubl/advisor.snapshot");
        assert_eq!(v["snapshot"]["counts"]["decision"]["ALLOW"], 1);
        assert_eq!(v["snapshot"]["counts"]["decision"]["DENY"], 1);
        assert_eq!(v["snapshot"]["counts"]["stage"]["CHECK"], 1);
        assert_eq!(v["snapshot"]["counts"]["stage"]["WF"], 1);
    }

    #[test]
    fn to_hub_event_maps_core_fields() {
        let event = ReceiptEvent {
            at_type: "ubl/event".to_string(),
            event_type: "ubl.receipt.wf".to_string(),
            schema_version: "1.0".to_string(),
            idempotency_key: "b3:receipt-1".to_string(),
            receipt_cid: "b3:receipt-1".to_string(),
            receipt_type: "ubl/user".to_string(),
            decision: Some("allow".to_string()),
            duration_ms: Some(12),
            timestamp: "2026-02-18T12:34:56.000Z".to_string(),
            pipeline_stage: "wf".to_string(),
            fuel_used: Some(7),
            rb_count: None,
            artifact_cids: vec!["b3:artifact-1".to_string()],
            metadata: json!({"@id":"chip-1","@ver":"1.0.0","code":"ok"}),
            input_cid: Some("b3:in".to_string()),
            output_cid: Some("b3:receipt-1".to_string()),
            binary_hash: Some("sha256:abc".to_string()),
            build_meta: Some(json!({"git":"abc123"})),
            world: Some("a/acme/t/prod".to_string()),
            actor: Some("did:key:z1#k1".to_string()),
            latency_ms: Some(12),
        };

        let hub = to_hub_event(&event);
        assert_eq!(hub["@type"], "ubl/event");
        assert_eq!(hub["@ver"], "1.0.0");
        assert_eq!(hub["stage"], "WF");
        assert_eq!(hub["@world"], "a/acme/t/prod");
        assert_eq!(hub["chip"]["type"], "ubl/user");
        assert_eq!(hub["receipt"]["cid"], "b3:receipt-1");
        assert_eq!(hub["receipt"]["decision"], "ALLOW");
        assert_eq!(hub["perf"]["fuel"], 7);
    }

    #[test]
    fn hub_matches_query_applies_stage_and_world_filters() {
        let event = json!({
            "@type": "ubl/event",
            "@ver": "1.0.0",
            "@id": "evt-1",
            "@world": "a/acme/t/prod",
            "stage": "CHECK",
            "chip": {"type": "ubl/user"},
            "receipt": {"decision": "DENY", "code": "check.policy.deny"},
            "actor": {"kid": "did:key:z1#k1"}
        });

        let q_ok = EventStreamQuery {
            world: Some("a/acme/t/prod".to_string()),
            stage: Some("check".to_string()),
            decision: Some("deny".to_string()),
            code: Some("check.policy.deny".to_string()),
            chip_type: Some("ubl/user".to_string()),
            actor: Some("did:key:z1#k1".to_string()),
            since: None,
            limit: None,
        };
        assert!(hub_matches_query(&event, &q_ok));

        let q_bad_world = EventStreamQuery {
            world: Some("a/other".to_string()),
            ..q_ok
        };
        assert!(!hub_matches_query(&event, &q_bad_world));
    }

    #[tokio::test]
    async fn registry_types_materializes_meta_chips() {
        let state = test_state(None);
        seed_meta_chip(
            &state,
            json!({
                "@type":"ubl/meta.register",
                "@id":"reg-1",
                "@ver":"1.0",
                "@world":"a/acme/t/prod",
                "target_type":"acme/invoice",
                "description":"Invoice type",
                "type_version":"1.0",
                "schema":{
                    "required_fields":[{"name":"amount","field_type":"string","description":"Amount"}],
                    "optional_fields":[],
                    "required_cap":"invoice:create"
                },
                "kats":[{
                    "label":"allow invoice",
                    "input":{"@type":"acme/invoice","@id":"i1","@ver":"1.0","@world":"a/acme/t/prod","amount":"10.00"},
                    "expected_decision":"allow"
                }]
            }),
            "b3:r-meta-1",
        )
        .await;
        seed_meta_chip(
            &state,
            json!({
                "@type":"ubl/meta.describe",
                "@id":"desc-1",
                "@ver":"1.0",
                "@world":"a/acme/t/prod",
                "target_type":"acme/invoice",
                "description":"Invoice type updated",
                "docs_url":"https://example.com/acme-invoice"
            }),
            "b3:r-meta-2",
        )
        .await;
        seed_meta_chip(
            &state,
            json!({
                "@type":"ubl/meta.deprecate",
                "@id":"dep-1",
                "@ver":"1.0",
                "@world":"a/acme/t/prod",
                "target_type":"acme/invoice",
                "reason":"use acme/invoice.v2",
                "replacement_type":"acme/invoice.v2",
                "sunset_at":"2026-12-01T00:00:00Z"
            }),
            "b3:r-meta-3",
        )
        .await;
        let app = build_router(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/v1/registry/types?world=a/acme/t/prod")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["@type"], "ubl/registry.types");
        assert_eq!(v["count"], 1);
        assert_eq!(v["types"][0]["type"], "acme/invoice");
        assert_eq!(v["types"][0]["deprecated"], true);
        assert_eq!(v["types"][0]["required_cap"], "invoice:create");
    }

    #[tokio::test]
    async fn registry_version_endpoint_returns_schema_and_kats() {
        let state = test_state(None);
        seed_meta_chip(
            &state,
            json!({
                "@type":"ubl/meta.register",
                "@id":"reg-v1",
                "@ver":"1.0",
                "@world":"a/acme/t/prod",
                "target_type":"acme/payment",
                "description":"Payment type",
                "type_version":"1.0",
                "schema":{
                    "required_fields":[{"name":"value","field_type":"string","description":"Value"}],
                    "optional_fields":[],
                    "required_cap":"payment:create"
                },
                "kats":[{
                    "label":"allow payment",
                    "input":{"@type":"acme/payment","@id":"p1","@ver":"1.0","@world":"a/acme/t/prod","value":"1"},
                    "expected_decision":"allow"
                }]
            }),
            "b3:r-meta-v1",
        )
        .await;
        let app = build_router(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/v1/registry/types/acme%2Fpayment/versions/1.0")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["@type"], "ubl/registry.version");
        assert_eq!(v["type"], "acme/payment");
        assert_eq!(v["version"], "1.0");
        assert_eq!(v["required_cap"], "payment:create");
        assert_eq!(v["kats"][0]["label"], "allow payment");
    }

    #[tokio::test]
    async fn console_and_registry_pages_render_html() {
        let app = build_router(test_state(None));

        let console_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/console")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(console_res.status(), StatusCode::OK);
        let console_body = to_bytes(console_res.into_body(), usize::MAX).await.unwrap();
        let console_html = String::from_utf8(console_body.to_vec()).unwrap();
        assert!(console_html.contains("UBL Console"));

        let registry_res = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/registry")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(registry_res.status(), StatusCode::OK);
        let registry_body = to_bytes(registry_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let registry_html = String::from_utf8(registry_body.to_vec()).unwrap();
        assert!(registry_html.contains("UBL Registry"));
    }

    #[tokio::test]
    async fn audit_pages_render_html() {
        let app = build_router(test_state(None));
        let reports_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/audit/reports")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reports_res.status(), StatusCode::OK);
        let reports_body = to_bytes(reports_res.into_body(), usize::MAX).await.unwrap();
        let reports_html = String::from_utf8(reports_body.to_vec()).unwrap();
        assert!(reports_html.contains("UBL Audit / reports"));

        let snapshots_res = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/audit/snapshots")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(snapshots_res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn audit_list_reports_returns_artifacts() {
        let state = test_state(None);
        seed_meta_chip(
            &state,
            json!({
                "@type":"ubl/audit.dataset.v1",
                "@id":"rpt-1",
                "@ver":"1.0.0",
                "@world":"a/acme/t/prod",
                "line_count": 3,
                "format": "ndjson"
            }),
            "b3:r-audit-1",
        )
        .await;
        let app = build_router(state);

        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v1/audit/reports?world=a/acme/t/prod")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["@type"], "ubl/audit.list");
        assert_eq!(v["kind"], "reports");
        assert_eq!(v["count"], 1);
        assert_eq!(v["rows"][0]["chip_type"], "ubl/audit.dataset.v1");
    }

    #[tokio::test]
    async fn registry_type_page_renders_for_wildcard_path() {
        let state = test_state(None);
        seed_meta_chip(
            &state,
            json!({
                "@type":"ubl/meta.register",
                "@id":"reg-html-1",
                "@ver":"1.0",
                "@world":"a/acme/t/prod",
                "target_type":"acme/invoice",
                "description":"Invoice type",
                "type_version":"1.0",
                "schema":{
                    "required_fields":[{"name":"amount","field_type":"string","description":"Amount"}],
                    "optional_fields":[],
                    "required_cap":"invoice:create"
                },
                "kats":[{
                    "label":"allow invoice",
                    "input":{"@type":"acme/invoice","@id":"i1","@ver":"1.0","@world":"a/acme/t/prod","amount":"10.00"},
                    "expected_decision":"allow"
                }]
            }),
            "b3:r-meta-html-1",
        )
        .await;
        let app = build_router(state);

        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/registry/acme/invoice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Registry Type: acme/invoice"));
    }

    #[tokio::test]
    async fn registry_kat_test_endpoint_runs_and_renders_result() {
        let state = test_state(None);
        seed_meta_chip(
            &state,
            json!({
                "@type":"ubl/meta.register",
                "@id":"reg-kat-1",
                "@ver":"1.0",
                "@world":"a/acme/t/prod",
                "target_type":"acme/invoice",
                "description":"Invoice type",
                "type_version":"1.0",
                "schema":{
                    "required_fields":[{"name":"amount","field_type":"string","description":"Amount"}],
                    "optional_fields":[],
                    "required_cap":"invoice:create"
                },
                "kats":[{
                    "label":"allow invoice",
                    "input":{"@type":"acme/invoice","@id":"i-kat-1","@ver":"1.0","@world":"a/acme/t/prod","amount":"10.00"},
                    "expected_decision":"allow"
                }]
            }),
            "b3:r-meta-kat-1",
        )
        .await;
        let app = build_router(state);

        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/registry/_kat_test")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "chip_type=acme%2Finvoice&version=1.0&kat_index=0",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("KAT Result"));
        assert!(html.contains("allow invoice"));
    }
}
