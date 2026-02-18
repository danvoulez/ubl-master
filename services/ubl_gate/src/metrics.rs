//! Prometheus metrics for UBL Gate (H15).
//!
//! Counters: allow/deny/knock_reject totals.
//! Histogram: pipeline latency in seconds.

use once_cell::sync::Lazy;
use prometheus::{
    Encoder, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder,
};

static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

static CHIPS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new("ubl_chips_total", "Total chips submitted to the gate").unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static ALLOW_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new("ubl_allow_total", "Chips that received Allow decision").unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static DENY_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new("ubl_deny_total", "Chips that received Deny decision").unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static KNOCK_REJECT_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new(
        "ubl_knock_reject_total",
        "Chips rejected at KNOCK stage (pre-pipeline)",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static ERROR_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new("ubl_errors_total", "Pipeline errors by error code"),
        &["code"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static PIPELINE_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    let h = Histogram::with_opts(
        HistogramOpts::new(
            "ubl_pipeline_seconds",
            "Pipeline processing latency in seconds",
        )
        .buckets(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0,
        ]),
    )
    .unwrap();
    REGISTRY.register(Box::new(h.clone())).unwrap();
    h
});

static CRYPTO_VERIFY_FAIL_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "ubl_crypto_verify_fail_total",
            "Crypto verification failures by component and mode",
        ),
        &["component", "mode"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static CANON_DIVERGENCE_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "ubl_canon_divergence_total",
            "Canonicalization divergence incidents by component",
        ),
        &["component"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static OUTBOX_PENDING: Lazy<IntGauge> = Lazy::new(|| {
    let g = IntGauge::new("ubl_outbox_pending", "Pending outbox events").unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

static OUTBOX_RETRY_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new("ubl_outbox_retry_total", "Outbox retry attempts").unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static IDEMPOTENCY_HIT_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new(
        "ubl_idempotency_hit_total",
        "Idempotency cache hits (replay served)",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static IDEMPOTENCY_REPLAY_BLOCK_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new(
        "ubl_idempotency_replay_block_total",
        "Replay requests blocked by idempotency",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static EVENTS_INGESTED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "ubl_events_ingested_total",
            "Events ingested into the Event Hub by stage and world",
        ),
        &["stage", "world"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static EVENTS_STREAM_CLIENTS: Lazy<IntGaugeVec> = Lazy::new(|| {
    let g = IntGaugeVec::new(
        Opts::new(
            "ubl_events_stream_clients",
            "Active event stream clients by world filter",
        ),
        &["world"],
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

static EVENTS_STREAM_DROPPED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "ubl_events_stream_dropped_total",
            "Dropped event stream deliveries by reason",
        ),
        &["reason"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub fn inc_chips_total() {
    CHIPS_TOTAL.inc();
}

pub fn inc_allow() {
    ALLOW_TOTAL.inc();
}

pub fn inc_deny() {
    DENY_TOTAL.inc();
}

pub fn inc_knock_reject() {
    KNOCK_REJECT_TOTAL.inc();
}

pub fn inc_error(code: &str) {
    ERROR_TOTAL.with_label_values(&[code]).inc();
}

pub fn observe_pipeline_seconds(secs: f64) {
    PIPELINE_SECONDS.observe(secs);
}

pub fn inc_crypto_verify_fail(component: &str, mode: &str) {
    CRYPTO_VERIFY_FAIL_TOTAL
        .with_label_values(&[component, mode])
        .inc();
}

pub fn inc_canon_divergence(component: &str) {
    CANON_DIVERGENCE_TOTAL.with_label_values(&[component]).inc();
}

pub fn set_outbox_pending(v: i64) {
    OUTBOX_PENDING.set(v);
}

pub fn inc_outbox_retry() {
    OUTBOX_RETRY_TOTAL.inc();
}

pub fn inc_idempotency_hit() {
    IDEMPOTENCY_HIT_TOTAL.inc();
}

pub fn inc_idempotency_replay_block() {
    IDEMPOTENCY_REPLAY_BLOCK_TOTAL.inc();
}

pub fn inc_events_ingested(stage: &str, world: &str) {
    EVENTS_INGESTED_TOTAL
        .with_label_values(&[stage, world])
        .inc();
}

pub fn inc_events_stream_clients(world: &str) {
    EVENTS_STREAM_CLIENTS.with_label_values(&[world]).inc();
}

pub fn dec_events_stream_clients(world: &str) {
    EVENTS_STREAM_CLIENTS.with_label_values(&[world]).dec();
}

pub fn inc_events_stream_dropped(reason: &str) {
    EVENTS_STREAM_DROPPED_TOTAL
        .with_label_values(&[reason])
        .inc();
}

pub fn encode_metrics() -> String {
    // Force lazy init of all metrics so they appear even at zero
    Lazy::force(&CHIPS_TOTAL);
    Lazy::force(&ALLOW_TOTAL);
    Lazy::force(&DENY_TOTAL);
    Lazy::force(&KNOCK_REJECT_TOTAL);
    Lazy::force(&ERROR_TOTAL);
    Lazy::force(&PIPELINE_SECONDS);
    Lazy::force(&CRYPTO_VERIFY_FAIL_TOTAL);
    Lazy::force(&CANON_DIVERGENCE_TOTAL);
    Lazy::force(&OUTBOX_PENDING);
    Lazy::force(&OUTBOX_RETRY_TOTAL);
    Lazy::force(&IDEMPOTENCY_HIT_TOTAL);
    Lazy::force(&IDEMPOTENCY_REPLAY_BLOCK_TOTAL);
    Lazy::force(&EVENTS_INGESTED_TOTAL);
    Lazy::force(&EVENTS_STREAM_CLIENTS);
    Lazy::force(&EVENTS_STREAM_DROPPED_TOTAL);

    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let mf = REGISTRY.gather();
    encoder.encode(&mf, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap_or_default()
}
