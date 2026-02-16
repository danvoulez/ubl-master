//! Prometheus metrics for UBL Gate (H15).
//!
//! Counters: allow/deny/knock_reject totals.
//! Histogram: pipeline latency in seconds.

use once_cell::sync::Lazy;
use prometheus::{
    Encoder, Histogram, HistogramOpts, IntCounter, IntCounterVec, Opts, Registry, TextEncoder,
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
        HistogramOpts::new("ubl_pipeline_seconds", "Pipeline processing latency in seconds")
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0]),
    )
    .unwrap();
    REGISTRY.register(Box::new(h.clone())).unwrap();
    h
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

pub fn encode_metrics() -> String {
    // Force lazy init of all metrics so they appear even at zero
    Lazy::force(&CHIPS_TOTAL);
    Lazy::force(&ALLOW_TOTAL);
    Lazy::force(&DENY_TOTAL);
    Lazy::force(&KNOCK_REJECT_TOTAL);
    Lazy::force(&ERROR_TOTAL);
    Lazy::force(&PIPELINE_SECONDS);

    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let mf = REGISTRY.gather();
    encoder.encode(&mf, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap_or_default()
}
