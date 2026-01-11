//! Prometheus metrics for VS observability.

use lazy_static::lazy_static;
use prometheus::{Counter, Gauge, Histogram, IntCounterVec, Opts, Registry};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    // Counter metrics
    pub static ref HEARTBEATS_TOTAL: Counter = Counter::new(
        "vs_heartbeats_total",
        "Total number of heartbeats received from game servers"
    ).unwrap();

    pub static ref PROTECTED_RECEIPTS_TOTAL: Counter = Counter::new(
        "vs_protected_receipts_total",
        "Total number of protected receipts issued"
    ).unwrap();

    pub static ref JOIN_REQUESTS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("vs_join_requests_total", "Total join requests by status"),
        &["status"] // success, rejected, error
    ).unwrap();

    pub static ref TPM_VERIFICATIONS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("vs_tpm_verifications_total", "Total TPM verifications by result"),
        &["result"] // success, failed, skipped
    ).unwrap();

    pub static ref REVOCATIONS_TOTAL: Counter = Counter::new(
        "vs_revocations_total",
        "Total number of session revocations"
    ).unwrap();

    // Gauge metrics
    pub static ref ACTIVE_SESSIONS: Gauge = Gauge::new(
        "vs_active_sessions",
        "Number of currently active game server sessions"
    ).unwrap();

    pub static ref ACTIVE_CONNECTIONS: Gauge = Gauge::new(
        "vs_active_connections",
        "Number of active QUIC connections"
    ).unwrap();

    // Histogram metrics
    pub static ref HEARTBEAT_LATENCY: Histogram = Histogram::with_opts(
        prometheus::HistogramOpts::new(
            "vs_heartbeat_latency_seconds",
            "Heartbeat processing latency in seconds"
        ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0])
    ).unwrap();

    pub static ref TPM_VERIFICATION_LATENCY: Histogram = Histogram::with_opts(
        prometheus::HistogramOpts::new(
            "vs_tpm_verification_latency_seconds",
            "TPM quote verification latency in seconds"
        ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0])
    ).unwrap();
}

/// Initialize and register all metrics.
pub fn register_metrics() {
    REGISTRY
        .register(Box::new(HEARTBEATS_TOTAL.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(PROTECTED_RECEIPTS_TOTAL.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(JOIN_REQUESTS_TOTAL.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(TPM_VERIFICATIONS_TOTAL.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(REVOCATIONS_TOTAL.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(ACTIVE_SESSIONS.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(ACTIVE_CONNECTIONS.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(HEARTBEAT_LATENCY.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(TPM_VERIFICATION_LATENCY.clone()))
        .unwrap();
}

/// Get metrics in Prometheus text format.
#[allow(dead_code)]
pub fn gather_metrics() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
