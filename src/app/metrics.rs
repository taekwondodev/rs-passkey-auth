use axum::{http::StatusCode, response::IntoResponse};
use axum_prometheus::PrometheusMetricLayer;

lazy_static::lazy_static! {
    pub static ref REGISTRATION_ATTEMPTS: prometheus::CounterVec = prometheus::register_counter_vec!(
        "webauthn_registration_attempts_total",
        "Total number of WebAuthn registration attempts",
        &["status"]
    ).unwrap();

    pub static ref LOGIN_ATTEMPTS: prometheus::CounterVec = prometheus::register_counter_vec!(
        "webauthn_login_attempts_total",
        "Total number of WebAuthn login attempts",
        &["status"]
    ).unwrap();

    pub static ref TOKEN_OPERATIONS: prometheus::CounterVec = prometheus::register_counter_vec!(
        "jwt_token_operations_total",
        "Total number of JWT token operations",
        &["operation", "status"]
    ).unwrap();

    pub static ref HEALTH_CHECKS: prometheus::CounterVec = prometheus::register_counter_vec!(
        "health_check_requests_total",
        "Total number of health check requests",
        &["status"]
    ).unwrap();
}

/// Get Prometheus metrics
///
/// Returns all metrics in Prometheus format for scraping by monitoring systems
#[utoipa::path(
    get,
    path = "/metrics",
    tag = "Monitoring",
    responses(
        (status = 200, description = "Prometheus metrics", content_type = "text/plain"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn metrics_handler() -> impl IntoResponse {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();

    match encoder.encode_to_string(&metric_families) {
        Ok(metrics) => (StatusCode::OK, metrics),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("Failed to encode metrics"),
        ),
    }
}

pub fn create_prometheus_layer() -> PrometheusMetricLayer<'static> {
    PrometheusMetricLayer::new()
}

pub fn track_registration_attempt(success: bool) {
    let status = if success { "success" } else { "failure" };
    REGISTRATION_ATTEMPTS.with_label_values(&[status]).inc();
}

pub fn track_login_attempt(success: bool) {
    let status = if success { "success" } else { "failure" };
    LOGIN_ATTEMPTS.with_label_values(&[status]).inc();
}

pub fn track_token_operation(operation: &str, success: bool) {
    let status = if success { "success" } else { "failure" };
    TOKEN_OPERATIONS
        .with_label_values(&[operation, status])
        .inc();
}

pub fn track_health_check(success: bool) {
    let status = if success { "healthy" } else { "unhealthy" };
    HEALTH_CHECKS.with_label_values(&[status]).inc();
}
