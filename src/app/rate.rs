use governor::middleware::StateInformationMiddleware;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};

#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    pub requests_per_second: u64,
    pub burst_size: u32,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 10,
            burst_size: 15,
        }
    }
}

pub type RateLimiterLayer =
    GovernorLayer<SmartIpKeyExtractor, StateInformationMiddleware, axum::body::Body>;

pub fn create_rate_limiter(config: RateLimiterConfig) -> RateLimiterLayer {
    let conf = GovernorConfigBuilder::default()
        .per_second(config.requests_per_second)
        .burst_size(config.burst_size)
        .key_extractor(SmartIpKeyExtractor)
        .use_headers()
        .finish()
        .expect("Failed to build governor config");

    GovernorLayer::new(conf)
}
