use std::env;

use axum::http::{self, HeaderValue, Method};
use tower_http::cors::CorsLayer;
use url::Url;

const ALLOWED_METHODS: [Method; 3] = [Method::GET, Method::POST, Method::OPTIONS];
const ALLOWED_HEADERS: [http::HeaderName; 2] =
    [http::header::CONTENT_TYPE, http::header::AUTHORIZATION];
const ALLOW_CREDENTIALS: bool = true;
const MAX_AGE: std::time::Duration = std::time::Duration::from_secs(86400);
const VARY_HEADERS: [http::HeaderName; 1] = [http::header::ORIGIN];

#[derive(Debug)]
pub struct OriginConfig {
    pub frontend_origin: String,
    pub frontend_url: Url,
    pub backend_domain: String,
}

impl OriginConfig {
    pub fn from_env() -> Self {
        let frontend_origin = env::var("ORIGIN_FRONTEND").unwrap();
        let frontend_url = Url::parse(&frontend_origin).unwrap();

        let _backend_url = env::var("URL_BACKEND").unwrap();
        let backend_url = Url::parse(&_backend_url).unwrap();
        let backend_domain = backend_url.host_str().unwrap().to_string();

        Self {
            frontend_origin,
            frontend_url,
            backend_domain,
        }
    }

    pub fn rp_id(&self) -> &str {
        &self.backend_domain
    }

    pub fn rp_origin(&self) -> &Url {
        &self.frontend_url
    }

    pub fn frontend_origin(&self) -> &str {
        &self.frontend_origin
    }

    pub fn create_cors_layer(&self) -> CorsLayer {
        let origin = self.frontend_origin.parse::<HeaderValue>().unwrap();
        CorsLayer::new()
            .allow_origin(origin)
            .allow_methods(ALLOWED_METHODS)
            .allow_headers(ALLOWED_HEADERS)
            .allow_credentials(ALLOW_CREDENTIALS)
            .max_age(MAX_AGE)
            .vary(VARY_HEADERS)
    }
}
