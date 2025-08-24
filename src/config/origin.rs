use std::env;

use axum::http::{self, HeaderValue, Method};
use tower_http::cors::CorsLayer;
use url::Url;

use crate::app::AppError;

#[derive(Debug, Clone)]
pub struct OriginConfig {
    pub frontend_origin: String,
    pub frontend_url: Url,
    pub backend_domain: String,
}

impl OriginConfig {
    pub fn from_env() -> Result<Self, AppError> {
        let frontend_origin = env::var("ORIGIN_FRONTEND")
            .map_err(|_| AppError::ConfigMissing("ORIGIN_FRONTEND".to_string()))?;
        let frontend_url = Url::parse(&frontend_origin).map_err(|_| {
            AppError::ConfigInvalid("ORIGIN_FRONTEND is not a valid URL".to_string())
        })?;

        let _backend_url = env::var("URL_BACKEND")
            .map_err(|_| AppError::ConfigMissing("URL_BACKEND".to_string()))?;
        let backend_url = Url::parse(&_backend_url)
            .map_err(|_| AppError::ConfigInvalid("URL_BACKEND is not a valid URL".to_string()))?;
        let backend_domain = backend_url
            .host_str()
            .ok_or_else(|| {
                AppError::ConfigInvalid("URL_BACKEND must have a valid host".to_string())
            })?
            .to_string();

        Ok(Self {
            frontend_origin: frontend_origin,
            frontend_url: frontend_url,
            backend_domain: backend_domain,
        })
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

    pub fn create_cors_layer(&self) -> Result<CorsLayer, AppError> {
        let origin = self
            .frontend_origin
            .parse::<HeaderValue>()
            .map_err(|_| AppError::ConfigInvalid("Invalid frontend URL for CORS".to_string()))?;

        let cors = CorsLayer::new()
            .allow_origin(origin)
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([http::header::CONTENT_TYPE, http::header::AUTHORIZATION])
            .allow_credentials(true)
            .max_age(std::time::Duration::from_secs(86400))
            .vary([http::header::ORIGIN]);

        Ok(cors)
    }
}
