use std::env;

use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::app::AppError;

pub struct WebAuthnConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: url::Url,
}

impl WebAuthnConfig {
    pub fn from_env() -> Result<Self, AppError> {
        let rp_name = env::var("WEBAUTHN_RP_NAME")
            .map_err(|_| AppError::ConfigMissing("WEBAUTHN_RP_NAME".to_string()))?;

        let rp_id = env::var("URL_BACKEND")
            .map_err(|_| AppError::ConfigMissing("URL_BACKEND".to_string()))?;

        let rp_origin_str = env::var("ORIGIN_FRONTEND")
            .map_err(|_| AppError::ConfigMissing("ORIGIN_FRONTEND".to_string()))?;

        let rp_origin = url::Url::parse(&rp_origin_str).map_err(|_| {
            AppError::ConfigInvalid("ORIGIN_FRONTEND is not a valid URL".to_string())
        })?;

        Ok(Self {
            rp_name,
            rp_id,
            rp_origin,
        })
    }

    pub fn create_webauthn(&self) -> Result<Webauthn, AppError> {
        let builder = WebauthnBuilder::new(&self.rp_id, &self.rp_origin).map_err(|e| {
            AppError::WebAuthnCreation(format!("Failed to create WebAuthnBuilder: {:?}", e))
        })?;

        let webauthn = builder.rp_name(&self.rp_name).build().map_err(|e| {
            AppError::WebAuthnCreation(format!("Failed to build Webauthn: {:?}", e))
        })?;

        Ok(webauthn)
    }
}
