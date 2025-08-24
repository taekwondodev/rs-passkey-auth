use std::env;

use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::{app::AppError, config::origin::OriginConfig};

pub struct WebAuthnConfig {
    pub rp_name: String,
}

impl WebAuthnConfig {
    pub fn from_env() -> Result<Self, AppError> {
        let rp_name = env::var("WEBAUTHN_RP_NAME")
            .map_err(|_| AppError::ConfigMissing("WEBAUTHN_RP_NAME".to_string()))?;

        Ok(Self { rp_name })
    }

    pub fn create_webauthn(&self, origin_config: &OriginConfig) -> Result<Webauthn, AppError> {
        let builder = WebauthnBuilder::new(&origin_config.rp_id(), &origin_config.rp_origin())
            .map_err(|e| {
                AppError::WebAuthnCreation(format!("Failed to create WebAuthnBuilder: {:?}", e))
            })?;

        let webauthn = builder.rp_name(&self.rp_name).build().map_err(|e| {
            AppError::WebAuthnCreation(format!("Failed to build Webauthn: {:?}", e))
        })?;

        Ok(webauthn)
    }
}
