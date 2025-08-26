use std::env;

use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::{app::AppError, config::origin::OriginConfig};

pub struct WebAuthnConfig {
    pub rp_name: String,
}

impl WebAuthnConfig {
    pub fn from_env() -> Result<Self, AppError> {
        let rp_name = env::var("WEBAUTHN_RP_NAME")?;

        Ok(Self { rp_name })
    }

    pub fn create_webauthn(&self, origin_config: &OriginConfig) -> Webauthn {
        let builder = WebauthnBuilder::new(&origin_config.rp_id(), &origin_config.rp_origin())
            .expect("Invalid Webauthn configuration");

        builder
            .rp_name(&self.rp_name)
            .build()
            .expect("Invalid Webauthn configuration")
    }
}
