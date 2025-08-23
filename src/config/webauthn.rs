use std::env;

use webauthn_rs::{Webauthn, WebauthnBuilder};

pub struct WebAuthnConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: url::Url,
}

impl WebAuthnConfig {
    pub fn from_env() -> Self {
        let rp_name = env::var("WEBAUTHN_RP_NAME").expect("WEBAUTHN_RP_NAME is not defined");
        let rp_id = env::var("URL_BACKEND").expect("URL_BACKEND is not definedd");
        let rp_origin =
            url::Url::parse(&env::var("ORIGIN_FRONTEND").expect("ORIGIN_FRONTEND is not defined"))
                .expect("ORIGIN_FRONTEND is not well defined");

        Self {
            rp_name: rp_name,
            rp_id: rp_id,
            rp_origin: rp_origin,
        }
    }

    pub fn create_webauthn(&self) -> Result<Webauthn, Box<dyn std::error::Error>> {
        let builder = WebauthnBuilder::new(&self.rp_id, &self.rp_origin)
            .map_err(|e| format!("Failed to create WebAuthnBuilder: {:?}", e))?;

        let webauthn = builder
            .rp_name(&self.rp_name)
            .build()
            .map_err(|e| format!("Failed to build Webauthn: {:?}", e))?;

        Ok(webauthn)
    }
}
