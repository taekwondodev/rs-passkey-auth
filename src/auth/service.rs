use std::sync::Arc;

use webauthn_rs::Webauthn;

use crate::{
    app::AppError,
    auth::{
        dto::{request::BeginRequest, response::BeginResponse},
        repo::AuthRepository,
    },
};

pub struct AuthService {
    webauthn: Webauthn,
    auth_repo: Arc<dyn AuthRepository>,
}

impl AuthService {
    pub fn new(webauthn: Webauthn, auth_repo: Arc<dyn AuthRepository>) -> Self {
        Self {
            webauthn: webauthn,
            auth_repo: auth_repo,
        }
    }

    pub async fn begin_register(&self, req: BeginRequest) -> Result<BeginResponse, AppError> {
        req.validate()?;

        match self.auth_repo.get_user_by_username(&req.username).await {
            Ok(_) => {
                return Err(AppError::AlreadyExists(format!("Username already exists")));
            }
            Err(AppError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }

        let user = self
            .auth_repo
            .create_user(&req.username, req.role.as_deref())
            .await?;

        let (ccr, passkey_registration) = self
            .webauthn
            .start_passkey_registration(user.id, &req.username, &req.username, None)
            .map_err(|e| {
                AppError::WebAuthnOperation(format!(
                    "Failed to start passkey registration: {:?}",
                    e
                ))
            })?;

        let session_data = serde_json::to_value(passkey_registration).map_err(|e| {
            AppError::WebAuthnOperation(format!("Failed to serialize session data: {:?}", e))
        })?;

        let session_id = self
            .auth_repo
            .create_webauthn_session(user.id, session_data, "registration")
            .await?;

        let opts = serde_json::to_value(ccr).map_err(|e| {
            AppError::WebAuthnOperation(format!("Failed to serialize options: {:?}", e))
        })?;

        Ok(BeginResponse {
            options: opts,
            session_id: session_id.to_string(),
        })
    }
}
