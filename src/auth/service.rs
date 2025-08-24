use std::sync::Arc;

use uuid::Uuid;
use webauthn_rs::{
    Webauthn,
    prelude::{PasskeyRegistration, RegisterPublicKeyCredential},
};

use crate::{
    app::AppError,
    auth::{
        dto::{
            request::{BeginRequest, FinishRequest},
            response::{BeginResponse, MessageResponse},
        },
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

    pub async fn finish_register(&self, req: FinishRequest) -> Result<MessageResponse, AppError> {
        req.validate()?;

        let session_id = Uuid::try_parse(&req.session_id)?;
        let user = self.auth_repo.get_user_by_username(&req.username).await?;
        let session = self
            .auth_repo
            .get_webauthn_session(session_id, "registration")
            .await?;
        let passkey_registration: PasskeyRegistration = serde_json::from_value(session.data)
            .map_err(|e| {
                AppError::WebAuthnOperation(format!("Failed to deserialize session data: {:?}", e))
            })?;
        let credentials: RegisterPublicKeyCredential = serde_json::from_value(req.credentials)
            .map_err(|e| {
                AppError::WebAuthnOperation(format!("Failed to deserialize credentials: {:?}", e))
            })?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(&credentials, &passkey_registration)
            .map_err(|e| {
                AppError::WebAuthnOperation(format!(
                    "Failed to finish passkey registration: {:?}",
                    e
                ))
            })?;
        self.auth_repo.create_credential(user.id, &passkey).await?;
        self.auth_repo.delete_webauthn_session(session_id).await?;
        self.auth_repo.activate_user(&req.username).await?;
        Ok(MessageResponse {
            message: "Registration completed successfully".to_string(),
        })
    }

    pub async fn begin_login(&self, req: BeginRequest) -> Result<BeginResponse, AppError> {
        req.validate()?;

        let user = self.auth_repo.get_user_by_username(&req.username).await?;
        let passkey = self.auth_repo.get_credential_by_user(user.id).await?;
        let (rcr, passkey_authentication) = self
            .webauthn
            .start_passkey_authentication(&passkey)
            .map_err(|e| AppError::WebAuthnOperation(format!("Failed to start login: {:?}", e)))?;
        let session_data = serde_json::to_value(passkey_authentication).map_err(|e| {
            AppError::WebAuthnOperation(format!("Failed to serialize session data: {:?}", e))
        })?;
        let session_id = self
            .auth_repo
            .create_webauthn_session(user.id, session_data, "login")
            .await?;
        let opts = serde_json::to_value(rcr).map_err(|e| {
            AppError::WebAuthnOperation(format!("Failed to serialize options: {:?}", e))
        })?;

        Ok(BeginResponse {
            options: opts,
            session_id: session_id.to_string(),
        })
    }
}
