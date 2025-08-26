use std::sync::Arc;

use uuid::Uuid;
use webauthn_rs::{
    Webauthn,
    prelude::{
        PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
        RegisterPublicKeyCredential,
    },
};

use crate::{
    app::AppError,
    auth::{
        dto::{
            request::{BeginRequest, FinishRequest},
            response::{BeginResponse, MessageResponse, TokenResponse},
        },
        repo::AuthRepository,
    },
    utils::jwt::JwtService,
};

pub struct AuthService {
    webauthn: Webauthn,
    auth_repo: Arc<dyn AuthRepository>,
    jwt_service: Arc<JwtService>,
}

impl AuthService {
    pub fn new(
        webauthn: Webauthn,
        auth_repo: Arc<dyn AuthRepository>,
        jwt_service: Arc<JwtService>,
    ) -> Self {
        Self {
            webauthn: webauthn,
            auth_repo: auth_repo,
            jwt_service: jwt_service,
        }
    }

    pub async fn begin_register(&self, req: BeginRequest) -> Result<BeginResponse, AppError> {
        req.validate()?;

        match self.auth_repo.get_user_by_username(&req.username).await {
            Ok(_) => {
                return Err(AppError::AlreadyExists(String::from(
                    "Username already exists",
                )));
            }
            Err(AppError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }

        let user = self
            .auth_repo
            .create_user(&req.username, req.role.as_deref())
            .await?;

        let (ccr, passkey_registration) = self.webauthn.start_passkey_registration(
            user.id,
            &req.username,
            &req.username,
            None,
        )?;

        // vedo se posso fare session_data e opts in parallelo
        let session_data = serde_json::to_value(passkey_registration)?;
        let opts = serde_json::to_value(ccr)?;

        let session_id = self
            .auth_repo
            .create_webauthn_session(user.id, session_data, "registration")
            .await?;

        Ok(BeginResponse {
            options: opts,
            session_id: String::from(session_id),
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

        // vedo se posso farli in parallelo
        let passkey_registration: PasskeyRegistration = serde_json::from_value(session.data)?;
        let credentials: RegisterPublicKeyCredential = serde_json::from_value(req.credentials)?;

        let passkey = self
            .webauthn
            .finish_passkey_registration(&credentials, &passkey_registration)?;

        self.auth_repo.create_credential(user.id, &passkey).await?;
        self.auth_repo.activate_user(&req.username).await?;

        // questo in un thread a parte
        self.auth_repo.delete_webauthn_session(session_id).await?;
        Ok(MessageResponse {
            message: String::from("Registration completed successfully"),
        })
    }

    pub async fn begin_login(&self, req: BeginRequest) -> Result<BeginResponse, AppError> {
        req.validate()?;

        let user = self.auth_repo.get_user_by_username(&req.username).await?;
        let passkey = self.auth_repo.get_credential_by_user(user.id).await?;
        let (rcr, passkey_authentication) = self.webauthn.start_passkey_authentication(&passkey)?;

        // vedo se posso farli in parallelo
        let session_data = serde_json::to_value(passkey_authentication)?;
        let opts = serde_json::to_value(rcr)?;

        let session_id = self
            .auth_repo
            .create_webauthn_session(user.id, session_data, "login")
            .await?;

        Ok(BeginResponse {
            options: opts,
            session_id: String::from(session_id),
        })
    }

    pub async fn finish_login(
        &self,
        req: FinishRequest,
    ) -> Result<(TokenResponse, String), AppError> {
        req.validate()?;

        let session_id = Uuid::try_parse(&req.session_id)?;
        let user = self.auth_repo.get_user_by_username(&req.username).await?;
        let session = self
            .auth_repo
            .get_webauthn_session(session_id, "login")
            .await?;

        // vedo se posso farli in parallelo
        let passkey_authentication: PasskeyAuthentication = serde_json::from_value(session.data)?;
        let credentials: PublicKeyCredential = serde_json::from_value(req.credentials)?;

        let result = self
            .webauthn
            .finish_passkey_authentication(&credentials, &passkey_authentication)?;

        if result.needs_update() {
            self.auth_repo
                .update_credential(result.cred_id(), result.counter())
                .await?;
        }

        // in un altro thread
        self.auth_repo.delete_webauthn_session(session_id).await?;

        let token_pair = self
            .jwt_service
            .generate_token_pair(user.id, &req.username, user.role)?;

        Ok((
            TokenResponse {
                message: String::from("Login completed successfully"),
                access_token: token_pair.access_token,
            },
            token_pair.refresh_token,
        ))
    }
}
