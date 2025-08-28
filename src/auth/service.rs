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
        model::WebAuthnSession,
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
            webauthn,
            auth_repo,
            jwt_service,
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

        let (session_data, opts) = self.prepare_session_data(passkey_registration, ccr).await?;
        self.create_session_response(user.id, session_data, opts, "login")
            .await
    }

    pub async fn finish_register(&self, req: FinishRequest) -> Result<MessageResponse, AppError> {
        req.validate()?;

        let (session_id, user, session) = self
            .get_user_and_session(&req.session_id, &req.username, "registration")
            .await?;

        let (passkey_registration, credentials) = tokio::join!(
            async { serde_json::from_value::<PasskeyRegistration>(session.data) },
            async { serde_json::from_value::<RegisterPublicKeyCredential>(req.credentials) }
        );
        let passkey_registration = passkey_registration?;
        let credentials = credentials?;

        let passkey = self
            .webauthn
            .finish_passkey_registration(&credentials, &passkey_registration)?;

        self.auth_repo.create_credential(user.id, &passkey).await?;
        self.auth_repo.activate_user(&user.username).await?;
        self.cleanup_session(session_id);

        Ok(MessageResponse {
            message: String::from("Registration completed successfully"),
        })
    }

    pub async fn begin_login(&self, req: BeginRequest) -> Result<BeginResponse, AppError> {
        req.validate()?;

        let user = self.auth_repo.get_user_by_username(&req.username).await?;
        let passkey = self.auth_repo.get_credential_by_user(user.id).await?;
        let (rcr, passkey_authentication) = self.webauthn.start_passkey_authentication(&passkey)?;

        let (session_data, opts) = self
            .prepare_session_data(passkey_authentication, rcr)
            .await?;

        self.create_session_response(user.id, session_data, opts, "login")
            .await
    }

    pub async fn finish_login(
        &self,
        req: FinishRequest,
    ) -> Result<(TokenResponse, String), AppError> {
        req.validate()?;

        let (session_id, user, session) = self
            .get_user_and_session(&req.session_id, &req.username, "login")
            .await?;

        let (passkey_authentication, credentials) = tokio::join!(
            async { serde_json::from_value::<PasskeyAuthentication>(session.data) },
            async { serde_json::from_value::<PublicKeyCredential>(req.credentials) }
        );
        let passkey_authentication = passkey_authentication?;
        let credentials = credentials?;

        let result = self
            .webauthn
            .finish_passkey_authentication(&credentials, &passkey_authentication)?;

        if result.needs_update() {
            self.auth_repo
                .update_credential(result.cred_id(), result.counter())
                .await?;
        }

        self.cleanup_session(session_id);

        let token_pair = self
            .jwt_service
            .generate_token_pair(user.id, &user.username, user.role);

        Ok((
            TokenResponse {
                message: String::from("Login completed successfully"),
                access_token: token_pair.access_token,
            },
            token_pair.refresh_token,
        ))
    }

    pub async fn refresh(&self, refresh_token: &str) -> Result<(TokenResponse, String), AppError> {
        // in valida token, devo controllare se è blacklistato
        // blacklisto il vecchio token
        // dai claims devo creare un nuovo token pair
        // ok
        todo!("unimplemented");
    }

    pub async fn logout(&self, refresh_token: &str) -> Result<MessageResponse, AppError> {
        // se è diverso da "" e valido, blacklisto in un thread a parte
        // a prescindere ok
        todo!("unimplemented");
    }

    async fn prepare_session_data<T, U>(
        &self,
        session_obj: T,
        options_obj: U,
    ) -> Result<(serde_json::Value, serde_json::Value), AppError>
    where
        T: serde::Serialize + Send,
        U: serde::Serialize + Send,
    {
        let (session_data, opts) =
            tokio::join!(async { serde_json::to_value(session_obj) }, async {
                serde_json::to_value(options_obj)
            });
        Ok((session_data?, opts?))
    }

    async fn create_session_response(
        &self,
        user_id: Uuid,
        session_data: serde_json::Value,
        opts: serde_json::Value,
        session_type: &str,
    ) -> Result<BeginResponse, AppError> {
        let session_id = self
            .auth_repo
            .create_webauthn_session(user_id, session_data, session_type)
            .await?;

        Ok(BeginResponse {
            options: opts,
            session_id: String::from(session_id),
        })
    }

    async fn get_user_and_session(
        &self,
        session_id_str: &str,
        username: &str,
        session_type: &str,
    ) -> Result<(Uuid, crate::auth::model::User, WebAuthnSession), AppError> {
        let session_id = Uuid::try_parse(session_id_str)?;
        let user = self.auth_repo.get_user_by_username(username).await?;
        let session = self
            .auth_repo
            .get_webauthn_session(session_id, session_type)
            .await?;

        Ok((session_id, user, session))
    }

    fn cleanup_session(&self, session_id: Uuid) {
        let auth_repo = Arc::clone(&self.auth_repo);
        tokio::spawn(async move {
            if let Err(e) = auth_repo.delete_webauthn_session(session_id).await {
                tracing::warn!("Failed to delete webauthn session {}: {}", session_id, e);
            }
        });
    }
}
