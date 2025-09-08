use rs_passkey_auth::{
    app::AppError,
    auth::{
        dto::response::{HealthStatus, ServiceHealth},
        model::{User, WebAuthnSession},
        traits::{AuthRepository, JwtService},
    },
    utils::jwt::{TokenClaims, TokenPair},
};
use uuid::Uuid;

use crate::common::helper::{mock_access_claims, mock_refresh_claims, mock_session, mock_user};

pub struct MockAuthRepository;

impl AuthRepository for MockAuthRepository {
    async fn check_db(&self) -> ServiceHealth {
        ServiceHealth {
            status: HealthStatus::Healthy,
            message: "OK".to_string(),
            response_time_ms: Some(100),
        }
    }

    async fn create_user(&self, _username: &str, _role: Option<&str>) -> Result<User, AppError> {
        Ok(mock_user())
    }

    async fn get_user_by_username(&self, _username: &str) -> Result<User, AppError> {
        Ok(mock_user())
    }

    async fn get_user_and_session(
        &self,
        _session_id: Uuid,
        _username: &str,
        _purpose: &str,
    ) -> Result<(User, WebAuthnSession), AppError> {
        Ok((mock_user(), mock_session()))
    }

    async fn get_active_user_with_credential(
        &self,
        _username: &str,
    ) -> Result<(User, Vec<webauthn_rs::prelude::Passkey>), AppError> {
        Ok((mock_user(), vec![]))
    }

    async fn create_webauthn_session(
        &self,
        _user_id: Uuid,
        _data: serde_json::Value,
        _purpose: &str,
    ) -> Result<Uuid, AppError> {
        let id = Uuid::parse_str("12345678-1234-1234-1234-123456789def").unwrap();
        Ok(id)
    }

    async fn delete_webauthn_session(&self, _id: Uuid) -> Result<(), AppError> {
        Ok(())
    }

    async fn update_credential(&self, _cred_id: &[u8], _new_counter: u32) -> Result<(), AppError> {
        Ok(())
    }

    async fn complete_registration(
        &self,
        _user_id: Uuid,
        _username: &str,
        _passkey: &webauthn_rs::prelude::Passkey,
    ) -> Result<(), AppError> {
        Ok(())
    }
}

pub struct MockJwtService;

impl JwtService for MockJwtService {
    fn get_public_key_base64(&self) -> String {
        "mock_public_key".to_string()
    }

    async fn check_redis(&self) -> ServiceHealth {
        ServiceHealth {
            status: HealthStatus::Healthy,
            message: "OK".to_string(),
            response_time_ms: Some(30),
        }
    }

    fn generate_token_pair(
        &self,
        _user_id: Uuid,
        _username: &str,
        _role: Option<&str>,
    ) -> TokenPair {
        TokenPair {
            access_token: "mock_access_token".to_string(),
            refresh_token: "mock_refresh_token".to_string(),
        }
    }

    async fn validate_refresh(&self, _token: &str) -> Result<TokenClaims, AppError> {
        Ok(mock_refresh_claims())
    }

    async fn validate_access(&self, _token: &str) -> Result<TokenClaims, AppError> {
        Ok(mock_access_claims())
    }

    async fn blacklist(&self, _jti: &str, _exp: i64) -> Result<(), AppError> {
        Ok(())
    }

    async fn is_blacklisted(&self, _jti: &str) -> Result<bool, AppError> {
        Ok(false)
    }
}
