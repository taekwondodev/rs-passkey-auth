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

use crate::common::{
    constants::{messages, responses, triggers},
    fixture::{mock_access_claims, mock_refresh_claims, mock_session, mock_user},
};

pub struct MockAuthRepository;

impl AuthRepository for MockAuthRepository {
    async fn check_db(&self) -> ServiceHealth {
        ServiceHealth {
            status: HealthStatus::Healthy,
            message: responses::HEALTHY_STATUS_OK.to_string(),
            response_time_ms: Some(responses::DB_RESPONSE_TIME_MS),
        }
    }

    async fn create_user(&self, username: &str, _role: Option<&str>) -> Result<User, AppError> {
        match username {
            triggers::USER_ALREADY_EXISTS => Err(AppError::AlreadyExists(
                messages::USER_ALREADY_EXISTS.to_string(),
            )),
            triggers::DB_ERROR => Err(AppError::InternalServer(
                messages::DB_CONNECTION_FAILED.to_string(),
            )),
            triggers::INVALID_USERNAME => Err(AppError::BadRequest(
                messages::INVALID_USERNAME_FORMAT.to_string(),
            )),
            triggers::SERVICE_DOWN => Err(AppError::ServiceUnavailable(
                messages::DB_SERVICE_DOWN.to_string(),
            )),
            _ => Ok(mock_user()),
        }
    }

    async fn get_user_by_username(&self, username: &str) -> Result<User, AppError> {
        match username {
            triggers::USER_NOT_FOUND => {
                Err(AppError::NotFound(messages::USER_NOT_FOUND.to_string()))
            }
            triggers::DB_ERROR => Err(AppError::InternalServer(
                messages::DB_CONNECTION_FAILED.to_string(),
            )),
            triggers::SERVICE_DOWN => Err(AppError::ServiceUnavailable(
                messages::DB_SERVICE_DOWN.to_string(),
            )),
            _ => Ok(mock_user()),
        }
    }

    async fn get_user_and_session(
        &self,
        _session_id: Uuid,
        username: &str,
        _purpose: &str,
    ) -> Result<(User, WebAuthnSession), AppError> {
        match username {
            triggers::SESSION_NOT_FOUND => {
                Err(AppError::NotFound(messages::SESSION_NOT_FOUND.to_string()))
            }
            triggers::USER_NOT_FOUND => {
                Err(AppError::NotFound(messages::USER_NOT_FOUND.to_string()))
            }
            triggers::DB_ERROR => Err(AppError::InternalServer(
                messages::DB_CONNECTION_FAILED.to_string(),
            )),
            _ => Ok((mock_user(), mock_session())),
        }
    }

    async fn get_active_user_with_credential(
        &self,
        username: &str,
    ) -> Result<(User, Vec<webauthn_rs::prelude::Passkey>), AppError> {
        match username {
            triggers::USER_NOT_FOUND => {
                Err(AppError::NotFound(messages::USER_NOT_FOUND.to_string()))
            }
            triggers::NO_CREDENTIALS => Err(AppError::NotFound(
                messages::NO_CREDENTIALS_FOUND.to_string(),
            )),
            triggers::DB_ERROR => Err(AppError::InternalServer(
                messages::DB_CONNECTION_FAILED.to_string(),
            )),
            _ => Ok((mock_user(), vec![])),
        }
    }

    async fn create_webauthn_session(
        &self,
        user_id: Uuid,
        _data: serde_json::Value,
        _purpose: &str,
    ) -> Result<Uuid, AppError> {
        if user_id.to_string() == triggers::SESSION_CREATION_ERROR_UUID {
            return Err(AppError::InternalServer(
                messages::SESSION_CREATION_FAILED.to_string(),
            ));
        }
        if user_id.to_string() == triggers::SERVICE_UNAVAILABLE_UUID {
            return Err(AppError::ServiceUnavailable(
                messages::DB_SERVICE_DOWN.to_string(),
            ));
        }
        let id = Uuid::parse_str(responses::MOCK_SESSION_UUID).unwrap();
        Ok(id)
    }

    async fn delete_webauthn_session(&self, id: Uuid) -> Result<(), AppError> {
        if id.to_string() == triggers::SESSION_NOT_FOUND_UUID {
            return Err(AppError::NotFound(messages::SESSION_NOT_FOUND.to_string()));
        }
        Ok(())
    }

    async fn update_credential(&self, cred_id: &[u8], _new_counter: u32) -> Result<(), AppError> {
        if cred_id == triggers::ERROR_CRED_ID {
            return Err(AppError::NotFound(
                messages::CREDENTIAL_NOT_FOUND.to_string(),
            ));
        }
        if cred_id == triggers::DB_ERROR_CRED_ID {
            return Err(AppError::InternalServer(messages::DB_ERROR.to_string()));
        }
        Ok(())
    }

    async fn complete_registration(
        &self,
        _user_id: Uuid,
        username: &str,
        _passkey: &webauthn_rs::prelude::Passkey,
    ) -> Result<(), AppError> {
        match username {
            triggers::REGISTRATION_FAILED => Err(AppError::InternalServer(
                messages::REGISTRATION_FAILED.to_string(),
            )),
            triggers::DB_ERROR => Err(AppError::InternalServer(messages::DB_ERROR.to_string())),
            _ => Ok(()),
        }
    }
}

pub struct MockJwtService;

impl JwtService for MockJwtService {
    fn get_public_key_base64(&self) -> String {
        responses::MOCK_PUBLIC_KEY.to_string()
    }

    async fn check_redis(&self) -> ServiceHealth {
        ServiceHealth {
            status: HealthStatus::Healthy,
            message: responses::HEALTHY_STATUS_OK.to_string(),
            response_time_ms: Some(responses::REDIS_RESPONSE_TIME_MS),
        }
    }

    fn generate_token_pair(
        &self,
        _user_id: Uuid,
        _username: &str,
        _role: Option<&str>,
    ) -> TokenPair {
        TokenPair {
            access_token: responses::MOCK_ACCESS_TOKEN.to_string(),
            refresh_token: responses::MOCK_REFRESH_TOKEN.to_string(),
        }
    }

    async fn validate_refresh(&self, token: &str) -> Result<TokenClaims, AppError> {
        match token {
            triggers::INVALID_TOKEN => Err(AppError::Unauthorized(
                messages::INVALID_REFRESH_TOKEN.to_string(),
            )),
            triggers::EXPIRED_TOKEN => {
                Err(AppError::Unauthorized(messages::TOKEN_EXPIRED.to_string()))
            }
            triggers::MALFORMED_TOKEN => {
                Err(AppError::BadRequest(messages::MALFORMED_TOKEN.to_string()))
            }
            triggers::REDIS_ERROR => Err(AppError::InternalServer(
                messages::REDIS_CONNECTION_FAILED.to_string(),
            )),
            _ => Ok(mock_refresh_claims()),
        }
    }

    async fn validate_access(&self, token: &str) -> Result<TokenClaims, AppError> {
        match token {
            triggers::INVALID_TOKEN => Err(AppError::Unauthorized(
                messages::INVALID_ACCESS_TOKEN.to_string(),
            )),
            triggers::EXPIRED_TOKEN => {
                Err(AppError::Unauthorized(messages::TOKEN_EXPIRED.to_string()))
            }
            triggers::BLACKLISTED_TOKEN => Err(AppError::Unauthorized(
                messages::TOKEN_BLACKLISTED.to_string(),
            )),
            triggers::MALFORMED_TOKEN => {
                Err(AppError::BadRequest(messages::MALFORMED_TOKEN.to_string()))
            }
            triggers::REDIS_ERROR => Err(AppError::InternalServer(
                messages::REDIS_CONNECTION_FAILED.to_string(),
            )),
            _ => Ok(mock_access_claims()),
        }
    }

    async fn blacklist(&self, jti: &str, _exp: i64) -> Result<(), AppError> {
        match jti {
            triggers::REDIS_ERROR => Err(AppError::InternalServer(
                messages::REDIS_CONNECTION_FAILED.to_string(),
            )),
            triggers::SERVICE_DOWN => Err(AppError::ServiceUnavailable(
                messages::REDIS_SERVICE_DOWN.to_string(),
            )),
            _ => Ok(()),
        }
    }

    async fn is_blacklisted(&self, jti: &str) -> Result<bool, AppError> {
        match jti {
            triggers::BLACKLISTED_JTI => Ok(true),
            triggers::REDIS_ERROR => Err(AppError::InternalServer(
                messages::REDIS_CONNECTION_FAILED.to_string(),
            )),
            _ => Ok(false),
        }
    }
}
