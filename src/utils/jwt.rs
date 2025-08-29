use std::env;

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use redis::aio::ConnectionManager;
use rusty_paseto::{
    core::{
        Key, Local, PasetoAsymmetricPrivateKey, PasetoAsymmetricPublicKey, PasetoSymmetricKey,
        Public, V4,
    },
    prelude::{
        CustomClaim, ExpirationClaim, IssuedAtClaim, PasetoBuilder, PasetoParser, SubjectClaim,
        TokenIdentifierClaim,
    },
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::app::AppError;

const ACCESS_TOKEN_DURATION: Duration = Duration::minutes(5);
const REFRESH_TOKEN_DURATION: Duration = Duration::days(1);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: Uuid,
    pub username: String,
    pub role: Option<String>,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

pub enum TokenType {
    Access,
    Refresh,
}

pub struct JwtService {
    redis_manager: ConnectionManager,
    symmetric_key: [u8; 32],
    private_key: [u8; 64],
    public_key: [u8; 32],
    access_token_duration: Duration,
    refresh_token_duration: Duration,
}

impl JwtService {
    pub fn new(conn_manager: ConnectionManager) -> Self {
        let secret_key = env::var("JWT_SECRET_KEY").unwrap();
        if secret_key.len() < 32 {
            panic!("JWT_SECRET_KEY must be at least 32 characters");
        }

        let mut symmetric_key = [0u8; 32];
        let key_bytes = secret_key.as_bytes();
        let len = std::cmp::min(key_bytes.len(), 32);
        symmetric_key[..len].copy_from_slice(&key_bytes[..len]);

        let signing_key = SigningKey::from_bytes(&symmetric_key);
        let verifying_key = signing_key.verifying_key();

        let private_key: [u8; 64] = {
            let mut key = [0u8; 64];
            key[..32].copy_from_slice(&signing_key.to_bytes());
            key[32..].copy_from_slice(&verifying_key.to_bytes());
            key
        };

        let public_key: [u8; 32] = verifying_key.to_bytes();

        Self {
            redis_manager: conn_manager,
            symmetric_key,
            private_key,
            public_key,
            access_token_duration: ACCESS_TOKEN_DURATION,
            refresh_token_duration: REFRESH_TOKEN_DURATION,
        }
    }

    pub fn generate_token_pair(
        &self,
        user_id: Uuid,
        username: &str,
        role: Option<String>,
    ) -> TokenPair {
        let now = Utc::now();
        let access_exp = now + self.access_token_duration;
        let refresh_exp = now + self.refresh_token_duration;

        let access_token = self.create_token(
            TokenType::Access,
            user_id,
            username,
            role.clone(),
            access_exp,
            now,
        );
        let refresh_token = self.create_token(
            TokenType::Refresh,
            user_id,
            username,
            role,
            refresh_exp,
            now,
        );

        TokenPair {
            access_token,
            refresh_token,
        }
    }

    pub async fn validate_refresh(&self, token: &str) -> Result<TokenClaims, AppError> {
        self.validate(TokenType::Refresh, token).await
    }

    pub async fn validate_access(&self, token: &str) -> Result<TokenClaims, AppError> {
        self.validate(TokenType::Access, token).await
    }

    pub async fn validate(
        &self,
        token_type: TokenType,
        token: &str,
    ) -> Result<TokenClaims, AppError> {
        let json_value = match token_type {
            TokenType::Access => {
                let _key = Key::from(&self.public_key);
                let key = PasetoAsymmetricPublicKey::<V4, Public>::from(&_key);
                PasetoParser::<V4, Public>::default()
                    .parse(token, &key)
                    .map_err(|_| {
                        AppError::Unauthorized(String::from("Invalid access token signature"))
                    })?
            }
            TokenType::Refresh => {
                let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(&self.symmetric_key));
                PasetoParser::<V4, Local>::default()
                    .parse(token, &key)
                    .map_err(|_| {
                        AppError::Unauthorized(String::from("Invalid refresh token signature"))
                    })?
            }
        };

        self.extract_claims(json_value).await
    }

    async fn extract_claims(&self, json_value: serde_json::Value) -> Result<TokenClaims, AppError> {
        let sub = Uuid::parse_str(json_value["sub"].as_str().unwrap()).unwrap();
        let username = json_value["username"].as_str().unwrap().to_string();
        let role = json_value["role"].as_str().map(|s| s.to_string());
        let jti = json_value["jti"].as_str().unwrap().to_string();

        let _iat = json_value["iat"].as_str().unwrap();
        let iat = chrono::DateTime::parse_from_rfc3339(_iat)
            .unwrap()
            .timestamp();
        let _exp = json_value["exp"].as_str().unwrap();
        let exp = chrono::DateTime::parse_from_rfc3339(_exp)
            .unwrap()
            .timestamp();
        let now = Utc::now().timestamp();
        if exp < now {
            return Err(AppError::Unauthorized(String::from("Token has expired")));
        }

        if self.is_blacklisted(&jti).await? {
            return Err(AppError::Unauthorized(String::from(
                "Token has been revoked",
            )));
        }

        Ok(TokenClaims {
            sub,
            username,
            role,
            jti,
            iat,
            exp,
        })
    }

    pub async fn blacklist(&self, jti: &str, exp: i64) -> Result<(), AppError> {
        let mut conn = self.redis_manager.clone();
        let redis_key = format!("blacklist:{}", jti);

        let now = Utc::now().timestamp();
        let ttl = if exp - now <= 0 { 1 } else { exp };

        use redis::AsyncCommands;
        let () = conn.set_ex(&redis_key, "1", ttl as u64).await?;

        Ok(())
    }

    pub async fn is_blacklisted(&self, jti: &str) -> Result<bool, AppError> {
        let mut conn = self.redis_manager.clone();
        let redis_key = format!("blacklist:{}", jti);

        let exists: bool = {
            use redis::AsyncCommands;
            conn.exists(&redis_key).await?
        };

        Ok(exists)
    }

    fn generate_jti() -> String {
        let uuid = Uuid::new_v4();
        BASE64_URL_SAFE_NO_PAD.encode(uuid.as_bytes())
    }

    fn create_token(
        &self,
        token_type: TokenType,
        user_id: Uuid,
        username: &str,
        role: Option<String>,
        exp: chrono::DateTime<Utc>,
        now: chrono::DateTime<Utc>,
    ) -> String {
        let jti = Self::generate_jti();
        let exp_iso = exp.to_rfc3339();
        let iat_iso = now.to_rfc3339();
        let _user_id = String::from(user_id);

        match token_type {
            TokenType::Access => {
                let _key = Key::from(&self.private_key);
                let key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&_key);
                self.create_access_token(key, jti, exp_iso, iat_iso, _user_id, username, role)
            }
            TokenType::Refresh => {
                let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(&self.symmetric_key));
                self.create_refresh_token(key, jti, exp_iso, iat_iso, _user_id, username, role)
            }
        }
    }

    fn create_access_token(
        &self,
        key: PasetoAsymmetricPrivateKey<'_, V4, Public>,
        jti: String,
        exp_iso: String,
        iat_iso: String,
        user_id: String,
        username: &str,
        role: Option<String>,
    ) -> String {
        if let Some(ref r) = role {
            PasetoBuilder::<V4, Public>::default()
                .set_claim(SubjectClaim::from(user_id.as_str()))
                .set_claim(ExpirationClaim::try_from(exp_iso.as_str()).unwrap())
                .set_claim(IssuedAtClaim::try_from(iat_iso.as_str()).unwrap())
                .set_claim(TokenIdentifierClaim::from(jti.as_str()))
                .set_claim(CustomClaim::try_from(("username", username)).unwrap())
                .set_claim(CustomClaim::try_from(("role", r.as_str())).unwrap())
                .build(&key)
                .unwrap()
        } else {
            PasetoBuilder::<V4, Public>::default()
                .set_claim(SubjectClaim::from(user_id.as_str()))
                .set_claim(ExpirationClaim::try_from(exp_iso.as_str()).unwrap())
                .set_claim(IssuedAtClaim::try_from(iat_iso.as_str()).unwrap())
                .set_claim(TokenIdentifierClaim::from(jti.as_str()))
                .set_claim(CustomClaim::try_from(("username", username)).unwrap())
                .build(&key)
                .unwrap()
        }
    }

    fn create_refresh_token(
        &self,
        key: PasetoSymmetricKey<V4, Local>,
        jti: String,
        exp_iso: String,
        iat_iso: String,
        user_id: String,
        username: &str,
        role: Option<String>,
    ) -> String {
        if let Some(ref r) = role {
            PasetoBuilder::<V4, Local>::default()
                .set_claim(SubjectClaim::from(user_id.as_str()))
                .set_claim(ExpirationClaim::try_from(exp_iso.as_str()).unwrap())
                .set_claim(IssuedAtClaim::try_from(iat_iso.as_str()).unwrap())
                .set_claim(TokenIdentifierClaim::from(jti.as_str()))
                .set_claim(CustomClaim::try_from(("username", username)).unwrap())
                .set_claim(CustomClaim::try_from(("role", r.as_str())).unwrap())
                .build(&key)
                .unwrap()
        } else {
            PasetoBuilder::<V4, Local>::default()
                .set_claim(SubjectClaim::from(user_id.as_str()))
                .set_claim(ExpirationClaim::try_from(exp_iso.as_str()).unwrap())
                .set_claim(IssuedAtClaim::try_from(iat_iso.as_str()).unwrap())
                .set_claim(TokenIdentifierClaim::from(jti.as_str()))
                .set_claim(CustomClaim::try_from(("username", username)).unwrap())
                .build(&key)
                .unwrap()
        }
    }
}
