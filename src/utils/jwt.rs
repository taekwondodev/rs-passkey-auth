use std::env;

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use rand::Rng;
use redis::aio::ConnectionManager;
use rusty_paseto::{
    core::{Key, Local, PasetoSymmetricKey, V4},
    prelude::{
        CustomClaim, ExpirationClaim, PasetoBuilder, PasetoParser, SubjectClaim,
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

pub struct JwtService {
    redis_manager: ConnectionManager,
    secret_key: [u8; 32],
    access_token_duration: Duration,
    refresh_token_duration: Duration,
}

impl JwtService {
    pub fn new(conn_manager: ConnectionManager) -> Self {
        let _secret_key = env::var("JWT_SECRET_KEY").unwrap();
        if _secret_key.len() < 32 {
            panic!("JWT_SECRET_KEY must be at least 32 characters");
        }

        let mut secret_key = [0u8; 32];
        let key_bytes = _secret_key.as_bytes();
        let len = std::cmp::min(key_bytes.len(), 32);
        secret_key[..len].copy_from_slice(&key_bytes[..len]);

        if len < 32 {
            let mut rng = rand::rng();
            for i in len..32 {
                secret_key[i] = rng.random();
            }
        }

        Self {
            redis_manager: conn_manager,
            secret_key,
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

        let access_token = self.create_token(user_id, username, role.clone(), access_exp);
        let refresh_token = self.create_token(user_id, username, role, refresh_exp);

        TokenPair {
            access_token,
            refresh_token,
        }
    }

    pub async fn validate(&self, token: &str) -> Result<TokenClaims, AppError> {
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(&self.secret_key));

        let json_value = {
            PasetoParser::<V4, Local>::default()
                .parse(token, &key)
                .map_err(|_| AppError::Unauthorized(String::from("Token signature is invalid")))?
        };

        let sub = Uuid::parse_str(json_value["sub"].as_str().unwrap()).unwrap();
        let username = json_value["username"].as_str().unwrap().to_string();
        let role = json_value["role"].as_str().map(|s| s.to_string());
        let jti = json_value["jti"].as_str().unwrap().to_string();
        let iat = json_value["iat"].as_i64().unwrap();
        let exp = json_value["exp"].as_i64().unwrap();

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
        user_id: Uuid,
        username: &str,
        role: Option<String>,
        exp: chrono::DateTime<Utc>,
    ) -> String {
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(&self.secret_key));

        let jti = Self::generate_jti();
        let exp_iso = exp.to_rfc3339();
        let _user_id = String::from(user_id);

        if let Some(ref r) = role {
            PasetoBuilder::<V4, Local>::default()
                .set_claim(SubjectClaim::from(_user_id.as_str()))
                .set_claim(ExpirationClaim::try_from(exp_iso.as_str()).unwrap())
                .set_claim(TokenIdentifierClaim::from(jti.as_str()))
                .set_claim(CustomClaim::try_from(("username", username)).unwrap())
                .set_claim(CustomClaim::try_from(("role", r.as_str())).unwrap())
                .build(&key)
                .unwrap()
        } else {
            PasetoBuilder::<V4, Local>::default()
                .set_claim(SubjectClaim::from(_user_id.as_str()))
                .set_claim(ExpirationClaim::try_from(exp_iso.as_str()).unwrap())
                .set_claim(TokenIdentifierClaim::from(jti.as_str()))
                .set_claim(CustomClaim::try_from(("username", username)).unwrap())
                .build(&key)
                .unwrap()
        }
    }
}
