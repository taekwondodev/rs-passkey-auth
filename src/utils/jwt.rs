use std::env;

use chrono::{Duration, Utc};
use rand::Rng;
use rusty_paseto::{
    core::{Key, Local, PasetoSymmetricKey, V4},
    prelude::{CustomClaim, ExpirationClaim, PasetoBuilder, PasetoParser, SubjectClaim},
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
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

pub struct JwtService {
    secret_key: [u8; 32],
    access_token_duration: Duration,
    refresh_token_duration: Duration,
}

impl JwtService {
    pub fn from_env() -> Result<Self, AppError> {
        let _secret_key = env::var("JWT_SECRET_KEY")?;
        if _secret_key.len() < 32 {
            return Err(AppError::ConfigInvalid(String::from(
                "JWT_SECRET_KEY must be at least 32 characters",
            )));
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

        Ok(Self {
            secret_key: secret_key,
            access_token_duration: ACCESS_TOKEN_DURATION,
            refresh_token_duration: REFRESH_TOKEN_DURATION,
        })
    }

    pub fn generate_token_pair(
        &self,
        user_id: Uuid,
        username: &str,
        role: Option<String>,
    ) -> Result<TokenPair, AppError> {
        let now = Utc::now();
        let access_exp = now + self.access_token_duration;
        let refresh_exp = now + self.refresh_token_duration;

        let access_token = self.create_token(user_id, username, role.clone(), access_exp);
        let refresh_token = self.create_token(user_id, username, role, refresh_exp);

        Ok(TokenPair {
            access_token: access_token,
            refresh_token: refresh_token,
        })
    }

    pub fn validate_token(&self, token: &str) -> Result<TokenClaims, AppError> {
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(&self.secret_key));
        let mut parser = PasetoParser::<V4, Local>::default();

        let json_value = parser.parse(token, &key).map_err(|_| {
            AppError::JWTSignatureInvalid(String::from("Token signature is invalid"))
        })?;

        let sub = Uuid::parse_str(json_value["sub"].as_str().unwrap()).unwrap();
        let username = json_value["username"].as_str().unwrap().to_string();
        let role = json_value["role"].as_str().map(|s| s.to_string());
        let iat = json_value["iat"].as_i64().unwrap();
        let exp = json_value["exp"].as_i64().unwrap();

        let now = Utc::now().timestamp();
        if exp < now {
            return Err(AppError::JWTExpired("Token has expired".to_string()));
        }

        Ok(TokenClaims {
            sub,
            username,
            role,
            iat,
            exp,
        })
    }

    fn create_token(
        &self,
        user_id: Uuid,
        username: &str,
        role: Option<String>,
        exp: chrono::DateTime<Utc>,
    ) -> String {
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(&self.secret_key));

        let exp_iso = exp.to_rfc3339();
        let _user_id = user_id.to_string();

        let token = if let Some(ref r) = role {
            PasetoBuilder::<V4, Local>::default()
                .set_claim(SubjectClaim::from(_user_id.as_str()))
                .set_claim(ExpirationClaim::try_from(exp_iso.as_str()).unwrap())
                .set_claim(CustomClaim::try_from(("username", username)).unwrap())
                .set_claim(CustomClaim::try_from(("role", r.as_str())).unwrap())
                .build(&key)
                .unwrap()
        } else {
            PasetoBuilder::<V4, Local>::default()
                .set_claim(SubjectClaim::from(_user_id.as_str()))
                .set_claim(ExpirationClaim::try_from(exp_iso.as_str()).unwrap())
                .set_claim(CustomClaim::try_from(("username", username)).unwrap())
                .build(&key)
                .unwrap()
        };
        token
    }
}
