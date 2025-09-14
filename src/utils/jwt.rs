use std::{env, time::Duration};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::Utc;
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

use crate::{
    app::AppError,
    auth::{dto::response::ServiceHealth, traits::JwtService},
    utils::health::check_redis_health,
};

const ACCESS_TOKEN_DURATION: Duration = Duration::from_secs(5 * 60);
const REFRESH_TOKEN_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenClaims {
    Access {
        sub: Uuid,
        username: String,
        role: Option<String>,
        iat: i64,
        exp: i64,
    },
    Refresh {
        sub: Uuid,
        username: String,
        role: Option<String>,
        jti: String,
        iat: i64,
        exp: i64,
    },
}

impl TokenClaims {
    pub fn new_access(
        user_id: Uuid,
        username: String,
        role: Option<String>,
        duration: Duration,
    ) -> Self {
        let now = Utc::now();
        let exp = now + duration;

        TokenClaims::Access {
            sub: user_id,
            username,
            role,
            iat: now.timestamp(),
            exp: exp.timestamp(),
        }
    }

    pub fn new_refresh(
        user_id: Uuid,
        username: String,
        role: Option<String>,
        duration: Duration,
    ) -> Self {
        let now = Utc::now();
        let exp = now + duration;

        TokenClaims::Refresh {
            sub: user_id,
            username,
            role,
            jti: Self::generate_jti(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
        }
    }

    pub async fn validate_access_token(jwt: &Jwt, token: &str) -> Result<Self, AppError> {
        let _key = Key::from(&jwt.public_key);
        let key = PasetoAsymmetricPublicKey::<V4, Public>::from(&_key);
        let json_value = PasetoParser::<V4, Public>::default().parse(token, &key)?;

        Self::extract_access_claims(json_value).await
    }

    pub async fn validate_refresh_token(jwt: &Jwt, token: &str) -> Result<Self, AppError> {
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(&jwt.symmetric_key));
        let json_value = PasetoParser::<V4, Local>::default().parse(token, &key)?;

        Self::extract_refresh_claims(jwt, json_value).await
    }

    pub fn to_token(&self, jwt: &Jwt) -> String {
        match self {
            TokenClaims::Access { .. } => self.create_access_token(jwt),
            TokenClaims::Refresh { .. } => self.create_refresh_token(jwt),
        }
    }

    async fn extract_access_claims(json_value: serde_json::Value) -> Result<Self, AppError> {
        let sub = Self::parse_uuid(&json_value, "sub");
        let username = Self::parse_string(&json_value, "username");
        let role = Self::parse_optional_string(&json_value, "role");
        let (iat, exp) = Self::parse_timestamps(&json_value);

        Self::check_expiration(exp)?;

        Ok(TokenClaims::Access {
            sub,
            username,
            role,
            iat,
            exp,
        })
    }

    async fn extract_refresh_claims(
        jwt: &Jwt,
        json_value: serde_json::Value,
    ) -> Result<Self, AppError> {
        let sub = Self::parse_uuid(&json_value, "sub");
        let username = Self::parse_string(&json_value, "username");
        let role = Self::parse_optional_string(&json_value, "role");
        let jti = Self::parse_string(&json_value, "jti");
        let (iat, exp) = Self::parse_timestamps(&json_value);

        Self::check_expiration(exp)?;

        if jwt.is_blacklisted(&jti).await? {
            return Err(AppError::Unauthorized("Token has been revoked".to_string()));
        }

        Ok(TokenClaims::Refresh {
            sub,
            username,
            role,
            jti,
            iat,
            exp,
        })
    }

    fn create_access_token(&self, jwt: &Jwt) -> String {
        if let TokenClaims::Access {
            sub,
            username,
            role,
            iat,
            exp,
        } = self
        {
            let _key = Key::from(&jwt.private_key);
            let key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&_key);
            let uid = sub.to_string();
            let (iat_rfc, exp_rfc) = Self::format_timestamps(*iat, *exp);

            if let Some(r) = role.as_ref() {
                PasetoBuilder::<V4, Public>::default()
                    .set_claim(SubjectClaim::from(uid.as_str()))
                    .set_claim(ExpirationClaim::try_from(exp_rfc.as_str()).unwrap())
                    .set_claim(IssuedAtClaim::try_from(iat_rfc.as_str()).unwrap())
                    .set_claim(CustomClaim::try_from(("username", username.as_str())).unwrap())
                    .set_claim(CustomClaim::try_from(("role", r.as_str())).unwrap())
                    .build(&key)
                    .unwrap()
            } else {
                PasetoBuilder::<V4, Public>::default()
                    .set_claim(SubjectClaim::from(uid.as_str()))
                    .set_claim(ExpirationClaim::try_from(exp_rfc.as_str()).unwrap())
                    .set_claim(IssuedAtClaim::try_from(iat_rfc.as_str()).unwrap())
                    .set_claim(CustomClaim::try_from(("username", username.as_str())).unwrap())
                    .build(&key)
                    .unwrap()
            }
        } else {
            panic!("Invalid token type for access token creation");
        }
    }

    fn create_refresh_token(&self, jwt: &Jwt) -> String {
        if let TokenClaims::Refresh {
            sub,
            username,
            role,
            jti,
            iat,
            exp,
        } = self
        {
            let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(&jwt.symmetric_key));
            let uid = sub.to_string();
            let (iat_rfc, exp_rfc) = Self::format_timestamps(*iat, *exp);

            if let Some(r) = role.as_ref() {
                PasetoBuilder::<V4, Local>::default()
                    .set_claim(SubjectClaim::from(uid.as_str()))
                    .set_claim(ExpirationClaim::try_from(exp_rfc.as_str()).unwrap())
                    .set_claim(IssuedAtClaim::try_from(iat_rfc.as_str()).unwrap())
                    .set_claim(TokenIdentifierClaim::from(jti.as_str()))
                    .set_claim(CustomClaim::try_from(("username", username.as_str())).unwrap())
                    .set_claim(CustomClaim::try_from(("role", r.as_str())).unwrap())
                    .build(&key)
                    .unwrap()
            } else {
                PasetoBuilder::<V4, Local>::default()
                    .set_claim(SubjectClaim::from(uid.as_str()))
                    .set_claim(ExpirationClaim::try_from(exp_rfc.as_str()).unwrap())
                    .set_claim(IssuedAtClaim::try_from(iat_rfc.as_str()).unwrap())
                    .set_claim(TokenIdentifierClaim::from(jti.as_str()))
                    .set_claim(CustomClaim::try_from(("username", username.as_str())).unwrap())
                    .build(&key)
                    .unwrap()
            }
        } else {
            panic!("Expected Refresh token claims")
        }
    }

    fn generate_jti() -> String {
        let uuid = Uuid::new_v4();
        BASE64_URL_SAFE_NO_PAD.encode(uuid.as_bytes())
    }

    fn parse_uuid(json_value: &serde_json::Value, field: &str) -> Uuid {
        json_value[field].as_str().unwrap().parse().unwrap()
    }

    fn parse_string(json_value: &serde_json::Value, field: &str) -> String {
        json_value[field].as_str().unwrap().to_string()
    }

    fn parse_optional_string(json_value: &serde_json::Value, field: &str) -> Option<String> {
        json_value[field].as_str().map(|s| s.to_string())
    }

    fn parse_timestamps(json_value: &serde_json::Value) -> (i64, i64) {
        let iat_str = json_value["iat"].as_str().unwrap();
        let exp_str = json_value["exp"].as_str().unwrap();

        let iat = chrono::DateTime::parse_from_rfc3339(iat_str)
            .unwrap()
            .timestamp();
        let exp = chrono::DateTime::parse_from_rfc3339(exp_str)
            .unwrap()
            .timestamp();

        (iat, exp)
    }

    fn format_timestamps(iat: i64, exp: i64) -> (String, String) {
        let iat_rfc = chrono::DateTime::from_timestamp(iat, 0)
            .unwrap()
            .to_rfc3339();
        let exp_rfc = chrono::DateTime::from_timestamp(exp, 0)
            .unwrap()
            .to_rfc3339();
        (iat_rfc, exp_rfc)
    }

    fn check_expiration(exp: i64) -> Result<(), AppError> {
        let now = Utc::now().timestamp();
        if exp < now {
            return Err(AppError::Unauthorized("Token has expired".to_string()));
        }
        Ok(())
    }

    pub fn sub(&self) -> &Uuid {
        match self {
            TokenClaims::Access { sub, .. } | TokenClaims::Refresh { sub, .. } => sub,
        }
    }

    pub fn username(&self) -> &str {
        match self {
            TokenClaims::Access { username, .. } | TokenClaims::Refresh { username, .. } => {
                username
            }
        }
    }

    pub fn role(&self) -> Option<&str> {
        match self {
            TokenClaims::Access { role, .. } | TokenClaims::Refresh { role, .. } => role.as_deref(),
        }
    }

    pub fn jti(&self) -> Option<&str> {
        match self {
            TokenClaims::Access { .. } => None,
            TokenClaims::Refresh { jti, .. } => Some(jti),
        }
    }

    pub fn exp(&self) -> i64 {
        match self {
            TokenClaims::Access { exp, .. } | TokenClaims::Refresh { exp, .. } => *exp,
        }
    }
}

#[derive(Debug)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

pub struct Jwt {
    redis_manager: ConnectionManager,
    symmetric_key: [u8; 32],
    private_key: [u8; 64],
    public_key: [u8; 32],
    access_token_duration: Duration,
    refresh_token_duration: Duration,
}

impl Jwt {
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
}

impl JwtService for Jwt {
    fn get_public_key_base64(&self) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(&self.public_key)
    }

    async fn check_redis(&self) -> ServiceHealth {
        check_redis_health(|| async {
            let mut conn = self.redis_manager.clone();
            use redis::AsyncCommands;
            let _: String = conn.ping().await?;
            Ok(())
        })
        .await
    }

    fn generate_token_pair(&self, user_id: Uuid, username: &str, role: Option<&str>) -> TokenPair {
        let access_claims = TokenClaims::new_access(
            user_id,
            username.to_string(),
            role.map(|s| s.to_string()),
            self.access_token_duration,
        );

        let refresh_claims = TokenClaims::new_refresh(
            user_id,
            username.to_string(),
            role.map(|s| s.to_string()),
            self.refresh_token_duration,
        );

        TokenPair {
            access_token: access_claims.to_token(self),
            refresh_token: refresh_claims.to_token(self),
        }
    }

    async fn validate_refresh(&self, token: &str) -> Result<TokenClaims, AppError> {
        TokenClaims::validate_refresh_token(self, token).await
    }

    async fn validate_access(&self, token: &str) -> Result<TokenClaims, AppError> {
        TokenClaims::validate_access_token(self, token).await
    }

    async fn blacklist(&self, jti: &str, exp: i64) -> Result<(), AppError> {
        let mut conn = self.redis_manager.clone();
        let redis_key = format!("blacklist:{}", jti);

        let now = Utc::now().timestamp();
        let ttl = if exp - now <= 0 { 1 } else { exp };

        use redis::AsyncCommands;
        let () = conn.set_ex(&redis_key, "1", ttl as u64).await?;

        Ok(())
    }

    async fn is_blacklisted(&self, jti: &str) -> Result<bool, AppError> {
        let mut conn = self.redis_manager.clone();
        let redis_key = format!("blacklist:{}", jti);

        let exists: bool = {
            use redis::AsyncCommands;
            conn.exists(&redis_key).await?
        };

        Ok(exists)
    }
}
