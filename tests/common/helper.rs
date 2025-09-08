use chrono::Utc;
use rs_passkey_auth::{
    auth::model::{User, WebAuthnSession},
    utils::jwt::TokenClaims,
};
use uuid::Uuid;

pub fn mock_user() -> User {
    User {
        id: Uuid::parse_str("12345678-1234-1234-1234-123456789abc").unwrap(),
        username: "test_user".to_string(),
        role: Some("user".to_string()),
        status: "active".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        is_active: true,
    }
}

pub fn mock_session() -> WebAuthnSession {
    WebAuthnSession {
        id: Uuid::parse_str("12345678-1234-1234-1234-123456789def").unwrap(),
        user_id: Uuid::parse_str("12345678-1234-1234-1234-123456789abc").unwrap(),
        data: serde_json::json!({}),
        purpose: "registration".to_string(),
        created_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::minutes(10),
    }
}

pub fn mock_access_claims() -> TokenClaims {
    TokenClaims {
        sub: Uuid::parse_str("12345678-1234-1234-1234-123456789ghi").unwrap(),
        username: "test_user".to_string(),
        role: Some("user".to_string()),
        exp: chrono::Utc::now().timestamp() + 900,
        iat: chrono::Utc::now().timestamp(),
        jti: None,
    }
}

pub fn mock_refresh_claims() -> TokenClaims {
    TokenClaims {
        sub: Uuid::parse_str("12345678-1234-1234-1234-123456789llm").unwrap(),
        username: "test_user".to_string(),
        role: Some("user".to_string()),
        exp: chrono::Utc::now().timestamp() + 3600,
        iat: chrono::Utc::now().timestamp(),
        jti: Some("mock_jti".to_string()),
    }
}
