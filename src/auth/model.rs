use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: Vec<u8>,
    pub user_id: Uuid,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub transports: Option<Vec<String>>,
    pub aaguid: Option<Uuid>,
    pub attestation_format: Option<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub data: serde_json::Value,
    pub purpose: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
