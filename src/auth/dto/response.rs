use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct BeginResponse {
    pub options: serde_json::Value,
    pub session_id: String,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub message: String,
    pub access_token: String,
}
