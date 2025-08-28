use std::fmt::{self};

use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    InternalServer(String),
    NotFound(String),
    AlreadyExists(String),
    Unauthorized(String),
    BadRequest(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::InternalServer(msg) => write!(f, "Internal server error: {}", msg),
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
            AppError::AlreadyExists(msg) => write!(f, "Already exists: {}", msg),
            AppError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            AppError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_type, message) = match self {
            AppError::InternalServer(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_server_error",
                self.to_string(),
            ),
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found", self.to_string()),
            AppError::AlreadyExists(_) => {
                (StatusCode::CONFLICT, "already_exists", self.to_string())
            }
            AppError::Unauthorized(_) => {
                (StatusCode::UNAUTHORIZED, "unauthorized", self.to_string())
            }
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request", self.to_string()),
        };

        let body = Json(json!({
            "error": {
                "type": error_type,
                "message": message
            }
        }));

        (status, body).into_response()
    }
}

impl From<deadpool_postgres::PoolError> for AppError {
    fn from(value: deadpool_postgres::PoolError) -> Self {
        AppError::InternalServer(value.to_string())
    }
}

impl From<tokio_postgres::Error> for AppError {
    fn from(value: tokio_postgres::Error) -> Self {
        AppError::InternalServer(value.to_string())
    }
}

impl From<redis::RedisError> for AppError {
    fn from(value: redis::RedisError) -> Self {
        AppError::InternalServer(value.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(value: serde_json::Error) -> Self {
        AppError::InternalServer(value.to_string())
    }
}

impl From<webauthn_rs::prelude::WebauthnError> for AppError {
    fn from(value: webauthn_rs::prelude::WebauthnError) -> Self {
        AppError::InternalServer(value.to_string())
    }
}

impl From<uuid::Error> for AppError {
    fn from(value: uuid::Error) -> Self {
        AppError::BadRequest(value.to_string())
    }
}
