use std::fmt;

use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    DatabaseConnection(String),
    DatabaseOperation(String),
    ConfigMissing(String),
    ConfigInvalid(String),
    WebAuthnCreation(String),
    WebAuthnOperation(String),
    ValidationError(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::DatabaseConnection(msg) => write!(f, "Database connection error: {}", msg),
            AppError::DatabaseOperation(msg) => write!(f, "Database operation error: {}", msg),
            AppError::ConfigMissing(msg) => write!(f, "Configuration missing: {}", msg),
            AppError::ConfigInvalid(msg) => write!(f, "Invalid configuration: {}", msg),
            AppError::WebAuthnCreation(msg) => write!(f, "WebAuthn creation error: {}", msg),
            AppError::WebAuthnOperation(msg) => write!(f, "WebAuthn operation error: {}", msg),
            AppError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_type, message) = match self {
            AppError::DatabaseConnection(_) | AppError::DatabaseOperation(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database error occurred".to_string(),
            ),
            AppError::ConfigMissing(_) | AppError::ConfigInvalid(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "config_error",
                "Configuration error".to_string(),
            ),
            AppError::WebAuthnCreation(_) | AppError::WebAuthnOperation(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "webauthn_error",
                "WebAuthn error occurred".to_string(),
            ),
            AppError::ValidationError(_) => (
                StatusCode::BAD_REQUEST,
                "validation_error",
                self.to_string(),
            ),
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

impl From<deadpool_postgres::CreatePoolError> for AppError {
    fn from(value: deadpool_postgres::CreatePoolError) -> Self {
        AppError::DatabaseConnection(value.to_string())
    }
}

impl From<deadpool_postgres::PoolError> for AppError {
    fn from(value: deadpool_postgres::PoolError) -> Self {
        AppError::DatabaseConnection(value.to_string())
    }
}

impl From<tokio_postgres::Error> for AppError {
    fn from(value: tokio_postgres::Error) -> Self {
        AppError::DatabaseOperation(value.to_string())
    }
}
