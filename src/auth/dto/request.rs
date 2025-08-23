use serde::Deserialize;

use crate::app::AppError;

#[derive(Debug, Deserialize)]
pub struct BeginRequest {
    pub username: String,
    pub role: Option<String>,
}

impl BeginRequest {
    #[inline]
    pub fn validate(&self) -> Result<(), AppError> {
        validate_username(&self.username)
    }
}

#[derive(Debug, Deserialize)]
pub struct FinishRequest {
    pub username: String,
    pub session_id: String,
    pub credentials: serde_json::Value,
}

impl FinishRequest {
    #[inline]
    pub fn validate(&self) -> Result<(), AppError> {
        validate_username(&self.username)?;

        if self.session_id.is_empty() {
            return Err(AppError::ValidationError(
                "Session ID cannot be empty".to_string(),
            ));
        }

        validate_credentials(&self.credentials)
    }
}

#[inline]
fn validate_username(username: &String) -> Result<(), AppError> {
    if username.is_empty() {
        return Err(AppError::ValidationError(
            "Username cannot be empty".to_string(),
        ));
    }
    if username.len() < 3 {
        return Err(AppError::ValidationError(
            "Username must be at least 3 characters".to_string(),
        ));
    }

    Ok(())
}

#[inline]
fn validate_credentials(credentials: &serde_json::Value) -> Result<(), AppError> {
    if credentials.is_null() {
        return Err(AppError::ValidationError("Invalid credentials".to_string()));
    }

    if !credentials.is_object() {
        return Err(AppError::ValidationError("Invalid credentials".to_string()));
    }

    if let Some(obj) = credentials.as_object() {
        if obj.is_empty() {
            return Err(AppError::ValidationError("Invalid credentials".to_string()));
        }
    }

    Ok(())
}
