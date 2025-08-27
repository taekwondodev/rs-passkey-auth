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
            return Err(AppError::BadRequest(String::from(
                "Session ID cannot be empty",
            )));
        }

        validate_credentials(&self.credentials)
    }
}

#[inline]
fn validate_username(username: &str) -> Result<(), AppError> {
    if username.is_empty() {
        return Err(AppError::BadRequest(String::from(
            "Username cannot be empty",
        )));
    }
    if username.len() < 3 {
        return Err(AppError::BadRequest(String::from(
            "Username must be at least 3 characters",
        )));
    }

    Ok(())
}

#[inline]
fn validate_credentials(credentials: &serde_json::Value) -> Result<(), AppError> {
    if credentials.is_null() {
        return Err(AppError::BadRequest(String::from("Invalid credentials")));
    }

    if !credentials.is_object() {
        return Err(AppError::BadRequest(String::from("Invalid credentials")));
    }

    if let Some(obj) = credentials.as_object() {
        if obj.is_empty() {
            return Err(AppError::BadRequest(String::from("Invalid credentials")));
        }
    }

    Ok(())
}
