use axum::{
    Json,
    extract::{FromRequest, Request},
};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::app::AppError;

#[derive(Debug, Deserialize, ToSchema)]
pub struct BeginRequest {
    #[schema(example = "john_doe", min_length = 3)]
    pub username: String,
    #[schema(example = "admin")]
    pub role: Option<String>,
}

impl<S> FromRequest<S> for BeginRequest
where
    S: Send + Sync,
{
    type Rejection = AppError;

    fn from_request(
        req: Request,
        state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        async move {
            let Json(request) = Json::<BeginRequest>::from_request(req, state).await?;
            request.validate()?;
            Ok(request)
        }
    }
}

impl BeginRequest {
    #[inline]
    pub fn validate(&self) -> Result<(), AppError> {
        validate_username(&self.username)
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct FinishRequest {
    #[schema(example = "john_doe")]
    pub username: String,
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub session_id: String,
    #[schema(example = json!({"id": "AQIDBAUGBwgJCgsMDQ4PEA", "rawId": "AQIDBAUGBwgJCgsMDQ4PEA", "type": "public-key"}))]
    pub credentials: serde_json::Value,
}

impl<S> FromRequest<S> for FinishRequest
where
    S: Send + Sync,
{
    type Rejection = AppError;

    fn from_request(
        req: Request,
        state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        async move {
            let Json(request) = Json::<FinishRequest>::from_request(req, state).await?;
            request.validate()?;
            Ok(request)
        }
    }
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
