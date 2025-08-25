use std::sync::Arc;

use axum::{Json, extract::State};

use crate::{
    app::{AppError, AppState},
    auth::dto::{
        request::{BeginRequest, FinishRequest},
        response::{BeginResponse, MessageResponse, TokenResponse},
    },
};

pub async fn begin_register(
    State(state): State<Arc<AppState>>,
    Json(request): Json<BeginRequest>,
) -> Result<Json<BeginResponse>, AppError> {
    let response = state.auth_service.begin_register(request).await?;
    Ok(Json(response))
}

pub async fn finish_register(
    State(state): State<Arc<AppState>>,
    Json(request): Json<FinishRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    let response = state.auth_service.finish_register(request).await?;
    Ok(Json(response))
}

pub async fn begin_login(
    State(state): State<Arc<AppState>>,
    Json(request): Json<BeginRequest>,
) -> Result<Json<BeginResponse>, AppError> {
    let response = state.auth_service.begin_login(request).await?;
    Ok(Json(response))
}

pub async fn finish_login(
    State(state): State<Arc<AppState>>,
    Json(request): Json<FinishRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let response = state.auth_service.finish_login(request).await?;
    Ok(Json(response))
}
