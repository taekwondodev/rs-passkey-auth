use std::sync::Arc;

use axum::{Json, extract::State};

use crate::{
    app::{AppError, AppState},
    auth::dto::{
        request::{BeginRequest, FinishRequest},
        response::{BeginResponse, TokenResponse},
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
    State(state): State<AppState>,
    Json(request): Json<FinishRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    // TODO: Implementare finish_register
    todo!("Implement finish_register")
}

pub async fn begin_login(
    State(state): State<AppState>,
    Json(request): Json<BeginRequest>,
) -> Result<Json<BeginResponse>, AppError> {
    // TODO: Implementare begin_authentication
    todo!("Implement begin_authentication")
}

pub async fn finish_login(
    State(state): State<AppState>,
    Json(request): Json<FinishRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    // TODO: Implementare finish_authentication
    todo!("Implement finish_authentication")
}
