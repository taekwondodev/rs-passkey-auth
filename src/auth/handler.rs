use std::sync::Arc;

use axum::{Json, extract::State};
use axum_extra::extract::CookieJar;

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
    jar: CookieJar,
    Json(request): Json<FinishRequest>,
) -> Result<(CookieJar, Json<TokenResponse>), AppError> {
    let (response, refresh_token) = state.auth_service.finish_login(request).await?;

    let cookie = state
        .cookie_service
        .create_refresh_token_cookie(&refresh_token);
    let updated_jar = jar.add(cookie);

    Ok((updated_jar, Json(response)))
}
