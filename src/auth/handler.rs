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
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    Json(request): Json<FinishRequest>,
) -> Result<(CookieJar, Json<TokenResponse>), AppError> {
    let (response, refresh_token) = state.auth_service.finish_login(request).await?;

    let cookie = state
        .cookie_service
        .create_refresh_token_cookie(&refresh_token);
    let updated_jar = jar.add(cookie);

    Ok((updated_jar, Json(response)))
}

pub async fn refresh(
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
) -> Result<(CookieJar, Json<TokenResponse>), AppError> {
    let refresh_token = state.cookie_service.get_refresh_token_from_jar(&jar)?;
    let (response, new_refresh_token) = state.auth_service.refresh(refresh_token).await?;

    let cookie = state
        .cookie_service
        .create_refresh_token_cookie(&new_refresh_token);
    let updated_jar = jar.add(cookie);

    Ok((updated_jar, Json(response)))
}

pub async fn logout(
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
) -> Result<(CookieJar, Json<MessageResponse>), AppError> {
    let refresh_token = state
        .cookie_service
        .get_refresh_token_from_jar(&jar)
        .unwrap_or_default();
    let response = state.auth_service.logout(refresh_token).await?;

    let clear_cookie = state.cookie_service.clear_refresh_token_cookie();
    let updated_jar = jar.add(clear_cookie);

    Ok((updated_jar, Json(response)))
}
