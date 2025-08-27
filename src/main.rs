use axum::{Router, routing::post};
use rs_passkey_auth::{
    app::{AppError, AppState},
    auth::handler,
    config::{origin::OriginConfig, postgres::DbConfig, webauthn::WebAuthnConfig},
    utils::jwt::JwtService,
};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), AppError> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_config = DbConfig::from_env();
    let db_pool = db_config.create_pool();
    let _conn = db_pool.get().await.map_err(AppError::from)?;

    let origin_config = OriginConfig::from_env();
    let webauthn_config = WebAuthnConfig::from_env();
    let webauthn = webauthn_config.create_webauthn(&origin_config);
    let cors_layer = origin_config.create_cors_layer();

    let jwt = JwtService::from_env();

    let state = AppState::new(webauthn, db_pool, jwt, origin_config);

    let app = Router::new()
        .route("/auth/register/begin", post(handler::begin_register))
        .route("/auth/register/finish", post(handler::finish_register))
        .route("/auth/login/begin", post(handler::begin_login))
        .route("/auth/login/finish", post(handler::finish_login))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(cors_layer);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("Server listening on http://0.0.0.0:8080");
    axum::serve(listener, app).await.unwrap();

    Ok(())
}
