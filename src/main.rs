use axum::{Router, routing::get};
use rs_passkey_auth::{
    app::AppState,
    config::{postgres::DbConfig, webauthn::WebAuthnConfig},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db_config = DbConfig::from_env();
    let db_pool = db_config
        .create_pool()
        .map_err(|e| format!("Failed to create database pool: {}", e))?;
    let _conn = db_pool
        .get()
        .await
        .map_err(|e| format!("Failed to get database connection: {}", e))?;

    let webauthn_config = WebAuthnConfig::from_env();
    let webauthn = webauthn_config
        .create_webauthn()
        .map_err(|e| format!("Failed to build webauthn: {}", e))?;

    let state = AppState::new(webauthn, db_pool);

    let app = Router::new()
        .route("/", get(|| async { "Hello World" }))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    println!("Server listening on http://0.0.0.0:8080");
    axum::serve(listener, app).await?;

    Ok(())
}
