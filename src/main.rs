use axum::{routing::get, routing::post};
use rs_passkey_auth::{
    app::{AppError, AppState, error::ErrorResponse},
    auth::{
        dto::{
            request::{BeginRequest, FinishRequest},
            response::{BeginResponse, MessageResponse, PublickKeyResponse, TokenResponse},
        },
        handler,
    },
    config::{
        origin::OriginConfig, postgres::DbConfig, redis::RedisConfig, webauthn::WebAuthnConfig,
    },
};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
    paths(
        handler::begin_register,
        handler::finish_register,
        handler::begin_login,
        handler::finish_login,
        handler::refresh,
        handler::logout,
        handler::get_public_key,
    ),
    components(
        schemas(
            BeginRequest,
            FinishRequest,
            BeginResponse,
            MessageResponse,
            TokenResponse,
            PublickKeyResponse,
            ErrorResponse,        )
    ),
    tags(
        (name = "Authentication", description = "WebAuthn-based authentication endpoints")
    ),
    info(
        title = "rs-passkey-auth API",
        description = "A secure authentication service using WebAuthn passkeys and PASETO tokens",
        version = "0.1.0",
        contact(
            name = "API Support",
            email = "support@example.com",
        ),
        license(
            name = "MIT",
            url = "https://opensource.org/licenses/MIT",
        ),
    ),
    servers(
        (url = "http://localhost:8080", description = "Local development server"),
    )
)]
struct ApiDoc;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer().with_filter(
                tracing_subscriber::filter::Targets::new()
                    .with_target("tower_http::trace", tracing::Level::INFO)
                    .with_target("rs_passkey_auth", tracing::Level::INFO)
                    .with_default(tracing::Level::WARN),
            ),
        )
        .init();

    let db_config = DbConfig::from_env();
    let db_pool = db_config.create_pool();

    let origin_config = OriginConfig::from_env();
    let webauthn_config = WebAuthnConfig::from_env();
    let webauthn = webauthn_config.create_webauthn(&origin_config);
    let cors_layer = origin_config.create_cors_layer();

    let redis_config = RedisConfig::from_env();
    let manager = redis_config.create_conn_manager().await;

    let state = AppState::new(webauthn, db_pool, manager, origin_config);
    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .route("/auth/register/begin", post(handler::begin_register))
        .route("/auth/register/finish", post(handler::finish_register))
        .route("/auth/login/begin", post(handler::begin_login))
        .route("/auth/login/finish", post(handler::finish_login))
        .route("/auth/refresh", post(handler::refresh))
        .route("/auth/logout", post(handler::logout))
        .route("/auth/public-key", get(handler::get_public_key))
        .with_state(state)
        .split_for_parts();

    let app = router
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(
                    tower_http::trace::DefaultMakeSpan::new().level(tracing::Level::INFO),
                )
                .on_request(|request: &axum::http::Request<_>, _span: &tracing::Span| {
                    tracing::info!("Started {} {}", request.method(), request.uri());
                })
                .on_response(
                    |response: &axum::http::Response<_>,
                     latency: std::time::Duration,
                     _span: &tracing::Span| {
                        tracing::info!(
                            "Completed with status {} in {:?}",
                            response.status(),
                            latency
                        );
                    },
                ),
        )
        .layer(cors_layer);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    tracing::info!("Server listening on http://0.0.0.0:8080");
    tracing::info!("Swagger UI available at http://0.0.0.0:8080/swagger-ui");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    tracing::info!("Server shutdown completed");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating graceful shutdown...");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown...");
        },
    }

    tracing::info!("Waiting for ongoing requests to complete...");
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
}
