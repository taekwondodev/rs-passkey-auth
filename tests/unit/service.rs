use rs_passkey_auth::{
    app::AppError,
    auth::{dto::request::BeginRequest, service::AuthService},
};
use url::Url;
use webauthn_rs::WebauthnBuilder;

use crate::common::mock::{MockAuthRepository, MockJwtService};

#[tokio::test]
async fn begin_register_success() -> Result<(), AppError> {
    let mock_auth_repo = std::sync::Arc::new(MockAuthRepository);
    let mock_jwt_service = std::sync::Arc::new(MockJwtService);

    let rp_origin = Url::parse("https://localhost:8080").unwrap();
    let builder = WebauthnBuilder::new("localhost", &rp_origin).unwrap();
    let webauthn = builder.build().unwrap();

    let auth_service = AuthService::new(webauthn, mock_auth_repo, mock_jwt_service);

    let request = BeginRequest {
        username: "test_user".to_string(),
        role: Some("user".to_string()),
    };

    let result = auth_service.begin_register(request).await;
    assert!(result.is_ok(), "begin_register should succeed");
    let response = result.unwrap();
    assert!(
        !response.session_id.is_empty(),
        "Session ID should not be empty"
    );
    assert!(!response.options.is_null(), "Options should not be null");

    Ok(())
}
