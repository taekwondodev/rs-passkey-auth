use rs_passkey_auth::{
    app::AppError,
    auth::{
        dto::{
            request::{BeginRequest, FinishRequest},
            response::HealthStatus,
        },
        service::AuthService,
    },
};
use std::sync::Arc;
use url::Url;
use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::common::{
    constants::{
        messages,
        responses::{DB_RESPONSE_TIME_MS, HEALTHY_STATUS_OK, MOCK_SESSION_UUID},
        test_data, triggers,
    },
    fixture::{mock_login_credentials, mock_register_credentials},
    mock::{MockAuthRepository, MockJwtService},
};

fn create_webauthn_service() -> Webauthn {
    let rp_origin = Url::parse(test_data::WEBAUTHN_ORIGIN).unwrap();
    let builder = WebauthnBuilder::new(test_data::WEBAUTHN_RP_NAME, &rp_origin).unwrap();
    builder.build().unwrap()
}

pub fn create_auth_service() -> AuthService<MockAuthRepository, MockJwtService> {
    let mock_auth_repo = Arc::new(MockAuthRepository::default());
    let mock_jwt_service = Arc::new(MockJwtService::default());
    let webauthn = create_webauthn_service();

    AuthService::new(webauthn, mock_auth_repo, mock_jwt_service)
}

pub fn create_auth_service_db_unhealthy() -> AuthService<MockAuthRepository, MockJwtService> {
    let mock_auth_repo = Arc::new(MockAuthRepository::unhealthy());
    let mock_jwt_service = Arc::new(MockJwtService::default());
    let webauthn = create_webauthn_service();

    AuthService::new(webauthn, mock_auth_repo, mock_jwt_service)
}

pub fn create_auth_service_redis_unhealthy() -> AuthService<MockAuthRepository, MockJwtService> {
    let mock_auth_repo = Arc::new(MockAuthRepository::default());
    let mock_jwt_service = Arc::new(MockJwtService::unhealthy());
    let webauthn = create_webauthn_service();

    AuthService::new(webauthn, mock_auth_repo, mock_jwt_service)
}

pub fn create_auth_service_both_unhealthy() -> AuthService<MockAuthRepository, MockJwtService> {
    let mock_auth_repo = Arc::new(MockAuthRepository::unhealthy());
    let mock_jwt_service = Arc::new(MockJwtService::unhealthy());
    let webauthn = create_webauthn_service();

    AuthService::new(webauthn, mock_auth_repo, mock_jwt_service)
}

pub fn create_begin_request() -> BeginRequest {
    BeginRequest {
        username: test_data::DEFAULT_USERNAME.to_string(),
        role: Some(test_data::DEFAULT_ROLE.to_string()),
    }
}

pub fn create_register_finish_request() -> FinishRequest {
    FinishRequest {
        username: test_data::DEFAULT_USERNAME.to_string(),
        session_id: MOCK_SESSION_UUID.to_string(),
        credentials: mock_register_credentials(),
    }
}

pub fn create_login_finish_request() -> FinishRequest {
    FinishRequest {
        username: test_data::DEFAULT_USERNAME.to_string(),
        session_id: MOCK_SESSION_UUID.to_string(),
        credentials: mock_login_credentials(),
    }
}

pub fn create_begin_request_with_username(username: &str) -> BeginRequest {
    BeginRequest {
        username: username.to_string(),
        role: Some(test_data::DEFAULT_ROLE.to_string()),
    }
}

pub fn create_register_finish_request_with_username(username: &str) -> FinishRequest {
    FinishRequest {
        username: username.to_string(),
        session_id: MOCK_SESSION_UUID.to_string(),
        credentials: mock_register_credentials(),
    }
}

pub fn create_login_finish_request_with_username(username: &str) -> FinishRequest {
    FinishRequest {
        username: username.to_string(),
        session_id: MOCK_SESSION_UUID.to_string(),
        credentials: mock_login_credentials(),
    }
}

pub struct ErrorTestCase {
    pub username: &'static str,
    pub expected_error: ExpectedError,
    pub test_name: &'static str,
}

pub struct RefreshErrorTestCase {
    pub refresh_token: &'static str,
    pub expected_error: ExpectedError,
    pub test_name: &'static str,
}

pub struct LogoutTestCase {
    pub refresh_token: &'static str,
    pub should_succeed: bool,
    pub test_name: &'static str,
}

pub enum ExpectedError {
    AlreadyExists(&'static str),
    InternalServer(&'static str),
    BadRequest(&'static str),
    ServiceUnavailable(&'static str),
    NotFound(&'static str),
    Unauthorized(&'static str),
}

impl ExpectedError {
    pub fn assert_matches(&self, error: AppError) {
        match (self, error) {
            (ExpectedError::AlreadyExists(expected_msg), AppError::AlreadyExists(actual_msg)) => {
                assert_eq!(*expected_msg, actual_msg);
            }
            (ExpectedError::InternalServer(expected_msg), AppError::InternalServer(actual_msg)) => {
                assert_eq!(*expected_msg, actual_msg);
            }
            (ExpectedError::BadRequest(expected_msg), AppError::BadRequest(actual_msg)) => {
                assert_eq!(*expected_msg, actual_msg);
            }
            (
                ExpectedError::ServiceUnavailable(expected_msg),
                AppError::ServiceUnavailable(actual_msg),
            ) => {
                assert_eq!(*expected_msg, actual_msg);
            }
            (ExpectedError::NotFound(expected_msg), AppError::NotFound(actual_msg)) => {
                assert_eq!(*expected_msg, actual_msg);
            }
            (ExpectedError::Unauthorized(expected_msg), AppError::Unauthorized(actual_msg)) => {
                assert_eq!(*expected_msg, actual_msg);
            }
            (expected, actual) => {
                panic!("Expected {:?} but got {:?}", expected, actual);
            }
        }
    }
}

impl std::fmt::Debug for ExpectedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpectedError::AlreadyExists(msg) => write!(f, "AlreadyExists({})", msg),
            ExpectedError::InternalServer(msg) => write!(f, "InternalServer({})", msg),
            ExpectedError::BadRequest(msg) => write!(f, "BadRequest({})", msg),
            ExpectedError::ServiceUnavailable(msg) => write!(f, "ServiceUnavailable({})", msg),
            ExpectedError::NotFound(msg) => write!(f, "NotFound({})", msg),
            ExpectedError::Unauthorized(msg) => write!(f, "Unauthorized({})", msg),
        }
    }
}

pub fn get_begin_register_error_test_cases() -> Vec<ErrorTestCase> {
    vec![
        ErrorTestCase {
            username: triggers::USER_ALREADY_EXISTS,
            expected_error: ExpectedError::AlreadyExists(messages::USER_ALREADY_EXISTS),
            test_name: "user_already_exists",
        },
        ErrorTestCase {
            username: triggers::DB_ERROR,
            expected_error: ExpectedError::InternalServer(messages::DB_CONNECTION_FAILED),
            test_name: "database_error",
        },
        ErrorTestCase {
            username: triggers::INVALID_USERNAME,
            expected_error: ExpectedError::BadRequest(messages::INVALID_USERNAME_FORMAT),
            test_name: "invalid_username",
        },
    ]
}

pub fn get_finish_register_error_test_cases() -> Vec<ErrorTestCase> {
    vec![
        ErrorTestCase {
            username: triggers::SESSION_NOT_FOUND,
            expected_error: ExpectedError::NotFound(messages::SESSION_NOT_FOUND),
            test_name: "session_not_found",
        },
        ErrorTestCase {
            username: triggers::USER_NOT_FOUND,
            expected_error: ExpectedError::NotFound(messages::USER_NOT_FOUND),
            test_name: "user_not_found",
        },
        ErrorTestCase {
            username: triggers::DB_ERROR,
            expected_error: ExpectedError::InternalServer(messages::DB_CONNECTION_FAILED),
            test_name: "database_error",
        },
    ]
}

pub fn get_begin_login_error_test_cases() -> Vec<ErrorTestCase> {
    vec![
        ErrorTestCase {
            username: triggers::USER_NOT_FOUND,
            expected_error: ExpectedError::NotFound(messages::USER_NOT_FOUND),
            test_name: "user_not_found",
        },
        ErrorTestCase {
            username: triggers::NO_CREDENTIALS,
            expected_error: ExpectedError::NotFound(messages::NO_CREDENTIALS_FOUND),
            test_name: "no_credentials",
        },
        ErrorTestCase {
            username: triggers::DB_ERROR,
            expected_error: ExpectedError::InternalServer(messages::DB_CONNECTION_FAILED),
            test_name: "database_error",
        },
    ]
}

pub fn get_finish_login_error_test_cases() -> Vec<ErrorTestCase> {
    vec![
        ErrorTestCase {
            username: triggers::USER_NOT_FOUND,
            expected_error: ExpectedError::NotFound(messages::USER_NOT_FOUND),
            test_name: "user_not_found",
        },
        ErrorTestCase {
            username: triggers::SESSION_NOT_FOUND,
            expected_error: ExpectedError::NotFound(messages::SESSION_NOT_FOUND),
            test_name: "session_not_found",
        },
        ErrorTestCase {
            username: triggers::DB_ERROR,
            expected_error: ExpectedError::InternalServer(messages::DB_CONNECTION_FAILED),
            test_name: "database_error",
        },
    ]
}

pub fn get_refresh_error_test_cases() -> Vec<RefreshErrorTestCase> {
    vec![
        RefreshErrorTestCase {
            refresh_token: triggers::INVALID_TOKEN,
            expected_error: ExpectedError::Unauthorized(messages::INVALID_REFRESH_TOKEN),
            test_name: "invalid_token",
        },
        RefreshErrorTestCase {
            refresh_token: triggers::EXPIRED_TOKEN,
            expected_error: ExpectedError::Unauthorized(messages::TOKEN_EXPIRED),
            test_name: "expired_token",
        },
        RefreshErrorTestCase {
            refresh_token: triggers::MALFORMED_TOKEN,
            expected_error: ExpectedError::BadRequest(messages::MALFORMED_TOKEN),
            test_name: "malformed_token",
        },
        RefreshErrorTestCase {
            refresh_token: triggers::REDIS_ERROR,
            expected_error: ExpectedError::InternalServer(messages::REDIS_CONNECTION_FAILED),
            test_name: "redis_error",
        },
    ]
}

pub fn get_logout_test_cases() -> Vec<LogoutTestCase> {
    vec![
        LogoutTestCase {
            refresh_token: triggers::INVALID_TOKEN,
            should_succeed: true,
            test_name: "invalid_token_still_succeeds",
        },
        LogoutTestCase {
            refresh_token: triggers::REDIS_ERROR,
            should_succeed: true,
            test_name: "redis_error_still_succeeds",
        },
        LogoutTestCase {
            refresh_token: "valid_token",
            should_succeed: true,
            test_name: "valid_token_succeeds",
        },
        LogoutTestCase {
            refresh_token: "",
            should_succeed: true,
            test_name: "empty_token_succeeds",
        },
    ]
}

pub async fn run_begin_register_error_test_case(test_case: &ErrorTestCase) {
    let auth_service = create_auth_service();
    let request = create_begin_request_with_username(test_case.username);

    let result = auth_service.begin_register(request).await;

    assert!(
        result.is_err(),
        "Test '{}' should fail but succeeded",
        test_case.test_name
    );

    let error = result.unwrap_err();
    test_case.expected_error.assert_matches(error);
}

pub async fn run_finish_register_error_test_case(test_case: &ErrorTestCase) {
    let auth_service = create_auth_service();
    let request = create_register_finish_request_with_username(test_case.username);

    let result = auth_service.finish_register(request).await;

    assert!(
        result.is_err(),
        "Test '{}' should fail but succeeded",
        test_case.test_name
    );

    let error = result.unwrap_err();
    test_case.expected_error.assert_matches(error);
}

pub async fn run_begin_login_error_test_case(test_case: &ErrorTestCase) {
    let auth_service = create_auth_service();
    let request = create_begin_request_with_username(test_case.username);

    let result = auth_service.begin_login(request).await;

    assert!(
        result.is_err(),
        "Test '{}' should fail but succeeded",
        test_case.test_name
    );

    let error = result.unwrap_err();
    test_case.expected_error.assert_matches(error);
}

pub async fn run_finish_login_error_test_case(test_case: &ErrorTestCase) {
    let auth_service = create_auth_service();
    let request = create_login_finish_request_with_username(test_case.username);

    let result = auth_service.finish_login(request).await;

    assert!(
        result.is_err(),
        "Test '{}' should fail but succeeded",
        test_case.test_name
    );

    let error = result.unwrap_err();
    test_case.expected_error.assert_matches(error);
}

pub async fn run_refresh_error_test_case(test_case: &RefreshErrorTestCase) {
    let auth_service = create_auth_service();

    let result = auth_service.refresh(test_case.refresh_token).await;

    assert!(
        result.is_err(),
        "Test '{}' should fail but succeeded",
        test_case.test_name
    );

    let error = result.unwrap_err();
    test_case.expected_error.assert_matches(error);
}

pub async fn run_logout_test_case(test_case: &LogoutTestCase) {
    let auth_service = create_auth_service();

    let result = auth_service.logout(test_case.refresh_token).await;

    if test_case.should_succeed {
        assert!(
            result.is_ok(),
            "Test '{}' should succeed but failed: {:?}",
            test_case.test_name,
            result
        );
        let response = result.unwrap();
        assert_eq!(response.message, "Logout completed successfully!");
    }
}

pub fn assert_successful_begin_register_response(
    result: Result<rs_passkey_auth::auth::dto::response::BeginResponse, AppError>,
) {
    assert!(result.is_ok(), "begin_register should succeed");
    let response = result.unwrap();
    assert!(
        !response.session_id.is_empty(),
        "Session ID should not be empty"
    );
    assert!(!response.options.is_null(), "Options should not be null");
}

pub fn assert_successful_finish_register_response(
    result: Result<rs_passkey_auth::auth::dto::response::MessageResponse, AppError>,
) {
    assert!(result.is_ok(), "finish_register should succeed");
    let response = result.unwrap();
    assert_eq!(
        response.message,
        "Registration completed successfully!".to_string()
    );
}

pub fn assert_successful_begin_login_response(
    result: Result<rs_passkey_auth::auth::dto::response::BeginResponse, AppError>,
) {
    assert!(result.is_ok(), "begin_login should succeed");
    let response = result.unwrap();
    assert!(
        !response.session_id.is_empty(),
        "Session ID should not be empty"
    );
    assert!(!response.options.is_null(), "Options should not be null");
}

pub fn assert_successful_finish_login_response(
    result: Result<(rs_passkey_auth::auth::dto::response::TokenResponse, String), AppError>,
) {
    assert!(result.is_ok(), "finish_login should succeed");
    let (token_response, refresh) = result.unwrap();
    assert_eq!(
        token_response.message,
        "Login completed successfully!".to_string()
    );
    assert_eq!(token_response.access_token, "mock_access_token".to_string());
    assert_eq!(refresh, "mock_refresh_token".to_string());
}

pub fn assert_successful_refresh_response(
    result: Result<(rs_passkey_auth::auth::dto::response::TokenResponse, String), AppError>,
) {
    assert!(result.is_ok(), "refresh should succeed");
    let (token_response, refresh) = result.unwrap();
    assert_eq!(
        token_response.message,
        "Refresh completed successfully!".to_string()
    );
    assert_eq!(token_response.access_token, "mock_access_token".to_string());
    assert_eq!(refresh, "mock_refresh_token".to_string());
}

pub fn assert_successful_logout_response(
    result: Result<rs_passkey_auth::auth::dto::response::MessageResponse, AppError>,
) {
    assert!(result.is_ok(), "logout should succeed");
    assert_eq!(
        result.unwrap().message,
        "Logout completed successfully!".to_string()
    );
}

pub fn assert_successful_healthy_response(
    result: Result<rs_passkey_auth::auth::dto::response::HealthResponse, AppError>,
) {
    assert!(result.is_ok(), "health_check should succeed");
    let response = result.unwrap();
    let db_checks = response.checks.database;

    assert_eq!(db_checks.status, HealthStatus::Healthy);
    assert_eq!(db_checks.message, HEALTHY_STATUS_OK.to_string());
    assert!(db_checks.response_time_ms.is_some());
    assert_eq!(db_checks.response_time_ms.unwrap(), DB_RESPONSE_TIME_MS);
}

pub fn assert_unhealthy_health_response(
    result: Result<rs_passkey_auth::auth::dto::response::HealthResponse, AppError>,
    expected_error_msg: &str,
) {
    assert!(
        result.is_err(),
        "health_check should fail when services are unhealthy"
    );

    match result.unwrap_err() {
        AppError::ServiceUnavailable(msg) => {
            assert!(
                msg.contains(expected_error_msg),
                "Error message should contain: {}",
                expected_error_msg
            );
        }
        other => panic!("Expected ServiceUnavailable error, got: {:?}", other),
    }
}
