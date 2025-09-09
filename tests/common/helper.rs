use rs_passkey_auth::{
    app::AppError,
    auth::{
        dto::request::{BeginRequest, FinishRequest},
        service::AuthService,
    },
};
use std::sync::Arc;
use url::Url;
use webauthn_rs::WebauthnBuilder;

use crate::common::{
    constants::{messages, responses::MOCK_SESSION_UUID, test_data, triggers},
    fixture::mock_credentials,
    mock::{MockAuthRepository, MockJwtService},
};

pub fn create_auth_service() -> AuthService<MockAuthRepository, MockJwtService> {
    let mock_auth_repo = Arc::new(MockAuthRepository);
    let mock_jwt_service = Arc::new(MockJwtService);

    let rp_origin = Url::parse(test_data::WEBAUTHN_ORIGIN).unwrap();
    let builder = WebauthnBuilder::new(test_data::WEBAUTHN_RP_NAME, &rp_origin).unwrap();
    let webauthn = builder.build().unwrap();

    AuthService::new(webauthn, mock_auth_repo, mock_jwt_service)
}

pub fn create_begin_request() -> BeginRequest {
    BeginRequest {
        username: test_data::DEFAULT_USERNAME.to_string(),
        role: Some(test_data::DEFAULT_ROLE.to_string()),
    }
}

pub fn create_finish_request() -> FinishRequest {
    FinishRequest {
        username: test_data::DEFAULT_USERNAME.to_string(),
        session_id: MOCK_SESSION_UUID.to_string(),
        credentials: mock_credentials(),
    }
}

pub fn create_begin_request_with_username(username: &str) -> BeginRequest {
    BeginRequest {
        username: username.to_string(),
        role: Some(test_data::DEFAULT_ROLE.to_string()),
    }
}

pub fn create_finish_request_with_username(username: &str) -> FinishRequest {
    FinishRequest {
        username: username.to_string(),
        session_id: MOCK_SESSION_UUID.to_string(),
        credentials: mock_credentials(),
    }
}

pub struct ErrorTestCase {
    pub username: &'static str,
    pub expected_error: ExpectedError,
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
        ErrorTestCase {
            username: triggers::SERVICE_DOWN,
            expected_error: ExpectedError::ServiceUnavailable(messages::DB_SERVICE_DOWN),
            test_name: "service_unavailable",
        },
    ]
}

pub async fn run_error_test_case(test_case: &ErrorTestCase) {
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
