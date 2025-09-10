pub mod triggers {
    pub const USER_ALREADY_EXISTS: &str = "user_already_exists";
    pub const DB_ERROR: &str = "db_error";
    pub const INVALID_USERNAME: &str = "invalid_username";
    pub const SERVICE_DOWN: &str = "service_down";
    pub const USER_NOT_FOUND: &str = "user_not_found";
    pub const SESSION_NOT_FOUND: &str = "session_not_found";
    pub const NO_CREDENTIALS: &str = "no_credentials";

    pub const INVALID_TOKEN: &str = "invalid_token";
    pub const EXPIRED_TOKEN: &str = "expired_token";
    pub const MALFORMED_TOKEN: &str = "malformed_token";
    pub const BLACKLISTED_TOKEN: &str = "blacklisted_token";
    pub const REDIS_ERROR: &str = "redis_error";
    pub const BLACKLISTED_JTI: &str = "blacklisted_jti";

    pub const SESSION_CREATION_ERROR_UUID: &str = "00000000-0000-0000-0000-000000000001";
    pub const SERVICE_UNAVAILABLE_UUID: &str = "00000000-0000-0000-0000-000000000002";
    pub const SESSION_NOT_FOUND_UUID: &str = "00000000-0000-0000-0000-000000000404";
}

pub mod messages {
    pub const USER_ALREADY_EXISTS: &str = "User already exists";
    pub const DB_CONNECTION_FAILED: &str = "Database connection failed";
    pub const INVALID_USERNAME_FORMAT: &str = "Invalid username format";
    pub const DB_SERVICE_DOWN: &str = "Database service is down";
    pub const USER_NOT_FOUND: &str = "User not found";
    pub const SESSION_NOT_FOUND: &str = "Session not found";
    pub const NO_CREDENTIALS_FOUND: &str = "No credentials found";
    pub const SESSION_CREATION_FAILED: &str = "Session creation failed";

    pub const INVALID_REFRESH_TOKEN: &str = "Invalid refresh token";
    pub const INVALID_ACCESS_TOKEN: &str = "Invalid access token";
    pub const TOKEN_EXPIRED: &str = "Token expired";
    pub const TOKEN_BLACKLISTED: &str = "Token is blacklisted";
    pub const MALFORMED_TOKEN: &str = "Malformed token";
    pub const REDIS_CONNECTION_FAILED: &str = "Redis connection failed";
    pub const REDIS_SERVICE_DOWN: &str = "Redis service is down";
}

pub mod responses {
    pub const MOCK_PUBLIC_KEY: &str = "mock_public_key";
    pub const MOCK_ACCESS_TOKEN: &str = "mock_access_token";
    pub const MOCK_REFRESH_TOKEN: &str = "mock_refresh_token";
    pub const MOCK_JTI: &str = "mock_jti";
    pub const MOCK_SESSION_UUID: &str = "12345678-1234-1234-1234-123456789def";
    pub const HEALTHY_STATUS_OK: &str = "OK";
    pub const DB_RESPONSE_TIME_MS: u64 = 100;
    pub const REDIS_RESPONSE_TIME_MS: u64 = 30;

    pub const REGISTRATION_SUCCESS: &str = "Registration completed successfully!";
    pub const LOGIN_SUCCESS: &str = "Login completed successfully!";
    pub const REFRESH_SUCCESS: &str = "Refresh completed successfully!";
    pub const LOGOUT_SUCCESS: &str = "Logout completed successfully!";
}

pub mod test_data {
    pub const DEFAULT_USERNAME: &str = "test_user";
    pub const DEFAULT_ROLE: &str = "user";
    pub const USER_STATUS_ACTIVE: &str = "active";
    pub const WEBAUTHN_ORIGIN: &str = "http://localhost:3000";
    pub const WEBAUTHN_RP_NAME: &str = "localhost";
    pub const DEFAULT_USER_UUID: &str = "12345678-1234-1234-1234-123456789abc";
    pub const REFRESH_USER_UUID: &str = "12345678-1234-1234-1234-123456789aaa";
    pub const ACCESS_USER_UUID: &str = "12345678-1234-1234-1234-123456789bbb";
    pub const LOGIN_SESSION_PURPOSE: &str = "login";
    pub const REGISTRATION_SESSION_PURPOSE: &str = "registration";
}
