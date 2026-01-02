use chrono::Utc;
use rs_passkey_auth::{
    auth::model::{User, WebAuthnSession},
    utils::jwt::claims::{AccessTokenClaims, RefreshTokenClaims},
};
use uuid::Uuid;

use crate::common::constants::{
    responses::{MOCK_JTI, MOCK_SESSION_UUID},
    test_data::{
        ACCESS_USER_UUID, DEFAULT_ROLE, DEFAULT_USER_UUID, DEFAULT_USERNAME, LOGIN_SESSION_PURPOSE,
        REFRESH_USER_UUID, REGISTRATION_SESSION_PURPOSE, USER_STATUS_ACTIVE,
    },
};

pub fn mock_user() -> User {
    User {
        id: Uuid::parse_str(DEFAULT_USER_UUID).unwrap(),
        username: DEFAULT_USERNAME.to_string(),
        role: Some(DEFAULT_ROLE.to_string()),
        status: USER_STATUS_ACTIVE.to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        is_active: true,
    }
}

pub fn mock_register_session() -> WebAuthnSession {
    WebAuthnSession {
        id: Uuid::parse_str(MOCK_SESSION_UUID).unwrap(),
        user_id: Uuid::parse_str(DEFAULT_USER_UUID).unwrap(),
        data: mock_register_session_data(),
        purpose: REGISTRATION_SESSION_PURPOSE.to_string(),
        created_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::minutes(10),
    }
}

pub fn mock_login_session() -> WebAuthnSession {
    WebAuthnSession {
        id: Uuid::parse_str(MOCK_SESSION_UUID).unwrap(),
        user_id: Uuid::parse_str(DEFAULT_USER_UUID).unwrap(),
        data: mock_login_session_data(),
        purpose: LOGIN_SESSION_PURPOSE.to_string(),
        created_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::minutes(10),
    }
}

pub fn mock_access_claims() -> AccessTokenClaims {
    AccessTokenClaims {
        sub: Uuid::parse_str(ACCESS_USER_UUID).unwrap(),
        username: DEFAULT_USERNAME.to_string(),
        role: Some(DEFAULT_ROLE.to_string()),
        exp: chrono::Utc::now().timestamp() + 900,
        iat: chrono::Utc::now().timestamp(),
    }
}

pub fn mock_refresh_claims() -> RefreshTokenClaims {
    RefreshTokenClaims {
        sub: Uuid::parse_str(REFRESH_USER_UUID).unwrap(),
        username: DEFAULT_USERNAME.to_string(),
        role: Some(DEFAULT_ROLE.to_string()),
        exp: chrono::Utc::now().timestamp() + 3600,
        iat: chrono::Utc::now().timestamp(),
        jti: MOCK_JTI.to_string(),
    }
}

pub fn mock_register_credentials() -> serde_json::Value {
    serde_json::json!({
        "id": "ddqKTpT0rDW9bZGpVsNlC9gRYwA",
        "rawId": "ddqKTpT0rDW9bZGpVsNlC9gRYwA",
        "response": {
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAPv8MAcVTk7MjAtuAgVX170AFHXaik6U9Kw1vW2RqVbDZQvYEWMApQECAyYgASFYICAcVADw5swzcjOny64uSpURBf5KTk0OtLBXw88XnebuIlggLg6ITKTw0skZ47_EdBA7A7TU6ihL61TwSgKyMRyaChE",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVnpyTF94cXdqelU0M0EwN2VVR2JYVThJYXJKcVUybFM4OXRJZzV2ZmQxYyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
        },
        "type": "public-key"
    })
}

pub fn mock_login_credentials() -> serde_json::Value {
    serde_json::json!({
        "id": "q5JZYrZEHrh-mqND0dYs0zPSyxM",
        "rawId": "q5JZYrZEHrh-mqND0dYs0zPSyxM",
        "response": {
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiOUtxZXZOVjhUQU92VWNLM3FQZXBIbHJOOUE1ekt1bWtQLTJrOG5DQW1WYyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
            "signature": "MEYCIQCixkIegU5fsn1PCP3ukNs_v_C-DRjRDzIcPkZ-CNN0KAIhAPKueNP0-pICYi5PBEUozZMbo2HgOA7prF9srY3L15Hz",
            "userHandle": "IacOeI9BRyGjyUj8B6-58Q"
        },
        "type": "public-key"
    })
}

fn mock_register_session_data() -> serde_json::Value {
    serde_json::json!({
        "rs": {
            "allow_synchronised_authenticators": true,
            "authenticator_attachment": null,
            "challenge": "VzrL_xqwjzU43A07eUGbXU8IarJqU2lS89tIg5vfd1c",
            "credential_algorithms": ["ES256", "RS256"],
            "exclude_credentials": [],
            "extensions": {
                "credProps": true,
                "credentialProtectionPolicy": "userVerificationRequired",
                "enforceCredentialProtectionPolicy": false,
                "uvm": true
            },
            "policy": "required",
            "require_resident_key": false
        }
    })
}

fn mock_login_session_data() -> serde_json::Value {
    serde_json::json!({
        "ast": {
            "allow_backup_eligible_upgrade": true,
            "appid": null,
            "challenge": "9KqevNV8TAOvUcK3qPepHlrN9A5zKumkP-2k8nCAmVc",
            "credentials": [
                {
                    "attestation": {
                        "data": "None",
                        "metadata": "None"
                    },
                    "attestation_format": "none",
                    "backup_eligible": true,
                    "backup_state": true,
                    "counter": 0,
                    "cred": {
                        "key": {
                            "EC_EC2": {
                                "curve": "SECP256R1",
                                "x": "zVpmd8-E42cDhFe5jFlykaIHhJKXBpZVOyFPww0hD4s",
                                "y": "pMqbaDbk8mp6FeTDE2-LR8weuC_E2sr7FX3P5EtfUKA"
                            }
                        },
                        "type_": "ES256"
                    },
                    "cred_id": "q5JZYrZEHrh-mqND0dYs0zPSyxM",
                    "extensions": {
                        "appid": "NotRequested",
                        "cred_props": "Ignored",
                        "cred_protect": "Ignored",
                        "hmac_create_secret": "NotRequested"
                    },
                    "registration_policy": "required",
                    "transports": null,
                    "user_verified": true
                }
            ],
            "policy": "required"
        }
    })
}
