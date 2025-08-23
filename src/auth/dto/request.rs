use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct BeginRequest {
    pub username: String,
    pub role: Option<String>,
}

impl BeginRequest {
    #[inline]
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_username(&self.username)
    }
}

#[derive(Debug, Deserialize)]
pub struct FinishRequest {
    pub username: String,
    pub session_id: String,
    pub credentials: serde_json::Value,
}

impl FinishRequest {
    #[inline]
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_username(&self.username)?;

        if self.session_id.is_empty() {
            return Err("Session ID cannot be empty");
        }

        validate_credentials(&self.credentials)
    }
}

#[inline]
fn validate_username(username: &String) -> Result<(), &'static str> {
    if username.is_empty() {
        return Err("Username cannot be empty");
    }
    if username.len() < 3 {
        return Err("Username must be at least 3 characters");
    }

    Ok(())
}

#[inline]
fn validate_credentials(credentials: &serde_json::Value) -> Result<(), &'static str> {
    if credentials.is_null() {
        return Err("Invalid credentials");
    }

    if !credentials.is_object() {
        return Err("Invalid credentials");
    }

    if let Some(obj) = credentials.as_object() {
        if obj.is_empty() {
            return Err("Invalid credentials");
        }
    }

    Ok(())
}
