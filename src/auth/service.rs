use std::sync::Arc;

use webauthn_rs::Webauthn;

use crate::auth::repo::AuthRepository;

pub struct AuthService {
    webauthn: Webauthn,
    auth_repo: Arc<dyn AuthRepository>,
}

impl AuthService {
    pub fn new(webauthn: Webauthn, auth_repo: Arc<dyn AuthRepository>) -> Self {
        Self {
            webauthn: webauthn,
            auth_repo: auth_repo,
        }
    }

    // altri metodi async
}
