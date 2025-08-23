use std::sync::Arc;

use webauthn_rs::Webauthn;

use crate::auth::repo::user_repo::AuthRepository;

pub struct AuthService {
    webauthn: Webauthn,
    user_repo: Arc<dyn AuthRepository>,
    // gli altri repo
}

impl AuthService {
    pub fn new(webauthn: Webauthn, user_repo: Arc<dyn AuthRepository>) -> Self {
        Self {
            webauthn: webauthn,
            user_repo: user_repo,
        }
    }

    // altri metodi async
}
