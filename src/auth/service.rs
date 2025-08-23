use std::sync::Arc;

use crate::auth::repo::user_repo::AuthRepository;

pub struct AuthService {
    user_repo: Arc<dyn AuthRepository>,
    // gli altri repo
    // webauthn instance
}

impl AuthService {
    pub fn new(user_repo: Arc<dyn AuthRepository>) -> Self {
        Self {
            user_repo: user_repo,
        }
    }

    // altri metodi async
}
