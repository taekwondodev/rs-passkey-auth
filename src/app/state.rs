use std::sync::Arc;

use deadpool_postgres::Pool;

use crate::auth::{
    repo::user_repo::{AuthRepository, UserRepository},
    service::AuthService,
};

#[derive(Clone)]
pub struct AppState {
    pub auth_service: Arc<AuthService>,
}

impl AppState {
    pub fn new(db: Pool) -> Self {
        let user_repo: Arc<dyn AuthRepository> = Arc::new(UserRepository::new(db.clone()));
        let auth_service = Arc::new(AuthService::new(user_repo));
        Self {
            auth_service: auth_service,
        }
    }

    #[cfg(test)]
    pub fn new_for_testing(auth_service: Arc<AuthService>) -> Self {
        Self { auth_service }
    }
}
