use std::sync::Arc;

use deadpool_postgres::Pool;
use webauthn_rs::Webauthn;

use crate::{
    auth::{
        repo::{AuthRepository, PgRepository},
        service::AuthService,
    },
    utils::jwt::JwtService,
};

pub struct AppState {
    pub auth_service: Arc<AuthService>,
}

impl AppState {
    pub fn new(webauthn: Webauthn, db: Pool, jwt: JwtService) -> Arc<Self> {
        let user_repo: Arc<dyn AuthRepository> = Arc::new(PgRepository::new(db.clone()));
        let jwt_service = Arc::new(jwt);
        let auth_service = Arc::new(AuthService::new(webauthn, user_repo, jwt_service));
        Arc::new(Self { auth_service })
    }

    #[cfg(test)]
    pub fn new_for_testing(auth_service: Arc<AuthService>) -> Arc<Self> {
        Arc::new(Self { auth_service })
    }
}
