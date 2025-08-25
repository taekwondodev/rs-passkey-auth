use std::sync::Arc;

use deadpool_postgres::Pool;
use webauthn_rs::Webauthn;

use crate::{
    auth::{
        repo::{AuthRepository, PgRepository},
        service::AuthService,
    },
    config::origin::OriginConfig,
    utils::{cookie::CookieService, jwt::JwtService},
};

pub struct AppState {
    pub auth_service: Arc<AuthService>,
    pub cookie_service: Arc<CookieService>,
}

impl AppState {
    pub fn new(
        webauthn: Webauthn,
        db: Pool,
        jwt: JwtService,
        origin_config: &OriginConfig,
    ) -> Arc<Self> {
        let user_repo: Arc<dyn AuthRepository> = Arc::new(PgRepository::new(db.clone()));
        let jwt_service = Arc::new(jwt);
        let auth_service = Arc::new(AuthService::new(webauthn, user_repo, jwt_service));
        let cookie_service = Arc::new(CookieService::new(origin_config).unwrap());

        Arc::new(Self {
            auth_service,
            cookie_service,
        })
    }

    #[cfg(test)]
    pub fn new_for_testing(
        auth_service: Arc<AuthService>,
        cookie_service: Arc<CookieService>,
    ) -> Arc<Self> {
        Arc::new(Self {
            auth_service,
            cookie_service,
        })
    }
}
