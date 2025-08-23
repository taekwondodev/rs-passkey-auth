use async_trait::async_trait;
use deadpool_postgres::Pool;

#[async_trait]
pub trait AuthRepository: Send + Sync {
    // async fn metodi
}

pub struct UserRepository {
    db: Pool,
}

impl UserRepository {
    pub fn new(db: Pool) -> Self {
        Self { db: db }
    }

    // gli altri metodi per refactoring
}

#[async_trait]
impl AuthRepository for UserRepository {
    // i metodi async dell'interfaccia
}
