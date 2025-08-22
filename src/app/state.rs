use deadpool_postgres::Pool;

#[derive(Clone)]
pub struct AppState {
    pub db: Pool,
}

impl AppState {
    pub fn new(db: Pool) -> Self {
        Self { db: db }
    }
}
