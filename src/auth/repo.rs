use async_trait::async_trait;
use deadpool_postgres::Pool;

use crate::{app::AppError, auth::model::User};

#[async_trait]
pub trait AuthRepository: Send + Sync {
    async fn create_user(&self, username: String, role: Option<String>) -> Result<User, AppError>;
    async fn get_user_by_username(&self, username: String) -> Result<User, AppError>;
    async fn activate_user(&self, username: String) -> Result<(), AppError>;
}

pub struct PgRepository {
    db: Pool,
}

impl PgRepository {
    pub fn new(db: Pool) -> Self {
        Self { db: db }
    }

    fn row_to_user(row: &tokio_postgres::Row) -> Result<User, AppError> {
        Ok(User {
            id: row.try_get("id")?,
            username: row.try_get("username")?,
            role: row.try_get("role")?,
            status: row.try_get("status")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            is_active: row.try_get("is_active")?,
        })
    }
}

#[async_trait]
impl AuthRepository for PgRepository {
    async fn create_user(&self, username: String, role: Option<String>) -> Result<User, AppError> {
        let client = &self.db.get().await?;

        let row = if let Some(i) = role {
            client
                .query_one(
                    "INSERT INTO users (username, role) VALUES ($1, $2) RETURNING *",
                    &[&username, &i],
                )
                .await?
        } else {
            client
                .query_one(
                    "INSERT INTO users (username) VALUES ($1) RETURNING *",
                    &[&username],
                )
                .await?
        };

        Self::row_to_user(&row)
    }

    async fn get_user_by_username(&self, username: String) -> Result<User, AppError> {
        let client = &self.db.get().await?;

        let row = client
            .query_one("SELECT * FROM users WHERE username = $1", &[&username])
            .await?;

        Self::row_to_user(&row)
    }

    async fn activate_user(&self, username: String) -> Result<(), AppError> {
        let client = &self.db.get().await?;

        client
            .execute(
                "UPDATE users SET status = 'active' WHERE username = $1",
                &[&username],
            )
            .await?;

        Ok(())
    }
}
