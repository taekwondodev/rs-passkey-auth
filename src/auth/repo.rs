use async_trait::async_trait;
use chrono::Utc;
use deadpool_postgres::Pool;
use uuid::Uuid;

use crate::{
    app::AppError,
    auth::model::{Credential, User, WebAuthnSession},
};

#[async_trait]
pub trait AuthRepository: Send + Sync {
    async fn create_user(&self, username: &str, role: Option<&str>) -> Result<User, AppError>;
    async fn get_user_by_username(&self, username: &str) -> Result<User, AppError>;
    async fn activate_user(&self, username: &str) -> Result<(), AppError>;
    async fn create_webauthn_session(
        &self,
        user_id: Uuid,
        data: serde_json::Value,
        purpose: &str,
    ) -> Result<Uuid, AppError>;
    async fn get_webauthn_session(
        &self,
        id: Uuid,
        purpose: &str,
    ) -> Result<WebAuthnSession, AppError>;
    async fn delete_webauthn_session(&self, id: Uuid) -> Result<(), AppError>;
    async fn create_credential(
        &self,
        id: &[u8],
        user_id: Uuid,
        public_key: &[u8],
        sign_count: i64,
    ) -> Result<(), AppError>;
    async fn get_credential_by_user(&self, user_id: Uuid) -> Result<Vec<Credential>, AppError>;
    async fn update_credential(&self, id: &[u8], sign_count: i64) -> Result<(), AppError>;
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

    fn row_to_webauthn_session(row: &tokio_postgres::Row) -> Result<WebAuthnSession, AppError> {
        Ok(WebAuthnSession {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            data: row.try_get("data")?,
            purpose: row.try_get("purpose")?,
            created_at: row.try_get("created_at")?,
            expires_at: row.try_get("expires_at")?,
        })
    }

    fn row_to_credential(row: &tokio_postgres::Row) -> Result<Credential, AppError> {
        Ok(Credential {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            public_key: row.try_get("public_key")?,
            sign_count: row.try_get("sign_count")?,
            created_at: row.try_get("created_at")?,
            last_used_at: row.try_get("last_used_at")?,
        })
    }
}

#[async_trait]
impl AuthRepository for PgRepository {
    async fn create_user(&self, username: &str, role: Option<&str>) -> Result<User, AppError> {
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

    async fn get_user_by_username(&self, username: &str) -> Result<User, AppError> {
        let client = &self.db.get().await?;

        match client
            .query_opt("SELECT * FROM users WHERE username = $1", &[&username])
            .await?
        {
            Some(row) => Self::row_to_user(&row),
            None => Err(AppError::NotFound(format!("Username not found"))),
        }
    }

    async fn activate_user(&self, username: &str) -> Result<(), AppError> {
        let client = &self.db.get().await?;

        client
            .execute(
                "UPDATE users SET status = 'active' WHERE username = $1",
                &[&username],
            )
            .await?;

        Ok(())
    }

    async fn create_webauthn_session(
        &self,
        user_id: Uuid,
        data: serde_json::Value,
        purpose: &str,
    ) -> Result<Uuid, AppError> {
        let client = &self.db.get().await?;
        let expire_at = Utc::now() + chrono::Duration::minutes(30);

        let row = client.query_one(
                "INSERT INTO webauthn_sessions (user_id, data, purpose, expires_at) VALUES ($1, $2, $3, $4)",
                &[&user_id, &data, &purpose, &expire_at],
            )
            .await?;

        Ok(row.get("id"))
    }

    async fn get_webauthn_session(
        &self,
        id: Uuid,
        purpose: &str,
    ) -> Result<WebAuthnSession, AppError> {
        let client = &self.db.get().await?;

        match client
            .query_opt(
                "SELECT * FROM webauthn_sessions WHERE id = $1 AND purpose = $2",
                &[&id, &purpose],
            )
            .await?
        {
            Some(row) => Self::row_to_webauthn_session(&row),
            None => Err(AppError::NotFound(format!("Session not found"))),
        }
    }

    async fn delete_webauthn_session(&self, id: Uuid) -> Result<(), AppError> {
        let client = &self.db.get().await?;

        client
            .execute("DELETE FROM webauthn_sessions WHERE id = $1", &[&id])
            .await?;

        Ok(())
    }

    async fn create_credential(
        &self,
        id: &[u8],
        user_id: Uuid,
        public_key: &[u8],
        sign_count: i64,
    ) -> Result<(), AppError> {
        let client = &self.db.get().await?;

        client
                .execute(
                    "INSERT INTO credentials (id, user_id, public_key, sign_count) VALUES ($1, $2, $3, $4)",
                    &[&id, &user_id, &public_key, &sign_count],
                )
                .await?;

        Ok(())
    }

    async fn get_credential_by_user(&self, user_id: Uuid) -> Result<Vec<Credential>, AppError> {
        let client = &self.db.get().await?;

        let rows = client
            .query("SELECT * FROM credentials WHERE user_id = $1", &[&user_id])
            .await?;

        let mut credentials = Vec::new();
        for row in rows {
            credentials.push(Self::row_to_credential(&row)?);
        }

        Ok(credentials)
    }

    async fn update_credential(&self, id: &[u8], sign_count: i64) -> Result<(), AppError> {
        let client = &self.db.get().await?;

        client
            .execute(
                "UPDATE credentials SET sign_count = $2 WHERE id = $1",
                &[&id, &sign_count],
            )
            .await?;

        Ok(())
    }
}
