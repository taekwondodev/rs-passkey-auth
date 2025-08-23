use async_trait::async_trait;
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use uuid::Uuid;

use crate::{
    app::AppError,
    auth::model::{Credential, User, WebAuthnSession},
};

#[async_trait]
pub trait AuthRepository: Send + Sync {
    async fn create_user(&self, username: String, role: Option<String>) -> Result<User, AppError>;
    async fn get_user_by_username(&self, username: String) -> Result<User, AppError>;
    async fn activate_user(&self, username: String) -> Result<(), AppError>;
    async fn create_webauthn_session(
        &self,
        id: Uuid,
        user_id: Uuid,
        data: serde_json::Value,
        purpose: String,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AppError>;
    async fn get_webauthn_session(
        &self,
        id: Uuid,
        purpose: String,
    ) -> Result<WebAuthnSession, AppError>;
    async fn delete_webauthn_session(&self, id: Uuid) -> Result<(), AppError>;
    async fn create_credential(
        &self,
        id: Vec<u8>,
        user_id: Uuid,
        public_key: Vec<u8>,
        sign_count: i64,
        transports: Option<Vec<String>>,
        aaguid: Option<Uuid>,
        attestation_format: Option<String>,
        backup_eligible: bool,
        backup_state: bool,
    ) -> Result<(), AppError>;
    async fn get_credential_by_user(&self, user_id: Uuid) -> Result<Vec<Credential>, AppError>;
    async fn update_credential(&self, id: Vec<u8>, sign_count: i64) -> Result<(), AppError>;
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
            transports: row.try_get("transports")?,
            aaguid: row.try_get("aaguid")?,
            attestation_format: row.try_get("attestation_format")?,
            backup_eligible: row.try_get("backup_eligible")?,
            backup_state: row.try_get("backup_state")?,
            created_at: row.try_get("created_at")?,
            last_used_at: row.try_get("last_used_at")?,
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

    async fn create_webauthn_session(
        &self,
        id: Uuid,
        user_id: Uuid,
        data: serde_json::Value,
        purpose: String,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AppError> {
        let client = &self.db.get().await?;

        client
                .execute(
                    "INSERT INTO webauthn_sessions (id, user_id, data, purpose, expires_at) VALUES ($1, $2, $3, $4, $5)",
                    &[&id, &user_id, &data, &purpose, &expires_at],
                )
                .await?;

        Ok(())
    }

    async fn get_webauthn_session(
        &self,
        id: Uuid,
        purpose: String,
    ) -> Result<WebAuthnSession, AppError> {
        let client = &self.db.get().await?;

        let row = client
            .query_one(
                "SELECT * FROM webauthn_sessions WHERE id = $1 AND purpose = $2",
                &[&id, &purpose],
            )
            .await?;

        Self::row_to_webauthn_session(&row)
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
        id: Vec<u8>,
        user_id: Uuid,
        public_key: Vec<u8>,
        sign_count: i64,
        transports: Option<Vec<String>>,
        aaguid: Option<Uuid>,
        attestation_format: Option<String>,
        backup_eligible: bool,
        backup_state: bool,
    ) -> Result<(), AppError> {
        let client = &self.db.get().await?;

        client
                .execute(
                    "INSERT INTO credentials (id, user_id, public_key, sign_count, transports, aaguid, attestation_format, backup_eligible, backup_state) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                    &[&id, &user_id, &public_key, &sign_count, &transports, &aaguid, &attestation_format, &backup_eligible, &backup_state],
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

    async fn update_credential(&self, id: Vec<u8>, sign_count: i64) -> Result<(), AppError> {
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
