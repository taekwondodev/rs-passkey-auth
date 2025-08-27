use async_trait::async_trait;
use chrono::Utc;
use deadpool_postgres::Pool;
use uuid::Uuid;

use crate::{
    app::AppError,
    auth::model::{User, WebAuthnSession},
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
        user_id: Uuid,
        passkey: &webauthn_rs::prelude::Passkey,
    ) -> Result<(), AppError>;
    async fn get_credential_by_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<webauthn_rs::prelude::Passkey>, AppError>;
    async fn update_credential(&self, cred_id: &[u8], new_counter: u32) -> Result<(), AppError>;
}

pub struct PgRepository {
    db: Pool,
}

impl PgRepository {
    pub fn new(db: Pool) -> Self {
        Self { db }
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
            None => Err(AppError::NotFound(String::from("Username not found"))),
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
            None => Err(AppError::NotFound(String::from("Session not found"))),
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
        user_id: Uuid,
        passkey: &webauthn_rs::prelude::Passkey,
    ) -> Result<(), AppError> {
        let client = &self.db.get().await?;
        let passkey_json = serde_json::to_value(passkey)?;

        client
            .execute(
                "INSERT INTO credentials (id, user_id, passkey) VALUES ($1, $2, $3)",
                &[&passkey.cred_id().as_slice(), &user_id, &passkey_json],
            )
            .await?;

        Ok(())
    }

    async fn get_credential_by_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<webauthn_rs::prelude::Passkey>, AppError> {
        let client = &self.db.get().await?;

        let rows = client
            .query(
                "SELECT passkey FROM credentials WHERE user_id = $1",
                &[&user_id],
            )
            .await?;

        let mut passkeys = Vec::new();
        for row in rows {
            let passkey_json: serde_json::Value = row.try_get("passkey")?;
            let passkey: webauthn_rs::prelude::Passkey = serde_json::from_value(passkey_json)?;
            passkeys.push(passkey);
        }

        Ok(passkeys)
    }

    async fn update_credential(&self, cred_id: &[u8], new_counter: u32) -> Result<(), AppError> {
        let client = &self.db.get().await?;

        client
            .execute(
                "UPDATE credentials
                    SET passkey = jsonb_set(passkey, '{counter}', $1::text::jsonb)
                    WHERE id = $2",
                &[&(new_counter as i64), &cred_id],
            )
            .await?;

        Ok(())
    }
}
