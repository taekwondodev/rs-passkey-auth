use chrono::Utc;
use deadpool_postgres::{Pool, Transaction};
use uuid::Uuid;

use crate::{
    app::AppError,
    auth::model::{User, WebAuthnSession},
};

pub struct AuthRepository {
    db: Pool,
}

impl AuthRepository {
    pub fn new(db: Pool) -> Self {
        Self { db }
    }

    pub async fn create_user(&self, username: &str, role: Option<&str>) -> Result<User, AppError> {
        let client = &self.db.get().await?;

        match self.get_user_by_username(&username).await {
            Ok(user) => {
                if user.status == "active" {
                    return Err(AppError::AlreadyExists(String::from(
                        "Username already exists",
                    )));
                } else {
                    return Ok(user);
                }
            }
            Err(AppError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }

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

    pub async fn get_user_by_username(&self, username: &str) -> Result<User, AppError> {
        let client = &self.db.get().await?;

        match client
            .query_opt("SELECT * FROM users WHERE username = $1", &[&username])
            .await?
        {
            Some(row) => Self::row_to_user(&row),
            None => Err(AppError::NotFound(String::from("Username not found"))),
        }
    }

    pub async fn get_user_and_session(
        &self,
        session_id: Uuid,
        username: &str,
        purpose: &str,
    ) -> Result<(User, WebAuthnSession), AppError> {
        let client = &self.db.get().await?;

        match client
            .query_opt(
                "SELECT
                        u.id, u.username, u.role, u.status, u.created_at, u.updated_at, u.is_active,
                        ws.id as session_id, ws.user_id, ws.data, ws.purpose,
                        ws.created_at as session_created_at, ws.expires_at
                     FROM users u
                     INNER JOIN webauthn_sessions ws ON u.id = ws.user_id
                     WHERE u.username = $1 AND ws.id = $2 AND ws.purpose = $3",
                &[&username, &session_id, &purpose],
            )
            .await?
        {
            Some(row) => {
                let user = Self::row_to_user(&row)?;
                let session = Self::row_to_webauthn_session(&row)?;
                Ok((user, session))
            }
            None => Err(AppError::NotFound(String::from(
                "User or session not found",
            ))),
        }
    }

    pub async fn get_active_user_with_credential(
        &self,
        username: &str,
    ) -> Result<(User, Vec<webauthn_rs::prelude::Passkey>), AppError> {
        let client = &self.db.get().await?;

        let rows = client
            .query(
                "SELECT
                        u.id, u.username, u.role, u.status, u.created_at, u.updated_at, u.is_active,
                        c.passkey
                     FROM users u
                     INNER JOIN credentials c ON u.id = c.user_id
                     WHERE u.username = $1 AND u.status = 'active'",
                &[&username],
            )
            .await?;

        if rows.is_empty() {
            return Err(AppError::NotFound(String::from(
                "User or credentials not found",
            )));
        }

        let user = Self::row_to_user(&rows[0])?;
        let mut passkeys = Vec::new();
        for row in rows {
            let passkey_json: serde_json::Value = row.try_get("passkey")?;
            let passkey: webauthn_rs::prelude::Passkey = serde_json::from_value(passkey_json)?;
            passkeys.push(passkey);
        }

        Ok((user, passkeys))
    }

    pub async fn create_webauthn_session(
        &self,
        user_id: Uuid,
        data: serde_json::Value,
        purpose: &str,
    ) -> Result<Uuid, AppError> {
        let client = &self.db.get().await?;
        let expire_at = Utc::now() + chrono::Duration::minutes(30);

        let row = client.query_one(
                "INSERT INTO webauthn_sessions (user_id, data, purpose, expires_at) VALUES ($1, $2, $3, $4) RETURNING id",
                &[&user_id, &data, &purpose, &expire_at],
            )
            .await?;

        Ok(row.get("id"))
    }

    pub async fn delete_webauthn_session(&self, id: Uuid) -> Result<(), AppError> {
        let client = &self.db.get().await?;

        client
            .execute("DELETE FROM webauthn_sessions WHERE id = $1", &[&id])
            .await?;

        Ok(())
    }

    pub async fn update_credential(
        &self,
        cred_id: &[u8],
        new_counter: u32,
    ) -> Result<(), AppError> {
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

    pub async fn complete_registration(
        &self,
        user_id: Uuid,
        username: &str,
        passkey: &webauthn_rs::prelude::Passkey,
    ) -> Result<(), AppError> {
        let mut client = self.db.get().await?;
        let tx = client.transaction().await?;

        self.create_credential(&tx, user_id, passkey).await?;
        self.activate_user(&tx, username).await?;

        tx.commit().await?;
        Ok(())
    }

    async fn activate_user(&self, tx: &Transaction<'_>, username: &str) -> Result<(), AppError> {
        tx.execute(
            "UPDATE users SET status = 'active' WHERE username = $1",
            &[&username],
        )
        .await?;

        Ok(())
    }

    async fn create_credential(
        &self,
        tx: &Transaction<'_>,
        user_id: Uuid,
        passkey: &webauthn_rs::prelude::Passkey,
    ) -> Result<(), AppError> {
        let passkey_json = serde_json::to_value(passkey)?;

        tx.execute(
            "INSERT INTO credentials (id, user_id, passkey) VALUES ($1, $2, $3)",
            &[&passkey.cred_id().as_slice(), &user_id, &passkey_json],
        )
        .await?;

        Ok(())
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
