//! Local users. Changing a password, role or enabled flag ends that user's
//! sessions in the same transaction (audit N7).

use sqlx::Row;
use sqlx::any::AnyRow;

use super::{Db, DbError, new_id, now_ms};
use crate::auth::Role;

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub role: Role,
    pub enabled: bool,
    pub must_change_password: bool,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
}

/// Stored instead of a hash for SSO users; it never verifies.
pub const NO_PASSWORD: &str = "!";

impl User {
    /// Signs in through an external provider and has no local password.
    pub fn is_external(&self) -> bool {
        self.password_hash == NO_PASSWORD
    }
}

fn from_row(r: &AnyRow) -> Result<User, DbError> {
    let role: String = r.try_get("role")?;
    Ok(User {
        id: r.try_get("id")?,
        username: r.try_get("username")?,
        password_hash: r.try_get("password_hash")?,
        // An unknown role in the DB grants the least privilege.
        role: role.parse().unwrap_or(Role::Viewer),
        enabled: r.try_get::<i64, _>("enabled")? != 0,
        must_change_password: r.try_get::<i64, _>("must_change_password")? != 0,
        created_at: r.try_get("created_at")?,
        last_login_at: r.try_get("last_login_at")?,
    })
}

impl Db {
    pub async fn count_users(&self) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar(self.sql("SELECT COUNT(*) FROM users"))
            .fetch_one(self.pool())
            .await?)
    }

    pub async fn count_enabled_admins(&self) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar(
            self.sql("SELECT COUNT(*) FROM users WHERE role = 'ADMIN' AND enabled = 1"),
        )
        .fetch_one(self.pool())
        .await?)
    }

    pub async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        role: Role,
        must_change_password: bool,
    ) -> Result<User, DbError> {
        let user = User {
            id: new_id(),
            username: username.to_owned(),
            password_hash: password_hash.to_owned(),
            role,
            enabled: true,
            must_change_password,
            created_at: now_ms(),
            last_login_at: None,
        };
        sqlx::query(self.sql(
            "INSERT INTO users (id, username, password_hash, role, enabled, must_change_password, created_at) \
             VALUES (?, ?, ?, ?, 1, ?, ?)",
        ))
        .bind(&user.id)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(role.as_str())
        .bind(i64::from(must_change_password))
        .bind(user.created_at)
        .execute(self.pool())
        .await?;
        Ok(user)
    }

    pub async fn user_by_username(&self, username: &str) -> Result<Option<User>, DbError> {
        let row = sqlx::query(self.sql(
            "SELECT id, username, password_hash, role, enabled, must_change_password, created_at, last_login_at \
             FROM users WHERE username = ?",
        ))
        .bind(username).fetch_optional(self.pool()).await?;
        row.as_ref().map(from_row).transpose()
    }

    pub async fn user_by_id(&self, id: &str) -> Result<Option<User>, DbError> {
        let row = sqlx::query(self.sql(
            "SELECT id, username, password_hash, role, enabled, must_change_password, created_at, last_login_at \
             FROM users WHERE id = ?",
        ))
        .bind(id)
        .fetch_optional(self.pool())
        .await?;
        row.as_ref().map(from_row).transpose()
    }

    pub async fn list_users(&self) -> Result<Vec<User>, DbError> {
        let rows = sqlx::query(self.sql(
            "SELECT id, username, password_hash, role, enabled, must_change_password, created_at, last_login_at \
             FROM users ORDER BY username",
        ))
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(from_row).collect()
    }

    pub async fn touch_login(&self, id: &str) -> Result<(), DbError> {
        sqlx::query(self.sql("UPDATE users SET last_login_at = ? WHERE id = ?"))
            .bind(now_ms())
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Store a new hash. `end_sessions` is false only for a silent rehash at login.
    pub async fn set_password(
        &self,
        id: &str,
        password_hash: &str,
        must_change: bool,
        end_sessions: bool,
    ) -> Result<(), DbError> {
        let mut tx = self.pool().begin().await?;
        sqlx::query(
            self.sql("UPDATE users SET password_hash = ?, must_change_password = ? WHERE id = ?"),
        )
        .bind(password_hash)
        .bind(i64::from(must_change))
        .bind(id)
        .execute(&mut *tx)
        .await?;
        if end_sessions {
            sqlx::query(self.sql("DELETE FROM sessions WHERE user_id = ?"))
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn set_role_enabled(
        &self,
        id: &str,
        role: Role,
        enabled: bool,
    ) -> Result<(), DbError> {
        let mut tx = self.pool().begin().await?;
        sqlx::query(self.sql("UPDATE users SET role = ?, enabled = ? WHERE id = ?"))
            .bind(role.as_str())
            .bind(i64::from(enabled))
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(self.sql("DELETE FROM sessions WHERE user_id = ?"))
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn delete_user(&self, id: &str) -> Result<bool, DbError> {
        let r = sqlx::query(self.sql("DELETE FROM users WHERE id = ?"))
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(r.rows_affected() > 0)
    }
}
