//! Browser sessions. Only the SHA-256 of the cookie value is stored.

use sqlx::Row;

use super::{Db, DbError, now_ms};
use crate::auth::token::{hash_secret, random_secret};
use crate::db::users::User;

#[derive(Debug, Clone)]
pub struct Session {
    pub id_hash: String,
    pub user_id: String,
    pub csrf_token: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub expires_at: i64,
}

impl Db {
    /// Returns the raw cookie value; it is never stored.
    pub async fn create_session(
        &self,
        user_id: &str,
        ttl_ms: i64,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(String, Session), DbError> {
        let raw = random_secret();
        let now = now_ms();
        let s = Session {
            id_hash: hash_secret(&raw),
            user_id: user_id.to_owned(),
            csrf_token: random_secret(),
            created_at: now,
            last_seen_at: now,
            expires_at: now.saturating_add(ttl_ms),
        };
        let ua: Option<String> = user_agent.map(|u| u.chars().take(255).collect());
        sqlx::query(self.sql(
            "INSERT INTO sessions (id_hash, user_id, csrf_token, created_at, last_seen_at, expires_at, ip, user_agent) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ))
        .bind(&s.id_hash)
        .bind(&s.user_id)
        .bind(&s.csrf_token)
        .bind(s.created_at)
        .bind(s.last_seen_at)
        .bind(s.expires_at)
        .bind(ip)
        .bind(ua)
        .execute(self.pool())
        .await?;
        Ok((raw, s))
    }

    /// Valid, unexpired, not idle, and the user is still enabled.
    pub async fn session_user(
        &self,
        raw: &str,
        idle_ms: i64,
    ) -> Result<Option<(Session, User)>, DbError> {
        let now = now_ms();
        let id_hash = hash_secret(raw);
        let row = sqlx::query(self.sql(
            "SELECT s.user_id, s.csrf_token, s.created_at, s.last_seen_at, s.expires_at \
             FROM sessions s WHERE s.id_hash = ?",
        ))
        .bind(&id_hash)
        .fetch_optional(self.pool())
        .await?;
        let Some(row) = row else { return Ok(None) };
        let s = Session {
            id_hash,
            user_id: row.try_get("user_id")?,
            csrf_token: row.try_get("csrf_token")?,
            created_at: row.try_get("created_at")?,
            last_seen_at: row.try_get("last_seen_at")?,
            expires_at: row.try_get("expires_at")?,
        };
        if s.expires_at <= now || now.saturating_sub(s.last_seen_at) > idle_ms {
            self.delete_session_hash(&s.id_hash).await?;
            return Ok(None);
        }
        let Some(user) = self.user_by_id(&s.user_id).await? else {
            return Ok(None);
        };
        if !user.enabled {
            self.delete_session_hash(&s.id_hash).await?;
            return Ok(None);
        }
        // At most one write a minute per session.
        if now - s.last_seen_at > 60_000 {
            sqlx::query(self.sql("UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?"))
                .bind(now)
                .bind(&s.id_hash)
                .execute(self.pool())
                .await?;
        }
        Ok(Some((s, user)))
    }

    pub async fn delete_session(&self, raw: &str) -> Result<(), DbError> {
        self.delete_session_hash(&hash_secret(raw)).await
    }

    async fn delete_session_hash(&self, id_hash: &str) -> Result<(), DbError> {
        sqlx::query(self.sql("DELETE FROM sessions WHERE id_hash = ?"))
            .bind(id_hash)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    pub async fn delete_user_sessions(&self, user_id: &str) -> Result<u64, DbError> {
        let r = sqlx::query(self.sql("DELETE FROM sessions WHERE user_id = ?"))
            .bind(user_id)
            .execute(self.pool())
            .await?;
        Ok(r.rows_affected())
    }

    pub async fn purge_expired_sessions(&self, idle_ms: i64) -> Result<u64, DbError> {
        let now = now_ms();
        let r =
            sqlx::query(self.sql("DELETE FROM sessions WHERE expires_at <= ? OR last_seen_at < ?"))
                .bind(now)
                .bind(now.saturating_sub(idle_ms))
                .execute(self.pool())
                .await?;
        Ok(r.rows_affected())
    }
}
