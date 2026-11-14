//! Remote agents: hosts that run scans against their own clamd and report back.

use sqlx::Row;
use sqlx::any::AnyRow;

use super::{Db, DbError, now_ms};
use crate::auth::token::{hash_secret, random_secret};

/// Agent secrets start with this, so they are easy to spot in a leak scan.
pub const SECRET_PREFIX: &str = "clamv_agent_";

#[derive(Debug, Clone)]
pub struct Agent {
    pub id: i64,
    pub name: String,
    pub prefix: String,
    pub enabled: bool,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub last_seen_at: Option<i64>,
    pub last_ip: Option<String>,
    pub version: Option<String>,
    pub clamd_version: Option<String>,
    pub roots: Vec<String>,
    pub slots: i64,
    /// Last known state, used to log transitions once.
    pub online: bool,
}

/// What an agent reports on each poll.
pub struct Heartbeat<'a> {
    pub ip: &'a str,
    pub version: &'a str,
    pub clamd_version: Option<&'a str>,
    pub roots: &'a [String],
    pub slots: i64,
}

fn from_row(r: &AnyRow) -> Result<Agent, DbError> {
    let roots: Option<String> = r.try_get("roots_json")?;
    Ok(Agent {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        prefix: r.try_get("prefix")?,
        enabled: r.try_get::<i64, _>("enabled")? != 0,
        created_at: r.try_get("created_at")?,
        created_by: r.try_get("created_by")?,
        last_seen_at: r.try_get("last_seen_at")?,
        last_ip: r.try_get("last_ip")?,
        version: r.try_get("version")?,
        clamd_version: r.try_get("clamd_version")?,
        roots: roots
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default(),
        slots: r.try_get("slots")?,
        online: r.try_get::<i64, _>("online")? != 0,
    })
}

macro_rules! select {
    ($tail:literal) => {
        concat!(
            "SELECT id, name, prefix, enabled, created_at, created_by, last_seen_at, last_ip, version, ",
            "clamd_version, roots_json, slots, online FROM agents ",
            $tail
        )
    };
}

impl Db {
    pub async fn list_agents(&self) -> Result<Vec<Agent>, DbError> {
        let rows = sqlx::query(self.sql(select!("ORDER BY name")))
            .fetch_all(self.pool())
            .await?;
        rows.iter().map(from_row).collect()
    }

    pub async fn agent(&self, id: i64) -> Result<Option<Agent>, DbError> {
        let row = sqlx::query(self.sql(select!("WHERE id = ?")))
            .bind(id)
            .fetch_optional(self.pool())
            .await?;
        row.as_ref().map(from_row).transpose()
    }

    /// The enabled-or-not agent owning `secret`.
    pub async fn agent_by_secret(&self, secret: &str) -> Result<Option<Agent>, DbError> {
        let row = sqlx::query(self.sql(select!("WHERE token_hash = ?")))
            .bind(hash_secret(secret))
            .fetch_optional(self.pool())
            .await?;
        row.as_ref().map(from_row).transpose()
    }

    /// Create an agent. The secret is returned once and only its hash is kept.
    pub async fn create_agent(
        &self,
        name: &str,
        created_by: &str,
    ) -> Result<(Agent, String), DbError> {
        let secret = format!("{SECRET_PREFIX}{}", random_secret());
        let prefix: String = secret.chars().take(SECRET_PREFIX.len() + 4).collect();
        sqlx::query(self.sql(
            "INSERT INTO agents (name, token_hash, prefix, enabled, created_at, created_by, slots, online) \
             VALUES (?, ?, ?, 1, ?, ?, 0, 0)",
        ))
        .bind(name)
        .bind(hash_secret(&secret))
        .bind(&prefix)
        .bind(now_ms())
        .bind(created_by)
        .execute(self.pool())
        .await?;
        let row = sqlx::query(self.sql(select!("WHERE name = ?")))
            .bind(name)
            .fetch_one(self.pool())
            .await?;
        Ok((from_row(&row)?, secret))
    }

    /// Replace an agent's secret; the old one stops working at once.
    pub async fn rotate_agent_secret(&self, id: i64) -> Result<Option<String>, DbError> {
        let secret = format!("{SECRET_PREFIX}{}", random_secret());
        let prefix: String = secret.chars().take(SECRET_PREFIX.len() + 4).collect();
        let r = sqlx::query(self.sql("UPDATE agents SET token_hash = ?, prefix = ? WHERE id = ?"))
            .bind(hash_secret(&secret))
            .bind(&prefix)
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok((r.rows_affected() == 1).then_some(secret))
    }

    pub async fn set_agent_enabled(&self, id: i64, enabled: bool) -> Result<bool, DbError> {
        let r = sqlx::query(self.sql("UPDATE agents SET enabled = ? WHERE id = ?"))
            .bind(i64::from(enabled))
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn heartbeat_agent(&self, id: i64, h: &Heartbeat<'_>) -> Result<(), DbError> {
        let roots = serde_json::to_string(h.roots).map_err(|e| DbError::Encode(e.to_string()))?;
        sqlx::query(self.sql(
            "UPDATE agents SET last_seen_at = ?, last_ip = ?, version = ?, clamd_version = ?, roots_json = ?, \
             slots = ? WHERE id = ?",
        ))
        .bind(now_ms())
        .bind(h.ip)
        .bind(h.version)
        .bind(h.clamd_version)
        .bind(roots)
        .bind(h.slots)
        .bind(id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Record the online flag; true if it changed (so the caller logs once).
    pub async fn set_agent_online(&self, id: i64, online: bool) -> Result<bool, DbError> {
        let r = sqlx::query(self.sql("UPDATE agents SET online = ? WHERE id = ? AND online = ?"))
            .bind(i64::from(online))
            .bind(id)
            .bind(i64::from(!online))
            .execute(self.pool())
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Delete an agent. Its unfinished jobs are failed first so nothing else runs them.
    pub async fn delete_agent(&self, id: i64) -> Result<bool, DbError> {
        let mut tx = self.pool().begin().await?;
        sqlx::query(self.sql(
            "UPDATE scan_jobs SET status = 'FINISHED', verdict = 'ERROR', finished_at = ?, \
             error_code = 'CONFIGURATION_UNAVAILABLE', error_message = 'The agent was removed.' \
             WHERE agent_id = ? AND status <> 'FINISHED'",
        ))
        .bind(now_ms())
        .bind(id)
        .execute(&mut *tx)
        .await?;
        let r = sqlx::query(self.sql("DELETE FROM agents WHERE id = ?"))
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(r.rows_affected() == 1)
    }
}
