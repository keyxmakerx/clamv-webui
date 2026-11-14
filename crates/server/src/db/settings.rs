//! Key/value application settings (Configuration Center values). They apply
//! on the next start and lose to env.

use sha2::{Digest, Sha256};
use sqlx::Row;

use super::{Db, DbError, Kind, now_ms};

impl Db {
    pub async fn setting(&self, name: &str) -> Result<Option<String>, DbError> {
        let v =
            sqlx::query_scalar::<_, String>(self.sql("SELECT value FROM settings WHERE name = ?"))
                .bind(name)
                .fetch_optional(self.pool())
                .await?;
        Ok(v)
    }

    pub async fn set_setting(
        &self,
        name: &str,
        value: &str,
        by: Option<&str>,
    ) -> Result<(), DbError> {
        let q = match self.kind() {
            Kind::Sqlite | Kind::Postgres => {
                "INSERT INTO settings (name, value, updated_at, updated_by) VALUES (?, ?, ?, ?) \
                 ON CONFLICT (name) DO UPDATE SET value = excluded.value, \
                 updated_at = excluded.updated_at, updated_by = excluded.updated_by"
            }
            Kind::MySql => {
                "INSERT INTO settings (name, value, updated_at, updated_by) VALUES (?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE value = VALUES(value), \
                 updated_at = VALUES(updated_at), updated_by = VALUES(updated_by)"
            }
        };
        sqlx::query(self.sql(q))
            .bind(name)
            .bind(value)
            .bind(now_ms())
            .bind(by)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    pub async fn delete_setting(&self, name: &str) -> Result<bool, DbError> {
        let r = sqlx::query(self.sql("DELETE FROM settings WHERE name = ?"))
            .bind(name)
            .execute(self.pool())
            .await?;
        Ok(r.rows_affected() > 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    pub name: String,
    pub value: String,
    pub updated_at: i64,
    pub updated_by: Option<String>,
}

/// A hash of every stored row, used to refuse an apply based on a stale review.
pub fn revision(rows: &[Setting]) -> String {
    let mut h = Sha256::new();
    for r in rows {
        h.update(r.name.as_bytes());
        h.update([0]);
        h.update(r.value.as_bytes());
        h.update([0]);
    }
    let d = h.finalize();
    d.iter().take(12).map(|b| format!("{b:02x}")).collect()
}

impl Db {
    pub async fn list_settings(&self) -> Result<Vec<Setting>, DbError> {
        let rows = sqlx::query(
            self.sql("SELECT name, value, updated_at, updated_by FROM settings ORDER BY name"),
        )
        .fetch_all(self.pool())
        .await?;
        rows.iter()
            .map(|r| {
                Ok(Setting {
                    name: r.try_get("name")?,
                    value: r.try_get("value")?,
                    updated_at: r.try_get("updated_at")?,
                    updated_by: r.try_get("updated_by")?,
                })
            })
            .collect()
    }

    /// Write changes (None removes) if the stored rows still match `expected`.
    /// Returns false when someone else changed settings since the review.
    pub async fn apply_settings(
        &self,
        changes: &[(String, Option<String>)],
        by: &str,
        expected: &str,
    ) -> Result<bool, DbError> {
        if revision(&self.list_settings().await?) != expected {
            return Ok(false);
        }
        let mut tx = self.pool().begin().await?;
        let now = now_ms();
        for (name, value) in changes {
            sqlx::query(self.sql("DELETE FROM settings WHERE name = ?"))
                .bind(name)
                .execute(&mut *tx)
                .await?;
            if let Some(v) = value {
                sqlx::query(self.sql(
                    "INSERT INTO settings (name, value, updated_at, updated_by) VALUES (?, ?, ?, ?)",
                ))
                .bind(name)
                .bind(v)
                .bind(now)
                .bind(by)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(true)
    }
}
