//! Watched folders and the files already handled in them (N6).

use sqlx::Row;
use sqlx::any::AnyRow;

use super::{Db, DbError, Kind, new_id, now_ms};

#[derive(Debug, Clone)]
pub struct Watch {
    pub id: String,
    pub path: String,
    pub endpoint_id: Option<i64>,
    pub enabled: bool,
    pub created_at: i64,
}

/// What was recorded for a file the last time it was handled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Processed {
    pub modified_ms: i64,
    pub size_bytes: i64,
    pub verdict: String,
    pub processed_at: i64,
}

fn from_row(r: &AnyRow) -> Result<Watch, DbError> {
    Ok(Watch {
        id: r.try_get("id")?,
        path: r.try_get("path")?,
        endpoint_id: r.try_get("endpoint_id")?,
        enabled: r.try_get::<i64, _>("enabled")? != 0,
        created_at: r.try_get("created_at")?,
    })
}

pub fn path_key(path: &str) -> String {
    crate::auth::token::hash_secret(path)
}

impl Db {
    pub async fn list_watches(&self) -> Result<Vec<Watch>, DbError> {
        let rows = sqlx::query(self.sql(
            "SELECT id, path, endpoint_id, enabled, created_at FROM watched_directories ORDER BY path",
        ))
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(from_row).collect()
    }

    pub async fn watch(&self, id: &str) -> Result<Option<Watch>, DbError> {
        let row = sqlx::query(self.sql(
            "SELECT id, path, endpoint_id, enabled, created_at FROM watched_directories WHERE id = ?",
        ))
        .bind(id)
        .fetch_optional(self.pool())
        .await?;
        row.as_ref().map(from_row).transpose()
    }

    pub async fn create_watch(
        &self,
        path: &str,
        endpoint_id: Option<i64>,
    ) -> Result<Watch, DbError> {
        let id = new_id();
        sqlx::query(self.sql(
            "INSERT INTO watched_directories (id, path, endpoint_id, enabled, created_at) VALUES (?, ?, ?, 1, ?)",
        ))
        .bind(&id)
        .bind(path)
        .bind(endpoint_id)
        .bind(now_ms())
        .execute(self.pool())
        .await?;
        self.watch(&id).await?.ok_or(DbError::Missing)
    }

    pub async fn set_watch_enabled(&self, id: &str, enabled: bool) -> Result<(), DbError> {
        sqlx::query(self.sql("UPDATE watched_directories SET enabled = ? WHERE id = ?"))
            .bind(i64::from(enabled))
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    pub async fn delete_watch(&self, id: &str) -> Result<bool, DbError> {
        let r = sqlx::query(self.sql("DELETE FROM watched_directories WHERE id = ?"))
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn processed(&self, path: &str) -> Result<Option<Processed>, DbError> {
        let row = sqlx::query(self.sql(
            "SELECT modified_ms, size_bytes, verdict, processed_at FROM processed_files WHERE path_sha256 = ?",
        ))
        .bind(path_key(path))
        .fetch_optional(self.pool())
        .await?;
        row.map(|r| {
            Ok(Processed {
                modified_ms: r.try_get("modified_ms")?,
                size_bytes: r.try_get("size_bytes")?,
                verdict: r.try_get("verdict")?,
                processed_at: r.try_get("processed_at")?,
            })
        })
        .transpose()
    }

    pub async fn record_processed(
        &self,
        path: &str,
        modified_ms: i64,
        size_bytes: i64,
        verdict: &str,
    ) -> Result<(), DbError> {
        let q = match self.kind() {
            Kind::Sqlite | Kind::Postgres => {
                "INSERT INTO processed_files (path_sha256, path, modified_ms, size_bytes, verdict, processed_at) \
                 VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (path_sha256) DO UPDATE SET \
                 modified_ms = excluded.modified_ms, size_bytes = excluded.size_bytes, \
                 verdict = excluded.verdict, processed_at = excluded.processed_at"
            }
            Kind::MySql => {
                "INSERT INTO processed_files (path_sha256, path, modified_ms, size_bytes, verdict, processed_at) \
                 VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE modified_ms = VALUES(modified_ms), \
                 size_bytes = VALUES(size_bytes), verdict = VALUES(verdict), processed_at = VALUES(processed_at)"
            }
        };
        sqlx::query(self.sql(q))
            .bind(path_key(path))
            .bind(path)
            .bind(modified_ms)
            .bind(size_bytes)
            .bind(verdict)
            .bind(now_ms())
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Targets of WATCH jobs not finished yet, so a file is not queued twice.
    pub async fn active_watch_targets(&self) -> Result<Vec<String>, DbError> {
        Ok(sqlx::query_scalar(
            self.sql("SELECT target FROM scan_jobs WHERE kind = 'WATCH' AND status <> 'FINISHED'"),
        )
        .fetch_all(self.pool())
        .await?)
    }

    /// Forget files handled before `before_ms`; they are checked again on the next pass (N5).
    pub async fn prune_processed(&self, before_ms: i64) -> Result<u64, DbError> {
        let r = sqlx::query(self.sql("DELETE FROM processed_files WHERE processed_at < ?"))
            .bind(before_ms)
            .execute(self.pool())
            .await?;
        Ok(r.rows_affected())
    }
}
