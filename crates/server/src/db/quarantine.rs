//! Quarantined files: where each came from and what happened to it since.

use sqlx::Row;

use super::stats::DetectionRow;
use super::{Db, DbError, new_id, now_ms};

pub const PENDING: &str = "PENDING";
pub const HELD: &str = "QUARANTINED";
pub const RESTORED: &str = "RESTORED";
pub const DELETED: &str = "DELETED";
pub const FAILED: &str = "FAILED";

#[derive(Debug, Clone)]
pub struct Item {
    pub id: String,
    pub agent_id: Option<i64>,
    pub original_path: String,
    pub signature: String,
    pub sha256: Option<String>,
    pub size_bytes: Option<i64>,
    pub job_id: Option<String>,
    pub state: String,
    pub error_code: Option<String>,
    pub created_by: Option<String>,
    pub created_at: i64,
    pub updated_by: Option<String>,
    pub updated_at: i64,
}

macro_rules! cols {
    () => {
        "id, agent_id, original_path, signature, sha256, size_bytes, job_id, state, error_code, created_by, created_at, updated_by, updated_at"
    };
}

fn item(r: &sqlx::any::AnyRow) -> Result<Item, DbError> {
    Ok(Item {
        id: r.try_get("id")?,
        agent_id: r.try_get("agent_id")?,
        original_path: r.try_get("original_path")?,
        signature: r.try_get("signature")?,
        sha256: r.try_get("sha256")?,
        size_bytes: r.try_get("size_bytes")?,
        job_id: r.try_get("job_id")?,
        state: r.try_get("state")?,
        error_code: r.try_get("error_code")?,
        created_by: r.try_get("created_by")?,
        created_at: r.try_get("created_at")?,
        updated_by: r.try_get("updated_by")?,
        updated_at: r.try_get("updated_at")?,
    })
}

impl Db {
    /// One detection, for quarantining it by id rather than by a path the browser sends.
    pub async fn detection(&self, id: i64) -> Result<Option<DetectionRow>, DbError> {
        let r = sqlx::query(self.sql(
            "SELECT id, job_id, found_at, path, signature, kind, endpoint_id, agent_id FROM detections WHERE id = ?",
        ))
        .bind(id)
        .fetch_optional(self.pool())
        .await?;
        r.map(|r| {
            Ok(DetectionRow {
                id: r.try_get("id")?,
                job_id: r.try_get("job_id")?,
                found_at: r.try_get("found_at")?,
                path: r.try_get("path")?,
                signature: r.try_get("signature")?,
                kind: r.try_get("kind")?,
                endpoint_id: r.try_get("endpoint_id")?,
                agent_id: r.try_get("agent_id")?,
            })
        })
        .transpose()
    }

    /// A finished job's detections, at most 100.
    pub async fn detections_for_job(&self, job: &str) -> Result<Vec<DetectionRow>, DbError> {
        let rows = sqlx::query(self.sql(
            "SELECT id, job_id, found_at, path, signature, kind, endpoint_id, agent_id FROM detections WHERE job_id = ? ORDER BY id LIMIT 100",
        ))
        .bind(job)
        .fetch_all(self.pool())
        .await?;
        rows.iter()
            .map(|r| {
                Ok(DetectionRow {
                    id: r.try_get("id")?,
                    job_id: r.try_get("job_id")?,
                    found_at: r.try_get("found_at")?,
                    path: r.try_get("path")?,
                    signature: r.try_get("signature")?,
                    kind: r.try_get("kind")?,
                    endpoint_id: r.try_get("endpoint_id")?,
                    agent_id: r.try_get("agent_id")?,
                })
            })
            .collect()
    }

    /// A new PENDING entry; None when this file is already held or on its way.
    pub async fn create_quarantine(
        &self,
        agent: Option<i64>,
        path: &str,
        signature: &str,
        by: &str,
    ) -> Result<Option<Item>, DbError> {
        let busy = self.list_quarantine(500).await?.into_iter().any(|i| {
            i.agent_id == agent
                && i.original_path == path
                && (i.state == PENDING || i.state == HELD)
        });
        if busy {
            return Ok(None);
        }
        let id = new_id();
        let now = now_ms();
        sqlx::query(self.sql(
            "INSERT INTO quarantine (id, agent_id, original_path, signature, state, created_by, created_at, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ))
        .bind(&id)
        .bind(agent)
        .bind(path)
        .bind(signature)
        .bind(PENDING)
        .bind(by)
        .bind(now)
        .bind(by)
        .bind(now)
        .execute(self.pool())
        .await?;
        self.quarantine_item(&id).await
    }

    pub async fn quarantine_item(&self, id: &str) -> Result<Option<Item>, DbError> {
        let r = sqlx::query(self.sql(concat!("SELECT ", cols!(), " FROM quarantine WHERE id = ?")))
            .bind(id)
            .fetch_optional(self.pool())
            .await?;
        r.as_ref().map(item).transpose()
    }

    pub async fn list_quarantine(&self, limit: i64) -> Result<Vec<Item>, DbError> {
        let rows = sqlx::query(self.sql(concat!(
            "SELECT ",
            cols!(),
            " FROM quarantine ORDER BY created_at DESC LIMIT ?"
        )))
        .bind(limit)
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(item).collect()
    }

    pub async fn set_quarantine_job(&self, id: &str, job: &str) -> Result<(), DbError> {
        sqlx::query(self.sql("UPDATE quarantine SET job_id = ? WHERE id = ?"))
            .bind(job)
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Move an entry on; `held` carries the file's sha256 and size once it is in quarantine.
    pub async fn set_quarantine_state(
        &self,
        id: &str,
        state: &str,
        error: Option<&str>,
        held: Option<(&str, i64)>,
        by: &str,
    ) -> Result<(), DbError> {
        sqlx::query(self.sql(
            "UPDATE quarantine SET state = ?, error_code = ?, sha256 = COALESCE(?, sha256), size_bytes = COALESCE(?, size_bytes), updated_by = ?, updated_at = ? WHERE id = ?",
        ))
        .bind(state)
        .bind(error)
        .bind(held.map(|h| h.0))
        .bind(held.map(|h| h.1))
        .bind(by)
        .bind(now_ms())
        .bind(id)
        .execute(self.pool())
        .await?;
        Ok(())
    }
}
