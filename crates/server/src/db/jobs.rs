//! Scan jobs. Claiming is an atomic `UPDATE ... WHERE status = 'QUEUED'`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::any::AnyRow;

use super::{Db, DbError, new_id, now_ms};

pub const QUEUED: &str = "QUEUED";
pub const RUNNING: &str = "RUNNING";
pub const FINISHED: &str = "FINISHED";

pub const OK: &str = "OK";
pub const VIRUS_FOUND: &str = "VIRUS_FOUND";
pub const ERROR: &str = "ERROR";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobFileError {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct Job {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub verdict: Option<String>,
    pub target: String,
    pub sha256: Option<String>,
    pub size_bytes: Option<i64>,
    pub endpoint_id: Option<i64>,
    pub schedule_id: Option<String>,
    pub submitted_by: Option<String>,
    pub transport: Option<String>,
    pub submitted_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub files_scanned: i64,
    /// `{path: [signature, ...]}`, the Java format.
    pub detections: BTreeMap<String, Vec<String>>,
    pub errors: Vec<JobFileError>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

impl Job {
    pub fn signatures(&self) -> Vec<String> {
        let mut v: Vec<String> = self.detections.values().flatten().cloned().collect();
        v.sort();
        v.dedup();
        v
    }

    pub fn duration_ms(&self) -> Option<i64> {
        Some(self.finished_at? - self.started_at?)
    }
}

/// What a caller supplies to create a job.
pub struct NewJob<'a> {
    pub kind: &'a str,
    pub target: &'a str,
    pub endpoint_id: Option<i64>,
    pub schedule_id: Option<&'a str>,
    pub submitted_by: Option<&'a str>,
    pub transport: &'a str,
    /// Start as RUNNING (uploads scan inside the request).
    pub running: bool,
}

/// The result written when a job finishes.
#[derive(Debug, Default)]
pub struct Outcome {
    pub verdict: &'static str,
    pub files_scanned: i64,
    pub detections: BTreeMap<String, Vec<String>>,
    pub errors: Vec<JobFileError>,
    pub error_code: Option<&'static str>,
    pub error_message: Option<String>,
    pub sha256: Option<String>,
    pub size_bytes: Option<i64>,
}

#[derive(Debug, Default)]
pub struct JobFilter {
    pub status: Option<String>,
    pub verdict: Option<String>,
    pub endpoint_id: Option<i64>,
}

fn from_row(r: &AnyRow) -> Result<Job, DbError> {
    let det: Option<String> = r.try_get("detections_json")?;
    let err: Option<String> = r.try_get("errors_json")?;
    Ok(Job {
        id: r.try_get("id")?,
        kind: r.try_get("kind")?,
        status: r.try_get("status")?,
        verdict: r.try_get("verdict")?,
        target: r.try_get("target")?,
        sha256: r.try_get("sha256")?,
        size_bytes: r.try_get("size_bytes")?,
        endpoint_id: r.try_get("endpoint_id")?,
        schedule_id: r.try_get("schedule_id")?,
        submitted_by: r.try_get("submitted_by")?,
        transport: r.try_get("transport")?,
        submitted_at: r.try_get("submitted_at")?,
        started_at: r.try_get("started_at")?,
        finished_at: r.try_get("finished_at")?,
        files_scanned: r.try_get("files_scanned")?,
        // Unreadable JSON shows as empty rather than failing the page.
        detections: det
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default(),
        errors: err
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default(),
        error_code: r.try_get("error_code")?,
        error_message: r.try_get("error_message")?,
    })
}

macro_rules! select {
    ($tail:literal) => {
        concat!(
            "SELECT id, kind, status, verdict, target, sha256, size_bytes, endpoint_id, schedule_id, ",
            "submitted_by, transport, submitted_at, started_at, finished_at, files_scanned, detections_json, ",
            "errors_json, error_code, error_message FROM scan_jobs ",
            $tail
        )
    };
}

impl Db {
    pub async fn create_job(&self, j: NewJob<'_>) -> Result<Job, DbError> {
        let id = new_id();
        let now = now_ms();
        let (status, started) = if j.running {
            (RUNNING, Some(now))
        } else {
            (QUEUED, None)
        };
        sqlx::query(self.sql(
            "INSERT INTO scan_jobs (id, kind, status, target, endpoint_id, schedule_id, submitted_by, transport, \
             submitted_at, started_at, files_scanned) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
        ))
        .bind(&id)
        .bind(j.kind)
        .bind(status)
        .bind(j.target)
        .bind(j.endpoint_id)
        .bind(j.schedule_id)
        .bind(j.submitted_by)
        .bind(j.transport)
        .bind(now)
        .bind(started)
        .execute(self.pool())
        .await?;
        self.job(&id).await?.ok_or(DbError::Missing)
    }

    pub async fn job(&self, id: &str) -> Result<Option<Job>, DbError> {
        let row = sqlx::query(self.sql(select!("WHERE id = ?")))
            .bind(id)
            .fetch_optional(self.pool())
            .await?;
        row.as_ref().map(from_row).transpose()
    }

    /// Oldest queued job ids first.
    pub async fn queued_jobs(&self, limit: i64) -> Result<Vec<String>, DbError> {
        Ok(sqlx::query_scalar(self.sql(
            "SELECT id FROM scan_jobs WHERE status = 'QUEUED' ORDER BY submitted_at, id LIMIT ?",
        ))
        .bind(limit)
        .fetch_all(self.pool())
        .await?)
    }

    /// True if this caller won the job.
    pub async fn claim_job(&self, id: &str) -> Result<bool, DbError> {
        let r = sqlx::query(self.sql(
            "UPDATE scan_jobs SET status = 'RUNNING', started_at = ? WHERE id = ? AND status = 'QUEUED'",
        ))
        .bind(now_ms())
        .bind(id)
        .execute(self.pool())
        .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn finish_job(&self, id: &str, o: &Outcome) -> Result<(), DbError> {
        let det = (!o.detections.is_empty())
            .then(|| serde_json::to_string(&o.detections))
            .transpose()
            .map_err(|e| DbError::Encode(e.to_string()))?;
        let err = (!o.errors.is_empty())
            .then(|| serde_json::to_string(&o.errors))
            .transpose()
            .map_err(|e| DbError::Encode(e.to_string()))?;
        sqlx::query(self.sql(
            "UPDATE scan_jobs SET status = 'FINISHED', verdict = ?, finished_at = ?, files_scanned = ?, \
             detections_json = ?, errors_json = ?, error_code = ?, error_message = ?, \
             sha256 = COALESCE(?, sha256), size_bytes = COALESCE(?, size_bytes) WHERE id = ?",
        ))
        .bind(o.verdict)
        .bind(now_ms())
        .bind(o.files_scanned)
        .bind(det)
        .bind(err)
        .bind(o.error_code)
        .bind(o.error_message.as_deref())
        .bind(o.sha256.as_deref())
        .bind(o.size_bytes)
        .bind(id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// After a restart, RUNNING jobs did not finish. Mark them failed instead
    /// of re-running hours of work blindly (N5). Returns how many.
    pub async fn interrupt_running_jobs(&self) -> Result<u64, DbError> {
        let r = sqlx::query(self.sql(
            "UPDATE scan_jobs SET status = 'FINISHED', verdict = 'ERROR', finished_at = ?, \
             error_code = 'SCAN_FAILED', error_message = 'Interrupted by a restart.' WHERE status = 'RUNNING'",
        ))
        .bind(now_ms())
        .execute(self.pool())
        .await?;
        Ok(r.rows_affected())
    }

    /// Newest first, with the total count for paging.
    pub async fn list_jobs(
        &self,
        f: &JobFilter,
        page: i64,
        size: i64,
    ) -> Result<(Vec<Job>, i64), DbError> {
        let total: i64 = sqlx::query_scalar(self.sql(
            "SELECT COUNT(*) FROM scan_jobs WHERE (? IS NULL OR status = ?) AND (? IS NULL OR verdict = ?) \
             AND (? IS NULL OR endpoint_id = ?)",
        ))
        .bind(f.status.as_deref())
        .bind(f.status.as_deref())
        .bind(f.verdict.as_deref())
        .bind(f.verdict.as_deref())
        .bind(f.endpoint_id)
        .bind(f.endpoint_id)
        .fetch_one(self.pool())
        .await?;
        let rows = sqlx::query(self.sql(select!(
            "WHERE (? IS NULL OR status = ?) AND (? IS NULL OR verdict = ?) AND (? IS NULL OR endpoint_id = ?) \
             ORDER BY submitted_at DESC, id DESC LIMIT ? OFFSET ?"
        )))
        .bind(f.status.as_deref())
        .bind(f.status.as_deref())
        .bind(f.verdict.as_deref())
        .bind(f.verdict.as_deref())
        .bind(f.endpoint_id)
        .bind(f.endpoint_id)
        .bind(size)
        .bind(page.saturating_mul(size))
        .fetch_all(self.pool())
        .await?;
        Ok((rows.iter().map(from_row).collect::<Result<_, _>>()?, total))
    }

    pub async fn count_active_jobs(&self) -> Result<(i64, i64), DbError> {
        let q: i64 =
            sqlx::query_scalar(self.sql("SELECT COUNT(*) FROM scan_jobs WHERE status = 'QUEUED'"))
                .fetch_one(self.pool())
                .await?;
        let r: i64 =
            sqlx::query_scalar(self.sql("SELECT COUNT(*) FROM scan_jobs WHERE status = 'RUNNING'"))
                .fetch_one(self.pool())
                .await?;
        Ok((q, r))
    }

    /// Delete finished jobs submitted before `before_ms` (N5).
    pub async fn prune_jobs(&self, before_ms: i64) -> Result<u64, DbError> {
        let r = sqlx::query(
            self.sql("DELETE FROM scan_jobs WHERE status = 'FINISHED' AND submitted_at < ?"),
        )
        .bind(before_ms)
        .execute(self.pool())
        .await?;
        Ok(r.rows_affected())
    }
}
