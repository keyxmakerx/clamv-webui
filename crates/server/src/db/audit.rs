//! Audit trail. Every entry is also written as a log line, so LogTide sees it.

use sqlx::Row;

use super::{Db, DbError, now_ms};

#[derive(Debug, Clone, Default)]
pub struct AuditEntry {
    pub username: Option<String>,
    pub action: &'static str,
    pub outcome: &'static str,
    pub details: Option<String>,
    pub job_id: Option<String>,
    pub transport: Option<&'static str>,
    pub endpoint_id: Option<i64>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuditRow {
    pub at: i64,
    pub username: Option<String>,
    pub action: String,
    pub outcome: Option<String>,
    pub details: Option<String>,
    pub job_id: Option<String>,
    pub ip: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuditApiRow {
    pub id: i64,
    pub at: i64,
    pub username: Option<String>,
    pub action: String,
    pub outcome: Option<String>,
    pub transport: Option<String>,
    pub endpoint_id: Option<i64>,
    pub job_id: Option<String>,
}

impl Db {
    /// Record an event. A failed insert is logged, never fatal to the caller.
    pub async fn audit(&self, e: AuditEntry) {
        tracing::info!(
            event = "audit",
            action = e.action,
            outcome = e.outcome,
            user = e.username.as_deref().unwrap_or("-"),
            ip = e.ip.as_deref().unwrap_or("-"),
            job = e.job_id.as_deref().unwrap_or("-"),
            details = e.details.as_deref().unwrap_or(""),
            "audit"
        );
        let details: Option<String> = e.details.map(|d| d.chars().take(2000).collect());
        let ua: Option<String> = e.user_agent.map(|d| d.chars().take(255).collect());
        let r = sqlx::query(self.sql(
            "INSERT INTO audit_events (at, username, action, outcome, details, job_id, transport, endpoint_id, ip, user_agent) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ))
        .bind(now_ms())
        .bind(e.username)
        .bind(e.action)
        .bind(e.outcome)
        .bind(details)
        .bind(e.job_id)
        .bind(e.transport)
        .bind(e.endpoint_id)
        .bind(e.ip)
        .bind(ua)
        .execute(self.pool())
        .await;
        if let Err(err) = r {
            tracing::error!(error = %err, action = e.action, "audit insert failed");
        }
    }

    pub async fn recent_audit(&self, limit: i64) -> Result<Vec<AuditRow>, DbError> {
        let rows = sqlx::query(self.sql(
            "SELECT at, username, action, outcome, details, job_id, ip FROM audit_events ORDER BY id DESC LIMIT ?",
        ))
        .bind(limit.clamp(1, 1000))
        .fetch_all(self.pool())
        .await?;
        rows.iter()
            .map(|r| {
                Ok(AuditRow {
                    at: r.try_get("at")?,
                    username: r.try_get("username")?,
                    action: r.try_get("action")?,
                    outcome: r.try_get("outcome")?,
                    details: r.try_get("details")?,
                    job_id: r.try_get("job_id")?,
                    ip: r.try_get("ip")?,
                })
            })
            .collect()
    }

    /// A page of events without IPs or details, newest first (for `/api/v1/audit`).
    pub async fn audit_page(
        &self,
        page: i64,
        size: i64,
    ) -> Result<(Vec<AuditApiRow>, i64), DbError> {
        let total: i64 = sqlx::query_scalar(self.sql("SELECT COUNT(*) FROM audit_events"))
            .fetch_one(self.pool())
            .await?;
        let rows = sqlx::query(self.sql(
            "SELECT id, at, username, action, outcome, transport, endpoint_id, job_id FROM audit_events \
             ORDER BY id DESC LIMIT ? OFFSET ?",
        ))
        .bind(size)
        .bind(page.saturating_mul(size))
        .fetch_all(self.pool())
        .await?;
        let items = rows
            .iter()
            .map(|r| {
                Ok(AuditApiRow {
                    id: r.try_get("id")?,
                    at: r.try_get("at")?,
                    username: r.try_get("username")?,
                    action: r.try_get("action")?,
                    outcome: r.try_get("outcome")?,
                    transport: r.try_get("transport")?,
                    endpoint_id: r.try_get("endpoint_id")?,
                    job_id: r.try_get("job_id")?,
                })
            })
            .collect::<Result<_, DbError>>()?;
        Ok((items, total))
    }

    /// Retention: delete entries older than `before_ms`.
    pub async fn prune_audit(&self, before_ms: i64) -> Result<u64, DbError> {
        let r = sqlx::query(self.sql("DELETE FROM audit_events WHERE at < ?"))
            .bind(before_ms)
            .execute(self.pool())
            .await?;
        Ok(r.rows_affected())
    }
}
