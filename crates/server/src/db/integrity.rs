//! Stored AIDE and rkhunter runs.

use sqlx::Row;
use sqlx::any::AnyRow;

use super::{Db, DbError, new_id, now_ms};
use crate::integrity::Report;

#[derive(Debug, Clone)]
pub struct StoredReport {
    pub agent_id: Option<i64>,
    pub report: Report,
    pub received_at: i64,
}

fn from_row(r: &AnyRow) -> Result<StoredReport, DbError> {
    let findings: String = r.try_get("findings_json")?;
    Ok(StoredReport {
        agent_id: r.try_get("agent_id")?,
        received_at: r.try_get("received_at")?,
        report: Report {
            tool: r.try_get("tool")?,
            ran_at: r.try_get("ran_at")?,
            ok: r.try_get::<i64, _>("ok")? != 0,
            summary: r.try_get("summary")?,
            findings: serde_json::from_str(&findings).unwrap_or_default(),
        },
    })
}

impl Db {
    /// Store a run unless this host already sent it. True when stored.
    pub async fn add_integrity_report(
        &self,
        agent_id: Option<i64>,
        r: &Report,
    ) -> Result<bool, DbError> {
        let q = match agent_id {
            Some(_) => {
                "SELECT COUNT(*) FROM integrity_reports WHERE agent_id = ? AND tool = ? AND ran_at = ?"
            }
            None => {
                "SELECT COUNT(*) FROM integrity_reports WHERE agent_id IS NULL AND tool = ? AND ran_at = ?"
            }
        };
        let mut c = sqlx::query_scalar::<_, i64>(self.sql(q));
        if let Some(a) = agent_id {
            c = c.bind(a);
        }
        if c.bind(&r.tool)
            .bind(r.ran_at)
            .fetch_one(self.pool())
            .await?
            > 0
        {
            return Ok(false);
        }
        let findings =
            serde_json::to_string(&r.findings).map_err(|e| DbError::Encode(e.to_string()))?;
        sqlx::query(self.sql(
            "INSERT INTO integrity_reports (id, agent_id, tool, ran_at, ok, summary, findings_json, received_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ))
        .bind(new_id())
        .bind(agent_id)
        .bind(&r.tool)
        .bind(r.ran_at)
        .bind(i64::from(r.ok))
        .bind(r.summary.chars().take(500).collect::<String>())
        .bind(findings)
        .bind(now_ms())
        .execute(self.pool())
        .await?;
        Ok(true)
    }

    /// The newest run per host and tool.
    pub async fn latest_integrity(&self) -> Result<Vec<StoredReport>, DbError> {
        let rows = sqlx::query(self.sql(
            "SELECT r.agent_id, r.tool, r.ran_at, r.ok, r.summary, r.findings_json, r.received_at \
             FROM integrity_reports r JOIN (SELECT agent_id, tool, MAX(ran_at) AS m FROM integrity_reports \
             GROUP BY agent_id, tool) x ON x.tool = r.tool AND x.m = r.ran_at \
             AND (x.agent_id = r.agent_id OR (x.agent_id IS NULL AND r.agent_id IS NULL)) \
             ORDER BY r.ran_at DESC",
        ))
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(from_row).collect()
    }

    /// (tool, ran_at) of the newest runs on one host, so restarts do not repeat alerts.
    pub async fn latest_integrity_runs(
        &self,
        agent_id: Option<i64>,
    ) -> Result<Vec<(String, i64)>, DbError> {
        Ok(self
            .latest_integrity()
            .await?
            .into_iter()
            .filter(|r| r.agent_id == agent_id)
            .map(|r| (r.report.tool, r.report.ran_at))
            .collect())
    }

    /// Recent runs, newest first, for the integrity page.
    pub async fn recent_integrity(&self, limit: i64) -> Result<Vec<StoredReport>, DbError> {
        let rows = sqlx::query(self.sql(
            "SELECT agent_id, tool, ran_at, ok, summary, findings_json, received_at \
             FROM integrity_reports ORDER BY ran_at DESC LIMIT ?",
        ))
        .bind(limit)
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(from_row).collect()
    }

    pub async fn prune_integrity(&self, before_ms: i64) -> Result<u64, DbError> {
        let r = sqlx::query(self.sql("DELETE FROM integrity_reports WHERE received_at < ?"))
            .bind(before_ms)
            .execute(self.pool())
            .await?;
        Ok(r.rows_affected())
    }
}
