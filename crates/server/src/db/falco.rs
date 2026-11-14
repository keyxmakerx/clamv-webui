//! Stored Falco alerts.

use sqlx::Row;

use super::{Db, DbError, new_id, now_ms};
use crate::falco::Alert;

#[derive(Debug, Clone)]
pub struct StoredAlert {
    pub agent_id: Option<i64>,
    pub alert: Alert,
}

impl Db {
    pub async fn add_falco_event(&self, agent_id: Option<i64>, a: &Alert) -> Result<(), DbError> {
        sqlx::query(self.sql(
            "INSERT INTO falco_events (id, agent_id, at, priority, rule, output, container, received_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ))
        .bind(new_id())
        .bind(agent_id)
        .bind(a.at)
        .bind(&a.priority)
        .bind(&a.rule)
        .bind(&a.output)
        .bind(a.container.as_deref())
        .bind(now_ms())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Alerts since `since`, newest first.
    pub async fn falco_since(&self, since: i64, limit: i64) -> Result<Vec<StoredAlert>, DbError> {
        let rows = sqlx::query(self.sql(
            "SELECT agent_id, at, priority, rule, output, container FROM falco_events \
             WHERE at >= ? ORDER BY at DESC LIMIT ?",
        ))
        .bind(since)
        .bind(limit)
        .fetch_all(self.pool())
        .await?;
        rows.iter()
            .map(|r| {
                Ok(StoredAlert {
                    agent_id: r.try_get("agent_id")?,
                    alert: Alert {
                        at: r.try_get("at")?,
                        priority: r.try_get("priority")?,
                        rule: r.try_get("rule")?,
                        output: r.try_get("output")?,
                        container: r.try_get("container")?,
                    },
                })
            })
            .collect()
    }

    /// Alert count and newest time per host since `since`.
    pub async fn falco_by_host(&self, since: i64) -> Result<Vec<(Option<i64>, i64, i64)>, DbError> {
        let rows = sqlx::query(self.sql(
            "SELECT agent_id, COUNT(*) AS n, MAX(at) AS last FROM falco_events WHERE at >= ? GROUP BY agent_id",
        ))
        .bind(since)
        .fetch_all(self.pool())
        .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("agent_id")?, r.try_get("n")?, r.try_get("last")?)))
            .collect()
    }

    pub async fn prune_falco(&self, before_ms: i64) -> Result<u64, DbError> {
        let r = sqlx::query(self.sql("DELETE FROM falco_events WHERE received_at < ?"))
            .bind(before_ms)
            .execute(self.pool())
            .await?;
        Ok(r.rows_affected())
    }
}
