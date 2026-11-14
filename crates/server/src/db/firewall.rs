//! Firewall plans, one per host: `central` is this server, `agent:<id>` an agent.

use sqlx::Row;

use super::{Db, DbError, now_ms};
use crate::firewall::Rule;

pub fn host_key(agent: Option<i64>) -> String {
    agent.map_or_else(|| "central".to_owned(), |id| format!("agent:{id}"))
}

#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub rules: Vec<Rule>,
    pub updated_by: Option<String>,
    pub updated_at: Option<i64>,
}

impl Db {
    pub async fn firewall_plan(&self, agent: Option<i64>) -> Result<Plan, DbError> {
        let row =
            sqlx::query(self.sql(
                "SELECT rules_json, updated_by, updated_at FROM firewall_plans WHERE host = ?",
            ))
            .bind(host_key(agent))
            .fetch_optional(self.pool())
            .await?;
        let Some(r) = row else {
            return Ok(Plan::default());
        };
        let raw: String = r.try_get("rules_json")?;
        Ok(Plan {
            rules: serde_json::from_str(&raw).unwrap_or_default(),
            updated_by: r.try_get("updated_by")?,
            updated_at: Some(r.try_get("updated_at")?),
        })
    }

    pub async fn set_firewall_plan(
        &self,
        agent: Option<i64>,
        rules: &[Rule],
        by: &str,
    ) -> Result<(), DbError> {
        let key = host_key(agent);
        let json = serde_json::to_string(rules).unwrap_or_else(|_| "[]".into());
        let mut tx = self.pool().begin().await?;
        sqlx::query(self.sql("DELETE FROM firewall_plans WHERE host = ?"))
            .bind(&key)
            .execute(&mut *tx)
            .await?;
        sqlx::query(self.sql(
            "INSERT INTO firewall_plans (host, rules_json, updated_by, updated_at) VALUES (?, ?, ?, ?)",
        ))
        .bind(&key)
        .bind(json)
        .bind(by)
        .bind(now_ms())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
