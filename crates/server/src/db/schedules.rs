//! Scheduled scans (F1). A run is claimed by moving `last_run_at` with a
//! compare-and-set, so a run starts once even with several replicas.

use sqlx::Row;
use sqlx::any::AnyRow;

use super::{Db, DbError, new_id, now_ms};

#[derive(Debug, Clone)]
pub struct Schedule {
    pub id: String,
    pub name: String,
    pub cron: String,
    pub paths: Vec<String>,
    pub endpoint_id: Option<i64>,
    pub enabled: bool,
    pub eicar_check: bool,
    pub created_at: i64,
    pub last_run_at: Option<i64>,
    pub last_job_id: Option<String>,
}

pub struct NewSchedule<'a> {
    pub name: &'a str,
    pub cron: &'a str,
    pub paths: &'a [String],
    pub endpoint_id: Option<i64>,
    pub eicar_check: bool,
}

fn from_row(r: &AnyRow) -> Result<Schedule, DbError> {
    let paths: String = r.try_get("paths_json")?;
    Ok(Schedule {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        cron: r.try_get("cron")?,
        paths: serde_json::from_str(&paths).unwrap_or_default(),
        endpoint_id: r.try_get("endpoint_id")?,
        enabled: r.try_get::<i64, _>("enabled")? != 0,
        eicar_check: r.try_get::<i64, _>("eicar_check")? != 0,
        created_at: r.try_get("created_at")?,
        last_run_at: r.try_get("last_run_at")?,
        last_job_id: r.try_get("last_job_id")?,
    })
}

impl Db {
    pub async fn list_schedules(&self) -> Result<Vec<Schedule>, DbError> {
        let rows = sqlx::query(self.sql(
            "SELECT id, name, cron, paths_json, endpoint_id, enabled, eicar_check, created_at, last_run_at, \
             last_job_id FROM scan_schedules ORDER BY name",
        ))
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(from_row).collect()
    }

    pub async fn schedule(&self, id: &str) -> Result<Option<Schedule>, DbError> {
        let row = sqlx::query(self.sql(
            "SELECT id, name, cron, paths_json, endpoint_id, enabled, eicar_check, created_at, last_run_at, \
             last_job_id FROM scan_schedules WHERE id = ?",
        ))
        .bind(id)
        .fetch_optional(self.pool())
        .await?;
        row.as_ref().map(from_row).transpose()
    }

    pub async fn create_schedule(&self, s: NewSchedule<'_>) -> Result<Schedule, DbError> {
        let id = new_id();
        let now = now_ms();
        let paths = serde_json::to_string(s.paths).map_err(|e| DbError::Encode(e.to_string()))?;
        sqlx::query(self.sql(
            "INSERT INTO scan_schedules (id, name, cron, paths_json, exclusions_json, endpoint_id, enabled, \
             max_streams, eicar_check, created_at, updated_at) VALUES (?, ?, ?, ?, '[]', ?, 1, 1, ?, ?, ?)",
        ))
        .bind(&id)
        .bind(s.name)
        .bind(s.cron)
        .bind(paths)
        .bind(s.endpoint_id)
        .bind(i64::from(s.eicar_check))
        .bind(now)
        .bind(now)
        .execute(self.pool())
        .await?;
        self.schedule(&id).await?.ok_or(DbError::Missing)
    }

    pub async fn set_schedule_enabled(&self, id: &str, enabled: bool) -> Result<(), DbError> {
        sqlx::query(self.sql("UPDATE scan_schedules SET enabled = ?, updated_at = ? WHERE id = ?"))
            .bind(i64::from(enabled))
            .bind(now_ms())
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    pub async fn delete_schedule(&self, id: &str) -> Result<bool, DbError> {
        let r = sqlx::query(self.sql("DELETE FROM scan_schedules WHERE id = ?"))
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Claim a run: true only for the caller that moved `last_run_at` from `prev`.
    pub async fn claim_schedule_run(
        &self,
        id: &str,
        prev: Option<i64>,
        now: i64,
    ) -> Result<bool, DbError> {
        let r = match prev {
            Some(p) => {
                sqlx::query(self.sql(
                    "UPDATE scan_schedules SET last_run_at = ? WHERE id = ? AND last_run_at = ?",
                ))
                .bind(now)
                .bind(id)
                .bind(p)
                .execute(self.pool())
                .await?
            }
            None => sqlx::query(self.sql(
                "UPDATE scan_schedules SET last_run_at = ? WHERE id = ? AND last_run_at IS NULL",
            ))
            .bind(now)
            .bind(id)
            .execute(self.pool())
            .await?,
        };
        Ok(r.rows_affected() == 1)
    }

    pub async fn set_schedule_last_job(&self, id: &str, job_id: &str) -> Result<(), DbError> {
        sqlx::query(self.sql("UPDATE scan_schedules SET last_job_id = ? WHERE id = ?"))
            .bind(job_id)
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Jobs of this schedule that have not finished yet.
    pub async fn schedule_active_jobs(&self, id: &str) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar(
            self.sql(
                "SELECT COUNT(*) FROM scan_jobs WHERE schedule_id = ? AND status <> 'FINISHED'",
            ),
        )
        .bind(id)
        .fetch_one(self.pool())
        .await?)
    }

    /// The newest EICAR control job of a schedule, if any.
    pub async fn last_control_job(&self, id: &str) -> Result<Option<super::jobs::Job>, DbError> {
        let job_id: Option<String> = sqlx::query_scalar(self.sql(
            "SELECT id FROM scan_jobs WHERE schedule_id = ? AND kind = 'CONTROL' ORDER BY submitted_at DESC, id DESC LIMIT 1",
        ))
        .bind(id)
        .fetch_optional(self.pool())
        .await?;
        match job_id {
            Some(j) => self.job(&j).await,
            None => Ok(None),
        }
    }
}
