//! Canary files managed from the UI, per host (`agent_id` NULL is this server).

use sqlx::Row;
use sqlx::any::AnyRow;

use super::{Db, DbError, new_id, now_ms};

/// Most canaries one host may have.
pub const MAX_PER_HOST: usize = 50;

#[derive(Debug, Clone)]
pub struct Canary {
    pub id: String,
    pub agent_id: Option<i64>,
    pub path: String,
    pub create_file: bool,
    /// None until the host has reported.
    pub armed: Option<bool>,
    pub checked_at: Option<i64>,
    pub last_tripped_at: Option<i64>,
    pub created_at: i64,
    pub created_by: Option<String>,
}

fn from_row(r: &AnyRow) -> Result<Canary, DbError> {
    Ok(Canary {
        id: r.try_get("id")?,
        agent_id: r.try_get("agent_id")?,
        path: r.try_get("path")?,
        create_file: r.try_get::<i64, _>("create_file")? != 0,
        armed: r.try_get::<Option<i64>, _>("armed")?.map(|v| v != 0),
        checked_at: r.try_get("checked_at")?,
        last_tripped_at: r.try_get("last_tripped_at")?,
        created_at: r.try_get("created_at")?,
        created_by: r.try_get("created_by")?,
    })
}

impl Db {
    pub async fn list_canaries(&self) -> Result<Vec<Canary>, DbError> {
        let rows = sqlx::query(self.sql(
            "SELECT id, agent_id, path, create_file, armed, checked_at, last_tripped_at, created_at, created_by \
             FROM canaries ORDER BY agent_id, path",
        ))
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(from_row).collect()
    }

    /// Canaries of one host; `None` is this server.
    pub async fn host_canaries(&self, agent_id: Option<i64>) -> Result<Vec<Canary>, DbError> {
        let rows = match agent_id {
            Some(a) => {
                sqlx::query(self.sql(
                    "SELECT id, agent_id, path, create_file, armed, checked_at, last_tripped_at, created_at, created_by \
                     FROM canaries WHERE agent_id = ? ORDER BY path",
                ))
                .bind(a)
                .fetch_all(self.pool())
                .await?
            }
            None => {
                sqlx::query(self.sql(
                    "SELECT id, agent_id, path, create_file, armed, checked_at, last_tripped_at, created_at, created_by \
                     FROM canaries WHERE agent_id IS NULL ORDER BY path",
                ))
                .fetch_all(self.pool())
                .await?
            }
        };
        rows.iter().map(from_row).collect()
    }

    pub async fn add_canary(
        &self,
        agent_id: Option<i64>,
        path: &str,
        create_file: bool,
        by: &str,
    ) -> Result<String, DbError> {
        let id = new_id();
        sqlx::query(self.sql(
            "INSERT INTO canaries (id, agent_id, path, create_file, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)",
        ))
        .bind(&id)
        .bind(agent_id)
        .bind(path)
        .bind(i64::from(create_file))
        .bind(now_ms())
        .bind(by)
        .execute(self.pool())
        .await?;
        Ok(id)
    }

    pub async fn canary(&self, id: &str) -> Result<Option<Canary>, DbError> {
        let row = sqlx::query(self.sql(
            "SELECT id, agent_id, path, create_file, armed, checked_at, last_tripped_at, created_at, created_by \
             FROM canaries WHERE id = ?",
        ))
        .bind(id)
        .fetch_optional(self.pool())
        .await?;
        row.as_ref().map(from_row).transpose()
    }

    pub async fn delete_canary(&self, id: &str) -> Result<bool, DbError> {
        let r = sqlx::query(self.sql("DELETE FROM canaries WHERE id = ?"))
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Whether the host could watch it, as last reported.
    pub async fn set_canary_armed(
        &self,
        agent_id: Option<i64>,
        path: &str,
        armed: bool,
    ) -> Result<(), DbError> {
        let q = match agent_id {
            Some(_) => {
                "UPDATE canaries SET armed = ?, checked_at = ? WHERE agent_id = ? AND path = ?"
            }
            None => {
                "UPDATE canaries SET armed = ?, checked_at = ? WHERE agent_id IS NULL AND path = ?"
            }
        };
        let mut s = sqlx::query(self.sql(q))
            .bind(i64::from(armed))
            .bind(now_ms());
        if let Some(a) = agent_id {
            s = s.bind(a);
        }
        s.bind(path).execute(self.pool()).await?;
        Ok(())
    }

    pub async fn canary_tripped(&self, agent_id: Option<i64>, path: &str) -> Result<(), DbError> {
        let q = match agent_id {
            Some(_) => "UPDATE canaries SET last_tripped_at = ? WHERE agent_id = ? AND path = ?",
            None => "UPDATE canaries SET last_tripped_at = ? WHERE agent_id IS NULL AND path = ?",
        };
        let mut s = sqlx::query(self.sql(q)).bind(now_ms());
        if let Some(a) = agent_id {
            s = s.bind(a);
        }
        s.bind(path).execute(self.pool()).await?;
        Ok(())
    }
}
