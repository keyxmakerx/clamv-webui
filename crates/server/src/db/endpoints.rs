//! clamd endpoints. Exactly one enabled endpoint is the default.

use sqlx::Row;
use sqlx::any::AnyRow;

use super::{Db, DbError, now_ms};

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub id: i64,
    pub name: String,
    pub address: String,
    pub enabled: bool,
    pub is_default: bool,
}

impl Endpoint {
    pub fn parsed(&self) -> Result<clamd::Endpoint, clamd::Error> {
        self.address.parse()
    }
}

fn from_row(r: &AnyRow) -> Result<Endpoint, DbError> {
    Ok(Endpoint {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        address: r.try_get("address")?,
        enabled: r.try_get::<i64, _>("enabled")? != 0,
        is_default: r.try_get::<i64, _>("is_default")? != 0,
    })
}

impl Db {
    pub async fn list_endpoints(&self) -> Result<Vec<Endpoint>, DbError> {
        let rows = sqlx::query(self.sql(
            "SELECT id, name, address, enabled, is_default FROM endpoints ORDER BY is_default DESC, name",
        ))
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(from_row).collect()
    }

    pub async fn endpoint(&self, id: i64) -> Result<Option<Endpoint>, DbError> {
        let row = sqlx::query(
            self.sql("SELECT id, name, address, enabled, is_default FROM endpoints WHERE id = ?"),
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await?;
        row.as_ref().map(from_row).transpose()
    }

    pub async fn default_endpoint(&self) -> Result<Option<Endpoint>, DbError> {
        let row = sqlx::query(self.sql(
            "SELECT id, name, address, enabled, is_default FROM endpoints WHERE is_default = 1 AND enabled = 1",
        ))
        .fetch_optional(self.pool())
        .await?;
        row.as_ref().map(from_row).transpose()
    }

    pub async fn create_endpoint(
        &self,
        name: &str,
        address: &str,
        make_default: bool,
    ) -> Result<Endpoint, DbError> {
        let mut tx = self.pool().begin().await?;
        let none_yet: i64 =
            sqlx::query_scalar(self.sql("SELECT COUNT(*) FROM endpoints WHERE is_default = 1"))
                .fetch_one(&mut *tx)
                .await?;
        let is_default = make_default || none_yet == 0;
        if is_default {
            sqlx::query(self.sql("UPDATE endpoints SET is_default = 0"))
                .execute(&mut *tx)
                .await?;
        }
        // Integer ids keep /api/v1 compatible with clamctl.
        let id: i64 =
            sqlx::query_scalar(self.sql("SELECT COALESCE(MAX(id), 0) + 1 FROM endpoints"))
                .fetch_one(&mut *tx)
                .await?;
        let e = Endpoint {
            id,
            name: name.to_owned(),
            address: address.to_owned(),
            enabled: true,
            is_default,
        };
        sqlx::query(self.sql(
            "INSERT INTO endpoints (id, name, address, enabled, is_default, created_at) VALUES (?, ?, ?, 1, ?, ?)",
        ))
        .bind(e.id)
        .bind(&e.name)
        .bind(&e.address)
        .bind(i64::from(is_default))
        .bind(now_ms())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(e)
    }

    pub async fn set_default_endpoint(&self, id: i64) -> Result<(), DbError> {
        let mut tx = self.pool().begin().await?;
        sqlx::query(self.sql("UPDATE endpoints SET is_default = 0"))
            .execute(&mut *tx)
            .await?;
        sqlx::query(self.sql("UPDATE endpoints SET is_default = 1, enabled = 1 WHERE id = ?"))
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn set_endpoint_enabled(&self, id: i64, enabled: bool) -> Result<(), DbError> {
        sqlx::query(self.sql("UPDATE endpoints SET enabled = ? WHERE id = ? AND is_default = 0"))
            .bind(i64::from(enabled))
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// The default endpoint cannot be deleted; pick another default first.
    pub async fn delete_endpoint(&self, id: i64) -> Result<bool, DbError> {
        let r = sqlx::query(self.sql("DELETE FROM endpoints WHERE id = ? AND is_default = 0"))
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(r.rows_affected() > 0)
    }
}
