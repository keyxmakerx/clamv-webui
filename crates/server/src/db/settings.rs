//! Key/value application settings (Configuration Center values).

use super::{Db, DbError, Kind, now_ms};

impl Db {
    pub async fn setting(&self, name: &str) -> Result<Option<String>, DbError> {
        let v =
            sqlx::query_scalar::<_, String>(self.sql("SELECT value FROM settings WHERE name = ?"))
                .bind(name)
                .fetch_optional(self.pool())
                .await?;
        Ok(v)
    }

    pub async fn set_setting(
        &self,
        name: &str,
        value: &str,
        by: Option<&str>,
    ) -> Result<(), DbError> {
        let q = match self.kind() {
            Kind::Sqlite | Kind::Postgres => {
                "INSERT INTO settings (name, value, updated_at, updated_by) VALUES (?, ?, ?, ?) \
                 ON CONFLICT (name) DO UPDATE SET value = excluded.value, \
                 updated_at = excluded.updated_at, updated_by = excluded.updated_by"
            }
            Kind::MySql => {
                "INSERT INTO settings (name, value, updated_at, updated_by) VALUES (?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE value = VALUES(value), \
                 updated_at = VALUES(updated_at), updated_by = VALUES(updated_by)"
            }
        };
        sqlx::query(self.sql(q))
            .bind(name)
            .bind(value)
            .bind(now_ms())
            .bind(by)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    pub async fn delete_setting(&self, name: &str) -> Result<bool, DbError> {
        let r = sqlx::query(self.sql("DELETE FROM settings WHERE name = ?"))
            .bind(name)
            .execute(self.pool())
            .await?;
        Ok(r.rows_affected() > 0)
    }
}
