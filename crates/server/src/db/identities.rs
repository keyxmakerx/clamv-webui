//! Links from an external identity (issuer + subject) to a local user row.

use super::{Db, DbError, now_ms};

impl Db {
    /// The user id linked to this principal, touching its last-seen time.
    pub async fn identity_user(&self, principal: &str) -> Result<Option<String>, DbError> {
        let id: Option<String> = sqlx::query_scalar(
            self.sql("SELECT user_id FROM external_identities WHERE principal_name = ?"),
        )
        .bind(principal)
        .fetch_optional(self.pool())
        .await?;
        if id.is_some() {
            sqlx::query(
                self.sql(
                    "UPDATE external_identities SET last_seen_at = ? WHERE principal_name = ?",
                ),
            )
            .bind(now_ms())
            .bind(principal)
            .execute(self.pool())
            .await?;
        }
        Ok(id)
    }

    pub async fn link_identity(
        &self,
        principal: &str,
        user_id: &str,
        source: &str,
        issuer: &str,
        subject: &str,
    ) -> Result<(), DbError> {
        let now = now_ms();
        sqlx::query(self.sql(
            "INSERT INTO external_identities (principal_name, user_id, source, issuer, subject, first_seen_at, last_seen_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        ))
        .bind(principal)
        .bind(user_id)
        .bind(source)
        .bind(issuer)
        .bind(subject)
        .bind(now)
        .bind(now)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// True when the user signs in through an external provider.
    pub async fn is_external_user(&self, user_id: &str) -> Result<bool, DbError> {
        let n: i64 = sqlx::query_scalar(
            self.sql("SELECT COUNT(*) FROM external_identities WHERE user_id = ?"),
        )
        .bind(user_id)
        .fetch_one(self.pool())
        .await?;
        Ok(n > 0)
    }
}
