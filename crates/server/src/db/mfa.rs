//! Second factors: TOTP seeds (sealed), recovery codes (hashed) and the
//! short-lived "password ok, code next" step of a sign-in.

use sqlx::Row;

use super::{Db, DbError, now_ms};
use crate::auth::token::{hash_secret, random_secret};

/// A sign-in waiting for its second factor expires after this.
pub const PENDING_TTL_MS: i64 = 5 * 60_000;
/// Wrong codes allowed per pending sign-in.
pub const PENDING_MAX_ATTEMPTS: i64 = 5;

pub struct Totp {
    pub secret: String,
    pub last_step: i64,
    pub created_at: i64,
}

pub struct Pending {
    pub id_hash: String,
    pub user_id: String,
    pub transport: String,
    pub attempts: i64,
}

impl Db {
    pub async fn totp(&self, user_id: &str) -> Result<Option<Totp>, DbError> {
        let row = sqlx::query(
            self.sql("SELECT secret, last_step, created_at FROM user_totp WHERE user_id = ?"),
        )
        .bind(user_id)
        .fetch_optional(self.pool())
        .await?;
        row.map(|r| {
            Ok(Totp {
                secret: r.try_get("secret")?,
                last_step: r.try_get("last_step")?,
                created_at: r.try_get("created_at")?,
            })
        })
        .transpose()
    }

    /// Turn TOTP on with fresh recovery codes (hashes), replacing any old ones.
    pub async fn enable_totp(
        &self,
        user_id: &str,
        sealed: &str,
        step: i64,
        recovery_hashes: &[String],
    ) -> Result<(), DbError> {
        let mut tx = self.pool().begin().await?;
        sqlx::query(self.sql("DELETE FROM user_totp WHERE user_id = ?"))
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(self.sql(
            "INSERT INTO user_totp (user_id, secret, last_step, created_at) VALUES (?, ?, ?, ?)",
        ))
        .bind(user_id)
        .bind(sealed)
        .bind(step)
        .bind(now_ms())
        .execute(&mut *tx)
        .await?;
        sqlx::query(self.sql("DELETE FROM recovery_codes WHERE user_id = ?"))
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        for h in recovery_hashes {
            sqlx::query(self.sql(
                "INSERT INTO recovery_codes (user_id, code_hash, used_at) VALUES (?, ?, NULL)",
            ))
            .bind(user_id)
            .bind(h)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Remove every second factor of a user (TOTP, recovery codes, passkeys).
    pub async fn clear_mfa(&self, user_id: &str) -> Result<(), DbError> {
        let mut tx = self.pool().begin().await?;
        for q in [
            "DELETE FROM user_totp WHERE user_id = ?",
            "DELETE FROM recovery_codes WHERE user_id = ?",
            "DELETE FROM passkeys WHERE user_id = ?",
            "DELETE FROM mfa_pending WHERE user_id = ?",
        ] {
            sqlx::query(self.sql(q))
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Turn TOTP off and drop the recovery codes; passkeys stay.
    pub async fn disable_totp(&self, user_id: &str) -> Result<(), DbError> {
        let mut tx = self.pool().begin().await?;
        for q in [
            "DELETE FROM user_totp WHERE user_id = ?",
            "DELETE FROM recovery_codes WHERE user_id = ?",
        ] {
            sqlx::query(self.sql(q))
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Record `step` as used. False if it (or a later one) was used already: no replays.
    pub async fn use_totp_step(&self, user_id: &str, step: i64) -> Result<bool, DbError> {
        let r = sqlx::query(
            self.sql("UPDATE user_totp SET last_step = ? WHERE user_id = ? AND last_step < ?"),
        )
        .bind(step)
        .bind(user_id)
        .bind(step)
        .execute(self.pool())
        .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn replace_recovery_codes(
        &self,
        user_id: &str,
        hashes: &[String],
    ) -> Result<(), DbError> {
        let mut tx = self.pool().begin().await?;
        sqlx::query(self.sql("DELETE FROM recovery_codes WHERE user_id = ?"))
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        for h in hashes {
            sqlx::query(self.sql(
                "INSERT INTO recovery_codes (user_id, code_hash, used_at) VALUES (?, ?, NULL)",
            ))
            .bind(user_id)
            .bind(h)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Spend a recovery code. True once per code.
    pub async fn use_recovery_code(&self, user_id: &str, hash: &str) -> Result<bool, DbError> {
        let r = sqlx::query(self.sql(
            "UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
        ))
        .bind(now_ms())
        .bind(user_id)
        .bind(hash)
        .execute(self.pool())
        .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn recovery_codes_left(&self, user_id: &str) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar(
            self.sql("SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL"),
        )
        .bind(user_id)
        .fetch_one(self.pool())
        .await?)
    }

    /// Start the second step of a sign-in. Returns the raw cookie value.
    pub async fn create_mfa_pending(
        &self,
        user_id: &str,
        transport: &str,
    ) -> Result<String, DbError> {
        let raw = random_secret();
        sqlx::query(self.sql("DELETE FROM mfa_pending WHERE user_id = ? OR expires_at < ?"))
            .bind(user_id)
            .bind(now_ms())
            .execute(self.pool())
            .await?;
        sqlx::query(self.sql(
            "INSERT INTO mfa_pending (id_hash, user_id, transport, attempts, expires_at) VALUES (?, ?, ?, 0, ?)",
        ))
        .bind(hash_secret(&raw))
        .bind(user_id)
        .bind(transport)
        .bind(now_ms() + PENDING_TTL_MS)
        .execute(self.pool())
        .await?;
        Ok(raw)
    }

    pub async fn mfa_pending(&self, raw: &str) -> Result<Option<Pending>, DbError> {
        let row = sqlx::query(self.sql(
            "SELECT id_hash, user_id, transport, attempts FROM mfa_pending WHERE id_hash = ? AND expires_at > ?",
        ))
        .bind(hash_secret(raw))
        .bind(now_ms())
        .fetch_optional(self.pool())
        .await?;
        row.map(|r| {
            Ok(Pending {
                id_hash: r.try_get("id_hash")?,
                user_id: r.try_get("user_id")?,
                transport: r.try_get("transport")?,
                attempts: r.try_get("attempts")?,
            })
        })
        .transpose()
    }

    /// Count an attempt before checking it. False once the limit is reached.
    pub async fn count_mfa_attempt(&self, id_hash: &str) -> Result<bool, DbError> {
        let r = sqlx::query(self.sql(
            "UPDATE mfa_pending SET attempts = attempts + 1 WHERE id_hash = ? AND attempts < ?",
        ))
        .bind(id_hash)
        .bind(PENDING_MAX_ATTEMPTS)
        .execute(self.pool())
        .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn delete_mfa_pending(&self, id_hash: &str) -> Result<(), DbError> {
        sqlx::query(self.sql("DELETE FROM mfa_pending WHERE id_hash = ?"))
            .bind(id_hash)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Which second factors a user has: (TOTP, passkey count).
    pub async fn mfa_methods(&self, user_id: &str) -> Result<(bool, i64), DbError> {
        let totp = self.totp(user_id).await?.is_some();
        let keys: i64 =
            sqlx::query_scalar(self.sql("SELECT COUNT(*) FROM passkeys WHERE user_id = ?"))
                .bind(user_id)
                .fetch_one(self.pool())
                .await?;
        Ok((totp, keys))
    }
}
