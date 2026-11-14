//! Passkeys (WebAuthn credentials) and their one-time challenges.

use sqlx::Row;
use sqlx::any::AnyRow;

use super::{Db, DbError, new_id, now_ms};
use crate::auth::token::{hash_secret, random_secret};

/// A challenge must be answered within this long.
pub const CHALLENGE_TTL_MS: i64 = 5 * 60_000;
pub const MAX_PASSKEYS: i64 = 10;

#[derive(Debug, Clone)]
pub struct Passkey {
    pub id: String,
    pub user_id: String,
    pub cred_id: String,
    pub name: String,
    pub public_key: String,
    pub sign_count: i64,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

fn from_row(r: &AnyRow) -> Result<Passkey, DbError> {
    Ok(Passkey {
        id: r.try_get("id")?,
        user_id: r.try_get("user_id")?,
        cred_id: r.try_get("cred_id")?,
        name: r.try_get("name")?,
        public_key: r.try_get("public_key")?,
        sign_count: r.try_get("sign_count")?,
        created_at: r.try_get("created_at")?,
        last_used_at: r.try_get("last_used_at")?,
    })
}

pub struct Challenge {
    pub purpose: String,
    pub user_id: Option<String>,
    pub challenge: String,
}

impl Db {
    pub async fn list_passkeys(&self, user_id: &str) -> Result<Vec<Passkey>, DbError> {
        let rows = sqlx::query(self.sql(
            "SELECT id, user_id, cred_id, name, public_key, sign_count, created_at, last_used_at \
             FROM passkeys WHERE user_id = ? ORDER BY created_at",
        ))
        .bind(user_id)
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(from_row).collect()
    }

    pub async fn passkey_by_cred(&self, cred_id: &str) -> Result<Option<Passkey>, DbError> {
        let row = sqlx::query(self.sql(
            "SELECT id, user_id, cred_id, name, public_key, sign_count, created_at, last_used_at \
             FROM passkeys WHERE cred_id = ?",
        ))
        .bind(cred_id)
        .fetch_optional(self.pool())
        .await?;
        row.as_ref().map(from_row).transpose()
    }

    pub async fn add_passkey(
        &self,
        user_id: &str,
        cred_id: &str,
        name: &str,
        public_key: &str,
        sign_count: i64,
    ) -> Result<(), DbError> {
        sqlx::query(self.sql(
            "INSERT INTO passkeys (id, user_id, cred_id, name, public_key, sign_count, created_at, last_used_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
        ))
        .bind(new_id())
        .bind(user_id)
        .bind(cred_id)
        .bind(name)
        .bind(public_key)
        .bind(sign_count)
        .bind(now_ms())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Record a use. False when the counter went backwards (a cloned key).
    pub async fn use_passkey(&self, id: &str, old: i64, new: i64) -> Result<bool, DbError> {
        if old > 0 && new <= old {
            return Ok(false);
        }
        let r = sqlx::query(self.sql(
            "UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ? AND sign_count = ?",
        ))
        .bind(new)
        .bind(now_ms())
        .bind(id)
        .bind(old)
        .execute(self.pool())
        .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn delete_passkey(&self, user_id: &str, id: &str) -> Result<bool, DbError> {
        let r = sqlx::query(self.sql("DELETE FROM passkeys WHERE id = ? AND user_id = ?"))
            .bind(id)
            .bind(user_id)
            .execute(self.pool())
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Store a challenge; returns (handle, challenge). The handle goes back with the answer.
    pub async fn create_challenge(
        &self,
        purpose: &str,
        user_id: Option<&str>,
    ) -> Result<(String, String), DbError> {
        let handle = random_secret();
        let challenge = random_secret();
        sqlx::query(self.sql("DELETE FROM webauthn_challenges WHERE expires_at < ?"))
            .bind(now_ms())
            .execute(self.pool())
            .await?;
        sqlx::query(self.sql(
            "INSERT INTO webauthn_challenges (id_hash, purpose, user_id, challenge, expires_at) VALUES (?, ?, ?, ?, ?)",
        ))
        .bind(hash_secret(&handle))
        .bind(purpose)
        .bind(user_id)
        .bind(&challenge)
        .bind(now_ms() + CHALLENGE_TTL_MS)
        .execute(self.pool())
        .await?;
        Ok((handle, challenge))
    }

    /// Take a challenge: it works once.
    pub async fn take_challenge(&self, handle: &str) -> Result<Option<Challenge>, DbError> {
        let h = hash_secret(handle);
        let row = sqlx::query(self.sql(
            "SELECT purpose, user_id, challenge FROM webauthn_challenges WHERE id_hash = ? AND expires_at > ?",
        ))
        .bind(&h)
        .bind(now_ms())
        .fetch_optional(self.pool())
        .await?;
        let r = sqlx::query(self.sql("DELETE FROM webauthn_challenges WHERE id_hash = ?"))
            .bind(&h)
            .execute(self.pool())
            .await?;
        if r.rows_affected() != 1 {
            return Ok(None);
        }
        row.map(|r| {
            Ok(Challenge {
                purpose: r.try_get("purpose")?,
                user_id: r.try_get("user_id")?,
                challenge: r.try_get("challenge")?,
            })
        })
        .transpose()
    }
}
