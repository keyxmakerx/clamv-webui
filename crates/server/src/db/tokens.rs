//! API tokens. Only the SHA-256 of the secret is stored; the secret is shown once.

use sqlx::Row;
use sqlx::any::AnyRow;

use super::{Db, DbError, now_ms};
use crate::auth::token::{hash_secret, random_secret};

pub const SCOPES: [&str; 6] = [
    "scan:upload",
    "scan:path",
    "jobs:read",
    "endpoints:read",
    "health:read",
    "audit:read",
];

/// Every secret starts with this, so leaked tokens are easy to spot and grep.
pub const SECRET_PREFIX: &str = "cvw_";

#[derive(Debug, Clone)]
pub struct ApiToken {
    pub id: i64,
    pub label: String,
    pub prefix: String,
    pub scopes: Vec<String>,
    /// None: every endpoint.
    pub endpoint_ids: Option<Vec<i64>>,
    /// None: every SCAN_ROOT.
    pub path_roots: Option<Vec<String>>,
    pub created_by: Option<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub last_used_at: Option<i64>,
}

impl ApiToken {
    pub fn has(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    pub fn active(&self, now: i64) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|e| e > now)
    }
}

pub struct NewToken<'a> {
    pub label: &'a str,
    pub scopes: &'a [String],
    pub endpoint_ids: Option<&'a [i64]>,
    pub path_roots: Option<&'a [String]>,
    pub created_by: &'a str,
    pub expires_at: Option<i64>,
}

fn from_row(r: &AnyRow) -> Result<ApiToken, DbError> {
    let scopes: String = r.try_get("scopes")?;
    let eps: Option<String> = r.try_get("endpoint_ids")?;
    let roots: Option<String> = r.try_get("path_roots")?;
    Ok(ApiToken {
        id: r.try_get("id")?,
        label: r.try_get("label")?,
        prefix: r.try_get("prefix")?,
        // Unknown scopes in the database grant nothing.
        scopes: scopes
            .split_whitespace()
            .filter(|s| SCOPES.contains(s))
            .map(str::to_owned)
            .collect(),
        // Unreadable restrictions fail closed: an empty list allows nothing.
        endpoint_ids: eps.map(|s| serde_json::from_str(&s).unwrap_or_default()),
        path_roots: roots.map(|s| serde_json::from_str(&s).unwrap_or_default()),
        created_by: r.try_get("created_by")?,
        created_at: r.try_get("created_at")?,
        expires_at: r.try_get("expires_at")?,
        revoked_at: r.try_get("revoked_at")?,
        last_used_at: r.try_get("last_used_at")?,
    })
}

impl Db {
    /// Returns the one-time secret and the stored token.
    pub async fn create_token(&self, t: NewToken<'_>) -> Result<(String, ApiToken), DbError> {
        let secret = format!("{SECRET_PREFIX}{}", random_secret());
        let hash = hash_secret(&secret);
        let prefix: String = secret.chars().take(12).collect();
        let eps = t
            .endpoint_ids
            .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
        let roots = t
            .path_roots
            .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
        sqlx::query(self.sql(
            "INSERT INTO api_tokens (label, token_hash, prefix, scopes, endpoint_ids, path_roots, created_by, \
             created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ))
        .bind(t.label)
        .bind(&hash)
        .bind(&prefix)
        .bind(t.scopes.join(" "))
        .bind(eps)
        .bind(roots)
        .bind(t.created_by)
        .bind(now_ms())
        .bind(t.expires_at)
        .execute(self.pool())
        .await?;
        let row = sqlx::query(self.sql(
            "SELECT id, label, prefix, scopes, endpoint_ids, path_roots, created_by, created_at, \
             expires_at, revoked_at, last_used_at FROM api_tokens WHERE token_hash = ?",
        ))
        .bind(&hash)
        .fetch_one(self.pool())
        .await?;
        Ok((secret, from_row(&row)?))
    }

    /// The active token for `secret`, touching last_used_at at most once a minute.
    pub async fn token_by_secret(&self, secret: &str) -> Result<Option<ApiToken>, DbError> {
        if !secret.starts_with(SECRET_PREFIX) || secret.len() > 128 {
            return Ok(None);
        }
        let row = sqlx::query(self.sql(
            "SELECT id, label, prefix, scopes, endpoint_ids, path_roots, created_by, created_at, \
             expires_at, revoked_at, last_used_at FROM api_tokens WHERE token_hash = ?",
        ))
        .bind(hash_secret(secret))
        .fetch_optional(self.pool())
        .await?;
        let Some(t) = row.as_ref().map(from_row).transpose()? else {
            return Ok(None);
        };
        let now = now_ms();
        if !t.active(now) {
            return Ok(None);
        }
        if t.last_used_at.is_none_or(|u| now - u > 60_000) {
            sqlx::query(self.sql("UPDATE api_tokens SET last_used_at = ? WHERE id = ?"))
                .bind(now)
                .bind(t.id)
                .execute(self.pool())
                .await?;
        }
        Ok(Some(t))
    }

    pub async fn list_tokens(&self) -> Result<Vec<ApiToken>, DbError> {
        let rows = sqlx::query(self.sql(
            "SELECT id, label, prefix, scopes, endpoint_ids, path_roots, created_by, created_at, \
             expires_at, revoked_at, last_used_at FROM api_tokens ORDER BY id DESC",
        ))
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(from_row).collect()
    }

    /// True if an active token was revoked.
    pub async fn revoke_token(&self, id: i64) -> Result<bool, DbError> {
        let r = sqlx::query(
            self.sql("UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL"),
        )
        .bind(now_ms())
        .bind(id)
        .execute(self.pool())
        .await?;
        Ok(r.rows_affected() == 1)
    }
}
