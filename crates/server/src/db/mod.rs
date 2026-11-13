//! Database access for SQLite, PostgreSQL, MySQL and MariaDB.
//!
//! One `AnyPool` and portable SQL: queries use `?` placeholders (rewritten to
//! `$n` for PostgreSQL), ids are UUIDv7 text, times are unix milliseconds and
//! booleans are 0/1 integers, so every column decodes the same on every backend.

pub mod audit;
pub mod endpoints;
pub mod sessions;
pub mod settings;
pub mod users;

use std::borrow::Cow;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::any::{AnyPoolOptions, install_default_drivers};
use sqlx::migrate::Migrator;
use sqlx::{AnyPool, AssertSqlSafe, Executor};

static MIGRATE_SQLITE: Migrator = sqlx::migrate!("./migrations/sqlite");
static MIGRATE_POSTGRES: Migrator = sqlx::migrate!("./migrations/postgres");
static MIGRATE_MYSQL: Migrator = sqlx::migrate!("./migrations/mysql");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Sqlite,
    Postgres,
    /// MySQL and MariaDB share a driver and migrations.
    MySql,
}

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("unsupported database URL; use sqlite:, postgres:, mysql: or mariadb:")]
    UnsupportedUrl,
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

#[derive(Debug, Clone)]
pub struct Db {
    pool: AnyPool,
    kind: Kind,
}

impl Db {
    /// Connect and run pending migrations.
    pub async fn open(url: &str, max_connections: u32) -> Result<Self, DbError> {
        let db = Self::connect(url, max_connections).await?;
        db.migrate().await?;
        Ok(db)
    }

    pub async fn connect(url: &str, max_connections: u32) -> Result<Self, DbError> {
        install_default_drivers();
        let (kind, url) = normalise_url(url)?;
        let mut opts = AnyPoolOptions::new()
            .max_connections(if kind == Kind::Sqlite {
                1.max(max_connections.min(4))
            } else {
                max_connections
            })
            .acquire_timeout(Duration::from_secs(10));
        if kind == Kind::Sqlite {
            opts = opts.after_connect(|conn, _| {
                Box::pin(async move {
                    conn.execute("PRAGMA foreign_keys = ON").await?;
                    conn.execute("PRAGMA busy_timeout = 5000").await?;
                    conn.execute("PRAGMA journal_mode = WAL").await?;
                    Ok(())
                })
            });
        }
        let pool = opts.connect(&url).await?;
        Ok(Self { pool, kind })
    }

    pub async fn migrate(&self) -> Result<(), DbError> {
        let m = match self.kind {
            Kind::Sqlite => &MIGRATE_SQLITE,
            Kind::Postgres => &MIGRATE_POSTGRES,
            Kind::MySql => &MIGRATE_MYSQL,
        };
        // A second instance starting at the same moment can race on the
        // bookkeeping table (seen on MariaDB); the retry then sees it applied.
        if let Err(first) = m.run(&self.pool).await {
            tracing::warn!(error = %first, "migration failed, retrying once");
            tokio::time::sleep(Duration::from_secs(2)).await;
            m.run(&self.pool).await?;
        }
        Ok(())
    }

    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Adapt a `?`-placeholder query to this backend. Only string literals
    /// are accepted, so user input can never become SQL.
    pub fn sql(&self, query: &'static str) -> AssertSqlSafe<Cow<'static, str>> {
        if self.kind != Kind::Postgres || !query.contains('?') {
            return AssertSqlSafe(Cow::Borrowed(query));
        }
        AssertSqlSafe(Cow::Owned(dollar_placeholders(query)))
    }

    pub async fn ping(&self) -> Result<(), DbError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// `?` → `$1`, `$2`, … outside single-quoted literals.
fn dollar_placeholders(query: &str) -> String {
    let mut out = String::with_capacity(query.len() + 8);
    let mut n = 0;
    let mut in_str = false;
    for c in query.chars() {
        match c {
            '\'' => {
                in_str = !in_str;
                out.push(c);
            }
            '?' if !in_str => {
                n += 1;
                out.push('$');
                out.push_str(&n.to_string());
            }
            _ => out.push(c),
        }
    }
    out
}

fn normalise_url(url: &str) -> Result<(Kind, String), DbError> {
    let scheme = url
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match scheme.as_str() {
        "sqlite" => {
            let mut u = url.to_owned();
            if !u.contains("mode=") && !u.contains(":memory:") {
                u.push(if u.contains('?') { '&' } else { '?' });
                u.push_str("mode=rwc");
            }
            Ok((Kind::Sqlite, u))
        }
        "postgres" | "postgresql" => Ok((Kind::Postgres, url.to_owned())),
        "mysql" => Ok((Kind::MySql, url.to_owned())),
        "mariadb" => Ok((Kind::MySql, format!("mysql{}", &url["mariadb".len()..]))),
        _ => Err(DbError::UnsupportedUrl),
    }
}

/// Scheme and host only, safe to log (never the password).
pub fn redact_url(url: &str) -> String {
    let scheme = url.split(':').next().unwrap_or("?");
    let host = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .map(|rest| rest.rsplit_once('@').map_or(rest, |(_, h)| h))
        .map(|rest| rest.split(['/', '?']).next().unwrap_or_default())
        .unwrap_or_default();
    if scheme.eq_ignore_ascii_case("sqlite") {
        "sqlite".to_owned()
    } else {
        format!("{scheme}://{host}")
    }
}

pub fn new_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_placeholders_for_postgres_only() {
        assert_eq!(
            dollar_placeholders("SELECT a FROM t WHERE x = ? AND y = '?' AND z = ?"),
            "SELECT a FROM t WHERE x = $1 AND y = '?' AND z = $2"
        );
    }

    #[test]
    fn redacts_credentials() {
        assert_eq!(
            redact_url("postgres://u:secret@db:5432/app?sslmode=require"),
            "postgres://db:5432"
        );
        assert_eq!(redact_url("mysql://root:pw@mysql/app"), "mysql://mysql");
        assert_eq!(redact_url("sqlite:///app/data/x.db"), "sqlite");
        assert!(!redact_url("mariadb://a:p%40ss@h/db").contains("p%40ss"));
    }

    #[test]
    fn normalises_urls() {
        assert_eq!(
            normalise_url("mariadb://h/db").ok().map(|x| x.1),
            Some("mysql://h/db".to_owned())
        );
        assert_eq!(
            normalise_url("sqlite://data/x.db").ok().map(|x| x.1),
            Some("sqlite://data/x.db?mode=rwc".to_owned())
        );
        assert!(normalise_url("h2:file:x").is_err());
    }
}
