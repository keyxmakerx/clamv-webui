//! Runtime configuration from flags and environment variables.

use std::net::SocketAddr;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    #[command(flatten)]
    pub config: Config,
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub enum Command {
    /// Run the web server (default).
    Serve,
    /// Probe /healthz on the local listener; for container HEALTHCHECK.
    Healthcheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Plain,
    Json,
}

#[derive(Debug, Clone, Args)]
pub struct Config {
    /// Listen address.
    #[arg(
        long,
        env = "LISTEN_ADDR",
        default_value = "0.0.0.0:8080",
        global = true
    )]
    pub listen: SocketAddr,

    /// Log filter, e.g. `info` or `info,clamv_webui=debug`.
    #[arg(long, env = "LOG_LEVEL", default_value = "info", global = true)]
    pub log_level: String,

    /// Log line format.
    #[arg(
        long,
        env = "LOG_FORMAT",
        value_enum,
        default_value = "plain",
        global = true
    )]
    pub log_format: LogFormat,

    /// Writable state directory (database, keys).
    #[arg(long, env = "DATA_DIR", default_value = "./data", global = true)]
    pub data_dir: std::path::PathBuf,

    /// Database URL: sqlite://, postgres://, mysql:// or mariadb://. Defaults to SQLite in DATA_DIR.
    #[arg(long, env = "DATABASE_URL", hide_env_values = true, global = true)]
    pub database_url: Option<String>,

    /// File holding the database URL (Docker secret). Wins over DATABASE_URL.
    #[arg(long, env = "DATABASE_URL_FILE", global = true)]
    pub database_url_file: Option<std::path::PathBuf>,

    /// Maximum database connections.
    #[arg(
        long,
        env = "DATABASE_MAX_CONNECTIONS",
        default_value_t = 10,
        global = true
    )]
    pub database_max_connections: u32,

    /// Default clamd endpoint: tcp://host:port or unix:///path.
    #[arg(
        long,
        env = "CLAMD_ENDPOINT",
        default_value = "tcp://clamav:3310",
        global = true
    )]
    pub clamd_endpoint: clamd::Endpoint,

    /// Per-request timeout for UI and API calls, in seconds.
    #[arg(
        long,
        env = "REQUEST_TIMEOUT_SECS",
        default_value_t = 60,
        global = true
    )]
    pub request_timeout_secs: u64,
}

impl Config {
    /// Resolve the database URL without ever logging it.
    pub fn database_url(&self) -> anyhow::Result<String> {
        if let Some(path) = &self.database_url_file {
            let raw = std::fs::read_to_string(path).map_err(|e| {
                anyhow::anyhow!("cannot read DATABASE_URL_FILE {}: {e}", path.display())
            })?;
            return Ok(raw.trim().to_owned());
        }
        if let Some(url) = &self.database_url {
            return Ok(url.clone());
        }
        Ok(format!(
            "sqlite://{}",
            self.data_dir.join("clamv-webui.db").display()
        ))
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }
}
