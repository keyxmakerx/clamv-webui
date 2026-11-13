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
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }
}
