//! Logging: plain or JSON lines on stdout, never ANSI colours (S11).

use tracing_subscriber::EnvFilter;

use crate::config::{Config, LogFormat};

pub fn init(cfg: &Config) {
    let filter = EnvFilter::try_new(&cfg.log_level).unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_target(true);
    match cfg.log_format {
        LogFormat::Json => builder.json().flatten_event(true).init(),
        LogFormat::Plain => builder.init(),
    }
}
