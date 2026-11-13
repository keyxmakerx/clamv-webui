//! clamv-webui: web UI for ClamAV clamd.

mod app;
mod config;
mod healthcheck;
mod logging;

use std::process::ExitCode;

use clap::Parser;

use crate::config::{Cli, Command};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve) {
        Command::Healthcheck => healthcheck::run(&cli.config).await,
        Command::Serve => {
            logging::init(&cli.config);
            match app::serve(cli.config).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    tracing::error!(error = %e, "fatal");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
