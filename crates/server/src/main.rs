//! clamv-webui: web UI for ClamAV clamd.

use std::process::ExitCode;

use clap::Parser;

use clamv_webui::config::{Cli, Command};
use clamv_webui::{app, healthcheck, logging};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve) {
        Command::Healthcheck => healthcheck::run(&cli.config).await,
        Command::ResetAdmin => {
            logging::init(&cli.config);
            match app::reset_admin(&cli.config).await {
                Ok(file) => {
                    println!("New admin password written to {}", file.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    tracing::error!(error = %e, "reset-admin failed");
                    ExitCode::FAILURE
                }
            }
        }
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
