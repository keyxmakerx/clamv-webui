//! palisade: web UI for ClamAV clamd.

use std::process::ExitCode;

use clap::Parser;

use palisade::config::{Cli, Command};
use palisade::{app, healthcheck, logging};

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
                    println!(
                        "With Docker, copy it to the host without printing it: docker compose cp palisade:{} ./admin-password",
                        file.display()
                    );
                    println!(
                        "Sign-in locks are kept in memory: restart the server to clear one now."
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    tracing::error!(error = %format_args!("{e:#}"), "reset-admin failed");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Agent => {
            logging::init(&cli.config);
            match palisade::agent::client::run(cli.config).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    tracing::error!(error = %format_args!("{e:#}"), "agent failed");
                    ExitCode::FAILURE
                }
            }
        }
        Command::HostSetup(h) => match palisade::hostsetup::run(&h).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("host-setup failed: {e:#}");
                ExitCode::FAILURE
            }
        },
        Command::Serve => {
            logging::init(&cli.config);
            match app::serve(cli.config).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    // The message names the setting and the fix; see app::preflight.
                    tracing::error!(error = %format_args!("{e:#}"), "cannot start");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
