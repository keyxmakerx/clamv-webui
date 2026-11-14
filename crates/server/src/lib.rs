//! clamv-webui library: everything except the process entry point.

// Handlers return axum Responses as errors by design.
#![allow(clippy::result_large_err)]

/// This build's version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod agent;
pub mod api;
pub mod app;
pub mod auth;
pub mod canary;
pub mod clamdconf;
pub mod config;
pub mod cron;
pub mod db;
pub mod falco;
pub mod fsevents;
pub mod healthcheck;
pub mod integrity;
pub mod logging;
pub mod metrics;
pub mod scan;
pub mod schedule;
pub mod settings;
pub mod timefmt;
pub mod timeline;
pub mod tls;
pub mod update;
pub mod watch;
pub mod web;
pub mod webhook;
