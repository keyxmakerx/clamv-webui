//! clamv-webui library: everything except the process entry point.

// Handlers return axum Responses as errors by design.
#![allow(clippy::result_large_err)]

pub mod agent;
pub mod api;
pub mod app;
pub mod auth;
pub mod config;
pub mod cron;
pub mod db;
pub mod healthcheck;
pub mod logging;
pub mod metrics;
pub mod scan;
pub mod schedule;
pub mod settings;
pub mod timefmt;
pub mod tls;
pub mod watch;
pub mod web;
pub mod webhook;
