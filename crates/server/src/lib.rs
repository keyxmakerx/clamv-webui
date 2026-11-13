//! clamv-webui library: everything except the process entry point.

// Handlers return axum Responses as errors by design.
#![allow(clippy::result_large_err)]

pub mod app;
pub mod auth;
pub mod config;
pub mod db;
pub mod healthcheck;
pub mod logging;
pub mod web;
