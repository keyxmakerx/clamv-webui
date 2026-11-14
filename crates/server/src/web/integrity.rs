//! AIDE and rkhunter runs from every host.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;

use super::admin::fmt_ts;
use super::session::Auth;
use super::{Nav, render};
use crate::app::AppState;
use crate::auth::Role;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/integrity", get(page))
}

pub struct Run {
    host: String,
    tool: String,
    ran: String,
    ok: bool,
    summary: String,
    findings: Vec<String>,
}

#[derive(Template)]
#[template(path = "integrity.html")]
struct IntegrityPage {
    nav: Nav,
    runs: Vec<Run>,
    aide: String,
    rkhunter: String,
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Operator) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let agents = st.db.list_agents().await.unwrap_or_default();
    let server = crate::canary::hostname();
    let runs = st
        .db
        .recent_integrity(100)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| Run {
            host: r.agent_id.map_or_else(
                || server.clone(),
                |id| {
                    agents
                        .iter()
                        .find(|a| a.id == id)
                        .map_or_else(|| format!("agent {id}"), |a| a.name.clone())
                },
            ),
            tool: r.report.tool,
            ran: fmt_ts(r.report.ran_at),
            ok: r.report.ok,
            summary: r.report.summary,
            findings: r.report.findings,
        })
        .collect();
    render(
        axum::http::StatusCode::OK,
        &IntegrityPage {
            nav: Nav::new("integrity", &s, &u),
            runs,
            aide: st.cfg.aide_log.display().to_string(),
            rkhunter: st.cfg.rkhunter_log.display().to_string(),
        },
    )
}
