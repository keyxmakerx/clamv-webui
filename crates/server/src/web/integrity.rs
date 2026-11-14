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

pub struct FalcoRow {
    at: String,
    host: String,
    priority: String,
    loud: bool,
    rule: String,
    container: String,
    output: String,
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
    falco: Vec<FalcoRow>,
    falco_path: String,
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
    let host_name = |id: Option<i64>| {
        id.map_or_else(
            || server.clone(),
            |id| {
                agents
                    .iter()
                    .find(|a| a.id == id)
                    .map_or_else(|| format!("agent {id}"), |a| a.name.clone())
            },
        )
    };
    let falco = st
        .db
        .falco_since(crate::db::now_ms() - 30 * 86_400_000, 200)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|s| FalcoRow {
            at: fmt_ts(s.alert.at),
            host: host_name(s.agent_id),
            loud: crate::falco::rank(&s.alert.priority) >= crate::falco::rank("error"),
            priority: s.alert.priority,
            rule: s.alert.rule,
            container: s.alert.container.unwrap_or_default(),
            output: s.alert.output,
        })
        .collect();
    render(
        axum::http::StatusCode::OK,
        &IntegrityPage {
            nav: Nav::new("integrity", &s, &u),
            runs,
            aide: st.cfg.aide_log.display().to_string(),
            rkhunter: st.cfg.rkhunter_log.display().to_string(),
            falco,
            falco_path: st.cfg.falco_events.display().to_string(),
        },
    )
}
