//! AIDE and rkhunter runs from every host.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Form, State};
use axum::response::Response;
use axum::routing::{get, post};
use serde::Deserialize;

use super::admin::{admin_post, audit, fmt_ts};
use super::session::Auth;
use super::{Nav, RequestInfo, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::db::users::User;
use crate::hostchecks::Action;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/integrity", get(page))
        .route("/integrity/run", post(run))
}

/// "" is this server, otherwise an enabled agent's id.
pub(super) async fn parse_host(st: &AppState, raw: &str) -> Result<Option<i64>, String> {
    match raw.trim() {
        "" => Ok(None),
        v => {
            let id: i64 = v.parse().map_err(|_| "Unknown host.".to_owned())?;
            match st.db.agent(id).await {
                Ok(Some(a)) if a.enabled => Ok(Some(id)),
                Ok(Some(_)) => Err("That agent is disabled.".into()),
                _ => Err("Unknown host.".into()),
            }
        }
    }
}

/// Start an allow-listed host check on a host. `confirmed` means a passkey was just used.
pub(super) async fn dispatch(
    st: &Arc<AppState>,
    me: &User,
    info: &RequestInfo,
    host: Option<i64>,
    act: &'static Action,
    confirmed: bool,
) -> Result<String, String> {
    if act.passkey && !confirmed {
        return Err(format!("{} needs your passkey.", act.label));
    }
    let name = match host {
        None => crate::canary::hostname(),
        Some(id) => st
            .db
            .agent(id)
            .await
            .ok()
            .flatten()
            .map_or_else(|| format!("agent {id}"), |a| a.name),
    };
    match host {
        None => {
            crate::hostchecks::run_here(st, act, &me.username)
                .await
                .map_err(|_| "Service unavailable.".to_owned())?;
        }
        Some(id) => {
            st.db
                .create_job(crate::db::jobs::NewJob {
                    kind: crate::hostchecks::KIND,
                    target: act.name,
                    endpoint_id: None,
                    schedule_id: None,
                    agent_id: Some(id),
                    submitted_by: Some(&me.username),
                    transport: "UI",
                    running: false,
                })
                .await
                .map_err(|_| "Service unavailable.".to_owned())?;
            st.agents.poke();
        }
    }
    let what = if act.passkey {
        "HOSTCHECK_BASELINE"
    } else {
        "HOSTCHECK"
    };
    if act.passkey {
        tracing::warn!(event = "hostcheck.baseline", user = %me.username, host = %name, action = act.name, "baseline change confirmed with a passkey");
    }
    audit(st, me, info, what, format!("{} on {name}", act.name)).await;
    Ok(format!(
        "{} sent to {name}. Results arrive with its next report.",
        act.label
    ))
}

#[derive(Deserialize)]
struct RunForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    host: String,
    #[serde(default)]
    action: String,
}

async fn run(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Form(f): Form<RunForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let mut nav = Nav::new("integrity", &s, &me);
    let r = match (
        crate::hostchecks::action(&f.action),
        parse_host(&st, &f.host).await,
    ) {
        (None, _) => Err("Unknown action.".to_owned()),
        (_, Err(m)) => Err(m),
        (Some(act), Ok(host)) => dispatch(&st, &me, &info, host, act, false).await,
    };
    match r {
        Ok(m) => nav.success = Some(m),
        Err(m) => nav.error = Some(m),
    }
    show(&st, nav).await
}

pub struct Managed {
    host: String,
    value: String,
    known: bool,
    read: String,
    aide: bool,
    rkhunter: bool,
    aide_timer: Option<bool>,
    rkhunter_timer: Option<bool>,
    error: String,
}

fn managed(st: &AppState, host: Option<i64>, name: String) -> Managed {
    let now = crate::db::now_ms();
    let got = st.host_units.get(host);
    let (u, at) = got.clone().unwrap_or_default();
    Managed {
        host: name,
        value: host.map(|h| h.to_string()).unwrap_or_default(),
        known: got.is_some(),
        read: if at > 0 {
            super::crowdsec::span(now - at)
        } else {
            String::new()
        },
        aide: u.aide,
        rkhunter: u.rkhunter,
        aide_timer: u.aide_timer,
        rkhunter_timer: u.rkhunter_timer,
        error: u.error.unwrap_or_default(),
    }
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
    managed: Vec<Managed>,
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Operator) {
        Ok(x) => x,
        Err(r) => return r,
    };
    show(&st, Nav::new("integrity", &s, &u)).await
}

async fn show(st: &AppState, nav: Nav) -> Response {
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
    let mut managed_rows = vec![managed(st, None, format!("{server} (this server)"))];
    managed_rows.extend(
        agents
            .iter()
            .filter(|a| a.enabled)
            .map(|a| managed(st, Some(a.id), a.name.clone())),
    );
    let status = if nav.error.is_some() {
        axum::http::StatusCode::BAD_REQUEST
    } else {
        axum::http::StatusCode::OK
    };
    render(
        status,
        &IntegrityPage {
            managed: managed_rows,
            nav,
            runs,
            aide: st.cfg.aide_log.display().to_string(),
            rkhunter: st.cfg.rkhunter_log.display().to_string(),
            falco,
            falco_path: st.cfg.falco_events.display().to_string(),
        },
    )
}
