//! Admin page for remote agents. A token is shown once, with a ready compose snippet.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use serde::Deserialize;

use super::admin::{admin_post, audit, fmt_ts};
use super::session::Auth;
use super::{Nav, RequestInfo, error_page, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::db::now_ms;
use crate::db::sessions::Session;
use crate::db::users::User;

const MAX_AGENTS: usize = 100;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin/agents", get(page).post(create))
        .route("/admin/agents/{id}/enabled", post(toggle))
        .route("/admin/agents/{id}/rotate", post(rotate))
        .route("/admin/agents/{id}/delete", post(delete))
}

pub struct AgentRow {
    id: i64,
    name: String,
    prefix: String,
    enabled: bool,
    state: &'static str,
    last_seen: String,
    ip: String,
    version: String,
    clamd: String,
    roots: Vec<String>,
    slots: i64,
    queued: usize,
    running: usize,
}

/// Shown once after creating an agent or rotating its token.
pub struct Enroll {
    name: String,
    secret: String,
    server: String,
    fingerprint: Option<String>,
}

#[derive(Template)]
#[template(path = "admin_agents.html")]
struct AgentsPage {
    nav: Nav,
    rows: Vec<AgentRow>,
    enroll: Option<Enroll>,
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Admin) {
        Ok(x) => x,
        Err(r) => return r,
    };
    show(&st, Nav::new("agents", &s, &u), None).await
}

async fn show(st: &AppState, nav: Nav, enroll: Option<Enroll>) -> Response {
    let Ok(list) = st.db.list_agents().await else {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    let now = now_ms();
    let mut rows = Vec::with_capacity(list.len());
    for a in list {
        let queued = st
            .db
            .agent_jobs(a.id, crate::db::jobs::QUEUED)
            .await
            .map_or(0, |l| l.len());
        let running = st
            .db
            .agent_jobs(a.id, crate::db::jobs::RUNNING)
            .await
            .map_or(0, |l| l.len());
        let state = if !a.enabled {
            "disabled"
        } else if a.last_seen_at.is_none() {
            "never connected"
        } else if crate::agent::is_online(&a, now) {
            "online"
        } else {
            "offline"
        };
        rows.push(AgentRow {
            id: a.id,
            name: a.name,
            prefix: a.prefix,
            enabled: a.enabled,
            state,
            last_seen: a.last_seen_at.map_or_else(|| "never".into(), fmt_ts),
            ip: a.last_ip.unwrap_or_default(),
            version: a.version.unwrap_or_default(),
            clamd: a.clamd_version.unwrap_or_else(|| "unknown".into()),
            roots: a.roots,
            slots: a.slots,
            queued,
            running,
        });
    }
    let status = if nav.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    render(status, &AgentsPage { nav, rows, enroll })
}

async fn result(
    st: &AppState,
    s: &Session,
    me: &User,
    error: Option<String>,
    success: Option<String>,
    enroll: Option<Enroll>,
) -> Response {
    let mut nav = Nav::new("agents", s, me);
    nav.error = error;
    nav.success = success;
    show(st, nav, enroll).await
}

/// The address agents should use: what the browser used to reach us.
fn server_url(st: &AppState, h: &HeaderMap) -> String {
    let scheme = if st.cfg.tls_enabled() {
        "https"
    } else {
        "http"
    };
    let host = h
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .filter(|v| {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c))
        })
        .unwrap_or("SERVER:8080");
    format!("{scheme}://{host}")
}

fn enroll(st: &AppState, h: &HeaderMap, name: String, secret: String) -> Enroll {
    let fingerprint = if st.cfg.tls_enabled() {
        crate::tls::files(&st.cfg)
            .ok()
            .and_then(|(c, _)| crate::tls::fingerprint(&c))
    } else {
        None
    };
    Enroll {
        name,
        secret,
        server: server_url(st, h),
        fingerprint,
    }
}

#[derive(Deserialize)]
struct CreateForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    name: String,
}

async fn create(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    headers: HeaderMap,
    Form(f): Form<CreateForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let name = f.name.trim();
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
    {
        return result(
            &st,
            &s,
            &me,
            Some("Names are 1 to 64 letters, digits, dots, dashes or underscores.".into()),
            None,
            None,
        )
        .await;
    }
    if st.db.list_agents().await.map_or(0, |l| l.len()) >= MAX_AGENTS {
        return result(
            &st,
            &s,
            &me,
            Some(format!("At most {MAX_AGENTS} agents.")),
            None,
            None,
        )
        .await;
    }
    match st.db.create_agent(name, &me.username).await {
        Ok((a, secret)) => {
            audit(&st, &me, &info, "AGENT_CREATE", a.name.clone()).await;
            tracing::info!(event = "agent.created", agent = %a.name, by = %me.username, "agent added");
            let e = enroll(&st, &headers, a.name.clone(), secret);
            result(
                &st,
                &s,
                &me,
                None,
                Some(format!("Added {}.", a.name)),
                Some(e),
            )
            .await
        }
        Err(_) => {
            result(
                &st,
                &s,
                &me,
                Some("That name is already taken.".into()),
                None,
                None,
            )
            .await
        }
    }
}

#[derive(Deserialize)]
struct ActionForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    enabled: Option<String>,
}

async fn toggle(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<ActionForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Ok(Some(a)) = (match id.parse::<i64>() {
        Ok(id) => st.db.agent(id).await,
        Err(_) => Ok(None),
    }) else {
        return result(&st, &s, &me, Some("Unknown agent.".into()), None, None).await;
    };
    let on = f.enabled.is_some();
    if st.db.set_agent_enabled(a.id, on).await.is_err() {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    let what = if on { "enabled" } else { "disabled" };
    audit(
        &st,
        &me,
        &info,
        "AGENT_UPDATE",
        format!("{} {what}", a.name),
    )
    .await;
    result(
        &st,
        &s,
        &me,
        None,
        Some(format!("{} {what}.", a.name)),
        None,
    )
    .await
}

async fn rotate(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<ActionForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Ok(Some(a)) = (match id.parse::<i64>() {
        Ok(id) => st.db.agent(id).await,
        Err(_) => Ok(None),
    }) else {
        return result(&st, &s, &me, Some("Unknown agent.".into()), None, None).await;
    };
    match st.db.rotate_agent_secret(a.id).await {
        Ok(Some(secret)) => {
            audit(&st, &me, &info, "AGENT_ROTATE", a.name.clone()).await;
            let e = enroll(&st, &headers, a.name.clone(), secret);
            result(
                &st,
                &s,
                &me,
                None,
                Some(format!(
                    "New token for {}; the old one no longer works.",
                    a.name
                )),
                Some(e),
            )
            .await
        }
        _ => error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    }
}

async fn delete(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<ActionForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Ok(Some(a)) = (match id.parse::<i64>() {
        Ok(id) => st.db.agent(id).await,
        Err(_) => Ok(None),
    }) else {
        return result(&st, &s, &me, Some("Unknown agent.".into()), None, None).await;
    };
    match st.db.delete_agent(a.id).await {
        Ok(true) => {
            audit(&st, &me, &info, "AGENT_DELETE", a.name.clone()).await;
            result(
                &st,
                &s,
                &me,
                None,
                Some(format!("Removed {}.", a.name)),
                None,
            )
            .await
        }
        _ => error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    }
}
