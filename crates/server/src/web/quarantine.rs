//! Quarantine page: files moved out of the scan roots, and putting them back or deleting them.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use serde::Deserialize;

use super::admin::{admin_post, audit, fmt_ts};
use super::session::Auth;
use super::{Nav, RequestInfo, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::db::quarantine as q;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/admin/quarantine", get(page).post(start))
}

pub struct Entry {
    id: String,
    host: String,
    path: String,
    signature: String,
    state: &'static str,
    held: bool,
    why: String,
    when: String,
    by: String,
    sha256: String,
    size: String,
}

#[derive(Template)]
#[template(path = "quarantine.html")]
struct QuarantinePage {
    nav: Nav,
    entries: Vec<Entry>,
    enabled: bool,
    auto: bool,
    dir: String,
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Admin) {
        Ok(x) => x,
        Err(r) => return r,
    };
    show(&st, Nav::new("quarantine", &s, &u)).await
}

fn state_label(s: &str) -> &'static str {
    match s {
        q::PENDING => "moving",
        q::HELD => "in quarantine",
        q::RESTORED => "restored",
        q::DELETED => "deleted",
        _ => "not moved",
    }
}

async fn show(st: &AppState, nav: Nav) -> Response {
    let agents = st.db.list_agents().await.unwrap_or_default();
    let server = crate::canary::hostname();
    let entries = st
        .db
        .list_quarantine(500)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|i| Entry {
            host: i.agent_id.map_or_else(
                || server.clone(),
                |id| {
                    agents
                        .iter()
                        .find(|a| a.id == id)
                        .map_or_else(|| format!("agent {id}"), |a| a.name.clone())
                },
            ),
            held: i.state == q::HELD,
            state: state_label(&i.state),
            why: i
                .error_code
                .as_deref()
                .map(crate::quarantine::message)
                .unwrap_or_default()
                .to_owned(),
            when: fmt_ts(i.updated_at),
            by: i.updated_by.unwrap_or_default(),
            sha256: i.sha256.unwrap_or_default(),
            size: i
                .size_bytes
                .map(|b| format!("{:.1} MB", b as f64 / 1_048_576.0))
                .unwrap_or_default(),
            id: i.id,
            path: i.original_path,
            signature: i.signature,
        })
        .collect();
    let code = if nav.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    render(
        code,
        &QuarantinePage {
            nav,
            entries,
            enabled: st.cfg.quarantine_dir.is_some(),
            auto: st.cfg.quarantine_auto,
            dir: st
                .cfg
                .quarantine_dir
                .as_ref()
                .map(|d| d.display().to_string())
                .unwrap_or_default(),
        },
    )
}

#[derive(Deserialize)]
struct StartForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    detection: String,
}

async fn start(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Form(f): Form<StartForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let mut nav = Nav::new("quarantine", &s, &me);
    let r = match f.detection.trim().parse::<i64>() {
        Ok(id) => crate::quarantine::start(&st, id, &me.username).await,
        Err(_) => Err("Unknown detection.".to_owned()),
    };
    match r {
        Ok(id) => {
            audit(&st, &me, &info, "QUARANTINE", id).await;
            nav.success =
                Some("Quarantine started. Files on agents move when the agent picks it up.".into());
        }
        Err(m) => nav.error = Some(m),
    }
    show(&st, nav).await
}
