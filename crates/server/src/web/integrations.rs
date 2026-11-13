//! Admin page for outgoing integrations.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use serde::Deserialize;

use super::admin::{admin_post, audit, fmt_ts};
use super::session::Auth;
use super::{Nav, RequestInfo, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::config::WebhookEvents;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin/integrations", get(page))
        .route("/admin/integrations/webhook/test", post(test))
}

#[derive(Template)]
#[template(path = "admin_integrations.html")]
struct Page {
    nav: Nav,
    host: Option<String>,
    discord: bool,
    all: bool,
    last: Option<(String, bool, String)>,
}

fn show(st: &AppState, nav: Nav) -> Response {
    let n = &st.notifier;
    let status = if nav.error.is_some() {
        StatusCode::BAD_GATEWAY
    } else {
        StatusCode::OK
    };
    render(
        status,
        &Page {
            nav,
            host: n.target().map(crate::webhook::Target::host),
            discord: n.target().is_some_and(crate::webhook::Target::is_discord),
            all: n.events() == WebhookEvents::All,
            last: n.last().map(|d| (fmt_ts(d.at), d.ok, d.detail)),
        },
    )
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    match auth.require(Role::Admin) {
        Ok((s, u)) => show(&st, Nav::new("integrations", &s, &u)),
        Err(r) => r,
    }
}

#[derive(Deserialize)]
struct CsrfForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

async fn test(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Form(f): Form<CsrfForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let r = st.notifier.test().await;
    audit(
        &st,
        &me,
        &info,
        "WEBHOOK_TEST",
        if r.is_ok() { "ok" } else { "failed" }.to_owned(),
    )
    .await;
    let mut nav = Nav::new("integrations", &s, &me);
    match r {
        Ok(()) => nav.success = Some("Test message delivered.".into()),
        Err(m) => nav.error = Some(format!("Test message failed: {m}")),
    }
    show(&st, nav)
}
