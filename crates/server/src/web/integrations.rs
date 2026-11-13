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
        .route("/admin/integrations/files/{name}", get(file))
}

#[derive(Template)]
#[template(path = "admin_integrations.html")]
struct Page {
    nav: Nav,
    host: Option<String>,
    discord: bool,
    all: bool,
    last: Option<(String, bool, String)>,
    metrics: bool,
}

const FILES: [(&str, &str, &str); 3] = [
    (
        "grafana-clamav-webui.json",
        "application/json",
        include_str!("../../../../dashboards/grafana-clamav-webui.json"),
    ),
    (
        "clamav-alerts.yml",
        "text/yaml; charset=utf-8",
        include_str!("../../../../dashboards/clamav-alerts.yml"),
    ),
    (
        "prometheus.yml.example",
        "text/yaml; charset=utf-8",
        include_str!("../../../../dashboards/prometheus.yml.example"),
    ),
];

async fn file(auth: Auth, axum::extract::Path(name): axum::extract::Path<String>) -> Response {
    use axum::response::IntoResponse;
    if let Err(r) = auth.require(Role::Admin) {
        return r;
    }
    match FILES.iter().find(|(n, _, _)| *n == name) {
        Some((n, ct, body)) => (
            [
                (axum::http::header::CONTENT_TYPE, (*ct).to_owned()),
                (
                    axum::http::header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{n}\""),
                ),
            ],
            *body,
        )
            .into_response(),
        None => super::error_page(StatusCode::NOT_FOUND, "Not found."),
    }
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
            metrics: st.cfg.metrics_token().is_some(),
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
