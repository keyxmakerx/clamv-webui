//! Timeline page: every sensor's events, with correlated incidents on top.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::get;
use serde::Deserialize;

use super::admin::fmt_ts;
use super::session::Auth;
use super::{Nav, render};
use crate::app::AppState;
use crate::auth::Role;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/timeline", get(page))
}

pub struct Row {
    at: String,
    host: String,
    sensor: &'static str,
    title: String,
    detail: String,
    href: String,
    linked: bool,
}

pub struct IncidentView {
    host: String,
    span: String,
    sensors: String,
    rows: Vec<Row>,
}

#[derive(Template)]
#[template(path = "timeline.html")]
struct TimelinePage {
    nav: Nav,
    range: String,
    host: String,
    host_q: String,
    hosts: Vec<(String, String)>,
    incidents: Vec<IncidentView>,
    rows: Vec<Row>,
}

impl TimelinePage {
    fn sensor_class(&self, s: &str) -> &'static str {
        match s {
            "ClamAV" => "bg-danger",
            "Canary" => "bg-warning text-dark",
            "Integrity" => "bg-info text-dark",
            _ => "bg-secondary",
        }
    }
}

#[derive(Deserialize)]
struct Q {
    range: Option<String>,
    host: Option<String>,
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn row(i: &crate::timeline::Item, linked: bool) -> Row {
    Row {
        at: fmt_ts(i.at),
        host: i.host.clone(),
        sensor: i.sensor,
        title: i.title.clone(),
        detail: i.detail.clone(),
        href: i.href.clone(),
        linked,
    }
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth, Query(q): Query<Q>) -> Response {
    let (s, u) = match auth.require(Role::Operator) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let range = match q.range.as_deref() {
        Some("24h") => "24h",
        Some("30d") => "30d",
        _ => "7d",
    };
    let span = match range {
        "24h" => 86_400_000,
        "30d" => 30 * 86_400_000,
        _ => 7 * 86_400_000,
    };
    let mut items = crate::timeline::collect(&st, crate::db::now_ms() - span).await;
    let mut hosts: Vec<String> = items.iter().map(|i| i.host.clone()).collect();
    hosts.sort();
    hosts.dedup();
    let host = q.host.unwrap_or_default();
    if !host.is_empty() {
        items.retain(|i| i.host == host);
    }
    let incidents = crate::timeline::incidents(&items);
    let in_incident = |i: &crate::timeline::Item| incidents.iter().any(|x| x.items.contains(i));
    let rows = items
        .iter()
        .take(500)
        .map(|i| row(i, in_incident(i)))
        .collect();
    let incidents = incidents
        .iter()
        .take(20)
        .map(|x| IncidentView {
            host: x.host.clone(),
            span: format!("{} to {}", fmt_ts(x.first), fmt_ts(x.last)),
            sensors: x.sensors.join(" + "),
            rows: x.items.iter().rev().map(|i| row(i, true)).collect(),
        })
        .collect();
    render(
        axum::http::StatusCode::OK,
        &TimelinePage {
            nav: Nav::new("timeline", &s, &u),
            range: range.to_owned(),
            host_q: enc(&host),
            host,
            hosts: hosts.iter().map(|h| (h.clone(), enc(h))).collect(),
            incidents,
            rows,
        },
    )
}
