//! Admin settings: edit, review the diff, apply. Saved values apply on restart.

use std::collections::BTreeMap;
use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};

use super::admin::{admin_post, audit};
use super::session::Auth;
use super::{Nav, RequestInfo, error_page, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::db::settings::{Setting, revision};
use crate::settings::{FIELDS, Field, Kind, field, locked, normalize};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin/settings", get(page))
        .route("/admin/settings/review", post(review))
        .route("/admin/settings/apply", post(apply))
}

pub struct Row {
    env: &'static str,
    label: &'static str,
    help: &'static str,
    kind: &'static str,
    min: i64,
    max: i64,
    options: Vec<&'static str>,
    value: String,
    default: String,
    locked: Option<String>,
    pending: bool,
}

pub struct Section {
    name: &'static str,
    rows: Vec<Row>,
}

#[derive(Template)]
#[template(path = "admin_settings.html")]
struct SettingsPage {
    nav: Nav,
    sections: Vec<Section>,
    deployment: Vec<(&'static str, String)>,
}

pub struct Change {
    env: &'static str,
    label: &'static str,
    old: String,
    new: String,
    value: String,
}

#[derive(Template)]
#[template(path = "admin_settings_review.html")]
struct ReviewPage {
    nav: Nav,
    changes: Vec<Change>,
    revision: String,
}

fn stored_map(rows: &[Setting]) -> BTreeMap<String, String> {
    rows.iter()
        .filter(|s| field(&s.name).is_some())
        .map(|s| (s.name.clone(), s.value.clone()))
        .collect()
}

/// What the field is without a UI value: env if pinned, else the default.
fn default_of(f: &Field) -> String {
    match crate::settings::check(&[]) {
        Ok(c) => (f.current)(&c),
        Err(_) => String::new(),
    }
}

fn show_value(f: &Field, v: &str) -> String {
    match (f.kind, v) {
        (_, "") => "(empty)".into(),
        (Kind::Bool, "true") => "yes".into(),
        (Kind::Bool, "false") => "no".into(),
        _ => v.to_owned(),
    }
}

fn deployment(st: &AppState) -> Vec<(&'static str, String)> {
    let c = &st.cfg;
    let set = |b: bool| if b { "set" } else { "not set" }.to_owned();
    let tls = if c.tls_self_signed {
        "self-signed".to_owned()
    } else if c.tls_cert_file.is_some() {
        "certificate files".to_owned()
    } else {
        "off (plain HTTP)".to_owned()
    };
    let db = c
        .database_url()
        .ok()
        .and_then(|u| u.split(':').next().map(str::to_owned))
        .unwrap_or_default();
    let roots: Vec<String> = c
        .scan_roots
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    vec![
        ("Listen address", c.listen.to_string()),
        ("TLS", tls),
        ("Database", db),
        ("Data directory", c.data_dir.display().to_string()),
        (
            "Scan roots",
            if roots.is_empty() {
                "none (path scans off)".into()
            } else {
                roots.join(", ")
            },
        ),
        (
            "clamd host allowlist",
            if c.clamd_host_allowlist.iter().all(|h| h.trim().is_empty()) {
                "any".into()
            } else {
                c.clamd_host_allowlist.join(", ")
            },
        ),
        (
            "Webhook URL",
            set(c.webhook_url.is_some() || c.webhook_url_file.is_some()),
        ),
        ("Metrics token", set(c.metrics_token().is_some())),
        ("Version", env!("CARGO_PKG_VERSION").to_owned()),
    ]
}

async fn show(st: &AppState, nav: Nav) -> Response {
    let Ok(rows) = st.db.list_settings().await else {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    let stored = stored_map(&rows);
    let mut sections: Vec<Section> = Vec::new();
    for f in FIELDS {
        let value = stored.get(f.env).cloned().unwrap_or_default();
        let lock = locked(f);
        let running = (f.current)(&st.cfg);
        let (kind, min, max, options) = match f.kind {
            Kind::Bool => ("bool", 0, 0, Vec::new()),
            Kind::Number { min, max } => ("number", min, max, Vec::new()),
            Kind::Select(o) => ("select", 0, 0, o.to_vec()),
            Kind::Cidrs => ("text", 0, 0, Vec::new()),
        };
        let row = Row {
            env: f.env,
            label: f.label,
            help: f.help,
            kind,
            min,
            max,
            options,
            pending: lock.is_none() && !value.is_empty() && value != running,
            default: default_of(f),
            value,
            locked: lock,
        };
        match sections.iter_mut().find(|s| s.name == f.section) {
            Some(s) => s.rows.push(row),
            None => sections.push(Section {
                name: f.section,
                rows: vec![row],
            }),
        }
    }
    let status = if nav.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    render(
        status,
        &SettingsPage {
            nav,
            sections,
            deployment: deployment(st),
        },
    )
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    match auth.require(Role::Admin) {
        Ok((s, u)) => show(&st, Nav::new("settings", &s, &u)).await,
        Err(r) => r,
    }
}

/// Validated changes from a submitted form: (field, new stored value or None).
fn changes(
    form: &[(String, String)],
    stored: &BTreeMap<String, String>,
) -> Result<Vec<(&'static Field, Option<String>)>, String> {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    for f in FIELDS {
        if locked(f).is_some() {
            continue;
        }
        let Some((_, raw)) = form.iter().find(|(k, _)| k == f.env) else {
            continue;
        };
        match normalize(f, raw) {
            Ok(v) if v.as_deref() != stored.get(f.env).map(String::as_str) => out.push((f, v)),
            Ok(_) => {}
            Err(e) => errors.push(e),
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors.join(" "))
    }
}

fn csrf_of(form: &[(String, String)]) -> Option<&str> {
    form.iter()
        .find(|(k, _)| k == "_csrf")
        .map(|(_, v)| v.as_str())
}

fn merged(
    stored: &BTreeMap<String, String>,
    ch: &[(&'static Field, Option<String>)],
) -> Vec<(String, String)> {
    let mut m = stored.clone();
    for (f, v) in ch {
        match v {
            Some(v) => m.insert(f.env.to_owned(), v.clone()),
            None => m.remove(f.env),
        };
    }
    m.into_iter().collect()
}

async fn review(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let (s, me) = match admin_post(auth, csrf_of(&form)) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let mut nav = Nav::new("settings", &s, &me);
    let Ok(rows) = st.db.list_settings().await else {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    let stored = stored_map(&rows);
    let ch = match changes(&form, &stored) {
        Ok(c) => c,
        Err(e) => {
            nav.error = Some(e);
            return show(&st, nav).await;
        }
    };
    if ch.is_empty() {
        nav.success = Some("Nothing changed.".into());
        return show(&st, nav).await;
    }
    if let Err(e) = crate::settings::check(&merged(&stored, &ch)) {
        nav.error = Some(format!("These settings do not fit together: {e}."));
        return show(&st, nav).await;
    }
    let changes = ch
        .iter()
        .map(|(f, v)| Change {
            env: f.env,
            label: f.label,
            old: stored.get(f.env).map_or_else(
                || format!("default ({})", show_value(f, &default_of(f))),
                |o| show_value(f, o),
            ),
            new: v.as_deref().map_or_else(
                || format!("default ({})", show_value(f, &default_of(f))),
                |n| show_value(f, n),
            ),
            value: v.clone().unwrap_or_default(),
        })
        .collect();
    render(
        StatusCode::OK,
        &ReviewPage {
            nav,
            changes,
            revision: revision(&rows),
        },
    )
}

async fn apply(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let (s, me) = match admin_post(auth, csrf_of(&form)) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let mut nav = Nav::new("settings", &s, &me);
    let Ok(rows) = st.db.list_settings().await else {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    let stored = stored_map(&rows);
    let ch = match changes(&form, &stored) {
        Ok(c) if !c.is_empty() => c,
        Ok(_) => {
            nav.success = Some("Nothing changed.".into());
            return show(&st, nav).await;
        }
        Err(e) => {
            nav.error = Some(e);
            return show(&st, nav).await;
        }
    };
    if let Err(e) = crate::settings::check(&merged(&stored, &ch)) {
        nav.error = Some(format!("These settings do not fit together: {e}."));
        return show(&st, nav).await;
    }
    let expected = form
        .iter()
        .find(|(k, _)| k == "_revision")
        .map_or("", |(_, v)| v.as_str());
    let writes: Vec<(String, Option<String>)> = ch
        .iter()
        .map(|(f, v)| (f.env.to_owned(), v.clone()))
        .collect();
    match st.db.apply_settings(&writes, &me.username, expected).await {
        Ok(true) => {}
        Ok(false) => {
            nav.error = Some(
                "Settings were changed by someone else since your review. Review again.".into(),
            );
            return show(&st, nav).await;
        }
        Err(_) => return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    }
    for (f, v) in &ch {
        audit(
            &st,
            &me,
            &info,
            "SETTINGS_UPDATE",
            format!("{}={}", f.env, v.as_deref().unwrap_or("(default)")),
        )
        .await;
    }
    tracing::info!(event = "settings.saved", count = ch.len(), by = %me.username, "settings saved; restart to apply");
    nav.success = Some(format!(
        "Saved {} setting(s). Restart the container to apply them.",
        ch.len()
    ));
    show(&st, nav).await
}
