//! Admin page for watched folders.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use serde::Deserialize;

use super::admin::{admin_post, audit, fmt_ts};
use super::session::Auth;
use super::{Nav, RequestInfo, error_page, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::db::endpoints::Endpoint;
use crate::db::sessions::Session;
use crate::db::users::User;
use crate::db::watch::Watch;
use crate::scan;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin/watch", get(page).post(create))
        .route("/admin/watch/{id}/enabled", post(toggle))
        .route("/admin/watch/{id}/delete", post(delete))
}

pub struct Row {
    id: String,
    path: String,
    endpoint: String,
    enabled: bool,
    created: String,
}

#[derive(Template)]
#[template(path = "admin_watch.html")]
struct WatchPage {
    nav: Nav,
    rows: Vec<Row>,
    endpoints: Vec<Endpoint>,
    roots: Vec<String>,
    poll: u64,
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Admin) {
        Ok(x) => x,
        Err(r) => return r,
    };
    show(&st, Nav::new("watch", &s, &u)).await
}

async fn show(st: &AppState, nav: Nav) -> Response {
    let (Ok(list), Ok(endpoints)) = (st.db.list_watches().await, st.db.list_endpoints().await)
    else {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    let rows = list
        .into_iter()
        .map(|w: Watch| Row {
            endpoint: w
                .endpoint_id
                .and_then(|id| endpoints.iter().find(|e| e.id == id))
                .map_or_else(|| "default".into(), |e| e.name.clone()),
            created: fmt_ts(w.created_at),
            id: w.id,
            path: w.path,
            enabled: w.enabled,
        })
        .collect();
    let status = if nav.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    render(
        status,
        &WatchPage {
            nav,
            rows,
            endpoints: endpoints.into_iter().filter(|e| e.enabled).collect(),
            roots: st
                .cfg
                .scan_roots
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            poll: st.cfg.watch_poll_secs.max(10),
        },
    )
}

async fn result(
    st: &AppState,
    s: &Session,
    me: &User,
    error: Option<String>,
    success: Option<String>,
) -> Response {
    let mut nav = Nav::new("watch", s, me);
    nav.error = error;
    nav.success = success;
    show(st, nav).await
}

#[derive(Deserialize)]
struct CreateForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    path: String,
    endpoint: Option<String>,
    existing: Option<String>,
}

async fn create(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Form(f): Form<CreateForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let fail = |m: String| result(&st, &s, &me, Some(m), None);
    let real = match scan::resolve_path(&st.cfg.scan_roots, f.path.trim()).await {
        Ok(p) if p.is_dir() => p,
        Ok(_) => return fail("Pick a folder, not a file.".into()).await,
        Err(m) => return fail(m.into()).await,
    };
    let Some(path) = real.to_str().map(str::to_owned) else {
        return fail("Only UTF-8 paths can be watched.".into()).await;
    };
    if st
        .db
        .list_watches()
        .await
        .unwrap_or_default()
        .iter()
        .any(|w| w.path == path)
    {
        return fail("That folder is already watched.".into()).await;
    }
    let endpoint_id = match f
        .endpoint
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        None => None,
        Some(v) => match v.parse::<i64>() {
            Ok(id) if matches!(st.db.endpoint(id).await, Ok(Some(_))) => Some(id),
            _ => return fail("Unknown endpoint.".into()).await,
        },
    };
    let scan_existing = f.existing.is_some();
    // Record what is there now first, so the watcher only sees later changes.
    let baselined = if scan_existing {
        0
    } else {
        crate::watch::baseline(&st, real.clone()).await
    };
    if st.db.create_watch(&path, endpoint_id).await.is_err() {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    audit(&st, &me, &info, "WATCH_CREATE", path.clone()).await;
    let msg = if scan_existing {
        format!("Watching {path}. Files already there are queued over the next passes.")
    } else {
        format!(
            "Watching {path}. {baselined} existing file(s) were recorded and will not be scanned until they change."
        )
    };
    result(&st, &s, &me, None, Some(msg)).await
}

#[derive(Deserialize)]
struct CsrfForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    enabled: Option<String>,
}

async fn target(
    st: &AppState,
    auth: Auth,
    csrf: Option<&str>,
    id: &str,
) -> Result<(Session, User, Watch), Response> {
    let (s, me) = admin_post(auth, csrf)?;
    match st.db.watch(id).await {
        Ok(Some(w)) => Ok((s, me, w)),
        _ => Err(result(st, &s, &me, Some("No such watched folder.".into()), None).await),
    }
}

async fn toggle(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let (s, me, w) = match target(&st, auth, f.csrf.as_deref(), &id).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let enabled = f.enabled.is_some();
    if st.db.set_watch_enabled(&w.id, enabled).await.is_err() {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    audit(
        &st,
        &me,
        &info,
        "WATCH_UPDATE",
        format!("{} enabled={enabled}", w.path),
    )
    .await;
    let word = if enabled { "resumed" } else { "paused" };
    result(
        &st,
        &s,
        &me,
        None,
        Some(format!("Watching {} {word}.", w.path)),
    )
    .await
}

async fn delete(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let (s, me, w) = match target(&st, auth, f.csrf.as_deref(), &id).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if st.db.delete_watch(&w.id).await.is_err() {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    // Another watch may still cover these files; keep them then.
    let still = st
        .db
        .list_watches()
        .await
        .unwrap_or_default()
        .iter()
        .any(|o| w.path.starts_with(&o.path) || o.path.starts_with(&w.path));
    if !still {
        let _ = st.db.forget_processed_under(&w.path).await;
    }
    audit(&st, &me, &info, "WATCH_DELETE", w.path.clone()).await;
    result(
        &st,
        &s,
        &me,
        None,
        Some(format!("Stopped watching {}.", w.path)),
    )
    .await
}
