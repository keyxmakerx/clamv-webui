//! Admin page for canary files on this server and on every agent.

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
use crate::db::canaries::MAX_PER_HOST;
use crate::db::sessions::Session;
use crate::db::users::User;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin/canaries", get(page).post(create))
        .route("/admin/canaries/{id}/delete", post(delete))
}

pub struct Row {
    id: String,
    host: String,
    path: String,
    /// "armed", "missing" or "waiting".
    state: &'static str,
    tripped: String,
    created: bool,
    rule: String,
    fixed: bool,
}

#[derive(Template)]
#[template(path = "admin_canaries.html")]
struct CanaryPage {
    nav: Nav,
    rows: Vec<Row>,
    hosts: Vec<(String, String)>,
    server: String,
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Admin) {
        Ok(x) => x,
        Err(r) => return r,
    };
    show(&st, Nav::new("canaries", &s, &u)).await
}

fn state(armed: Option<bool>) -> &'static str {
    match armed {
        Some(true) => "armed",
        Some(false) => "missing",
        None => "waiting",
    }
}

async fn show(st: &AppState, nav: Nav) -> Response {
    let (Ok(list), Ok(agents)) = (st.db.list_canaries().await, st.db.list_agents().await) else {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    let server = crate::canary::hostname();
    let mut rows: Vec<Row> = st
        .cfg
        .canary_files
        .iter()
        .map(|p| {
            let path = p.display().to_string();
            Row {
                id: String::new(),
                host: server.clone(),
                state: state(st.canaries.armed(&path)),
                tripped: String::new(),
                created: false,
                rule: crate::canary::audit_rule(&path),
                path,
                fixed: true,
            }
        })
        .collect();
    for c in list {
        let (host, armed) = match c.agent_id {
            None => (server.clone(), st.canaries.armed(&c.path)),
            Some(a) => (
                agents
                    .iter()
                    .find(|x| x.id == a)
                    .map_or_else(|| format!("agent {a}"), |x| x.name.clone()),
                c.armed,
            ),
        };
        rows.push(Row {
            id: c.id,
            host,
            state: state(armed),
            tripped: c.last_tripped_at.map(fmt_ts).unwrap_or_default(),
            created: c.create_file,
            rule: crate::canary::audit_rule(&c.path),
            path: c.path,
            fixed: false,
        });
    }
    let mut hosts = vec![(String::new(), format!("{server} (this server)"))];
    hosts.extend(agents.iter().map(|a| (a.id.to_string(), a.name.clone())));
    let status = if nav.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    render(
        status,
        &CanaryPage {
            nav,
            rows,
            hosts,
            server,
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
    let mut nav = Nav::new("canaries", s, me);
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
    #[serde(default)]
    host: String,
    create: Option<String>,
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
    let path = f.path.trim().to_owned();
    if let Err(m) = crate::canary::valid_path(&path) {
        return fail(m.into()).await;
    }
    let agent = match f.host.trim() {
        "" => None,
        v => match v.parse::<i64>() {
            Ok(id) => match st.db.agent(id).await {
                Ok(Some(a)) => Some(a),
                _ => return fail("Unknown agent.".into()).await,
            },
            Err(_) => return fail("Unknown agent.".into()).await,
        },
    };
    let agent_id = agent.as_ref().map(|a| a.id);
    // Scans open every file they read, so a canary inside a scanned folder would trip itself.
    let roots: Vec<String> = match &agent {
        None => st
            .cfg
            .scan_roots
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        Some(a) => a.roots.clone(),
    };
    if let Some(r) = roots.iter().find(|r| {
        let r = r.trim_end_matches('/');
        path.starts_with(&format!("{r}/"))
    }) {
        return fail(format!(
            "{path} is inside the scanned folder {r}; scans would trip it. Put canaries next to what they guard, outside scanned folders."
        ))
        .await;
    }
    let existing = st.db.host_canaries(agent_id).await.unwrap_or_default();
    if existing.iter().any(|c| c.path == path)
        || (agent_id.is_none()
            && st
                .cfg
                .canary_files
                .iter()
                .any(|p| p.as_os_str() == path.as_str()))
    {
        return fail("That canary already exists on this host.".into()).await;
    }
    if existing.len() >= MAX_PER_HOST {
        return fail(format!("At most {MAX_PER_HOST} canaries per host.")).await;
    }
    if st
        .db
        .add_canary(agent_id, &path, f.create.is_some(), &me.username)
        .await
        .is_err()
    {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    let host = agent
        .as_ref()
        .map_or_else(crate::canary::hostname, |a| a.name.clone());
    audit(&st, &me, &info, "CANARY_CREATE", format!("{host}: {path}")).await;
    tracing::info!(event = "canary.added", host = %host, path = %path, by = %me.username, "canary added");
    if agent_id.is_none() {
        crate::canary::reload(&st).await;
    } else {
        // Wake waiting agents so the new list goes out now.
        st.agents.poke();
    }
    let msg = if agent_id.is_some() {
        format!("Canary added. {host} picks it up within a few seconds if it is online.")
    } else {
        "Canary added and armed if the file exists.".to_owned()
    };
    result(&st, &s, &me, None, Some(msg)).await
}

#[derive(Deserialize)]
struct CsrfForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

async fn delete(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Ok(Some(c)) = st.db.canary(&id).await else {
        return result(&st, &s, &me, Some("No such canary.".into()), None).await;
    };
    if st.db.delete_canary(&id).await.is_err() {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    audit(&st, &me, &info, "CANARY_DELETE", c.path.clone()).await;
    if c.agent_id.is_none() {
        crate::canary::reload(&st).await;
    } else {
        st.agents.poke();
    }
    // The decoy file stays: removing files is left to people.
    result(
        &st,
        &s,
        &me,
        None,
        Some(format!(
            "Canary removed. {} itself was left in place.",
            c.path
        )),
    )
    .await
}
