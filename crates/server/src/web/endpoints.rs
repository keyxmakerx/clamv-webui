//! clamd endpoint status and the admin endpoints page.

use std::sync::Arc;
use std::time::Duration;

use askama::Template;
use axum::Router;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use serde::Deserialize;

use super::admin::{admin_post, audit};
use super::session::Auth;
use super::{Nav, RequestInfo, error_page, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::db::endpoints::Endpoint;
use crate::db::sessions::Session;
use crate::db::users::User;

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ENDPOINTS: usize = 32;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin/endpoints", get(page).post(create))
        .route("/admin/endpoints/{id}/default", post(make_default))
        .route("/admin/endpoints/{id}/enabled", post(toggle))
        .route("/admin/endpoints/{id}/delete", post(delete))
        .route("/admin/endpoints/{id}/test", post(test))
}

/// What one endpoint looks like right now.
pub enum Status {
    Up(String),
    Down(String),
    Disabled,
}

pub struct EndpointView {
    pub id: String,
    pub name: String,
    pub address: String,
    pub enabled: bool,
    pub is_default: bool,
    pub status: Status,
}

/// PING then VERSION, bounded by PROBE_TIMEOUT.
pub async fn probe(st: &AppState, e: &Endpoint) -> Status {
    if !e.enabled {
        return Status::Disabled;
    }
    let Ok(ep) = e.parsed() else {
        return Status::Down("invalid address".into());
    };
    let client = st.clamd(ep);
    let r = tokio::time::timeout(PROBE_TIMEOUT, async {
        client.ping().await?;
        client.version().await
    })
    .await;
    match r {
        Ok(Ok(v)) => Status::Up(v),
        Ok(Err(err)) => {
            tracing::warn!(event = "clamd.unreachable", endpoint = %e.name, error = %err, "clamd probe failed");
            Status::Down(err.to_string())
        }
        Err(_) => {
            tracing::warn!(event = "clamd.unreachable", endpoint = %e.name, "clamd probe timed out");
            Status::Down("timed out".into())
        }
    }
}

/// Probe every endpoint at once; keeps list order.
pub async fn probe_all(st: &Arc<AppState>, list: Vec<Endpoint>) -> Vec<EndpointView> {
    let mut set = tokio::task::JoinSet::new();
    for (i, e) in list.into_iter().enumerate() {
        let st = st.clone();
        set.spawn(async move {
            let status = probe(&st, &e).await;
            (
                i,
                EndpointView {
                    id: e.id,
                    name: e.name,
                    address: e.address,
                    enabled: e.enabled,
                    is_default: e.is_default,
                    status,
                },
            )
        });
    }
    let mut out = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(x) = r {
            out.push(x);
        }
    }
    out.sort_by_key(|(i, _)| *i);
    out.into_iter().map(|(_, v)| v).collect()
}

#[derive(Template)]
#[template(path = "admin_endpoints.html")]
struct EndpointsPage {
    nav: Nav,
    endpoints: Vec<EndpointView>,
    allowlist: String,
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Admin) {
        Ok(x) => x,
        Err(r) => return r,
    };
    show(&st, Nav::new("endpoints", &s, &u)).await
}

async fn show(st: &Arc<AppState>, nav: Nav) -> Response {
    let list = match st.db.list_endpoints().await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "list endpoints failed");
            return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
        }
    };
    // The page lists without probing; Test probes one.
    let endpoints = list
        .into_iter()
        .map(|e| EndpointView {
            status: if e.enabled {
                Status::Down(String::new())
            } else {
                Status::Disabled
            },
            id: e.id,
            name: e.name,
            address: e.address,
            enabled: e.enabled,
            is_default: e.is_default,
        })
        .collect();
    let status = if nav.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    let allowlist = st
        .cfg
        .clamd_host_allowlist
        .iter()
        .map(|h| h.trim())
        .filter(|h| !h.is_empty())
        .collect::<Vec<_>>()
        .join(", ");
    render(
        status,
        &EndpointsPage {
            nav,
            endpoints,
            allowlist,
        },
    )
}

async fn result(
    st: &Arc<AppState>,
    s: &Session,
    me: &User,
    error: Option<String>,
    success: Option<String>,
) -> Response {
    let mut nav = Nav::new("endpoints", s, me);
    nav.error = error;
    nav.success = success;
    show(st, nav).await
}

fn valid_name(n: &str) -> bool {
    (1..=64).contains(&n.chars().count()) && !n.chars().any(char::is_control)
}

/// Parse and sanity-check an admin-supplied address.
fn parse_address(a: &str) -> Result<clamd::Endpoint, &'static str> {
    let ep: clamd::Endpoint = a
        .parse()
        .map_err(|_| "Use tcp://host:port or unix:///path/to/clamd.sock.")?;
    match &ep {
        clamd::Endpoint::Tcp { host, .. } => {
            let ok = host.len() <= 253
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'));
            if !ok {
                return Err("That host name is not valid.");
            }
        }
        clamd::Endpoint::Unix(p) => {
            if !p.is_absolute() || a.len() > 512 || a.chars().any(char::is_control) {
                return Err("Socket paths must be absolute.");
            }
        }
    }
    Ok(ep)
}

#[derive(Deserialize)]
struct CreateForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    // Defaults so a malformed form still hits the role check first.
    #[serde(default)]
    name: String,
    #[serde(default)]
    address: String,
    make_default: Option<String>,
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
    let name = f.name.trim();
    if !valid_name(name) {
        return result(
            &st,
            &s,
            &me,
            Some("Names are 1 to 64 characters.".into()),
            None,
        )
        .await;
    }
    let ep = match parse_address(f.address.trim()) {
        Ok(ep) => ep,
        Err(m) => return result(&st, &s, &me, Some(m.into()), None).await,
    };
    if !st.endpoint_allowed(&ep) {
        tracing::warn!(event = "clamd.endpoint_denied", endpoint = %ep, user = %me.username, "endpoint not on CLAMD_HOST_ALLOWLIST");
        return result(
            &st,
            &s,
            &me,
            Some("That host is not on CLAMD_HOST_ALLOWLIST.".into()),
            None,
        )
        .await;
    }
    if st.db.list_endpoints().await.map_or(0, |l| l.len()) >= MAX_ENDPOINTS {
        return result(
            &st,
            &s,
            &me,
            Some(format!("At most {MAX_ENDPOINTS} endpoints.")),
            None,
        )
        .await;
    }
    let address = ep.to_string();
    match st
        .db
        .create_endpoint(name, &address, f.make_default.is_some())
        .await
    {
        Ok(_) => {
            audit(
                &st,
                &me,
                &info,
                "ENDPOINT_CREATE",
                format!("{name} {address}"),
            )
            .await;
            result(&st, &s, &me, None, Some(format!("Added {name}."))).await
        }
        Err(_) => {
            result(
                &st,
                &s,
                &me,
                Some("That name is already taken.".into()),
                None,
            )
            .await
        }
    }
}

#[derive(Deserialize)]
struct CsrfForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

#[derive(Deserialize)]
struct ToggleForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    enabled: Option<String>,
}

/// Admin + CSRF + an existing endpoint.
async fn target(
    st: &Arc<AppState>,
    auth: Auth,
    csrf: Option<&str>,
    id: &str,
) -> Result<(Session, User, Endpoint), Response> {
    let (s, me) = admin_post(auth, csrf)?;
    match st.db.endpoint(id).await {
        Ok(Some(e)) => Ok((s, me, e)),
        _ => Err(result(st, &s, &me, Some("No such endpoint.".into()), None).await),
    }
}

async fn make_default(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let (s, me, e) = match target(&st, auth, f.csrf.as_deref(), &id).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if st.db.set_default_endpoint(&e.id).await.is_err() {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    audit(&st, &me, &info, "ENDPOINT_DEFAULT", e.name.clone()).await;
    result(
        &st,
        &s,
        &me,
        None,
        Some(format!("{} is now the default.", e.name)),
    )
    .await
}

async fn toggle(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<ToggleForm>,
) -> Response {
    let (s, me, e) = match target(&st, auth, f.csrf.as_deref(), &id).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if e.is_default {
        return result(
            &st,
            &s,
            &me,
            Some("The default endpoint is always enabled.".into()),
            None,
        )
        .await;
    }
    let enabled = f.enabled.is_some();
    if st.db.set_endpoint_enabled(&e.id, enabled).await.is_err() {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    audit(
        &st,
        &me,
        &info,
        "ENDPOINT_UPDATE",
        format!("{} enabled={enabled}", e.name),
    )
    .await;
    let word = if enabled { "enabled" } else { "disabled" };
    result(&st, &s, &me, None, Some(format!("{} {word}.", e.name))).await
}

async fn delete(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let (s, me, e) = match target(&st, auth, f.csrf.as_deref(), &id).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    match st.db.delete_endpoint(&e.id).await {
        Ok(true) => {
            audit(
                &st,
                &me,
                &info,
                "ENDPOINT_DELETE",
                format!("{} {}", e.name, e.address),
            )
            .await;
            result(&st, &s, &me, None, Some(format!("Deleted {}.", e.name))).await
        }
        Ok(false) => {
            result(
                &st,
                &s,
                &me,
                Some("Pick another default before deleting this one.".into()),
                None,
            )
            .await
        }
        Err(_) => error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    }
}

async fn test(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let (s, me, mut e) = match target(&st, auth, f.csrf.as_deref(), &id).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    e.enabled = true;
    match probe(&st, &e).await {
        Status::Up(v) => {
            result(
                &st,
                &s,
                &me,
                None,
                Some(format!("{} answered: {v}", e.name)),
            )
            .await
        }
        Status::Down(m) => {
            result(
                &st,
                &s,
                &me,
                Some(format!("{} did not answer: {m}", e.name)),
                None,
            )
            .await
        }
        Status::Disabled => result(&st, &s, &me, None, None).await,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_address;

    #[test]
    fn addresses() {
        assert!(parse_address("tcp://clamav:3310").is_ok());
        assert!(parse_address("clamav:3310").is_ok());
        assert!(parse_address("tcp://[::1]:3310").is_ok());
        assert!(parse_address("unix:///run/clamav/clamd.sock").is_ok());
        assert!(parse_address("unix://relative.sock").is_err());
        assert!(parse_address("tcp://a/b:3310").is_err());
        assert!(parse_address("tcp://host:0").is_err());
        assert!(parse_address("http://x:1").is_err());
    }
}
