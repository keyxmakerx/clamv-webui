//! Browser UI: pages, login, static assets.

pub mod admin;
pub mod csrf;
pub mod endpoints;
pub mod scan;
pub mod schedules;
pub mod session;
pub mod tokens;

use endpoints::Status;

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use serde::Deserialize;

use crate::app::AppState;
use crate::auth::login::Failure;
use crate::auth::{Role, password};
use crate::db::audit::AuditEntry;
use crate::db::users::User;
use session::{Auth, clear_cookie, client_ip, set_cookie};

#[derive(rust_embed::Embed)]
#[folder = "static/"]
struct Assets;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(|| async { Redirect::to("/dashboard") }))
        .route("/login", get(login_page).post(login))
        .route("/logout", axum::routing::post(logout))
        .route(
            "/account/password",
            get(password_page).post(change_password),
        )
        .route("/dashboard", get(dashboard))
        .merge(admin::routes())
        .merge(endpoints::routes())
        .merge(scan::routes())
        .merge(tokens::routes())
        .merge(schedules::routes())
        .route("/{*path}", get(asset))
}

/// Shared data for the page shell.
pub struct Nav {
    pub page: &'static str,
    pub username: String,
    pub role: Role,
    pub is_admin: bool,
    pub is_operator: bool,
    pub csrf: String,
    pub error: Option<String>,
    pub success: Option<String>,
}

impl Nav {
    pub fn new(page: &'static str, s: &crate::db::sessions::Session, u: &User) -> Self {
        Self {
            page,
            username: u.username.clone(),
            role: u.role,
            is_admin: u.role.allows(Role::Admin),
            is_operator: u.role.allows(Role::Operator),
            csrf: s.csrf_token.clone(),
            error: None,
            success: None,
        }
    }
}

pub fn render<T: Template>(status: StatusCode, t: &T) -> Response {
    match t.render() {
        Ok(html) => (status, [(header::CACHE_CONTROL, "no-store")], Html(html)).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "template render failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage<'a> {
    status: u16,
    message: &'a str,
}

/// Generic error page; details belong in the log, not here.
pub fn error_page(status: StatusCode, message: &str) -> Response {
    render(
        status,
        &ErrorPage {
            status: status.as_u16(),
            message,
        },
    )
}

async fn asset(Path(path): Path<String>) -> Response {
    match Assets::get(&path) {
        Some(file) => {
            let mime = file.metadata.mimetype();
            let mut res = file.data.into_owned().into_response();
            if let Ok(v) = HeaderValue::from_str(mime) {
                res.headers_mut().insert(header::CONTENT_TYPE, v);
            }
            res.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=86400"),
            );
            res
        }
        None => error_page(StatusCode::NOT_FOUND, "Page not found."),
    }
}

// ---- login ----

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    error: Option<&'static str>,
    info: Option<&'static str>,
    username: String,
}

#[derive(Deserialize)]
struct LoginQuery {
    logout: Option<String>,
    changed: Option<String>,
}

async fn login_page(auth: Auth, Query(q): Query<LoginQuery>) -> Response {
    if auth.0.is_some() {
        return Redirect::to("/dashboard").into_response();
    }
    let info = if q.logout.is_some() {
        Some("You have signed out.")
    } else if q.changed.is_some() {
        Some("Password changed. Sign in again.")
    } else {
        None
    };
    render(
        StatusCode::OK,
        &LoginPage {
            error: None,
            info,
            username: String::new(),
        },
    )
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

const BAD_LOGIN: &str = "Invalid username or password.";

async fn login(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    req_parts: RequestInfo,
    Form(f): Form<LoginForm>,
) -> Response {
    let username: String = f.username.trim().chars().take(64).collect();
    let ip = req_parts.ip;
    let page = |status, error| {
        render(
            status,
            &LoginPage {
                error: Some(error),
                info: None,
                username: username.clone(),
            },
        )
    };
    let user = match crate::auth::login::authenticate(
        &st,
        &username,
        &f.password,
        ip,
        req_parts.user_agent.as_deref(),
        "UI",
    )
    .await
    {
        Ok(u) => u,
        Err(Failure::Locked) => {
            return page(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many login attempts. Try again later.",
            );
        }
        Err(Failure::Bad) => return page(StatusCode::UNAUTHORIZED, BAD_LOGIN),
        Err(Failure::Unavailable) => {
            return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
        }
    };
    // Fresh session id on every login (no fixation); drop any old one.
    if let Some((old, _)) = auth.0 {
        let _ = st.db.delete_session_by_hash(&old.id_hash).await;
    }
    let ua = req_parts.user_agent.as_deref();
    let ip_s = ip.to_string();
    let (raw, _) = match st
        .db
        .create_session(&user.id, st.cfg.session_max_ms(), Some(&ip_s), ua)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "session create failed");
            return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
        }
    };
    let _ = st.db.touch_login(&user.id).await;
    st.db
        .audit(AuditEntry {
            username: Some(user.username.clone()),
            action: "LOGIN",
            outcome: "OK",
            transport: Some("UI"),
            ip: Some(ip.to_string()),
            user_agent: req_parts.user_agent.clone(),
            ..Default::default()
        })
        .await;
    tracing::info!(event = "auth.login", user = %user.username, ip = %ip, "signed in");
    let to = if user.must_change_password {
        "/account/password"
    } else {
        "/dashboard"
    };
    let cookie = set_cookie(&raw, st.cfg.session_max_ms() / 1000, st.cfg.cookie_secure);
    ([(header::SET_COOKIE, cookie)], Redirect::to(to)).into_response()
}

#[derive(Deserialize)]
struct CsrfOnly {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

async fn logout(State(st): State<Arc<AppState>>, auth: Auth, Form(f): Form<CsrfOnly>) -> Response {
    if let Some((s, u)) = auth.0 {
        if !csrf::token_ok(&s.csrf_token, f.csrf.as_deref()) {
            return error_page(
                StatusCode::FORBIDDEN,
                "Your session form expired. Reload and try again.",
            );
        }
        let _ = st.db.delete_session_by_hash(&s.id_hash).await;
        tracing::info!(event = "auth.logout", user = %u.username, "signed out");
    }
    (
        [(header::SET_COOKIE, clear_cookie(st.cfg.cookie_secure))],
        Redirect::to("/login?logout"),
    )
        .into_response()
}

// ---- password change ----

#[derive(Template)]
#[template(path = "password.html")]
struct PasswordPage {
    csrf: String,
    must_change: bool,
    error: Option<String>,
}

async fn password_page(auth: Auth) -> Response {
    let Some((s, u)) = auth.0 else {
        return Redirect::to("/login").into_response();
    };
    render(
        StatusCode::OK,
        &PasswordPage {
            csrf: s.csrf_token,
            must_change: u.must_change_password,
            error: None,
        },
    )
}

#[derive(Deserialize)]
struct PasswordForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    current: String,
    new: String,
    confirm: String,
}

async fn change_password(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Form(f): Form<PasswordForm>,
) -> Response {
    let Some((s, u)) = auth.0 else {
        return Redirect::to("/login").into_response();
    };
    if !csrf::token_ok(&s.csrf_token, f.csrf.as_deref()) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Your session form expired. Reload and try again.",
        );
    }
    let fail = |msg: &str| {
        render(
            StatusCode::BAD_REQUEST,
            &PasswordPage {
                csrf: s.csrf_token.clone(),
                must_change: u.must_change_password,
                error: Some(msg.to_owned()),
            },
        )
    };
    match crate::auth::login::authenticate(
        &st,
        &u.username,
        &f.current,
        info.ip,
        info.user_agent.as_deref(),
        "UI",
    )
    .await
    {
        Ok(_) => {}
        Err(Failure::Locked) => return fail("Too many attempts. Try again later."),
        Err(Failure::Bad) => return fail("Current password is wrong."),
        Err(Failure::Unavailable) => {
            return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
        }
    }
    if f.new != f.confirm {
        return fail("The new passwords do not match.");
    }
    if f.new == f.current {
        return fail("Choose a password different from the current one.");
    }
    let new_pw = f.new.clone();
    let hash = match tokio::task::spawn_blocking(move || password::hash(&new_pw)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => return fail(&e.to_string()),
        Err(_) => return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    };
    if let Err(e) = st.db.set_password(&u.id, &hash, false, true).await {
        tracing::error!(error = %e, "password update failed");
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    st.db
        .audit(AuditEntry {
            username: Some(u.username.clone()),
            action: "PASSWORD_CHANGE",
            outcome: "OK",
            transport: Some("UI"),
            ip: Some(info.ip.to_string()),
            ..Default::default()
        })
        .await;
    tracing::info!(event = "auth.password_changed", user = %u.username, ip = %info.ip, "password changed; sessions ended");
    (
        [(header::SET_COOKIE, clear_cookie(st.cfg.cookie_secure))],
        Redirect::to("/login?changed"),
    )
        .into_response()
}

// ---- dashboard ----

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    nav: Nav,
    endpoints: Vec<endpoints::EndpointView>,
}

async fn dashboard(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Viewer) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let list = match st.db.list_endpoints().await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "list endpoints failed");
            return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
        }
    };
    // Raw clamd errors go to the log; the page shows a short reason.
    let mut endpoints = endpoints::probe_all(&st, list).await;
    for e in &mut endpoints {
        if let Status::Down(m) = &mut e.status {
            *m = "no response".to_owned();
        }
    }
    render(
        StatusCode::OK,
        &DashboardPage {
            nav: Nav::new("dashboard", &s, &u),
            endpoints,
        },
    )
}

// ---- request info ----

/// Client IP (socket peer only) and user agent.
pub struct RequestInfo {
    pub ip: std::net::IpAddr,
    pub user_agent: Option<String>,
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for RequestInfo {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self {
            ip: client_ip(&parts.extensions),
            user_agent: header_str(&parts.headers, header::USER_AGENT),
        })
    }
}

fn header_str(h: &HeaderMap, name: header::HeaderName) -> Option<String> {
    h.get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(255).collect())
}
