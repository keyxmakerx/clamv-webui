//! Browser UI: pages, login, static assets.

pub mod admin;
pub mod csrf;
pub mod endpoints;
pub mod integrations;
pub mod oidc;
pub mod scan;
pub mod schedules;
pub mod session;
pub mod settings;
pub mod tokens;
pub mod watch;

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
        .route("/clamd", get(clamd_status))
        .merge(admin::routes())
        .merge(endpoints::routes())
        .merge(scan::routes())
        .merge(tokens::routes())
        .merge(schedules::routes())
        .merge(watch::routes())
        .merge(integrations::routes())
        .merge(settings::routes())
        .merge(oidc::routes())
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
pub(crate) struct LoginPage {
    pub error: Option<&'static str>,
    pub info: Option<&'static str>,
    pub username: String,
    pub sso: Option<String>,
    pub ldap: bool,
    pub source: String,
}

#[derive(Deserialize)]
struct LoginQuery {
    logout: Option<String>,
    changed: Option<String>,
}

async fn login_page(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    Query(q): Query<LoginQuery>,
) -> Response {
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
            sso: st.oidc.as_ref().map(|o| o.label().to_owned()),
            ldap: st.ldap.is_some(),
            source: String::new(),
        },
    )
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    #[serde(default)]
    source: String,
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
    let source = if f.source == "ldap" && st.ldap.is_some() {
        "ldap"
    } else {
        ""
    }
    .to_owned();
    let page = |status, error| {
        render(
            status,
            &LoginPage {
                error: Some(error),
                info: None,
                username: username.clone(),
                sso: st.oidc.as_ref().map(|o| o.label().to_owned()),
                ldap: st.ldap.is_some(),
                source: source.clone(),
            },
        )
    };
    if source == "ldap" {
        use crate::auth::login::DirectoryFailure as D;
        let ua = req_parts.user_agent.as_deref();
        let user = match crate::auth::login::authenticate_ldap(&st, &username, &f.password, ip, ua)
            .await
        {
            Ok(u) => u,
            Err(D::Locked) => {
                return page(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many login attempts. Try again later.",
                );
            }
            Err(D::Bad) => return page(StatusCode::UNAUTHORIZED, BAD_LOGIN),
            Err(D::Denied) => {
                return page(
                    StatusCode::FORBIDDEN,
                    "Your account is not in a group that may use this app.",
                );
            }
            Err(D::Disabled) => {
                return page(StatusCode::FORBIDDEN, "Your account is disabled here.");
            }
            Err(D::Unavailable) => {
                return page(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "The directory is unavailable right now.",
                );
            }
        };
        return match begin_session(&st, auth, &user, &req_parts, "LDAP").await {
            Ok((cookie, to)) => ([(header::SET_COOKIE, cookie)], Redirect::to(to)).into_response(),
            Err(r) => r,
        };
    }
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
    match begin_session(&st, auth, &user, &req_parts, "UI").await {
        Ok((cookie, to)) => ([(header::SET_COOKIE, cookie)], Redirect::to(to)).into_response(),
        Err(r) => r,
    }
}

/// Create a fresh session (no fixation), audit the login, and return the cookie and landing page.
pub(crate) async fn begin_session(
    st: &AppState,
    auth: Auth,
    user: &User,
    info: &RequestInfo,
    transport: &'static str,
) -> Result<(String, &'static str), Response> {
    if let Some((old, _)) = auth.0 {
        let _ = st.db.delete_session_by_hash(&old.id_hash).await;
    }
    let ip_s = info.ip.to_string();
    let (raw, _) = match st
        .db
        .create_session(
            &user.id,
            st.cfg.session_max_ms(),
            Some(&ip_s),
            info.user_agent.as_deref(),
        )
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "session create failed");
            return Err(error_page(
                StatusCode::SERVICE_UNAVAILABLE,
                "Service unavailable.",
            ));
        }
    };
    let _ = st.db.touch_login(&user.id).await;
    st.db
        .audit(AuditEntry {
            username: Some(user.username.clone()),
            action: "LOGIN",
            outcome: "OK",
            transport: Some(transport),
            ip: Some(ip_s),
            user_agent: info.user_agent.clone(),
            ..Default::default()
        })
        .await;
    tracing::info!(event = "auth.login", user = %user.username, ip = %info.ip, transport, "signed in");
    let to = if user.must_change_password {
        "/account/password"
    } else {
        "/dashboard"
    };
    Ok((
        set_cookie(&raw, st.cfg.session_max_ms() / 1000, st.cfg.cookie_secure),
        to,
    ))
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
        if u.is_external()
            && let Some(o) = &st.oidc
            && let Some(url) = o.logout_url().await
        {
            return (
                [(header::SET_COOKIE, clear_cookie(st.cfg.cookie_secure))],
                Redirect::to(&url),
            )
                .into_response();
        }
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
    let error = u
        .is_external()
        .then(|| "Your password is managed by your sign-in provider.".to_owned());
    render(
        StatusCode::OK,
        &PasswordPage {
            csrf: s.csrf_token,
            must_change: u.must_change_password,
            error,
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
    endpoints: Vec<(endpoints::EndpointView, String, bool)>,
    day: (i64, i64, i64),
    active: (i64, i64),
    recent: Vec<scan::JobRow>,
    controls: Vec<(String, String, bool)>,
}

impl DashboardPage {
    fn badge(&self, v: &str) -> &'static str {
        scan::badge(v)
    }
}

/// Signature age from a clamd VERSION reply, and whether it is over a week.
fn signature_age(version: &str) -> (String, bool) {
    let (_, _, time) = crate::api::split_version(version);
    match time.as_deref().and_then(crate::timefmt::parse_clamd_date) {
        Some(t) => {
            let h = (crate::db::now_ms() - t).max(0) / 3_600_000;
            let text = if h < 48 {
                format!("signatures {h} h old")
            } else {
                format!("signatures {} days old", h / 24)
            };
            (text, h > 168)
        }
        None => (String::new(), false),
    }
}

#[derive(Template)]
#[template(path = "clamd.html")]
struct ClamdPage {
    nav: Nav,
    rows: Vec<crate::metrics::ClamdStatus>,
}

async fn clamd_status(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Viewer) {
        Ok(x) => x,
        Err(r) => return r,
    };
    render(
        StatusCode::OK,
        &ClamdPage {
            nav: Nav::new("clamd", &s, &u),
            rows: st.metrics.clamd_status(),
        },
    )
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
    let endpoints = endpoints
        .into_iter()
        .map(|e| {
            let (age, stale) = match &e.status {
                Status::Up(v) => signature_age(v),
                _ => (String::new(), false),
            };
            (e, age, stale)
        })
        .collect();
    let day = st
        .db
        .job_counts_since(crate::db::now_ms() - 86_400_000)
        .await
        .unwrap_or_default();
    let active = st.db.count_active_jobs().await.unwrap_or_default();
    // Job details are operator data; viewers see the counts only.
    let recent = if u.role.allows(Role::Operator) {
        let names = scan::endpoint_names(&st).await;
        st.db
            .list_jobs(&crate::db::jobs::JobFilter::default(), 0, 8)
            .await
            .map(|(j, _)| j.iter().map(|j| scan::row(j, &names)).collect())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let mut controls = Vec::new();
    for sc in st.db.list_schedules().await.unwrap_or_default() {
        if !sc.eicar_check {
            continue;
        }
        if let Ok(Some(j)) = st.db.last_control_job(&sc.id).await {
            let ok = j.verdict.as_deref() == Some(crate::db::jobs::OK);
            controls.push((sc.name.clone(), admin::fmt_ts(j.submitted_at), ok));
        }
    }
    render(
        StatusCode::OK,
        &DashboardPage {
            nav: Nav::new("dashboard", &s, &u),
            endpoints,
            day,
            active,
            recent,
            controls,
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
