//! Browser UI: pages, login, static assets.

pub mod admin;
pub mod agents;
pub mod canaries;
pub mod charts;
pub mod clamdconf;
pub mod coverage;
pub mod crowdsec;
pub mod csrf;
pub mod detections;
pub mod endpoints;
pub mod integrations;
pub mod integrity;
pub mod mfa;
pub mod oidc;
pub mod passkeys;
pub mod scan;
pub mod schedules;
pub mod search;
pub mod session;
pub mod settings;
pub mod timeline;
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
        .merge(agents::routes())
        .merge(clamdconf::routes())
        .merge(schedules::routes())
        .merge(watch::routes())
        .merge(integrations::routes())
        .merge(settings::routes())
        .merge(oidc::routes())
        .merge(mfa::routes())
        .merge(passkeys::routes())
        .merge(detections::routes())
        .merge(canaries::routes())
        .merge(coverage::routes())
        .merge(integrity::routes())
        .merge(timeline::routes())
        .merge(crowdsec::routes())
        .route(
            "/{*path}",
            get(asset).layer(tower_http::compression::CompressionLayer::new()),
        )
}

/// Short hash over every static file, appended as `?v=` so browsers can keep
/// assets for a year and still pick up a new image at once.
pub fn asset_v() -> &'static str {
    static V: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    V.get_or_init(|| {
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        let mut names: Vec<_> = Assets::iter().collect();
        names.sort();
        for n in names {
            if let Some(f) = Assets::get(&n) {
                ctx.update(n.as_bytes());
                ctx.update(&f.metadata.sha256_hash());
            }
        }
        ctx.finish().as_ref()[..6]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    })
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

async fn asset(Path(path): Path<String>, uri: axum::http::Uri, headers: HeaderMap) -> Response {
    match Assets::get(&path) {
        Some(file) => {
            let etag: String = file.metadata.sha256_hash()[..16]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let etag = format!("\"{etag}\"");
            // A matching ?v= means this exact content, so it never changes.
            let versioned = uri
                .query()
                .is_some_and(|q| q.split('&').any(|p| p == format!("v={}", asset_v())));
            let cache = if versioned {
                "public, max-age=31536000, immutable"
            } else {
                "public, max-age=3600"
            };
            let fresh = headers
                .get(header::IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.split(',').any(|t| t.trim() == etag));
            let mut res = if fresh {
                StatusCode::NOT_MODIFIED.into_response()
            } else {
                let mut r = file.data.into_owned().into_response();
                if let Ok(v) = HeaderValue::from_str(file.metadata.mimetype()) {
                    r.headers_mut().insert(header::CONTENT_TYPE, v);
                }
                r
            };
            let h = res.headers_mut();
            h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
            if let Ok(v) = HeaderValue::from_str(&etag) {
                h.insert(header::ETAG, v);
            }
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
        return mfa::after_password(&st, auth, &user, &req_parts, "LDAP").await;
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
    mfa::after_password(&st, auth, &user, &req_parts, "UI").await
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
    range: String,
    kpis: Vec<Kpi>,
    chart: String,
    top_sigs: Vec<Top>,
    top_folders: Vec<Top>,
    top_hosts: Vec<Top>,
    recent_hits: Vec<DetView>,
    endpoints: Vec<(endpoints::EndpointView, String, bool)>,
    recent: Vec<scan::JobRow>,
    controls: Vec<(String, String, bool)>,
    update: Option<crate::update::Release>,
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

#[derive(Deserialize)]
struct DashQuery {
    range: Option<String>,
}

pub struct Kpi {
    pub label: &'static str,
    pub value: String,
    pub delta: String,
    pub tone: &'static str,
    pub href: String,
}

pub struct Top {
    pub label: String,
    pub count: i64,
    pub max: i64,
    pub href: String,
}

pub struct DetView {
    pub at: String,
    pub path: String,
    pub signature: String,
    pub host: String,
    pub job_id: String,
}

fn enc(v: &str) -> String {
    url::form_urlencoded::byte_serialize(v.as_bytes()).collect()
}

fn delta(now: i64, before: i64) -> String {
    if before == 0 {
        // No earlier data to compare with.
        return String::new();
    }
    let pct = (now - before) * 100 / before;
    match pct {
        0 => "same as before".into(),
        p if p > 0 => format!("+{p}% vs previous"),
        p => format!("{p}% vs previous"),
    }
}

/// Parent folders of detections, counted, most first.
pub(crate) fn folders(paths: &[String], n: usize) -> Vec<(String, i64)> {
    let mut m: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for p in paths {
        let readable = p.split(crate::watch::RAW_MARK).next().unwrap_or(p);
        let dir = std::path::Path::new(readable)
            .parent()
            .map(|d| d.to_string_lossy().into_owned())
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| "(upload)".into());
        *m.entry(dir).or_default() += 1;
    }
    let mut v: Vec<_> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

fn tops(v: Vec<(String, i64)>, href: impl Fn(&str) -> String) -> Vec<Top> {
    let max = v.iter().map(|x| x.1).max().unwrap_or(1).max(1);
    v.into_iter()
        .map(|(label, count)| Top {
            href: href(&label),
            label,
            count,
            max,
        })
        .collect()
}

async fn dashboard(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    headers: HeaderMap,
    Query(q): Query<DashQuery>,
) -> Response {
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
    let now = crate::db::now_ms();
    let offset = tz_offset_ms(&headers);
    let range = match q.range.as_deref() {
        Some("7d") => "7d",
        Some("30d") => "30d",
        _ => "24h",
    };
    let (span, bucket, hourly) = match range {
        "7d" => (7 * 86_400_000, 6 * 3_600_000, true),
        "30d" => (30 * 86_400_000, 86_400_000, false),
        _ => (86_400_000, 3_600_000, true),
    };
    let since = now - span;
    let cur = st.db.job_counts_since(since).await.unwrap_or_default();
    let all = st
        .db
        .job_counts_since(since - span)
        .await
        .unwrap_or_default();
    let prev = (all.0 - cur.0, all.1 - cur.1, all.2 - cur.2);
    let files = st.db.files_scanned_since(since).await.unwrap_or(0);
    let hits = st
        .db
        .count_detections(&crate::db::stats::DetectionFilter {
            since: Some(since),
            ..Default::default()
        })
        .await
        .unwrap_or(0);
    let active = st.db.count_active_jobs().await.unwrap_or_default();
    let agents = st.db.list_agents().await.unwrap_or_default();
    let online = agents
        .iter()
        .filter(|a| crate::agent::is_online(a, now))
        .count();
    let is_op = u.role.allows(Role::Operator);
    let jl = |extra: &str| {
        if is_op {
            format!("/jobs?range={range}{extra}")
        } else {
            String::new()
        }
    };
    let mut kpis = vec![
        Kpi {
            label: "Scans",
            value: cur.0.to_string(),
            delta: delta(cur.0, prev.0),
            tone: "",
            href: jl(""),
        },
        Kpi {
            label: "Scans with detections",
            value: cur.1.to_string(),
            delta: delta(cur.1, prev.1),
            tone: if cur.1 > 0 { "danger" } else { "ok" },
            href: jl("&verdict=VIRUS_FOUND"),
        },
        Kpi {
            label: "Infected files",
            value: hits.to_string(),
            delta: String::new(),
            tone: if hits > 0 { "danger" } else { "ok" },
            href: if is_op {
                format!("/detections?range={range}")
            } else {
                String::new()
            },
        },
        Kpi {
            label: "Failed scans",
            value: cur.2.to_string(),
            delta: delta(cur.2, prev.2),
            tone: if cur.2 > 0 { "warn" } else { "" },
            href: jl("&verdict=ERROR"),
        },
        Kpi {
            label: "Files scanned",
            value: files.to_string(),
            delta: String::new(),
            tone: "",
            href: String::new(),
        },
        Kpi {
            label: "Queued · running",
            value: format!("{} · {}", active.0, active.1),
            delta: String::new(),
            tone: "",
            href: if is_op {
                "/jobs?status=QUEUED".into()
            } else {
                String::new()
            },
        },
    ];
    if !agents.is_empty() {
        kpis.push(Kpi {
            label: "Agents online",
            value: format!("{online} / {}", agents.len()),
            delta: String::new(),
            tone: if online < agents.iter().filter(|a| a.enabled).count() {
                "warn"
            } else {
                "ok"
            },
            href: if u.role.allows(Role::Admin) {
                "/admin/agents".into()
            } else {
                String::new()
            },
        });
    }
    let buckets = st
        .db
        .activity(since, bucket, offset)
        .await
        .unwrap_or_default();
    let count = usize::try_from(span / bucket).unwrap_or(24) + 1;
    let chart = charts::activity(&buckets, since, bucket, count, offset, hourly);

    let names = scan::endpoint_names(&st).await;
    let f = crate::db::stats::DetectionFilter {
        since: Some(since),
        ..Default::default()
    };
    let (top_sigs, top_folders, top_hosts, recent_hits, recent) = if is_op {
        let sigs = st.db.detection_signatures(&f, 8).await.unwrap_or_default();
        let paths = st.db.detection_paths(&f, 5000).await.unwrap_or_default();
        let hosts: Vec<(String, i64)> = st
            .db
            .detection_sources(&f)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(e, a, n)| (names.label(e, a), n))
            .take(8)
            .collect();
        let recent_hits = st
            .db
            .list_detections(&crate::db::stats::DetectionFilter::default(), 0, 6)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|d| DetView {
                at: admin::fmt_ts(d.found_at),
                host: names.label(d.endpoint_id, d.agent_id),
                path: d.path,
                signature: d.signature,
                job_id: d.job_id,
            })
            .collect();
        let recent = st
            .db
            .list_jobs(&crate::db::jobs::JobFilter::default(), 0, 8)
            .await
            .map(|(j, _)| j.iter().map(|j| scan::row(j, &names)).collect())
            .unwrap_or_default();
        (
            tops(sigs, |l| {
                format!("/detections?range={range}&signature={}", enc(l))
            }),
            tops(folders(&paths, 8), |l| {
                format!(
                    "/detections?range={range}&q={}",
                    enc(&format!("path:\"{l}\""))
                )
            }),
            tops(hosts, |l| {
                format!(
                    "/detections?range={range}&q={}",
                    enc(&format!("host=\"{l}\""))
                )
            }),
            recent_hits,
            recent,
        )
    } else {
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new())
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
            range: range.to_owned(),
            kpis,
            chart,
            top_sigs,
            top_folders,
            top_hosts,
            recent_hits,
            endpoints,
            recent,
            controls,
            update: u
                .role
                .allows(Role::Admin)
                .then(|| st.updates.available())
                .flatten(),
        },
    )
}

/// Browser time-zone offset (minutes east of UTC) from the `clamv_tz` cookie, in ms.
pub fn tz_offset_ms(h: &HeaderMap) -> i64 {
    session::cookie(h, "clamv_tz")
        .and_then(|v| v.parse::<i64>().ok())
        .map_or(0, |m| m.clamp(-14 * 60, 14 * 60) * 60_000)
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
