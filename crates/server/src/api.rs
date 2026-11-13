//! `/api/v1`: the JSON API that `clamctl` and its MCP server speak.
//!
//! Wire-compatible with `openapi/clamav-v1.yaml`. Authentication is a bearer
//! token, HTTP Basic (same throttle as the login form, S2) or the browser
//! session. Writes without a bearer token need the session CSRF token in
//! `X-CSRF-TOKEN`. Every route checks its own scope (lesson 8).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::{FromRequestParts, Multipart, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::app::AppState;
use crate::auth::Role;
use crate::auth::login::{Failure, authenticate};
use crate::auth::token::constant_time_eq;
use crate::db::audit::AuditEntry;
use crate::db::endpoints::Endpoint;
use crate::db::jobs::{self, Job, JobFilter, NewJob};
use crate::db::now_ms;
use crate::db::sessions::Session;
use crate::db::tokens::{ApiToken, NewToken, SCOPES};
use crate::db::users::User;
use crate::scan;
use crate::timefmt::{parse_clamd_date, rfc3339};
use crate::web::session::{COOKIE, client_ip, cookie, set_cookie};

const CSRF_HEADER: &str = "X-CSRF-TOKEN";
const MAX_PAGE: i64 = 100;
/// Signatures older than this are STALE (Java `api.v1.clamd.max-database-age-hours`).
const MAX_SIGNATURE_AGE_HOURS: i64 = 168;
/// Sessions created for Basic-auth writes are short-lived.
const BASIC_SESSION_MS: i64 = 15 * 60 * 1000;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/auth", get(whoami))
        .route("/api/v1/csrf", get(csrf_token))
        .route("/api/v1/health/live", get(live))
        .route("/api/v1/health/ready", get(ready))
        .route("/api/v1/health/clamd", get(clamd_health))
        .route("/api/v1/metrics/clamd", get(clamd_metrics))
        .route("/api/v1/endpoints", get(endpoints))
        .route("/api/v1/jobs", get(list_jobs))
        .route("/api/v1/jobs/{id}", get(job))
        .route("/api/v1/jobs/{id}/progress", get(progress))
        .route("/api/v1/scans/paths", post(scan_path))
        .route("/api/v1/audit", get(audit))
        .route("/api/v1/tokens", get(list_tokens).post(create_token))
        .route("/api/v1/tokens/{id}", delete(revoke_token))
        .route("/api/v1/openapi.yaml", get(openapi))
        .route(
            "/api/v1/{*rest}",
            get(api_404).post(api_404).delete(api_404),
        )
}

/// Upload route; the router gives it the large body limit and no timeout.
pub fn upload_routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/v1/scans/uploads", post(scan_uploads))
}

pub fn err(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"error": code, "message": message, "timestamp": rfc3339(now_ms())})),
    )
        .into_response()
}

fn ok(status: StatusCode, body: Value) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

fn forbidden() -> Response {
    err(
        StatusCode::FORBIDDEN,
        "forbidden",
        "Insufficient privilege.",
    )
}

fn bad(message: &str) -> Response {
    err(StatusCode::BAD_REQUEST, "invalid_request", message)
}

fn unavailable() -> Response {
    err(
        StatusCode::SERVICE_UNAVAILABLE,
        "internal_error",
        "Service unavailable.",
    )
}

// ---- authentication ----

pub enum Who {
    User(User),
    Token(ApiToken),
}

pub enum Via {
    Bearer,
    Basic,
    Cookie,
}

/// The authenticated caller.
pub struct Principal {
    pub who: Who,
    pub via: Via,
    /// The cookie session belonging to this user, if one came with the request.
    pub session: Option<Session>,
    pub ip: std::net::IpAddr,
    pub user_agent: Option<String>,
}

fn role_allows(role: Role, scope: &str) -> bool {
    match scope {
        "health:read" | "endpoints:read" => true,
        "jobs:read" | "scan:upload" | "scan:path" => role.allows(Role::Operator),
        "audit:read" => role.allows(Role::Admin),
        _ => false,
    }
}

impl Principal {
    pub fn name(&self) -> String {
        match &self.who {
            Who::User(u) => u.username.clone(),
            Who::Token(t) => format!("token:{}", t.label),
        }
    }

    fn require(&self, scope: &str) -> Result<(), Response> {
        let yes = match &self.who {
            Who::User(u) => role_allows(u.role, scope),
            Who::Token(t) => t.has(scope),
        };
        if yes { Ok(()) } else { Err(forbidden()) }
    }

    fn endpoint_ok(&self, id: Option<i64>) -> bool {
        match (&self.who, id) {
            (Who::Token(t), Some(id)) => t.endpoint_ids.as_ref().is_none_or(|l| l.contains(&id)),
            // A restricted token never sees jobs without an endpoint.
            (Who::Token(t), None) => t.endpoint_ids.is_none(),
            (Who::User(_), _) => true,
        }
    }

    /// Writes without a bearer token must carry the session CSRF token.
    fn check_csrf(&self, headers: &HeaderMap) -> Result<(), Response> {
        if matches!(self.via, Via::Bearer) {
            return Ok(());
        }
        let supplied = headers
            .get(CSRF_HEADER)
            .or_else(|| headers.get("X-XSRF-TOKEN"))
            .and_then(|v| v.to_str().ok());
        match (&self.session, supplied) {
            (Some(s), Some(t)) if constant_time_eq(&s.csrf_token, t) => Ok(()),
            _ => {
                tracing::warn!(event = "auth.csrf_rejected", principal = %self.name(), "API write without a valid CSRF token");
                Err(err(
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    "CSRF token missing or invalid; GET /api/v1/csrf first.",
                ))
            }
        }
    }

    fn transport(&self) -> &'static str {
        match self.via {
            Via::Bearer => "API_TOKEN",
            Via::Basic => "API_BASIC",
            Via::Cookie => "API_SESSION",
        }
    }

    async fn audit(
        &self,
        st: &AppState,
        action: &'static str,
        job: Option<&Job>,
        details: Option<String>,
    ) {
        st.db
            .audit(AuditEntry {
                username: Some(self.name()),
                action,
                outcome: "OK",
                details,
                job_id: job.map(|j| j.id.clone()),
                transport: Some(self.transport()),
                endpoint_id: job.and_then(|j| j.endpoint_id),
                ip: Some(self.ip.to_string()),
                user_agent: self.user_agent.clone(),
            })
            .await;
    }
}

impl FromRequestParts<Arc<AppState>> for Principal {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, st: &Arc<AppState>) -> Result<Self, Response> {
        let ip = client_ip(&parts.extensions);
        let user_agent = parts
            .headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(256).collect::<String>());
        let session = match cookie(&parts.headers, COOKIE) {
            Some(raw) => st
                .db
                .session_user(&raw, st.cfg.session_idle_ms())
                .await
                .map_err(|_| unavailable())?,
            None => None,
        };
        let authz = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let (who, via) = match authz {
            Some(a) if a.len() > 7 && a[..7].eq_ignore_ascii_case("bearer ") => {
                match st.db.token_by_secret(a[7..].trim()).await {
                    Ok(Some(t)) => (Who::Token(t), Via::Bearer),
                    Ok(None) => {
                        tracing::warn!(event = "auth.failed", ip = %ip, transport = "API_TOKEN", "invalid, expired or revoked API token");
                        return Err(err(
                            StatusCode::UNAUTHORIZED,
                            "invalid_token",
                            "Missing, invalid or expired bearer token.",
                        ));
                    }
                    Err(_) => return Err(unavailable()),
                }
            }
            Some(a) if a.len() > 6 && a[..6].eq_ignore_ascii_case("basic ") => {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(a[6..].trim())
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok());
                let Some((name, pw)) = decoded.as_deref().and_then(|d| d.split_once(':')) else {
                    return Err(err(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized",
                        "Authentication required.",
                    ));
                };
                let name: String = name.trim().chars().take(64).collect();
                match authenticate(st, &name, pw, ip, user_agent.as_deref(), "API_BASIC").await {
                    Ok(u) => (Who::User(u), Via::Basic),
                    Err(Failure::Locked) => {
                        return Err(err(
                            StatusCode::TOO_MANY_REQUESTS,
                            "rate_limited",
                            "Too many failed sign-ins. Try again later.",
                        ));
                    }
                    Err(Failure::Bad) => {
                        return Err(err(
                            StatusCode::UNAUTHORIZED,
                            "unauthorized",
                            "Authentication required.",
                        ));
                    }
                    Err(Failure::Unavailable) => return Err(unavailable()),
                }
            }
            Some(_) => {
                return Err(err(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "Authentication required.",
                ));
            }
            None => match &session {
                Some((_, u)) => (Who::User(u.clone()), Via::Cookie),
                None => {
                    return Err(err(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized",
                        "Authentication required.",
                    ));
                }
            },
        };
        if let Who::User(u) = &who
            && u.must_change_password
        {
            return Err(err(
                StatusCode::FORBIDDEN,
                "forbidden",
                "Change the password in the web UI first.",
            ));
        }
        // Only a session of this same user can back a CSRF token.
        let session = match (&who, session) {
            (Who::User(u), Some((s, su))) if su.id == u.id => Some(s),
            _ => None,
        };
        Ok(Principal {
            who,
            via,
            session,
            ip,
            user_agent,
        })
    }
}

// ---- identity and CSRF ----

async fn whoami(p: Principal) -> Response {
    let kind = match p.who {
        Who::User(_) => "user",
        Who::Token(_) => "token",
    };
    ok(
        StatusCode::OK,
        json!({"authenticated": true, "principal": p.name(), "authentication": kind}),
    )
}

async fn csrf_token(State(st): State<Arc<AppState>>, p: Principal) -> Response {
    let Who::User(u) = &p.who else {
        return bad("Bearer requests do not need a CSRF token.");
    };
    let body = |t: &str| json!({"token": t, "headerName": CSRF_HEADER, "parameterName": "_csrf"});
    if let Some(s) = &p.session {
        return ok(StatusCode::OK, body(&s.csrf_token));
    }
    // Basic clients get a short session cookie to pair with the token.
    let ip = p.ip.to_string();
    match st
        .db
        .create_session(&u.id, BASIC_SESSION_MS, Some(&ip), p.user_agent.as_deref())
        .await
    {
        Ok((raw, s)) => (
            StatusCode::OK,
            [
                (header::CACHE_CONTROL, "no-store".to_owned()),
                (
                    header::SET_COOKIE,
                    set_cookie(&raw, BASIC_SESSION_MS / 1000, st.cfg.cookie_secure),
                ),
            ],
            Json(body(&s.csrf_token)),
        )
            .into_response(),
        Err(_) => unavailable(),
    }
}

// ---- health ----

async fn live(_p: Principal) -> Response {
    ok(
        StatusCode::OK,
        json!({"status": "UP", "component": "web", "at": rfc3339(now_ms())}),
    )
}

async fn ready(State(st): State<Arc<AppState>>, _p: Principal) -> Response {
    let up = st.db.ping().await.is_ok();
    ok(
        if up {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        json!({"status": if up { "UP" } else { "DOWN" }, "component": "database", "at": rfc3339(now_ms())}),
    )
}

#[derive(Deserialize)]
struct EndpointQuery {
    #[serde(rename = "endpointId")]
    endpoint_id: Option<i64>,
}

/// The requested (or default) endpoint, if this caller may use it.
async fn visible_endpoint(
    st: &AppState,
    p: &Principal,
    id: Option<i64>,
) -> Result<Endpoint, Response> {
    let ep = match id {
        Some(id) => st.db.endpoint(id).await.map_err(|_| unavailable())?,
        None => st.db.default_endpoint().await.map_err(|_| unavailable())?,
    };
    match ep {
        Some(e) if e.enabled && p.endpoint_ok(Some(e.id)) => Ok(e),
        _ => Err(err(StatusCode::NOT_FOUND, "not_found", "No such endpoint.")),
    }
}

/// `ClamAV 1.4.0/27000/Thu Nov 12 09:00:00 2026` -> (version, db version, db time).
pub(crate) fn split_version(v: &str) -> (String, Option<String>, Option<String>) {
    let mut it = v.splitn(3, '/');
    let engine = it.next().unwrap_or_default().trim().to_owned();
    let db = it.next().map(|s| s.trim().to_owned());
    let time = it.next().map(|s| s.trim().to_owned());
    (engine, db, time)
}

async fn clamd_health(
    State(st): State<Arc<AppState>>,
    p: Principal,
    Query(q): Query<EndpointQuery>,
) -> Response {
    if let Err(r) = p.require("health:read") {
        return r;
    }
    let ep = match visible_endpoint(&st, &p, q.endpoint_id).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let now = now_ms();
    let version = match ep.parsed() {
        Ok(addr) => {
            let c = st.clamd(addr);
            tokio::time::timeout(Duration::from_secs(5), async {
                c.ping().await?;
                c.version().await
            })
            .await
            .ok()
            .and_then(Result::ok)
        }
        Err(_) => None,
    };
    let Some(v) = version else {
        tracing::warn!(event = "clamd.unreachable", endpoint = %ep.name, "clamd health check failed");
        return ok(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"endpointId": ep.id, "endpoint": ep.name, "connectivity": "DOWN", "version": null,
                   "signatureDatabaseVersion": null, "signatureDatabaseTime": null,
                   "signatureDatabaseTimestamp": null, "signatureDatabaseFreshness": "UNKNOWN",
                   "signatureAgeHours": null, "checkedAt": rfc3339(now)}),
        );
    };
    let (engine, db, time) = split_version(&v);
    let ts = time.as_deref().and_then(parse_clamd_date);
    let age = ts.map(|t| (now - t).max(0) / 3_600_000);
    let fresh = match age {
        Some(a) if a > MAX_SIGNATURE_AGE_HOURS => "STALE",
        Some(_) => "FRESH",
        None => "UNKNOWN",
    };
    let status = if fresh == "STALE" {
        tracing::warn!(event = "clamd.signatures_stale", endpoint = %ep.name, age_hours = age.unwrap_or(0), "clamd signatures are stale");
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    ok(
        status,
        json!({"endpointId": ep.id, "endpoint": ep.name, "connectivity": "UP", "version": engine,
               "signatureDatabaseVersion": db, "signatureDatabaseTime": time,
               "signatureDatabaseTimestamp": ts.map(rfc3339), "signatureDatabaseFreshness": fresh,
               "signatureAgeHours": age, "checkedAt": rfc3339(now)}),
    )
}

/// Allowlisted numbers from clamd STATS.
pub fn parse_stats(raw: &str) -> Value {
    let mut threads = BTreeMap::new();
    let mut queue = BTreeMap::new();
    let mut memory = BTreeMap::new();
    let mut pools: Option<i64> = None;
    for line in raw.lines() {
        let line = line.trim();
        if let Some(r) = line.strip_prefix("POOLS:") {
            pools = r.trim().parse().ok();
        } else if let Some(r) = line.strip_prefix("THREADS:") {
            let words: Vec<&str> = r.split_whitespace().collect();
            for pair in words.chunks(2) {
                if let [k, v] = pair
                    && matches!(*k, "live" | "idle" | "max" | "idle-timeout")
                    && let Ok(n) = v.parse::<i64>()
                {
                    threads.insert((*k).to_owned(), n);
                }
            }
        } else if let Some(r) = line.strip_prefix("QUEUE:") {
            if let Some(n) = r
                .split_whitespace()
                .next()
                .and_then(|n| n.parse::<i64>().ok())
            {
                queue.insert("items".to_owned(), n);
            }
        } else if let Some(r) = line.strip_prefix("MEMSTATS:") {
            let words: Vec<&str> = r.split_whitespace().collect();
            for pair in words.chunks(2) {
                if let [k, v] = pair
                    && matches!(
                        *k,
                        "heap"
                            | "mmap"
                            | "used"
                            | "free"
                            | "releasable"
                            | "pools_used"
                            | "pools_total"
                    )
                    && *v != "N/A"
                    && v.len() <= 32
                {
                    memory.insert((*k).to_owned(), (*v).to_owned());
                }
            }
        }
    }
    json!({"threads": threads, "queue": queue, "pools": pools, "memory": memory})
}

async fn clamd_metrics(
    State(st): State<Arc<AppState>>,
    p: Principal,
    Query(q): Query<EndpointQuery>,
) -> Response {
    if let Err(r) = p.require("health:read") {
        return r;
    }
    let ep = match visible_endpoint(&st, &p, q.endpoint_id).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let stats = match ep.parsed() {
        Ok(addr) => tokio::time::timeout(Duration::from_secs(5), st.clamd(addr).stats())
            .await
            .ok()
            .and_then(Result::ok),
        Err(_) => None,
    };
    let mut body = stats.as_deref().map_or_else(
        || json!({"threads": {}, "queue": {}, "pools": null, "memory": {}}),
        parse_stats,
    );
    body["endpointId"] = json!(ep.id);
    body["ok"] = json!(stats.is_some());
    body["checkedAt"] = json!(rfc3339(now_ms()));
    ok(StatusCode::OK, body)
}

async fn endpoints(State(st): State<Arc<AppState>>, p: Principal) -> Response {
    if let Err(r) = p.require("endpoints:read") {
        return r;
    }
    let Ok(list) = st.db.list_endpoints().await else {
        return unavailable();
    };
    let items: Vec<Value> = list
        .iter()
        .filter(|e| p.endpoint_ok(Some(e.id)))
        .map(|e| json!({"id": e.id, "name": e.name, "enabled": e.enabled}))
        .collect();
    ok(StatusCode::OK, Value::Array(items))
}

// ---- jobs ----

fn job_json(j: &Job) -> Value {
    let error = j
        .error_code
        .as_ref()
        .map(|c| json!({"code": c, "message": j.error_message.clone().unwrap_or_default()}));
    json!({
        "id": j.id,
        "type": j.kind,
        "status": j.status,
        "verdict": j.verdict,
        "endpointId": j.endpoint_id,
        // Only the upload display name; path targets stay private.
        "filename": (j.kind == scan::KIND_UPLOAD).then(|| j.target.clone()),
        "sizeBytes": j.size_bytes,
        "submittedAt": rfc3339(j.submitted_at),
        "startedAt": j.started_at.map(rfc3339),
        "finishedAt": j.finished_at.map(rfc3339),
        "signatures": j.signatures().into_iter().take(1000).map(|s| s.chars().take(256).collect::<String>()).collect::<Vec<_>>(),
        "durationMillis": j.duration_ms(),
        "quarantineStatus": if j.kind == scan::KIND_UPLOAD { "NOT_APPLICABLE" } else { "UNKNOWN" },
        "error": error,
    })
}

#[derive(Deserialize)]
struct JobsQuery {
    page: Option<i64>,
    size: Option<i64>,
    #[serde(rename = "endpointId")]
    endpoint_id: Option<i64>,
    status: Option<String>,
    verdict: Option<String>,
}

fn paging(page: Option<i64>, size: Option<i64>, default: i64) -> Result<(i64, i64), Response> {
    let page = page.unwrap_or(0);
    let size = size.unwrap_or(default);
    if !(0..=1_000_000).contains(&page) || !(1..=MAX_PAGE).contains(&size) {
        return Err(bad("page must be >= 0 and size between 1 and 100."));
    }
    Ok((page, size))
}

fn page_json(items: Vec<Value>, page: i64, size: i64, total: i64) -> Value {
    json!({"items": items, "page": page, "size": size, "totalItems": total,
           "totalPages": (total + size - 1) / size})
}

async fn list_jobs(
    State(st): State<Arc<AppState>>,
    p: Principal,
    q: Result<Query<JobsQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    if let Err(r) = p.require("jobs:read") {
        return r;
    }
    let Ok(Query(q)) = q else {
        return bad("Invalid query parameters.");
    };
    let (page, size) = match paging(q.page, q.size, 25) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if q.status
        .as_deref()
        .is_some_and(|s| ![jobs::QUEUED, jobs::RUNNING, jobs::FINISHED].contains(&s))
    {
        return bad("Unknown status.");
    }
    if q.verdict
        .as_deref()
        .is_some_and(|v| ![jobs::OK, jobs::VIRUS_FOUND, jobs::ERROR].contains(&v))
    {
        return bad("Unknown verdict.");
    }
    let endpoint_id = match (&p.who, q.endpoint_id) {
        (_, Some(id)) if !p.endpoint_ok(Some(id)) => return forbidden(),
        (Who::Token(t), None) => match t.endpoint_ids.as_deref() {
            None => None,
            Some([only]) => Some(*only),
            Some(_) => return bad("endpointId is required for this token."),
        },
        (_, id) => id,
    };
    let f = JobFilter {
        status: q.status,
        verdict: q.verdict,
        endpoint_id,
    };
    match st.db.list_jobs(&f, page, size).await {
        Ok((list, total)) => ok(
            StatusCode::OK,
            page_json(list.iter().map(job_json).collect(), page, size, total),
        ),
        Err(_) => unavailable(),
    }
}

async fn visible_job(st: &AppState, p: &Principal, id: &str) -> Result<Job, Response> {
    if id.len() > 64 {
        return Err(err(StatusCode::NOT_FOUND, "not_found", "No such job."));
    }
    match st.db.job(id).await {
        Ok(Some(j)) if p.endpoint_ok(j.endpoint_id) => Ok(j),
        Ok(_) => Err(err(StatusCode::NOT_FOUND, "not_found", "No such job.")),
        Err(_) => Err(unavailable()),
    }
}

async fn job(State(st): State<Arc<AppState>>, p: Principal, Path(id): Path<String>) -> Response {
    if let Err(r) = p.require("jobs:read") {
        return r;
    }
    match visible_job(&st, &p, &id).await {
        Ok(j) => ok(StatusCode::OK, job_json(&j)),
        Err(r) => r,
    }
}

async fn progress(
    State(st): State<Arc<AppState>>,
    p: Principal,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = p.require("jobs:read") {
        return r;
    }
    match visible_job(&st, &p, &id).await {
        Ok(j) => ok(
            StatusCode::OK,
            json!({"jobId": j.id, "status": j.status, "completed": j.status == jobs::FINISHED,
                   "verdict": j.verdict,
                   "updatedAt": rfc3339(j.finished_at.or(j.started_at).unwrap_or(j.submitted_at))}),
        ),
        Err(r) => r,
    }
}

// ---- scans ----

fn rate_limited(st: &AppState, p: &Principal) -> Result<(), Response> {
    let key = match &p.who {
        Who::User(u) => format!("u:{}", u.id),
        Who::Token(t) => format!("t:{}", t.id),
    };
    if st.scan_rate.allow(&key) {
        Ok(())
    } else {
        tracing::warn!(event = "api.rate_limited", principal = %p.name(), ip = %p.ip, "scan rate limit exceeded");
        Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_exceeded",
            "Scan rate limit exceeded.",
        ))
    }
}

/// Endpoint for a new job: requested or default, enabled, and visible to the caller.
async fn job_endpoint(st: &AppState, p: &Principal, id: Option<i64>) -> Result<Endpoint, Response> {
    match id {
        Some(id) if id <= 0 => Err(bad("endpointId must be positive.")),
        Some(id) if !p.endpoint_ok(Some(id)) => Err(forbidden()),
        _ => match scan::pick_endpoint(st, id).await {
            Some(e) if p.endpoint_ok(Some(e.id)) => Ok(e),
            Some(_) => Err(forbidden()),
            None => Err(err(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "No enabled clamd endpoint.",
            )),
        },
    }
}

#[derive(Deserialize)]
struct PathScan {
    path: String,
    #[serde(rename = "endpointId")]
    endpoint_id: Option<i64>,
}

async fn scan_path(
    State(st): State<Arc<AppState>>,
    p: Principal,
    headers: HeaderMap,
    body: Result<Json<PathScan>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(r) = p.require("scan:path").and_then(|()| p.check_csrf(&headers)) {
        return r;
    }
    let Ok(Json(body)) = body else {
        return bad("Send JSON with a path.");
    };
    if let Err(r) = rate_limited(&st, &p) {
        return r;
    }
    if st.cfg.scan_roots.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Path scans are off: SCAN_ROOTS is not set.",
        );
    }
    let ep = match job_endpoint(&st, &p, body.endpoint_id).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let real = match scan::resolve_path(&st.cfg.scan_roots, body.path.trim()).await {
        Ok(r) => r,
        Err(m) => {
            tracing::warn!(event = "scan.path_rejected", principal = %p.name(), ip = %p.ip, path = %body.path, "path outside SCAN_ROOTS or missing");
            return bad(m);
        }
    };
    // A token may be narrowed to some roots; each must itself sit inside SCAN_ROOTS.
    if let Who::Token(t) = &p.who
        && let Some(roots) = &t.path_roots
    {
        let mut inside = false;
        for r in roots {
            if let Ok(rr) = scan::resolve_path(&st.cfg.scan_roots, r).await
                && real.starts_with(&rr)
            {
                inside = true;
                break;
            }
        }
        if !inside {
            tracing::warn!(event = "scan.path_rejected", principal = %p.name(), ip = %p.ip, path = %body.path, "path outside the token's roots");
            return err(
                StatusCode::FORBIDDEN,
                "forbidden",
                "Token path restriction violation.",
            );
        }
    }
    let Some(target) = real.to_str() else {
        return bad("Only UTF-8 paths can be queued.");
    };
    let name = p.name();
    let job = match st
        .db
        .create_job(NewJob {
            kind: scan::KIND_PATH,
            target,
            endpoint_id: Some(ep.id),
            schedule_id: None,
            submitted_by: Some(&name),
            transport: p.transport(),
            running: false,
        })
        .await
    {
        Ok(j) => j,
        Err(_) => return unavailable(),
    };
    p.audit(&st, "SCAN_PATH", Some(&job), Some(job.target.clone()))
        .await;
    st.runner.poke();
    ok(
        StatusCode::ACCEPTED,
        json!({"jobId": job.id, "status": job.status, "created": 1, "jobIds": [job.id]}),
    )
}

async fn scan_uploads(
    State(st): State<Arc<AppState>>,
    p: Principal,
    headers: HeaderMap,
    mp: Result<Multipart, axum::extract::multipart::MultipartRejection>,
) -> Response {
    if let Err(r) = p
        .require("scan:upload")
        .and_then(|()| p.check_csrf(&headers))
    {
        return r;
    }
    let Ok(mut mp) = mp else {
        return bad("Send the files as multipart/form-data.");
    };
    if let Err(r) = rate_limited(&st, &p) {
        return r;
    }
    let name = p.name();
    let mut endpoint_id: Option<i64> = None;
    let mut ids: Vec<String> = Vec::new();
    loop {
        let field = match mp.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(_) => return bad("The upload could not be read."),
        };
        match field.name() {
            Some("endpointId") => {
                let raw = field.text().await.unwrap_or_default();
                match raw.trim().parse::<i64>() {
                    Ok(id) => endpoint_id = Some(id),
                    Err(_) if raw.trim().is_empty() => {}
                    Err(_) => return bad("endpointId must be a number."),
                }
            }
            Some("files") => {
                if ids.len() >= st.cfg.upload_max_files {
                    return err(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "upload_too_large",
                        "Too many files in one upload.",
                    );
                }
                let ep = match job_endpoint(&st, &p, endpoint_id).await {
                    Ok(e) => e,
                    Err(r) => return r,
                };
                let fname = crate::web::scan::display_name(field.file_name());
                let job = match st
                    .db
                    .create_job(NewJob {
                        kind: scan::KIND_UPLOAD,
                        target: &fname,
                        endpoint_id: Some(ep.id),
                        schedule_id: None,
                        submitted_by: Some(&name),
                        transport: p.transport(),
                        running: true,
                    })
                    .await
                {
                    Ok(j) => j,
                    Err(_) => return unavailable(),
                };
                p.audit(&st, "SCAN_UPLOAD", Some(&job), Some(fname.clone()))
                    .await;
                let o = crate::web::scan::scan_field(&st, &ep, field, &fname).await;
                scan::finish(&st, &job, Some(&ep), o).await;
                ids.push(job.id);
            }
            _ => {}
        }
    }
    if ids.is_empty() {
        return bad("No files were uploaded.");
    }
    ok(
        StatusCode::ACCEPTED,
        json!({"created": ids.len(), "jobIds": ids}),
    )
}

// ---- audit ----

#[derive(Deserialize)]
struct PageQuery {
    page: Option<i64>,
    size: Option<i64>,
}

async fn audit(
    State(st): State<Arc<AppState>>,
    p: Principal,
    q: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    if let Err(r) = p.require("audit:read") {
        return r;
    }
    let Ok(Query(q)) = q else {
        return bad("Invalid query parameters.");
    };
    let (page, size) = match paging(q.page, q.size, 25) {
        Ok(x) => x,
        Err(r) => return r,
    };
    match st.db.audit_page(page, size).await {
        Ok((rows, total)) => {
            let items = rows
                .iter()
                .map(|r| {
                    json!({"id": r.id, "at": rfc3339(r.at), "actor": r.username, "action": r.action,
                           "outcome": r.outcome, "transport": r.transport, "endpointId": r.endpoint_id,
                           "jobId": r.job_id})
                })
                .collect();
            ok(StatusCode::OK, page_json(items, page, size, total))
        }
        Err(_) => unavailable(),
    }
}

// ---- tokens (admin browser session only) ----

pub fn token_json(t: &ApiToken) -> Value {
    json!({
        "id": t.id, "label": t.label, "prefix": t.prefix, "scopes": t.scopes,
        "endpointIds": t.endpoint_ids, "pathRoots": t.path_roots, "createdBy": t.created_by,
        "createdAt": rfc3339(t.created_at), "expiresAt": t.expires_at.map(rfc3339),
        "revokedAt": t.revoked_at.map(rfc3339), "lastUsedAt": t.last_used_at.map(rfc3339),
        "active": t.active(now_ms()),
    })
}

fn admin_session(p: &Principal) -> Result<&User, Response> {
    match (&p.who, &p.via) {
        // Cookie or Basic (Basic writes also pass the session CSRF check); never a token.
        (Who::User(u), Via::Cookie | Via::Basic) if u.role.allows(Role::Admin) => Ok(u),
        _ => Err(err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Only administrators may issue credentials.",
        )),
    }
}

async fn list_tokens(State(st): State<Arc<AppState>>, p: Principal) -> Response {
    if let Err(r) = admin_session(&p) {
        return r;
    }
    match st.db.list_tokens().await {
        Ok(l) => ok(
            StatusCode::OK,
            Value::Array(l.iter().map(token_json).collect()),
        ),
        Err(_) => unavailable(),
    }
}

#[derive(Deserialize)]
pub struct TokenRequest {
    pub label: String,
    pub scopes: Vec<String>,
    #[serde(rename = "endpointIds")]
    pub endpoint_ids: Option<Vec<i64>>,
    #[serde(rename = "pathRoots")]
    pub path_roots: Option<Vec<String>>,
    /// Unix milliseconds or RFC 3339 is not parsed here; the UI sends days.
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
}

/// Validate a token request; returns a user-facing error message.
pub async fn validate_token(
    st: &AppState,
    label: &str,
    scopes: &[String],
    endpoint_ids: Option<&[i64]>,
    path_roots: Option<&[String]>,
) -> Result<(), String> {
    if label.trim().is_empty() || label.chars().count() > 100 || label.chars().any(char::is_control)
    {
        return Err("Labels are 1 to 100 characters.".into());
    }
    if scopes.is_empty() || scopes.iter().any(|s| !SCOPES.contains(&s.as_str())) {
        return Err(format!("Scopes must be some of: {}.", SCOPES.join(", ")));
    }
    if let Some(ids) = endpoint_ids {
        for id in ids {
            if !matches!(st.db.endpoint(*id).await, Ok(Some(_))) {
                return Err(format!("Unknown endpoint id {id}."));
            }
        }
    }
    if let Some(roots) = path_roots {
        for r in roots {
            if scan::resolve_path(&st.cfg.scan_roots, r).await.is_err() {
                return Err(format!("Path root {r} is not inside SCAN_ROOTS."));
            }
        }
    }
    Ok(())
}

/// Parse `YYYY-MM-DDTHH:MM:SS(.fff)Z` (the subset clients send).
fn parse_rfc3339(s: &str) -> Option<i64> {
    let s = s.trim().strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-');
    let (y, m, dd): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let time = time.split('.').next()?;
    let mut t = time.split(':');
    let (h, mi, se): (i64, i64, i64) = (
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    );
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mon = months.get(usize::try_from(m - 1).ok()?)?;
    parse_clamd_date(&format!("Mon {mon} {dd} {h:02}:{mi:02}:{se:02} {y}"))
}

async fn create_token(
    State(st): State<Arc<AppState>>,
    p: Principal,
    headers: HeaderMap,
    body: Result<Json<TokenRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let me = match admin_session(&p) {
        Ok(u) => u.clone(),
        Err(r) => return r,
    };
    if let Err(r) = p.check_csrf(&headers) {
        return r;
    }
    let Ok(Json(req)) = body else {
        return bad("Send JSON with label and scopes.");
    };
    let expires_at = match req.expires_at.as_deref() {
        None => None,
        Some(s) => match parse_rfc3339(s) {
            Some(t) if t > now_ms() => Some(t),
            _ => return bad("expiresAt must be a future UTC time like 2027-01-01T00:00:00Z."),
        },
    };
    if let Err(m) = validate_token(
        &st,
        &req.label,
        &req.scopes,
        req.endpoint_ids.as_deref(),
        req.path_roots.as_deref(),
    )
    .await
    {
        return bad(&m);
    }
    match st
        .db
        .create_token(NewToken {
            label: req.label.trim(),
            scopes: &req.scopes,
            endpoint_ids: req.endpoint_ids.as_deref(),
            path_roots: req.path_roots.as_deref(),
            created_by: &me.username,
            expires_at,
        })
        .await
    {
        Ok((secret, t)) => {
            p.audit(
                &st,
                "TOKEN_CREATE",
                None,
                Some(format!("{} ({})", t.label, t.prefix)),
            )
            .await;
            ok(
                StatusCode::CREATED,
                json!({"token": token_json(&t), "secret": secret}),
            )
        }
        Err(_) => unavailable(),
    }
}

async fn revoke_token(
    State(st): State<Arc<AppState>>,
    p: Principal,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = admin_session(&p)
        .map(|_| ())
        .and_then(|()| p.check_csrf(&headers))
    {
        return r;
    }
    let Ok(id) = id.parse::<i64>() else {
        return err(StatusCode::NOT_FOUND, "not_found", "No such token.");
    };
    match st.db.revoke_token(id).await {
        Ok(true) => {
            p.audit(&st, "TOKEN_REVOKE", None, Some(id.to_string()))
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => err(StatusCode::NOT_FOUND, "not_found", "No such token."),
        Err(_) => unavailable(),
    }
}

async fn api_404() -> Response {
    err(StatusCode::NOT_FOUND, "not_found", "No such API route.")
}

async fn openapi(_p: Principal) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/yaml"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        include_str!("../openapi/clamav-v1.yaml"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stats_and_versions() {
        let raw = "POOLS: 1\n\nSTATE: VALID PRIMARY\nTHREADS: live 1  idle 0 max 12 idle-timeout 30\nQUEUE: 0 items\n\tSTATS 0.000033\n\nMEMSTATS: heap N/A mmap N/A used N/A free N/A releasable N/A pools 1 pools_used 1306.598M pools_total 1306.643M\nEND";
        let v = parse_stats(raw);
        assert_eq!(v["threads"]["max"], 12);
        assert_eq!(v["queue"]["items"], 0);
        assert_eq!(v["pools"], 1);
        assert_eq!(v["memory"]["pools_used"], "1306.598M");
        assert!(v["memory"].get("heap").is_none());
        let (e, db, t) = split_version("ClamAV 1.4.0/27000/Thu Nov 12 09:00:00 2026");
        assert_eq!((e.as_str(), db.as_deref()), ("ClamAV 1.4.0", Some("27000")));
        assert!(t.as_deref().and_then(parse_clamd_date).is_some());
        assert!(parse_rfc3339("2027-01-01T00:00:00Z").is_some());
        assert!(parse_rfc3339("2027-01-01").is_none());
    }
}
