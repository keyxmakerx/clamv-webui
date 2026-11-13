//! Scan submission (upload and path) and the job pages. OPERATOR and up.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::multipart::Field;
use axum::extract::{Form, Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use super::admin::fmt_ts;
use super::session::Auth;
use super::{Nav, RequestInfo, csrf, error_page, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::db::audit::AuditEntry;
use crate::db::endpoints::Endpoint;
use crate::db::jobs::{self, Job, JobFilter, NewJob, Outcome};
use crate::db::sessions::Session;
use crate::db::users::User;
use crate::scan;

const PAGE_SIZE: i64 = 50;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/scan", get(scan_page))
        .route("/scan/path", post(scan_path))
        .route("/jobs", get(jobs_page))
        .route("/jobs/{id}", get(job_page))
}

/// The upload route; the caller gives it its own body limit and no request timeout.
pub fn upload_routes() -> Router<Arc<AppState>> {
    Router::new().route("/scan/upload", post(scan_upload))
}

// ---- scan page ----

#[derive(Template)]
#[template(path = "scan.html")]
struct ScanPage {
    nav: Nav,
    endpoints: Vec<Endpoint>,
    roots: Vec<String>,
    max_mb: u64,
    max_files: usize,
    path: String,
}

async fn scan_page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Operator) {
        Ok(x) => x,
        Err(r) => return r,
    };
    show_scan(&st, Nav::new("scan", &s, &u), String::new()).await
}

async fn show_scan(st: &AppState, nav: Nav, path: String) -> Response {
    let endpoints = match st.db.list_endpoints().await {
        Ok(l) => l.into_iter().filter(|e| e.enabled).collect(),
        Err(e) => {
            tracing::error!(error = %e, "list endpoints failed");
            return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
        }
    };
    let status = if nav.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    render(
        status,
        &ScanPage {
            nav,
            endpoints,
            roots: st
                .cfg
                .scan_roots
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            max_mb: st.cfg.clamd_max_stream_mb,
            max_files: st.cfg.upload_max_files,
            path,
        },
    )
}

async fn scan_error(st: &AppState, s: &Session, u: &User, msg: &str, path: String) -> Response {
    let mut nav = Nav::new("scan", s, u);
    nav.error = Some(msg.to_owned());
    show_scan(st, nav, path).await
}

/// Empty means the default endpoint; otherwise it must exist and be enabled.
async fn chosen_endpoint(st: &AppState, raw: Option<&str>) -> Result<Option<i64>, &'static str> {
    match raw.map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(None),
        Some(v) => {
            let id: i64 = v.parse().map_err(|_| "Unknown endpoint.")?;
            match st.db.endpoint(id).await {
                Ok(Some(e)) if e.enabled => Ok(Some(id)),
                _ => Err("Unknown endpoint."),
            }
        }
    }
}

// ---- path scan ----

#[derive(Deserialize)]
struct PathForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    path: String,
    endpoint: Option<String>,
}

async fn scan_path(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Form(f): Form<PathForm>,
) -> Response {
    let (s, u) = match auth.require(Role::Operator) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !csrf::token_ok(&s.csrf_token, f.csrf.as_deref()) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Your session form expired. Reload and try again.",
        );
    }
    let input = f.path.trim().to_owned();
    if st.cfg.scan_roots.is_empty() {
        return scan_error(
            &st,
            &s,
            &u,
            "Path scans are off: SCAN_ROOTS is not set.",
            input,
        )
        .await;
    }
    let endpoint_id = match chosen_endpoint(&st, f.endpoint.as_deref()).await {
        Ok(e) => e,
        Err(m) => return scan_error(&st, &s, &u, m, input).await,
    };
    let real = match scan::resolve_path(&st.cfg.scan_roots, &input).await {
        Ok(p) => p,
        Err(m) => {
            tracing::warn!(event = "scan.path_rejected", user = %u.username, ip = %info.ip, path = %input, "path outside SCAN_ROOTS or missing");
            return scan_error(&st, &s, &u, m, input).await;
        }
    };
    // Store the resolved path; it is checked again when the job runs.
    let Some(target) = real.to_str() else {
        return scan_error(&st, &s, &u, "Only UTF-8 paths can be queued.", input).await;
    };
    let job = match st
        .db
        .create_job(NewJob {
            kind: scan::KIND_PATH,
            target,
            endpoint_id,
            schedule_id: None,
            submitted_by: Some(&u.username),
            transport: "UI",
            running: false,
        })
        .await
    {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(error = %e, "create job failed");
            return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
        }
    };
    audit_scan(&st, &u, &info, &job, "SCAN_PATH").await;
    st.runner.poke();
    Redirect::to(&format!("/jobs/{}", job.id)).into_response()
}

async fn audit_scan(st: &AppState, u: &User, info: &RequestInfo, job: &Job, action: &'static str) {
    st.db
        .audit(AuditEntry {
            username: Some(u.username.clone()),
            action,
            outcome: "OK",
            details: Some(job.target.clone()),
            job_id: Some(job.id.clone()),
            transport: Some("UI"),
            endpoint_id: job.endpoint_id,
            ip: Some(info.ip.to_string()),
            user_agent: info.user_agent.clone(),
        })
        .await;
}

// ---- upload scan ----

/// A display name only: never used as a path.
fn display_name(raw: Option<&str>) -> String {
    let base = raw.unwrap_or("").rsplit(['/', '\\']).next().unwrap_or("");
    let clean: String = base.chars().filter(|c| !c.is_control()).take(255).collect();
    let clean = clean.trim();
    if clean.is_empty() {
        "upload".to_owned()
    } else {
        clean.to_owned()
    }
}

/// Stream one multipart file straight into clamd INSTREAM. Nothing touches disk (S3).
async fn scan_field(st: &AppState, ep: &Endpoint, mut field: Field<'_>, name: &str) -> Outcome {
    let Ok(addr) = ep.parsed() else {
        return scan::failure(
            scan::CONFIGURATION_UNAVAILABLE,
            "Endpoint address is invalid.",
        );
    };
    let client = st.clamd(addr);
    let (mut w, r) = tokio::io::duplex(256 * 1024);
    let feed = async {
        let mut hasher = Sha256::new();
        let mut size: u64 = 0;
        loop {
            match field.chunk().await {
                Ok(Some(chunk)) => {
                    hasher.update(&chunk);
                    size += chunk.len() as u64;
                    // clamd stopped reading (limit or error); its reply says why.
                    if w.write_all(&chunk).await.is_err() {
                        return Ok((None, size));
                    }
                }
                Ok(None) => break,
                Err(e) => return Err(e),
            }
        }
        drop(w);
        Ok((Some(format!("{:x}", hasher.finalize())), size))
    };
    let (fed, scanned) = tokio::join!(feed, client.instream(r));
    // A broken upload must never be reported as clean: the scanner saw a truncated file.
    let (sha, size) = match fed {
        Ok(x) => x,
        Err(e) => {
            tracing::warn!(file = %name, error = %e, "upload interrupted");
            return scan::failure(scan::SCAN_FAILED, "The upload was interrupted.");
        }
    };
    let mut o = match scanned {
        Ok(mut report) => {
            for d in &mut report.detections {
                d.path = name.to_owned();
            }
            for e in &mut report.errors {
                e.path = name.to_owned();
            }
            scan::outcome(report)
        }
        Err(clamd::Error::StreamTooLarge(_)) => scan::failure(
            scan::LIMIT_EXCEEDED,
            &format!(
                "The file is larger than the {} MiB stream limit.",
                st.cfg.clamd_max_stream_mb
            ),
        ),
        Err(e) => {
            tracing::warn!(file = %name, endpoint = %ep.name, error = %e, "clamd stream scan failed");
            scan::failure(scan::SCAN_FAILED, "clamd did not complete the scan.")
        }
    };
    o.sha256 = sha;
    o.size_bytes = i64::try_from(size).ok();
    o
}

async fn scan_upload(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    mp: Result<Multipart, axum::extract::multipart::MultipartRejection>,
) -> Response {
    let (s, u) = match auth.require(Role::Operator) {
        Ok(x) => x,
        Err(r) => return r,
    };
    // Role first, then the body shape.
    let Ok(mut mp) = mp else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Send the files as multipart/form-data.",
        );
    };
    // The token field comes first so nothing is scanned for a forged request.
    let token = match mp.next_field().await {
        Ok(Some(f)) if f.name() == Some("_csrf") => f.text().await.ok(),
        _ => None,
    };
    if !csrf::token_ok(&s.csrf_token, token.as_deref()) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Your session form expired. Reload and try again.",
        );
    }
    let mut endpoint_id = None;
    let mut ids: Vec<String> = Vec::new();
    loop {
        let field = match mp.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(user = %u.username, error = %e, "bad multipart upload");
                return error_page(StatusCode::BAD_REQUEST, "The upload could not be read.");
            }
        };
        match field.name() {
            Some("endpoint") => {
                let raw = field.text().await.unwrap_or_default();
                match chosen_endpoint(&st, Some(&raw)).await {
                    Ok(e) => endpoint_id = e,
                    Err(m) => return scan_error(&st, &s, &u, m, String::new()).await,
                }
            }
            Some("files") => {
                // Browsers send an empty part when no file was picked.
                if field.file_name().is_none_or(str::is_empty) {
                    continue;
                }
                if ids.len() >= st.cfg.upload_max_files {
                    return scan_error(
                        &st,
                        &s,
                        &u,
                        &format!("At most {} files per upload.", st.cfg.upload_max_files),
                        String::new(),
                    )
                    .await;
                }
                let name = display_name(field.file_name());
                let Some(ep) = scan::pick_endpoint(&st, endpoint_id).await else {
                    return scan_error(&st, &s, &u, "No enabled clamd endpoint.", String::new())
                        .await;
                };
                let job = match st
                    .db
                    .create_job(NewJob {
                        kind: scan::KIND_UPLOAD,
                        target: &name,
                        endpoint_id: Some(ep.id),
                        schedule_id: None,
                        submitted_by: Some(&u.username),
                        transport: "UI",
                        running: true,
                    })
                    .await
                {
                    Ok(j) => j,
                    Err(e) => {
                        tracing::error!(error = %e, "create job failed");
                        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
                    }
                };
                audit_scan(&st, &u, &info, &job, "SCAN_UPLOAD").await;
                let o = scan_field(&st, &ep, field, &name).await;
                scan::finish(&st, &job, Some(&ep), o).await;
                ids.push(job.id);
            }
            _ => {}
        }
    }
    match ids.as_slice() {
        [] => scan_error(&st, &s, &u, "Pick at least one file.", String::new()).await,
        [one] => Redirect::to(&format!("/jobs/{one}")).into_response(),
        _ => Redirect::to("/jobs").into_response(),
    }
}

// ---- jobs ----

pub struct JobRow {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub verdict: String,
    pub target: String,
    pub endpoint: String,
    pub submitted_by: String,
    pub submitted: String,
    pub duration: String,
    pub signatures: String,
    pub problems: usize,
}

fn badge(verdict: &str) -> &'static str {
    match verdict {
        jobs::OK => "bg-success",
        jobs::VIRUS_FOUND => "bg-danger",
        jobs::ERROR => "bg-warning text-dark",
        _ => "bg-secondary",
    }
}

fn fmt_duration(ms: Option<i64>) -> String {
    match ms {
        None => String::new(),
        Some(ms) if ms < 1000 => format!("{ms} ms"),
        Some(ms) if ms < 60_000 => format!("{:.1} s", ms as f64 / 1000.0),
        Some(ms) => format!("{}m {}s", ms / 60_000, ms % 60_000 / 1000),
    }
}

fn fmt_size(b: Option<i64>) -> String {
    let Some(b) = b else { return String::new() };
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", units[i])
    }
}

fn row(j: &Job, names: &std::collections::HashMap<i64, String>) -> JobRow {
    JobRow {
        id: j.id.clone(),
        kind: j.kind.clone(),
        status: j.status.clone(),
        verdict: j.verdict.clone().unwrap_or_default(),
        target: j.target.clone(),
        endpoint: j
            .endpoint_id
            .and_then(|id| names.get(&id).cloned())
            .unwrap_or_else(|| "default".to_owned()),
        submitted_by: j.submitted_by.clone().unwrap_or_default(),
        submitted: fmt_ts(j.submitted_at),
        duration: fmt_duration(j.duration_ms()),
        signatures: j.signatures().join(", "),
        problems: j.errors.len(),
    }
}

async fn endpoint_names(st: &AppState) -> std::collections::HashMap<i64, String> {
    st.db
        .list_endpoints()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|e| (e.id, e.name))
        .collect()
}

#[derive(Template)]
#[template(path = "jobs.html")]
struct JobsPage {
    nav: Nav,
    rows: Vec<JobRow>,
    status: String,
    verdict: String,
    page: i64,
    pages: i64,
    total: i64,
    refresh: bool,
}

impl JobsPage {
    fn badge(&self, v: &str) -> &'static str {
        badge(v)
    }

    fn link(&self, page: i64) -> String {
        let mut q = format!("/jobs?page={page}");
        if !self.status.is_empty() {
            q.push_str(&format!("&status={}", self.status));
        }
        if !self.verdict.is_empty() {
            q.push_str(&format!("&verdict={}", self.verdict));
        }
        q
    }
}

#[derive(Deserialize)]
struct JobsQuery {
    page: Option<i64>,
    status: Option<String>,
    verdict: Option<String>,
}

/// Only known values pass through to the query.
fn known(v: Option<String>, allowed: &[&str]) -> Option<String> {
    v.filter(|v| allowed.contains(&v.as_str()))
}

async fn jobs_page(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    Query(q): Query<JobsQuery>,
) -> Response {
    let (s, u) = match auth.require(Role::Operator) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let filter = JobFilter {
        status: known(q.status, &[jobs::QUEUED, jobs::RUNNING, jobs::FINISHED]),
        verdict: known(q.verdict, &[jobs::OK, jobs::VIRUS_FOUND, jobs::ERROR]),
        endpoint_id: None,
    };
    let page = q.page.unwrap_or(0).clamp(0, 100_000);
    let (list, total) = match st.db.list_jobs(&filter, page, PAGE_SIZE).await {
        Ok(x) => x,
        Err(e) => {
            tracing::error!(error = %e, "list jobs failed");
            return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
        }
    };
    let names = endpoint_names(&st).await;
    let refresh = list.iter().any(|j| j.status != jobs::FINISHED);
    render(
        StatusCode::OK,
        &JobsPage {
            nav: Nav::new("jobs", &s, &u),
            rows: list.iter().map(|j| row(j, &names)).collect(),
            status: filter.status.unwrap_or_default(),
            verdict: filter.verdict.unwrap_or_default(),
            page,
            pages: (total + PAGE_SIZE - 1) / PAGE_SIZE,
            total,
            refresh,
        },
    )
}

#[derive(Template)]
#[template(path = "job.html")]
struct JobDetail {
    nav: Nav,
    j: JobRow,
    sha256: String,
    size: String,
    started: String,
    finished: String,
    files: i64,
    detections: Vec<(String, String)>,
    errors: Vec<(String, String)>,
    more_errors: usize,
    error_code: String,
    error_message: String,
    refresh: bool,
}

impl JobDetail {
    fn badge(&self, v: &str) -> &'static str {
        badge(v)
    }
}

async fn job_page(State(st): State<Arc<AppState>>, auth: Auth, Path(id): Path<String>) -> Response {
    let (s, u) = match auth.require(Role::Operator) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let job = match st.db.job(&id).await {
        Ok(Some(j)) => j,
        Ok(None) => return error_page(StatusCode::NOT_FOUND, "No such job."),
        Err(e) => {
            tracing::error!(error = %e, "load job failed");
            return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
        }
    };
    let names = endpoint_names(&st).await;
    const SHOW: usize = 1000;
    let detections = job
        .detections
        .iter()
        .flat_map(|(p, sigs)| sigs.iter().map(move |s| (p.clone(), s.clone())))
        .take(SHOW)
        .collect();
    let errors = job
        .errors
        .iter()
        .take(SHOW)
        .map(|e| (e.path.clone(), e.message.clone()))
        .collect();
    render(
        StatusCode::OK,
        &JobDetail {
            nav: Nav::new("jobs", &s, &u),
            j: row(&job, &names),
            sha256: job.sha256.clone().unwrap_or_default(),
            size: fmt_size(job.size_bytes),
            started: job.started_at.map(fmt_ts).unwrap_or_default(),
            finished: job.finished_at.map(fmt_ts).unwrap_or_default(),
            files: job.files_scanned,
            detections,
            errors,
            more_errors: job.errors.len().saturating_sub(SHOW),
            error_code: job.error_code.clone().unwrap_or_default(),
            error_message: job.error_message.clone().unwrap_or_default(),
            refresh: job.status != jobs::FINISHED,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_are_basenames() {
        assert_eq!(display_name(Some("../../etc/passwd")), "passwd");
        assert_eq!(display_name(Some("C:\\Users\\a\\b.exe")), "b.exe");
        assert_eq!(display_name(Some("a\u{0}b\nc")), "abc");
        assert_eq!(display_name(Some("")), "upload");
        assert_eq!(display_name(None), "upload");
    }

    #[test]
    fn sizes_and_durations() {
        assert_eq!(fmt_size(Some(68)), "68 B");
        assert_eq!(fmt_size(Some(1536)), "1.5 KiB");
        assert_eq!(fmt_duration(Some(1500)), "1.5 s");
        assert_eq!(fmt_duration(Some(125_000)), "2m 5s");
    }
}
