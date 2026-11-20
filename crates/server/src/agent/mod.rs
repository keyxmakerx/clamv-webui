//! Remote agents (server side).
//!
//! An agent is this same binary run with `agent` on another host, next to its
//! own clamd. It connects out to the server, so it needs no open port:
//! it long-polls `/agent/v1/poll` for jobs and posts each result back.
//! The agent enforces its own `SCAN_ROOTS`; the server only pre-checks paths
//! against the roots the agent reported, for a quick answer in the UI.

pub mod client;
pub mod outbox;
pub mod policy;
pub mod proto;

use std::path::{Component, Path};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{FromRequestParts, Path as UrlPath, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use tokio::sync::watch;

use crate::app::AppState;
use crate::db::agents::{Agent, Heartbeat};
use crate::db::jobs::{self, Job};
use crate::db::now_ms;
use crate::scan;
use proto::{AgentEvent, Assignment, Failure, PollRequest, PollResponse, ResultRequest};

/// An agent that has not polled for this long is offline.
pub const OFFLINE_AFTER_MS: i64 = 90_000;
/// A running job on an agent offline this long is failed.
const LOST_AFTER_MS: i64 = 10 * 60_000;
/// Queued jobs for an agent that stays offline expire after this.
const QUEUED_EXPIRE_MS: i64 = 24 * 3_600_000;
/// How long a poll waits for work before answering empty.
pub const POLL_HOLD: Duration = Duration::from_secs(25);
/// Most jobs handed out per poll.
const MAX_BATCH: u32 = 8;

/// Error code for a job the server gave up on while its agent was away; a late result may still finish it.
pub const AGENT_LOST: &str = "AGENT_LOST";
/// Error code for a job an operator cancelled.
pub const CANCELLED: &str = "CANCELLED";

/// Wakes waiting polls when a job is queued for any agent.
pub struct Hub {
    tx: watch::Sender<u64>,
    /// Agents refused for their protocol version: id to (their protocol, their version).
    mismatch: std::sync::Mutex<std::collections::HashMap<i64, (u32, String)>>,
}

impl Default for Hub {
    fn default() -> Self {
        Self {
            tx: watch::channel(0).0,
            mismatch: std::sync::Mutex::default(),
        }
    }
}

impl Hub {
    pub fn poke(&self) {
        self.tx.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// What to tell the operator when this agent speaks another protocol version.
    pub fn version_hint(&self, agent_id: i64) -> Option<String> {
        let g = self.mismatch.lock().ok()?;
        let (theirs, version) = g.get(&agent_id)?;
        Some(if *theirs < proto::MIN_PROTOCOL {
            format!("Agent v{version} is too old for this server: update the agent.")
        } else {
            format!("Agent v{version} is newer than this server: update the server.")
        })
    }

    fn set_mismatch(&self, agent_id: i64, v: Option<(u32, String)>) {
        if let Ok(mut g) = self.mismatch.lock() {
            match v {
                Some(v) => g.insert(agent_id, v),
                None => g.remove(&agent_id),
            };
        }
    }
}

pub fn is_online(a: &Agent, now: i64) -> bool {
    a.enabled && a.last_seen_at.is_some_and(|t| now - t < OFFLINE_AFTER_MS)
}

/// Lexical check that `path` is absolute, has no `..`, and sits under one of `roots`.
pub fn path_in_roots(roots: &[String], path: &str) -> bool {
    let p = Path::new(path);
    if path.len() > 4096
        || path.bytes().any(|b| matches!(b, 0 | b'\n' | b'\r'))
        || !p.is_absolute()
        || p.components().any(|c| matches!(c, Component::ParentDir))
    {
        return false;
    }
    roots
        .iter()
        .any(|r| Path::new(r).is_absolute() && p.starts_with(r))
}

/// Why a job cannot go to this agent, if it cannot.
pub fn refuse(a: &Agent, path: &str) -> Option<&'static str> {
    if !a.enabled {
        return Some("That agent is disabled.");
    }
    if a.last_seen_at.is_none() {
        return Some("That agent has not connected yet.");
    }
    if !path_in_roots(&a.roots, path) {
        return Some(scan::PATH_REJECTED);
    }
    None
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/agent/v1/poll", post(poll))
        .route("/agent/v1/jobs/{id}/result", post(result))
        .route("/agent/v1/events", post(events))
}

fn reply(status: StatusCode, msg: &'static str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(proto::ErrorBody { error: msg }),
    )
        .into_response()
}

/// The calling agent, from `Authorization: Bearer pal_agent_...`.
pub struct Caller {
    agent: Agent,
    ip: std::net::IpAddr,
}

impl FromRequestParts<Arc<AppState>> for Caller {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, st: &Arc<AppState>) -> Result<Self, Response> {
        let ip = crate::web::session::client_ip(&parts.extensions);
        let secret = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .filter(|a| a.len() > 7 && a[..7].eq_ignore_ascii_case("bearer "))
            .map(|a| a[7..].trim());
        let Some(secret) = secret.filter(|s| s.starts_with(crate::db::agents::SECRET_PREFIX))
        else {
            tracing::warn!(event = "agent.auth_failed", ip = %ip, "agent request without an agent token");
            return Err(reply(StatusCode::UNAUTHORIZED, "invalid agent token"));
        };
        match st.db.agent_by_secret(secret).await {
            Ok(Some(agent)) if agent.enabled => Ok(Self { agent, ip }),
            Ok(Some(agent)) => {
                tracing::warn!(event = "agent.disabled", agent = %agent.name, ip = %ip, "disabled agent tried to connect");
                Err(reply(StatusCode::FORBIDDEN, "agent disabled"))
            }
            Ok(None) => {
                tracing::warn!(event = "agent.auth_failed", ip = %ip, "unknown agent token");
                Err(reply(StatusCode::UNAUTHORIZED, "invalid agent token"))
            }
            Err(_) => Err(reply(StatusCode::SERVICE_UNAVAILABLE, "unavailable")),
        }
    }
}

fn clip(s: &str, n: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(n).collect()
}

async fn poll(
    State(st): State<Arc<AppState>>,
    c: Caller,
    Json(req): Json<PollRequest>,
) -> Response {
    if !(proto::MIN_PROTOCOL..=proto::PROTOCOL).contains(&req.protocol) {
        let version = clip(&req.version, 64);
        tracing::warn!(event = "agent.protocol_mismatch", agent = %c.agent.name, theirs = req.protocol, ours = proto::PROTOCOL, agent_version = %version, "agent speaks another protocol version; update the older side");
        st.agents
            .set_mismatch(c.agent.id, Some((req.protocol, version)));
        return reply(StatusCode::UPGRADE_REQUIRED, "protocol version mismatch");
    }
    st.agents.set_mismatch(c.agent.id, None);
    let kinds: Vec<String> = if req.protocol < 2 {
        proto::LEGACY_KINDS
            .iter()
            .map(|k| (*k).to_owned())
            .collect()
    } else {
        req.kinds.iter().take(64).map(|k| clip(k, 32)).collect()
    };
    let mut rx = st.agents.tx.subscribe();
    let roots: Vec<String> = req.roots.iter().take(64).map(|r| clip(r, 4096)).collect();
    let version = clip(&req.version, 64);
    let clamd_version = req.clamd_version.as_deref().map(|v| clip(v, 255));
    let ip = c.ip.to_string();
    let hb = Heartbeat {
        ip: &ip,
        version: &version,
        clamd_version: clamd_version.as_deref(),
        roots: &roots,
        slots: i64::from(req.slots.min(256)),
    };
    if st.db.heartbeat_agent(c.agent.id, &hb).await.is_err() {
        return reply(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    }
    if st
        .db
        .set_agent_online(c.agent.id, true)
        .await
        .unwrap_or(false)
    {
        tracing::info!(event = "agent.online", agent = %c.agent.name, ip = %ip, version = %version, clamd = clamd_version.as_deref().unwrap_or("-"), "agent connected");
    }
    reconcile(&st, &c.agent, &req.running).await;
    if let Some(u) = req.host_checks.clone() {
        st.host_units.set(Some(c.agent.id), u.cleaned());
    }
    for cs in req
        .canaries
        .iter()
        .take(crate::db::canaries::MAX_PER_HOST * 2)
    {
        let _ = st
            .db
            .set_canary_armed(Some(c.agent.id), &clip(&cs.path, 1024), cs.armed)
            .await;
    }
    let specs = |l: Vec<crate::db::canaries::Canary>| {
        l.into_iter()
            .map(|c| crate::canary::Spec {
                path: c.path,
                create: c.create_file,
            })
            .collect::<Vec<_>>()
    };
    let mut canaries = st.db.host_canaries(Some(c.agent.id)).await.ok().map(specs);
    // An agent that has not reported every canary yet gets the list at once.
    let current = canaries.as_ref().is_none_or(|l| {
        l.iter()
            .all(|s| req.canaries.iter().any(|r| r.path == s.path))
    });
    let free = req.free.min(MAX_BATCH);
    let mut jobs = Vec::new();
    if free > 0 {
        jobs = claim(&st, &c.agent, free, &kinds).await;
        if jobs.is_empty() && req.wait && current {
            let _ = tokio::time::timeout(POLL_HOLD, rx.changed()).await;
            jobs = claim(&st, &c.agent, free, &kinds).await;
            // Canaries may have changed while we waited.
            canaries = st.db.host_canaries(Some(c.agent.id)).await.ok().map(specs);
        }
    }
    let cancel = cancelled(&st, &c.agent, &req.running).await;
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(PollResponse {
            jobs,
            canaries,
            cancel,
        }),
    )
        .into_response()
}

/// Jobs the agent runs that were cancelled here; it stops them.
async fn cancelled(st: &AppState, a: &Agent, running: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for id in running.iter().take(256) {
        if let Ok(Some(j)) = st.db.job(&clip(id, 64)).await
            && j.agent_id == Some(a.id)
            && j.status == jobs::FINISHED
            && j.error_code.as_deref() == Some(CANCELLED)
        {
            out.push(j.id);
        }
    }
    out
}

async fn claim(st: &AppState, a: &Agent, n: u32, kinds: &[String]) -> Vec<Assignment> {
    let list = match st.db.claim_agent_jobs(a.id, i64::from(n)).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, agent = %a.name, "could not claim agent jobs");
            return Vec::new();
        }
    };
    let mut out = Vec::with_capacity(list.len());
    for j in list {
        if !kinds.contains(&j.kind) {
            let o = scan::failure(
                proto::UNSUPPORTED,
                "This agent is too old for this job type: update the agent.",
            );
            scan::finish(st, &j, &a.name, o).await;
            continue;
        }
        tracing::info!(event = "agent.job_assigned", agent = %a.name, job_id = %j.id, kind = %j.kind, scan_target = %j.target, "job sent to agent");
        out.push(Assignment {
            id: j.id,
            kind: j.kind,
            target: j.target,
        });
    }
    out
}

/// Jobs we think the agent runs but it does not: lost to an agent restart
/// or a dropped poll answer. A grace period covers answers still in flight.
async fn reconcile(st: &AppState, a: &Agent, running: &[String]) {
    let Ok(ours) = st.db.agent_jobs(a.id, jobs::RUNNING).await else {
        return;
    };
    let now = now_ms();
    for j in ours {
        if !running.iter().any(|r| r == &j.id) && j.started_at.is_some_and(|t| now - t > 60_000) {
            let o = scan::failure(
                AGENT_LOST,
                "The agent lost this job (it restarted or lost the connection); a late result still counts.",
            );
            scan::finish(st, &j, &a.name, o).await;
        }
    }
}

async fn result(
    State(st): State<Arc<AppState>>,
    c: Caller,
    UrlPath(id): UrlPath<String>,
    Json(req): Json<ResultRequest>,
) -> Response {
    let job = match st.db.job(&id).await {
        Ok(Some(j)) if j.agent_id == Some(c.agent.id) && j.status == jobs::RUNNING => j,
        // Given up on while the agent was away: take the result after all.
        Ok(Some(j))
            if j.agent_id == Some(c.agent.id)
                && j.status == jobs::FINISHED
                && j.error_code.as_deref() == Some(AGENT_LOST) =>
        {
            match st.db.reopen_lost_job(&j.id, c.agent.id).await {
                Ok(true) => {
                    tracing::info!(event = "agent.result_late", agent = %c.agent.name, job_id = %j.id, "late result accepted for a job given up on");
                    match st.db.job(&id).await {
                        Ok(Some(j)) => j,
                        _ => return reply(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
                    }
                }
                Ok(false) => {
                    return reply(StatusCode::CONFLICT, "job is not running on this agent");
                }
                Err(_) => return reply(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            }
        }
        Ok(_) => return reply(StatusCode::CONFLICT, "job is not running on this agent"),
        Err(_) => return reply(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    };
    if job.kind == crate::schedule::KIND_CONTROL {
        let report = req.report.map(|r| Ok(r.into_report()));
        crate::schedule::control_done(&st, &job, &c.agent.name, report).await;
        return StatusCode::NO_CONTENT.into_response();
    }
    if job.kind == crate::quarantine::KIND {
        crate::quarantine::agent_result(
            &st,
            c.agent.id,
            &job.target,
            req.quarantine.clone(),
            req.failure.as_ref().map(|f| f.code.as_str()),
        )
        .await;
    }
    let o = match (req.report, req.failure) {
        (Some(r), _) => scan::outcome(r.into_report()),
        (None, Some(f)) => failure_outcome(&f),
        (None, None) => scan::failure(scan::SCAN_FAILED, "The agent sent an empty result."),
    };
    stored_reply(scan::finish(&st, &job, &c.agent.name, o).await)
}

/// 503 when the result could not be stored, so the agent keeps it queued and sends it again.
fn stored_reply(stored: scan::Stored) -> Response {
    match stored {
        scan::Stored::Failed => reply(StatusCode::SERVICE_UNAVAILABLE, "result not stored; retry"),
        scan::Stored::Saved | scan::Stored::AlreadyFinished => {
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

/// A real-time scan becomes a finished WATCH job; a canary raises an alert.
async fn events(
    State(st): State<Arc<AppState>>,
    c: Caller,
    Json(ev): Json<AgentEvent>,
) -> Response {
    // Real-time scans arrive one file at a time; cap them so a broken or
    // hostile agent cannot fill the job table.
    if !st.agent_events.allow(&c.agent.id.to_string()) {
        tracing::warn!(event = "agent.rate_limited", agent = %c.agent.name, ip = %c.ip, "agent sent too many events");
        return reply(StatusCode::TOO_MANY_REQUESTS, "too many events");
    }
    match ev {
        AgentEvent::Canary { path, what } => {
            let path = proto::clean(&path, 4096);
            let what = proto::clean(&what, 200);
            let _ = st.db.canary_tripped(Some(c.agent.id), &path).await;
            crate::canary::tripped(&st, &c.agent.name, &path, &what).await;
        }
        AgentEvent::Falco { alerts } => {
            let alerts: Vec<_> = alerts
                .into_iter()
                .take(500)
                .map(crate::falco::Alert::cleaned)
                .collect();
            crate::falco::record(&st, Some(c.agent.id), &c.agent.name, alerts).await;
        }
        AgentEvent::Firewall { snapshot } => {
            st.firewalls.set(Some(c.agent.id), snapshot);
        }
        AgentEvent::Integrity { report } => {
            if let Some(r) = report.cleaned() {
                crate::integrity::record(&st, Some(c.agent.id), &c.agent.name, r).await;
            }
        }
        AgentEvent::Scan {
            path,
            report,
            failure,
        } => {
            let path = proto::clean(&path, 4096);
            // Raw (non-UTF-8) keys carry the folder as readable text before the mark.
            let readable = path.split(crate::watch::RAW_MARK).next().unwrap_or(&path);
            if !path_in_roots(&c.agent.roots, readable) {
                return reply(StatusCode::BAD_REQUEST, "path outside this agent's roots");
            }
            let submitted = format!("agent:{}", c.agent.name);
            let job = match st
                .db
                .create_job(jobs::NewJob {
                    kind: scan::KIND_WATCH,
                    target: &path,
                    endpoint_id: None,
                    schedule_id: None,
                    agent_id: Some(c.agent.id),
                    submitted_by: Some(&submitted),
                    transport: "AGENT_REALTIME",
                    running: true,
                })
                .await
            {
                Ok(j) => j,
                Err(_) => return reply(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            };
            let o = match (report, failure) {
                (Some(r), _) => scan::outcome(r.into_report()),
                (None, Some(f)) if f.code == scan::LIMIT_EXCEEDED => scan::failure(
                    scan::LIMIT_EXCEEDED,
                    "The file is larger than the agent's CLAMD_MAX_STREAM_MB.",
                ),
                (None, Some(f)) => failure_outcome(&f),
                (None, None) => scan::failure(scan::SCAN_FAILED, "The agent sent an empty result."),
            };
            return stored_reply(scan::finish(&st, &job, &c.agent.name, o).await);
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

fn failure_outcome(f: &Failure) -> jobs::Outcome {
    use crate::hostchecks as hc;
    match f.code.as_str() {
        hc::NO_BUS => scan::failure(hc::NO_BUS, hc::message(hc::NO_BUS)),
        hc::DENIED => scan::failure(hc::DENIED, hc::message(hc::DENIED)),
        hc::NOT_INSTALLED => scan::failure(hc::NOT_INSTALLED, hc::message(hc::NOT_INSTALLED)),
        hc::FAILED => scan::failure(hc::FAILED, hc::message(hc::FAILED)),
        scan::POLICY_REJECTED => scan::failure(scan::POLICY_REJECTED, scan::PATH_REJECTED),
        proto::UNSUPPORTED => scan::failure(
            proto::UNSUPPORTED,
            "This agent is too old for this job type: update the agent.",
        ),
        c if c.starts_with("QUARANTINE_") => {
            use crate::quarantine as q;
            let code = [
                q::OFF,
                q::NOT_INFECTED,
                q::READ_ONLY,
                q::EXISTS,
                q::REJECTED,
            ]
            .into_iter()
            .find(|k| *k == c)
            .unwrap_or(q::FAILED);
            scan::failure(code, q::message(code))
        }
        super::agent::policy::REFUSED => scan::failure(
            super::agent::policy::REFUSED,
            "This agent's host does not allow that action; add it to AGENT_ALLOW on the agent.",
        ),
        super::agent::policy::RATE_LIMITED => scan::failure(
            super::agent::policy::RATE_LIMITED,
            "This agent refused: too many actions of that kind in the last hour.",
        ),
        scan::CONFIGURATION_UNAVAILABLE => scan::failure(
            scan::CONFIGURATION_UNAVAILABLE,
            "The agent's clamd is not configured correctly.",
        ),
        _ => scan::failure(
            scan::SCAN_FAILED,
            "clamd on the agent did not complete the scan.",
        ),
    }
}

/// Every 30 s: log online/offline changes, fail work stuck on agents that went away.
pub fn spawn_monitor(st: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            monitor(&st).await;
        }
    });
}

pub async fn monitor(st: &AppState) {
    let Ok(list) = st.db.list_agents().await else {
        return;
    };
    let now = now_ms();
    for a in list {
        let online = is_online(&a, now);
        if !online && st.db.set_agent_online(a.id, false).await.unwrap_or(false) {
            tracing::warn!(event = "agent.offline", agent = %a.name, last_ip = a.last_ip.as_deref().unwrap_or("-"), "agent stopped polling");
        }
        if online {
            continue;
        }
        let gone_for = a.last_seen_at.map_or(i64::MAX, |t| now - t);
        if gone_for > LOST_AFTER_MS {
            fail_where(
                st,
                &a,
                jobs::RUNNING,
                |j| j.started_at.unwrap_or(0),
                0,
                "The agent went offline during the scan; a late result still counts.",
            )
            .await;
        }
        fail_where(
            st,
            &a,
            jobs::QUEUED,
            |j| j.submitted_at,
            QUEUED_EXPIRE_MS,
            "The agent was offline for a day; the job expired.",
        )
        .await;
    }
}

async fn fail_where(
    st: &AppState,
    a: &Agent,
    status: &str,
    at: impl Fn(&Job) -> i64,
    older_than: i64,
    msg: &str,
) {
    let Ok(list) = st.db.agent_jobs(a.id, status).await else {
        return;
    };
    let now = now_ms();
    for j in list.iter().filter(|j| now - at(j) > older_than) {
        let code = if status == jobs::RUNNING {
            AGENT_LOST
        } else {
            scan::CONFIGURATION_UNAVAILABLE
        };
        let o = scan::failure(code, msg);
        if status == jobs::QUEUED {
            // Not RUNNING, so finish() would skip it; store directly.
            if st
                .db
                .finish_job_if(&j.id, jobs::QUEUED, &o)
                .await
                .unwrap_or(false)
            {
                tracing::warn!(event = "scan.failed", job_id = %j.id, agent = %a.name, reason = msg, "queued agent job expired");
            }
        } else {
            scan::finish(st, j, &a.name, o).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_are_checked_lexically() {
        let roots = vec!["/data".to_owned(), "/srv/media".to_owned()];
        assert!(path_in_roots(&roots, "/data"));
        assert!(path_in_roots(&roots, "/data/a/b"));
        assert!(path_in_roots(&roots, "/srv/media/x"));
        assert!(!path_in_roots(&roots, "/database"));
        assert!(!path_in_roots(&roots, "/data/../etc"));
        assert!(!path_in_roots(&roots, "data/x"));
        assert!(!path_in_roots(&roots, "/data/x\n"));
        assert!(!path_in_roots(&["rel".to_owned()], "rel/x"));
        assert!(!path_in_roots(&[], "/data"));
    }
}
