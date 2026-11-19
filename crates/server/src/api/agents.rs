//! `/api/v1` for agents, schedules and job cancel, so `clamctl` and MCP can do what the UI does.
//!
//! A token limited to some endpoints or path roots never reaches an agent:
//! those limits are about this server's clamd and folders.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Principal, Who, bad, err, forbidden, ok, unavailable, visible_job};
use crate::app::AppState;
use crate::cron::Cron;
use crate::db::agents::Agent;
use crate::db::now_ms;
use crate::db::schedules::{NewSchedule, Schedule};
use crate::scan;
use crate::timefmt::rfc3339;

const MAX_PATHS: usize = 50;

/// True if this caller may send work to agents at all.
fn reaches_agents(p: &Principal) -> bool {
    match &p.who {
        Who::User(_) => true,
        Who::Token(t) => t.endpoint_ids.is_none() && t.path_roots.is_none(),
    }
}

fn agent_json(st: &AppState, a: &Agent, now: i64) -> Value {
    json!({
        "id": a.id,
        "name": a.name,
        "enabled": a.enabled,
        "online": crate::agent::is_online(a, now),
        "lastSeenAt": a.last_seen_at.map(rfc3339),
        "version": a.version,
        "clamdVersion": a.clamd_version,
        "roots": a.roots,
        "slots": a.slots,
        "versionHint": st.agents.version_hint(a.id),
    })
}

/// `GET /api/v1/agents`
pub async fn list(State(st): State<Arc<AppState>>, p: Principal) -> Response {
    if let Err(r) = p.require("endpoints:read") {
        return r;
    }
    if !reaches_agents(&p) {
        return ok(StatusCode::OK, json!([]));
    }
    let Ok(list) = st.db.list_agents().await else {
        return unavailable();
    };
    let now = now_ms();
    ok(
        StatusCode::OK,
        Value::Array(list.iter().map(|a| agent_json(&st, a, now)).collect()),
    )
}

/// An agent named by id or by name in a request.
pub async fn find_agent(
    st: &AppState,
    id: Option<i64>,
    name: Option<&str>,
) -> Result<Option<Agent>, Response> {
    if id.is_none() && name.is_none_or(|n| n.trim().is_empty()) {
        return Ok(None);
    }
    let Ok(list) = st.db.list_agents().await else {
        return Err(unavailable());
    };
    let found = list.into_iter().find(|a| {
        id.is_some_and(|i| i == a.id)
            || name.is_some_and(|n| n.trim().eq_ignore_ascii_case(&a.name))
    });
    match found {
        Some(a) => Ok(Some(a)),
        None => Err(bad("Unknown agent.")),
    }
}

/// Queue a path scan on an agent; the caller has checked scope and CSRF.
pub async fn scan_on_agent(st: &AppState, p: &Principal, a: &Agent, path: &str) -> Response {
    if !reaches_agents(p) {
        return forbidden();
    }
    if let Some(m) = crate::agent::refuse(a, path) {
        tracing::warn!(event = "scan.path_rejected", principal = %p.name(), ip = %p.ip, path = %path, agent = %a.name, "path outside the agent's SCAN_ROOTS");
        return bad(m);
    }
    let name = p.name();
    let job = match st
        .db
        .create_job(crate::db::jobs::NewJob {
            kind: scan::KIND_PATH,
            target: path,
            endpoint_id: None,
            schedule_id: None,
            agent_id: Some(a.id),
            submitted_by: Some(&name),
            transport: p.transport(),
            running: false,
        })
        .await
    {
        Ok(j) => j,
        Err(_) => return unavailable(),
    };
    p.audit(
        st,
        "SCAN_PATH",
        Some(&job),
        Some(format!("agent:{} {}", a.name, job.target)),
    )
    .await;
    st.agents.poke();
    if !crate::agent::is_online(a, now_ms()) {
        tracing::info!(event = "scan.queued_offline", job_id = %job.id, agent = %a.name, "path scan queued for an offline agent");
    }
    ok(
        StatusCode::ACCEPTED,
        json!({"jobId": job.id, "status": job.status, "created": 1, "jobIds": [job.id], "agentId": a.id}),
    )
}

/// `POST /api/v1/jobs/{id}/cancel`
pub async fn cancel(
    State(st): State<Arc<AppState>>,
    p: Principal,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = p.require("scan:path").and_then(|()| p.check_csrf(&headers)) {
        return r;
    }
    let job = match visible_job(&st, &p, &id).await {
        Ok(j) => j,
        Err(r) => return r,
    };
    if job.agent_id.is_some() && !reaches_agents(&p) {
        return forbidden();
    }
    match crate::cancel::cancel(&st, &job, &p.name()).await {
        Ok(()) => {
            p.audit(&st, "CANCEL_JOB", Some(&job), Some(job.target.clone()))
                .await;
            match st.db.job(&job.id).await {
                Ok(Some(j)) => ok(StatusCode::OK, super::job_json(&j)),
                _ => unavailable(),
            }
        }
        Err(m) => err(StatusCode::CONFLICT, "conflict", m),
    }
}

// ---- schedules ----

fn schedule_json(s: &Schedule, agents: &[Agent]) -> Value {
    let next = match s.cron.parse::<Cron>() {
        Ok(c) if s.enabled => c
            .next_after(now_ms().max(s.last_run_at.unwrap_or(0)))
            .map(rfc3339),
        _ => None,
    };
    json!({
        "id": s.id,
        "name": s.name,
        "cron": s.cron,
        "paths": s.paths,
        "endpointId": s.endpoint_id,
        "agentId": s.agent_id,
        "agent": s.agent_id.and_then(|id| agents.iter().find(|a| a.id == id)).map(|a| a.name.clone()),
        "enabled": s.enabled,
        "eicarCheck": s.eicar_check,
        "createdAt": rfc3339(s.created_at),
        "lastRunAt": s.last_run_at.map(rfc3339),
        "lastJobId": s.last_job_id,
        "nextRunAt": next,
    })
}

/// `GET /api/v1/schedules`
pub async fn list_schedules(State(st): State<Arc<AppState>>, p: Principal) -> Response {
    if let Err(r) = p.require("schedules:read") {
        return r;
    }
    let (Ok(list), Ok(agents)) = (st.db.list_schedules().await, st.db.list_agents().await) else {
        return unavailable();
    };
    let items: Vec<Value> = list
        .iter()
        .filter(|s| match s.agent_id {
            Some(_) => reaches_agents(&p),
            None => p.endpoint_ok(s.endpoint_id),
        })
        .map(|s| schedule_json(s, &agents))
        .collect();
    ok(StatusCode::OK, Value::Array(items))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewScheduleBody {
    name: String,
    cron: String,
    paths: Vec<String>,
    endpoint_id: Option<i64>,
    agent_id: Option<i64>,
    agent: Option<String>,
    #[serde(default)]
    eicar_check: bool,
}

/// `POST /api/v1/schedules`
pub async fn create_schedule(
    State(st): State<Arc<AppState>>,
    p: Principal,
    headers: HeaderMap,
    body: Result<Json<NewScheduleBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(r) = p
        .require("schedules:write")
        .and_then(|()| p.check_csrf(&headers))
    {
        return r;
    }
    let Ok(Json(b)) = body else {
        return bad("Send JSON with name, cron and paths.");
    };
    let name = b.name.trim();
    if name.is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control) {
        return bad("Names are 1 to 100 characters.");
    }
    let cron = b.cron.trim();
    if let Err(e) = cron.parse::<Cron>() {
        return bad(&format!("cron: {e}."));
    }
    let agent = match find_agent(&st, b.agent_id, b.agent.as_deref()).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if agent.is_some() && b.endpoint_id.is_some() {
        return bad("Give endpointId or an agent, not both.");
    }
    if agent.is_some() && !reaches_agents(&p) {
        return forbidden();
    }
    if agent.is_none() {
        match b.endpoint_id {
            Some(id) if id <= 0 => return bad("endpointId must be positive."),
            Some(id) if !p.endpoint_ok(Some(id)) => return forbidden(),
            Some(id) => match st.db.endpoint(id).await {
                Ok(Some(e)) if e.enabled => {}
                Ok(_) => return bad("Unknown or disabled endpoint."),
                Err(_) => return unavailable(),
            },
            None if !p.endpoint_ok(None) => return bad("endpointId is required for this token."),
            None => {}
        }
        if st.cfg.scan_roots.is_empty() {
            return bad("Set SCAN_ROOTS before adding schedules.");
        }
    }
    let mut paths: Vec<String> = Vec::new();
    for line in b.paths.iter().map(|l| l.trim()).filter(|l| !l.is_empty()) {
        let path = match &agent {
            Some(a) => match crate::agent::refuse(a, line) {
                None => line.to_owned(),
                Some(m) => return bad(&format!("{line}: {m}")),
            },
            None => match scan::resolve_path(&st.cfg.scan_roots, line).await {
                Ok(r) => match r.to_str() {
                    Some(s) if st.excluded(s) => {
                        return bad(&format!("{line}: {}", scan::PATH_EXCLUDED));
                    }
                    Some(s) => s.to_owned(),
                    None => return bad(&format!("{line}: only UTF-8 paths can be scheduled.")),
                },
                Err(m) => return bad(&format!("{line}: {m}")),
            },
        };
        if let (None, Who::Token(t)) = (&agent, &p.who)
            && let Some(roots) = &t.path_roots
        {
            let mut inside = false;
            for r in roots {
                if let Ok(rr) = scan::resolve_path(&st.cfg.scan_roots, r).await
                    && std::path::Path::new(&path).starts_with(&rr)
                {
                    inside = true;
                }
            }
            if !inside {
                return forbidden();
            }
        }
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    if paths.is_empty() || paths.len() > MAX_PATHS {
        return bad(&format!("Give 1 to {MAX_PATHS} paths."));
    }
    let created = st
        .db
        .create_schedule(NewSchedule {
            name,
            cron,
            paths: &paths,
            endpoint_id: if agent.is_some() { None } else { b.endpoint_id },
            agent_id: agent.as_ref().map(|a| a.id),
            eicar_check: b.eicar_check,
            exclusions: &[],
            window: None,
            time_zone: None,
        })
        .await;
    match created {
        Ok(s) => {
            p.audit(
                &st,
                "SCHEDULE_CREATE",
                None,
                Some(format!("{name} [{cron}] {}", paths.join(", "))),
            )
            .await;
            let agents = st.db.list_agents().await.unwrap_or_default();
            ok(StatusCode::CREATED, schedule_json(&s, &agents))
        }
        Err(_) => err(
            StatusCode::CONFLICT,
            "conflict",
            "That name is already taken.",
        ),
    }
}

async fn visible_schedule(st: &AppState, p: &Principal, id: &str) -> Result<Schedule, Response> {
    let missing = || err(StatusCode::NOT_FOUND, "not_found", "No such schedule.");
    if id.len() > 64 {
        return Err(missing());
    }
    match st.db.schedule(id).await {
        Ok(Some(s))
            if match s.agent_id {
                Some(_) => reaches_agents(p),
                None => p.endpoint_ok(s.endpoint_id),
            } =>
        {
            Ok(s)
        }
        Ok(_) => Err(missing()),
        Err(_) => Err(unavailable()),
    }
}

/// `POST /api/v1/schedules/{id}/run`
pub async fn run_schedule(
    State(st): State<Arc<AppState>>,
    p: Principal,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = p
        .require("schedules:write")
        .and_then(|()| p.check_csrf(&headers))
    {
        return r;
    }
    let s = match visible_schedule(&st, &p, &id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    match crate::schedule::run(&st, &s, "api").await {
        Ok(n) => {
            p.audit(&st, "SCHEDULE_RUN", None, Some(s.name.clone()))
                .await;
            ok(
                StatusCode::ACCEPTED,
                json!({"scheduleId": s.id, "created": n}),
            )
        }
        Err(m) => err(StatusCode::CONFLICT, "conflict", &m),
    }
}

#[derive(Deserialize)]
pub struct PatchBody {
    enabled: Option<bool>,
}

/// `PATCH /api/v1/schedules/{id}`: pause or resume.
pub async fn patch_schedule(
    State(st): State<Arc<AppState>>,
    p: Principal,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<Json<PatchBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(r) = p
        .require("schedules:write")
        .and_then(|()| p.check_csrf(&headers))
    {
        return r;
    }
    let Ok(Json(PatchBody {
        enabled: Some(enabled),
    })) = body
    else {
        return bad("Send JSON with enabled.");
    };
    let s = match visible_schedule(&st, &p, &id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if st.db.set_schedule_enabled(&s.id, enabled).await.is_err() {
        return unavailable();
    }
    p.audit(
        &st,
        "SCHEDULE_UPDATE",
        None,
        Some(format!("{} enabled={enabled}", s.name)),
    )
    .await;
    match st.db.schedule(&s.id).await {
        Ok(Some(s)) => {
            let agents = st.db.list_agents().await.unwrap_or_default();
            ok(StatusCode::OK, schedule_json(&s, &agents))
        }
        _ => unavailable(),
    }
}

/// `DELETE /api/v1/schedules/{id}`
pub async fn delete_schedule(
    State(st): State<Arc<AppState>>,
    p: Principal,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = p
        .require("schedules:write")
        .and_then(|()| p.check_csrf(&headers))
    {
        return r;
    }
    let s = match visible_schedule(&st, &p, &id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if st.db.delete_schedule(&s.id).await.is_err() {
        return unavailable();
    }
    p.audit(&st, "SCHEDULE_DELETE", None, Some(s.name.clone()))
        .await;
    axum::response::IntoResponse::into_response(StatusCode::NO_CONTENT)
}
