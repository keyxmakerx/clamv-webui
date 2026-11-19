//! The scheduler (F1) and the EICAR negative control (F2).
//!
//! Every 30 s each enabled schedule whose next cron time has passed is
//! claimed once and queued as PATH jobs. Missed runs while the server was
//! down collapse into one. A run is skipped while the previous one is still
//! going. With the control on, each run first streams the EICAR test file to
//! clamd; if clamd does not flag it, `eicar.control_failed` is logged at
//! ERROR, because a scanner that misses EICAR misses everything.
//!
//! Cron fields and scan windows are read in the schedule's time zone. Outside
//! its window a schedule starts no runs, and its queued jobs from a run that
//! started inside the window are dropped when the window closes (running scans
//! finish). Exclusions split a run into the folders and files around them.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use jiff::tz::TimeZone;

use crate::app::AppState;
use crate::cron::Cron;
use crate::db::endpoints::Endpoint;
use crate::db::jobs::{self, Job, NewJob, Outcome};
use crate::db::now_ms;
use crate::db::schedules::Schedule;
use crate::scan;

pub const KIND_CONTROL: &str = "CONTROL";

/// Error code for a scheduled job its scan window closed on before it started.
pub const WINDOW_CLOSED: &str = "WINDOW_CLOSED";

/// At most this many scan jobs per run once exclusions split the paths.
pub const MAX_RUN_JOBS: usize = 500;

/// The server's default schedule zone: SCHEDULE_TZ, else TZ if it names a zone, else UTC.
pub fn default_zone(cfg: &crate::config::Config) -> (String, TimeZone) {
    let from_env = std::env::var("TZ").ok();
    for name in [cfg.schedule_tz.as_deref(), from_env.as_deref()]
        .into_iter()
        .flatten()
    {
        let name = name.trim_start_matches(':');
        if let Ok(tz) = crate::cron::zone(name)
            && !name.is_empty()
        {
            return (name.to_owned(), tz);
        }
    }
    ("UTC".into(), TimeZone::UTC)
}

/// The zone a schedule runs in, and its name.
pub fn zone_of(cfg: &crate::config::Config, s: &Schedule) -> (String, TimeZone) {
    match s.time_zone.as_deref().map(|z| (z, crate::cron::zone(z))) {
        Some((name, Ok(tz))) => (name.to_owned(), tz),
        _ => default_zone(cfg),
    }
}

/// True when `ms` falls inside the window (always true without one).
pub fn in_window(window: Option<(i64, i64)>, tz: &TimeZone, ms: i64) -> bool {
    let Some((start, end)) = window else {
        return true;
    };
    let m = crate::cron::local_minute(tz, ms);
    if start < end {
        (start..end).contains(&m)
    } else {
        m >= start || m < end
    }
}

/// The next `n` start times of a schedule (cron times outside its window are skipped).
pub fn next_runs(
    cron: &Cron,
    window: Option<(i64, i64)>,
    tz: &TimeZone,
    from: i64,
    n: usize,
) -> Vec<i64> {
    let mut out = Vec::new();
    let mut t = from;
    // Bounded: a window that never meets the cron gives up quickly.
    for _ in 0..(n * 2000) {
        let Some(next) = cron.next_after_in(t, tz) else {
            break;
        };
        if in_window(window, tz, next) {
            out.push(next);
            if out.len() == n {
                break;
            }
        }
        t = next;
    }
    out
}

/// `p` is `ex` or lies under it, compared by path components.
fn covered(p: &Path, ex: &Path) -> bool {
    p.starts_with(ex)
}

/// Split `paths` around `exclusions`: a path inside an exclusion is dropped, a
/// path with an exclusion inside it is replaced by its other children.
pub async fn expand(paths: &[String], exclusions: &[String]) -> Result<Vec<String>, String> {
    let ex: Vec<&Path> = exclusions.iter().map(Path::new).collect();
    let mut out = Vec::new();
    let mut todo: Vec<std::path::PathBuf> = paths.iter().rev().map(Into::into).collect();
    while let Some(p) = todo.pop() {
        if ex.iter().any(|e| covered(&p, e)) {
            continue;
        }
        if !ex.iter().any(|e| covered(e, &p)) {
            match p.to_str() {
                Some(s) => out.push(s.to_owned()),
                None => {
                    tracing::warn!(event = "schedule.skipped_name", path = %p.display(), "name is not UTF-8; not scheduled")
                }
            }
            if out.len() > MAX_RUN_JOBS {
                return Err(format!(
                    "The exclusions split this run into more than {MAX_RUN_JOBS} scans; exclude higher up or use ExcludePath in clamd.conf."
                ));
            }
            continue;
        }
        // An exclusion lies inside: scan the siblings around it instead.
        let mut rd = tokio::fs::read_dir(&p)
            .await
            .map_err(|_| format!("{}: cannot be listed.", p.display()))?;
        let mut kids = Vec::new();
        while let Ok(Some(e)) = rd.next_entry().await {
            // Symlinks are not followed, as clamd does not follow them by default.
            if e.file_type().await.is_ok_and(|t| t.is_dir() || t.is_file()) {
                kids.push(e.path());
            }
        }
        kids.sort();
        todo.extend(kids.into_iter().rev());
    }
    Ok(out)
}

/// The EICAR test file, assembled at run time so this binary is not itself flagged.
pub fn eicar() -> Vec<u8> {
    let mut v = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$".to_vec();
    v.extend_from_slice(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
    v
}

pub fn spawn(st: Arc<AppState>) {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(30));
        loop {
            every.tick().await;
            if let Err(e) = tick(&st).await {
                tracing::warn!(error = %e, "scheduler tick failed");
            }
        }
    });
}

pub async fn tick(st: &AppState) -> Result<(), crate::db::DbError> {
    let now = now_ms();
    for s in st.db.list_schedules().await? {
        let (_, tz) = zone_of(&st.cfg, &s);
        let open = in_window(s.window, &tz, now);
        if !open {
            close_window(st, &s, &tz).await;
        }
        if !s.enabled {
            continue;
        }
        let Ok(cron) = s.cron.parse::<Cron>() else {
            continue;
        };
        let base = s.last_run_at.unwrap_or(s.created_at);
        if cron.next_after_in(base, &tz).is_some_and(|t| t <= now) {
            if open {
                let _ = run(st, &s, "cron").await;
            } else if st
                .db
                .claim_schedule_run(&s.id, s.last_run_at, now)
                .await
                .unwrap_or(false)
            {
                tracing::info!(event = "schedule.outside_window", schedule = %s.name, "run time is outside the scan window; skipped");
            }
        }
    }
    Ok(())
}

/// Drop queued jobs from a run that started inside the window that has now closed.
async fn close_window(st: &AppState, s: &Schedule, tz: &TimeZone) {
    if s.window.is_none() {
        return;
    }
    let Ok(queued) = st.db.schedule_queued_jobs(&s.id).await else {
        return;
    };
    let o = scan::failure(
        WINDOW_CLOSED,
        "The schedule's scan window closed before this path started.",
    );
    let mut dropped = 0;
    for j in queued
        .iter()
        .filter(|j| in_window(s.window, tz, j.submitted_at))
    {
        if st
            .db
            .finish_job_if(&j.id, jobs::QUEUED, &o)
            .await
            .unwrap_or(false)
        {
            dropped += 1;
        }
    }
    if dropped > 0 {
        tracing::warn!(event = "schedule.window_closed", schedule = %s.name, jobs = dropped, "scan window closed; queued paths dropped until the next run");
    }
}

/// Start one run of `s` now. Returns how many scan jobs were queued.
pub async fn run(st: &AppState, s: &Schedule, trigger: &'static str) -> Result<usize, String> {
    let now = now_ms();
    let active = st
        .db
        .schedule_active_jobs(&s.id)
        .await
        .map_err(|e| e.to_string())?;
    if active > 0 {
        // Still advance the clock so a long scan does not retry every tick.
        let _ = st.db.claim_schedule_run(&s.id, s.last_run_at, now).await;
        tracing::warn!(event = "schedule.skipped", schedule = %s.name, active, trigger, "previous run still going; run skipped");
        return Err("The previous run is still going.".into());
    }
    if !st
        .db
        .claim_schedule_run(&s.id, s.last_run_at, now)
        .await
        .map_err(|e| e.to_string())?
    {
        return Err("This run was already started.".into());
    }
    let target = match s.agent_id {
        Some(id) => match st.db.agent(id).await.ok().flatten() {
            Some(a) if a.enabled => Target::Agent(a),
            _ => {
                tracing::error!(event = "schedule.failed", schedule = %s.name, trigger, "the schedule's agent is missing or disabled");
                return Err("The schedule's agent is missing or disabled.".into());
            }
        },
        None => match scan::pick_endpoint(st, s.endpoint_id).await {
            Some(ep) => Target::Local(ep),
            None => {
                tracing::error!(event = "schedule.failed", schedule = %s.name, trigger, "no enabled clamd endpoint");
                return Err("No enabled clamd endpoint.".into());
            }
        },
    };
    let (endpoint_id, agent_id, where_) = match &target {
        Target::Local(ep) => (Some(ep.id), None, ep.name.clone()),
        Target::Agent(a) => (None, Some(a.id), format!("agent:{}", a.name)),
    };
    if s.eicar_check {
        match &target {
            Target::Local(ep) => {
                control(st, s, ep).await;
            }
            Target::Agent(a) => queue_control(st, s, a.id).await,
        }
    }
    let paths = match (&target, s.exclusions.is_empty()) {
        (_, true) => s.paths.clone(),
        (Target::Local(_), false) => match expand(&s.paths, &s.exclusions).await {
            Ok(p) => p,
            Err(m) => {
                tracing::error!(event = "schedule.failed", schedule = %s.name, trigger, reason = %m, "could not apply exclusions");
                return Err(m);
            }
        },
        // The agent's files are not visible here: only whole paths can be left out.
        (Target::Agent(_), false) => s
            .paths
            .iter()
            .filter(|p| {
                !s.exclusions
                    .iter()
                    .any(|e| covered(Path::new(p), Path::new(e)))
            })
            .cloned()
            .collect(),
    };
    let by = format!("schedule:{}", s.name);
    let mut last = None;
    let mut queued = 0;
    for p in &paths {
        match st
            .db
            .create_job(NewJob {
                kind: scan::KIND_PATH,
                target: p,
                endpoint_id,
                schedule_id: Some(&s.id),
                agent_id,
                submitted_by: Some(&by),
                transport: "SCHEDULER",
                running: false,
            })
            .await
        {
            Ok(j) => {
                queued += 1;
                last = Some(j.id);
            }
            Err(e) => {
                tracing::error!(event = "schedule.failed", schedule = %s.name, path = %p, error = %e, "could not queue scheduled job")
            }
        }
    }
    if let Some(id) = &last {
        let _ = st.db.set_schedule_last_job(&s.id, id).await;
    }
    st.runner.poke();
    st.agents.poke();
    tracing::info!(event = "schedule.started", schedule = %s.name, endpoint = %where_, jobs = queued, trigger, "scheduled scan started");
    Ok(queued)
}

/// Stream EICAR to the endpoint; record the result as a CONTROL job.
pub async fn control(st: &AppState, s: &Schedule, ep: &Endpoint) -> bool {
    let by = format!("schedule:{}", s.name);
    let job = match st
        .db
        .create_job(NewJob {
            kind: KIND_CONTROL,
            target: "EICAR test file",
            endpoint_id: Some(ep.id),
            schedule_id: Some(&s.id),
            agent_id: None,
            submitted_by: Some(&by),
            transport: "SCHEDULER",
            running: true,
        })
        .await
    {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(event = "eicar.control_failed", schedule = %s.name, endpoint = %ep.name, error = %e, "could not record EICAR control");
            return false;
        }
    };
    let result = match ep.parsed() {
        Ok(addr) => tokio::time::timeout(
            Duration::from_secs(30),
            st.clamd(addr).instream(&eicar()[..]),
        )
        .await
        .ok(),
        Err(_) => None,
    };
    control_done(st, &job, &ep.name, result).await
}

enum Target {
    Local(Endpoint),
    Agent(crate::db::agents::Agent),
}

/// Queue the EICAR control for an agent, next to the run's path jobs.
async fn queue_control(st: &AppState, s: &Schedule, agent_id: i64) {
    let by = format!("schedule:{}", s.name);
    if let Err(e) = st
        .db
        .create_job(NewJob {
            kind: KIND_CONTROL,
            target: "EICAR test file",
            endpoint_id: None,
            schedule_id: Some(&s.id),
            agent_id: Some(agent_id),
            submitted_by: Some(&by),
            transport: "SCHEDULER",
            running: false,
        })
        .await
    {
        tracing::error!(event = "eicar.control_failed", schedule = %s.name, error = %e, "could not queue EICAR control");
    }
}

/// Judge a control result (`None`: clamd did not answer), store, log and alert.
pub async fn control_done(
    st: &AppState,
    job: &Job,
    ep: &str,
    result: Option<Result<clamd::ScanReport, clamd::Error>>,
) -> bool {
    let (ok, outcome) = match result {
        Some(Ok(r)) if r.detections.iter().any(|d| !d.is_limit_exceeded()) => (
            true,
            Outcome {
                verdict: jobs::OK,
                files_scanned: 1,
                ..Outcome::default()
            },
        ),
        Some(Ok(_)) => (
            false,
            scan::failure(
                scan::SCAN_FAILED,
                "clamd did not detect the EICAR test file.",
            ),
        ),
        _ => (
            false,
            scan::failure(scan::SCAN_FAILED, "clamd did not answer the EICAR check."),
        ),
    };
    let schedule = job
        .submitted_by
        .as_deref()
        .and_then(|b| b.strip_prefix("schedule:"))
        .unwrap_or("-");
    match st.db.finish_job_if(&job.id, jobs::RUNNING, &outcome).await {
        Ok(true) => {}
        Ok(false) => return ok,
        Err(e) => tracing::error!(error = %e, "could not store EICAR control"),
    }
    if ok {
        tracing::info!(
            event = "eicar.control_ok",
            schedule,
            endpoint = ep,
            "EICAR control detected"
        );
    } else {
        tracing::error!(
            event = "eicar.control_failed",
            schedule,
            endpoint = ep,
            reason = outcome.error_message.as_deref().unwrap_or(""),
            "EICAR control failed: scan results cannot be trusted"
        );
    }
    st.metrics.record(job, &outcome, None);
    if !ok {
        st.notifier
            .notify(scan::event("eicar.control_failed", job, ep, &outcome));
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_span_midnight() {
        let utc = TimeZone::UTC;
        let at = |h: i64, m: i64| (h * 60 + m) * 60_000;
        let night = Some((22 * 60, 6 * 60));
        assert!(in_window(night, &utc, at(23, 0)));
        assert!(in_window(night, &utc, at(5, 59)));
        assert!(!in_window(night, &utc, at(6, 0)));
        assert!(!in_window(night, &utc, at(12, 0)));
        let day = Some((9 * 60, 17 * 60));
        assert!(in_window(day, &utc, at(9, 0)));
        assert!(!in_window(day, &utc, at(17, 0)));
        assert!(in_window(None, &utc, at(3, 0)));
        let c: Cron = "0 * * * *".parse().expect("cron");
        let runs = next_runs(&c, night, &utc, at(12, 0), 3);
        assert_eq!(runs, vec![at(22, 0), at(23, 0), at(24, 0)]);
    }

    #[test]
    fn eicar_is_the_standard_68_bytes() {
        let e = super::eicar();
        assert_eq!(e.len(), 68);
        assert!(e.starts_with(b"X5O!P%@AP"));
    }
}
