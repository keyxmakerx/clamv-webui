//! The scheduler (F1) and the EICAR negative control (F2).
//!
//! Every 30 s each enabled schedule whose next cron time has passed is
//! claimed once and queued as PATH jobs. Missed runs while the server was
//! down collapse into one. A run is skipped while the previous one is still
//! going. With the control on, each run first streams the EICAR test file to
//! clamd; if clamd does not flag it, `eicar.control_failed` is logged at
//! ERROR, because a scanner that misses EICAR misses everything.

use std::sync::Arc;
use std::time::Duration;

use crate::app::AppState;
use crate::cron::Cron;
use crate::db::endpoints::Endpoint;
use crate::db::jobs::{self, NewJob, Outcome};
use crate::db::now_ms;
use crate::db::schedules::Schedule;
use crate::scan;

pub const KIND_CONTROL: &str = "CONTROL";

/// The EICAR test file, assembled at run time so this binary is not itself flagged.
pub fn eicar() -> Vec<u8> {
    let mut v = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$".to_vec();
    v.extend_from_slice(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
    v
}

pub fn spawn(st: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            if let Err(e) = due(&st).await {
                tracing::warn!(error = %e, "scheduler tick failed");
            }
        }
    });
}

async fn due(st: &AppState) -> Result<(), crate::db::DbError> {
    let now = now_ms();
    for s in st.db.list_schedules().await? {
        if !s.enabled {
            continue;
        }
        let Ok(cron) = s.cron.parse::<Cron>() else {
            continue;
        };
        let base = s.last_run_at.unwrap_or(s.created_at);
        if cron.next_after(base).is_some_and(|t| t <= now) {
            let _ = run(st, &s, "cron").await;
        }
    }
    Ok(())
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
    let Some(ep) = scan::pick_endpoint(st, s.endpoint_id).await else {
        tracing::error!(event = "schedule.failed", schedule = %s.name, trigger, "no enabled clamd endpoint");
        return Err("No enabled clamd endpoint.".into());
    };
    if s.eicar_check {
        control(st, s, &ep).await;
    }
    let by = format!("schedule:{}", s.name);
    let mut last = None;
    let mut queued = 0;
    for p in &s.paths {
        match st
            .db
            .create_job(NewJob {
                kind: scan::KIND_PATH,
                target: p,
                endpoint_id: Some(ep.id),
                schedule_id: Some(&s.id),
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
    tracing::info!(event = "schedule.started", schedule = %s.name, endpoint = %ep.name, jobs = queued, trigger, "scheduled scan started");
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
    if ok {
        tracing::info!(event = "eicar.control_ok", schedule = %s.name, endpoint = %ep.name, "EICAR control detected");
    } else {
        tracing::error!(event = "eicar.control_failed", schedule = %s.name, endpoint = %ep.name, reason = outcome.error_message.as_deref().unwrap_or(""), "EICAR control failed: scan results cannot be trusted");
    }
    if let Err(e) = st.db.finish_job(&job.id, &outcome).await {
        tracing::error!(error = %e, "could not store EICAR control");
    }
    if !ok {
        st.notifier.notify(scan::event(
            "eicar.control_failed",
            &job,
            &ep.name,
            &outcome,
        ));
    }
    ok
}

#[cfg(test)]
mod tests {
    #[test]
    fn eicar_is_the_standard_68_bytes() {
        let e = super::eicar();
        assert_eq!(e.len(), 68);
        assert!(e.starts_with(b"X5O!P%@AP"));
    }
}
