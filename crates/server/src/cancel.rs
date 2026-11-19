//! Cancel a queued or running job, on this server or on an agent.
//!
//! The job is finished first (verdict ERROR, code CANCELLED), so any result
//! that arrives afterwards is ignored. A local scan is then stopped at once;
//! an agent hears on its next poll, which is woken for it.

use crate::app::AppState;
use crate::db::jobs::{self, Job, Outcome};

pub use crate::agent::CANCELLED;

/// Job kinds that can be stopped while running; the others are short and run to the end.
const STOPPABLE: [&str; 2] = [crate::scan::KIND_PATH, crate::scan::KIND_WATCH];

/// Why this job cannot be cancelled now, if it cannot.
pub fn refuse(j: &Job) -> Option<&'static str> {
    match j.status.as_str() {
        jobs::QUEUED => None,
        jobs::RUNNING if STOPPABLE.contains(&j.kind.as_str()) => None,
        jobs::RUNNING => Some("This kind of job cannot be stopped once it runs."),
        _ => Some("This job has already finished."),
    }
}

/// Cancel `j` for `who`. Returns a message for the user when it could not be done.
pub async fn cancel(st: &AppState, j: &Job, who: &str) -> Result<(), &'static str> {
    if let Some(m) = refuse(j) {
        return Err(m);
    }
    let o = Outcome {
        verdict: jobs::ERROR,
        error_code: Some(CANCELLED),
        error_message: Some(format!(
            "Cancelled by {}.",
            who.chars()
                .filter(|c| !c.is_control())
                .take(64)
                .collect::<String>()
        )),
        ..Outcome::default()
    };
    match st.db.finish_job_if(&j.id, &j.status, &o).await {
        Ok(true) => {}
        Ok(false) => return Err("This job has already finished."),
        Err(e) => {
            tracing::error!(job_id = %j.id, error = %e, "could not cancel job");
            return Err("Service unavailable.");
        }
    }
    let was_running = j.status == jobs::RUNNING;
    if was_running {
        match j.agent_id {
            Some(_) => st.agents.poke(),
            None => {
                st.runner.stop(&j.id);
            }
        }
    }
    tracing::warn!(event = "job.cancelled", job_id = %j.id, kind = %j.kind, scan_target = %j.target, by = %who, running = was_running, agent_id = j.agent_id.unwrap_or(0), "job cancelled");
    Ok(())
}
