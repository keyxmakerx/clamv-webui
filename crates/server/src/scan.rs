//! Scan execution: path policy, the job runner and result handling.
//!
//! Every detection, limit hit and per-file error is logged with a stable
//! `event` field (N1), because logs are the operator's alert path.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use crate::app::AppState;
use crate::db::endpoints::Endpoint;
use crate::db::jobs::{self, Job, JobFileError, Outcome};

pub const KIND_UPLOAD: &str = "UPLOAD";
pub const KIND_PATH: &str = "PATH";

/// Error codes shared with `/api/v1` (`JobError.code`).
pub const POLICY_REJECTED: &str = "POLICY_REJECTED";
pub const CONFIGURATION_UNAVAILABLE: &str = "CONFIGURATION_UNAVAILABLE";
pub const LIMIT_EXCEEDED: &str = "LIMIT_EXCEEDED";
pub const SCAN_FAILED: &str = "SCAN_FAILED";

/// One generic answer for "outside the roots" and "does not exist" (no existence oracle, S9).
pub const PATH_REJECTED: &str = "That path is not allowed or does not exist.";

/// Resolve `input` to a real path inside one of `roots`, following symlinks.
/// Called when a job is submitted and again right before it runs (S5).
pub async fn resolve_path(roots: &[PathBuf], input: &str) -> Result<PathBuf, &'static str> {
    if input.is_empty()
        || input.len() > 4096
        || input.bytes().any(|b| matches!(b, 0 | b'\n' | b'\r'))
        || !Path::new(input).is_absolute()
    {
        return Err(PATH_REJECTED);
    }
    let real = tokio::fs::canonicalize(input)
        .await
        .map_err(|_| PATH_REJECTED)?;
    for root in roots {
        if let Ok(r) = tokio::fs::canonicalize(root).await
            && real.starts_with(&r)
        {
            return Ok(real);
        }
    }
    Err(PATH_REJECTED)
}

/// Turn a clamd report into a stored outcome.
///
/// `Heuristics.Limits.Exceeded.*` hits mean "not fully scanned", not malware,
/// so they are kept as per-file errors with their own code.
pub fn outcome(report: clamd::ScanReport) -> Outcome {
    let mut detections: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut errors: Vec<JobFileError> = report
        .errors
        .into_iter()
        .map(|e| JobFileError {
            path: e.path,
            message: e.message,
        })
        .collect();
    let mut limit_hits = 0usize;
    for d in report.detections {
        if d.is_limit_exceeded() {
            limit_hits += 1;
            errors.push(JobFileError {
                path: d.path,
                message: format!("{} (not fully scanned)", d.signature),
            });
        } else {
            detections.entry(d.path).or_default().push(d.signature);
        }
    }
    let files = report.ok as usize + detections.len() + errors.len();
    let (verdict, code, msg) = if !detections.is_empty() {
        (jobs::VIRUS_FOUND, None, None)
    } else if errors.is_empty() {
        (jobs::OK, None, None)
    } else if limit_hits == errors.len() {
        (
            jobs::ERROR,
            Some(LIMIT_EXCEEDED),
            Some(format!("{limit_hits} file(s) exceeded clamd scan limits.")),
        )
    } else {
        (
            jobs::ERROR,
            Some(SCAN_FAILED),
            Some(format!("{} file(s) could not be scanned.", errors.len())),
        )
    };
    Outcome {
        verdict,
        files_scanned: i64::try_from(files).unwrap_or(i64::MAX),
        detections,
        errors,
        error_code: code,
        error_message: msg,
        ..Outcome::default()
    }
}

/// A whole-job failure (clamd down, policy, limits) with a fixed public message.
pub fn failure(code: &'static str, message: &str) -> Outcome {
    Outcome {
        verdict: jobs::ERROR,
        error_code: Some(code),
        error_message: Some(message.to_owned()),
        ..Outcome::default()
    }
}

/// Log every result line, then store the outcome.
pub async fn finish(st: &AppState, job: &Job, endpoint: Option<&Endpoint>, o: Outcome) {
    let ep = endpoint.map_or("-", |e| e.name.as_str());
    for (path, sigs) in &o.detections {
        for sig in sigs {
            tracing::warn!(event = "scan.detected", job_id = %job.id, kind = %job.kind, endpoint = ep, path = %path, signature = %sig, "malware detected");
        }
    }
    for e in &o.errors {
        if e.message.starts_with("Heuristics.Limits.Exceeded") {
            tracing::warn!(event = "scan.limit_exceeded", job_id = %job.id, kind = %job.kind, endpoint = ep, path = %e.path, reason = %e.message, "file not fully scanned");
        } else {
            tracing::warn!(event = "scan.error", job_id = %job.id, kind = %job.kind, endpoint = ep, path = %e.path, reason = %e.message, "file could not be scanned");
        }
    }
    match o.error_code {
        Some(code) if o.detections.is_empty() && o.errors.is_empty() => {
            tracing::error!(event = "scan.failed", job_id = %job.id, kind = %job.kind, endpoint = ep, target = %job.target, code, reason = o.error_message.as_deref().unwrap_or(""), "scan failed");
        }
        _ => {
            tracing::info!(event = "scan.finished", job_id = %job.id, kind = %job.kind, endpoint = ep, target = %job.target, verdict = o.verdict, files = o.files_scanned, detections = o.detections.len(), errors = o.errors.len(), "scan finished");
        }
    }
    if let Err(e) = st.db.finish_job(&job.id, &o).await {
        tracing::error!(event = "scan.store_failed", job_id = %job.id, error = %e, "could not store scan result");
    }
}

/// The job's endpoint if set and enabled, else the default.
pub async fn pick_endpoint(st: &AppState, id: Option<i64>) -> Option<Endpoint> {
    if let Some(id) = id {
        return st
            .db
            .endpoint(id)
            .await
            .ok()
            .flatten()
            .filter(|e| e.enabled);
    }
    st.db.default_endpoint().await.ok().flatten()
}

/// Runs queued path jobs, at most `SCAN_CONCURRENCY` at once.
pub struct Runner {
    wake: Notify,
    permits: Arc<Semaphore>,
}

impl Runner {
    pub fn new(concurrency: usize) -> Self {
        Self {
            wake: Notify::new(),
            permits: Arc::new(Semaphore::new(concurrency.max(1))),
        }
    }

    /// Tell the dispatcher a job was queued.
    pub fn poke(&self) {
        self.wake.notify_one();
    }

    pub fn busy(&self, capacity: usize) -> usize {
        capacity.saturating_sub(self.permits.available_permits())
    }
}

/// Start the dispatcher. Jobs left RUNNING by a crash are marked interrupted first.
pub async fn start(st: Arc<AppState>) {
    match st.db.interrupt_running_jobs().await {
        Ok(n) if n > 0 => {
            tracing::warn!(
                event = "scan.interrupted",
                jobs = n,
                "jobs interrupted by restart"
            )
        }
        Ok(_) => {}
        Err(e) => tracing::error!(error = %e, "could not reset running jobs"),
    }
    tokio::spawn(async move {
        loop {
            dispatch(&st).await;
            tokio::select! {
                () = st.runner.wake.notified() => {}
                () = tokio::time::sleep(Duration::from_secs(30)) => {}
            }
        }
    });
}

async fn dispatch(st: &Arc<AppState>) {
    let ids = match st.db.queued_jobs(50).await {
        Ok(ids) => ids,
        Err(e) => {
            tracing::warn!(error = %e, "could not list queued jobs");
            return;
        }
    };
    for id in ids {
        let Ok(permit) = st.runner.permits.clone().acquire_owned().await else {
            return;
        };
        match st.db.claim_job(&id).await {
            Ok(true) => {
                let st = st.clone();
                tokio::spawn(async move { run(st, id, permit).await });
            }
            Ok(false) => {}
            Err(e) => tracing::warn!(error = %e, job_id = %id, "claim failed"),
        }
    }
}

async fn run(st: Arc<AppState>, id: String, _permit: OwnedSemaphorePermit) {
    let job = match st.db.job(&id).await {
        Ok(Some(j)) => j,
        _ => return,
    };
    match job.kind.as_str() {
        KIND_PATH => run_path(&st, &job).await,
        other => {
            let o = failure(SCAN_FAILED, "This job type cannot be run.");
            tracing::error!(job_id = %id, kind = other, "unknown job kind");
            finish(&st, &job, None, o).await;
        }
    }
}

async fn run_path(st: &AppState, job: &Job) {
    let Some(ep) = pick_endpoint(st, job.endpoint_id).await else {
        return finish(
            st,
            job,
            None,
            failure(CONFIGURATION_UNAVAILABLE, "No enabled clamd endpoint."),
        )
        .await;
    };
    // Re-check at use time: the tree may have changed since submission.
    let path = match resolve_path(&st.cfg.scan_roots, &job.target).await {
        Ok(p) => p,
        Err(m) => return finish(st, job, Some(&ep), failure(POLICY_REJECTED, m)).await,
    };
    let Ok(addr) = ep.parsed() else {
        return finish(
            st,
            job,
            Some(&ep),
            failure(CONFIGURATION_UNAVAILABLE, "Endpoint address is invalid."),
        )
        .await;
    };
    let o = match st.clamd(addr).multiscan(&path).await {
        Ok(report) => outcome(report),
        Err(e) => {
            tracing::warn!(job_id = %job.id, endpoint = %ep.name, error = %e, "clamd path scan failed");
            failure(SCAN_FAILED, "clamd did not complete the scan.")
        }
    };
    finish(st, job, Some(&ep), o).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(dets: &[(&str, &str)], errs: &[(&str, &str)], ok: u64) -> clamd::ScanReport {
        clamd::ScanReport {
            detections: dets
                .iter()
                .map(|(p, s)| clamd::Detection {
                    path: (*p).into(),
                    signature: (*s).into(),
                })
                .collect(),
            errors: errs
                .iter()
                .map(|(p, m)| clamd::FileError {
                    path: (*p).into(),
                    message: (*m).into(),
                })
                .collect(),
            ok,
        }
    }

    #[test]
    fn classifies_results() {
        let o = outcome(report(&[], &[], 1));
        assert_eq!((o.verdict, o.error_code), (jobs::OK, None));

        let o = outcome(report(
            &[("/d/a", "Eicar-Signature")],
            &[("/d/b", "Access denied")],
            0,
        ));
        assert_eq!(o.verdict, jobs::VIRUS_FOUND);
        assert_eq!(o.errors.len(), 1, "errors kept next to detections (N3)");

        let o = outcome(report(
            &[("/d/big.iso", "Heuristics.Limits.Exceeded.MaxFileSize")],
            &[],
            0,
        ));
        assert_eq!(
            (o.verdict, o.error_code),
            (jobs::ERROR, Some(LIMIT_EXCEEDED))
        );
        assert!(o.detections.is_empty(), "limit hits are not malware");

        let o = outcome(report(
            &[("/d/big.iso", "Heuristics.Limits.Exceeded.MaxScanSize")],
            &[("/d/x", "lstat() failed")],
            0,
        ));
        assert_eq!(o.error_code, Some(SCAN_FAILED));
    }

    #[tokio::test]
    async fn paths_stay_inside_roots() {
        let base = std::env::temp_dir().join(format!("clamv-roots-{}", crate::db::new_id()));
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(root.join("sub")).expect("mkdir");
        std::fs::create_dir_all(&outside).expect("mkdir");
        std::fs::write(outside.join("secret"), b"x").expect("write");
        let roots = vec![root.clone()];
        let ok = resolve_path(&roots, root.join("sub").to_str().expect("utf8")).await;
        assert!(ok.is_ok());
        let dotdot = format!("{}/sub/../../outside/secret", root.display());
        assert_eq!(resolve_path(&roots, &dotdot).await, Err(PATH_REJECTED));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, root.join("link")).expect("symlink");
            let via = format!("{}/link/secret", root.display());
            assert_eq!(
                resolve_path(&roots, &via).await,
                Err(PATH_REJECTED),
                "symlink escape"
            );
        }
        assert_eq!(
            resolve_path(&roots, "relative/path").await,
            Err(PATH_REJECTED)
        );
        assert_eq!(
            resolve_path(&roots, &format!("{}\n", root.display())).await,
            Err(PATH_REJECTED)
        );
        assert_eq!(
            resolve_path(&[], root.to_str().expect("utf8")).await,
            Err(PATH_REJECTED)
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
