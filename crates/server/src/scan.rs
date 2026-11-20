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
pub const KIND_WATCH: &str = "WATCH";

/// Error codes shared with `/api/v1` (`JobError.code`).
pub const POLICY_REJECTED: &str = "POLICY_REJECTED";
pub const CONFIGURATION_UNAVAILABLE: &str = "CONFIGURATION_UNAVAILABLE";
pub const LIMIT_EXCEEDED: &str = "LIMIT_EXCEEDED";
pub const SCAN_FAILED: &str = "SCAN_FAILED";

/// The path matches an ExcludePath rule in the mounted clamd.conf.
pub const PATH_EXCLUDED: &str = "That path is excluded by ExcludePath in clamd.conf.";

/// One generic answer for "outside the roots" and "does not exist" (no existence oracle, S9).
pub const PATH_REJECTED: &str = "That path is not allowed or does not exist.";

/// Resolve `input` to a real path inside one of `roots`, following symlinks.
/// Called when a job is submitted and again right before it runs (S5).
pub async fn resolve_path(roots: &[PathBuf], input: &str) -> Result<PathBuf, &'static str> {
    if input.is_empty()
        || input.len() > 4096
        || input.bytes().any(|b| matches!(b, 0 | b'\n' | b'\r'))
    {
        return Err(PATH_REJECTED);
    }
    resolve_os_path(roots, Path::new(input)).await
}

/// `resolve_path` for a path that may not be UTF-8.
pub async fn resolve_os_path(roots: &[PathBuf], input: &Path) -> Result<PathBuf, &'static str> {
    if !input.is_absolute() {
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

/// What happened to a result handed to [`finish`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stored {
    Saved,
    /// Someone else finished the job first; this result was ignored.
    AlreadyFinished,
    /// The database refused every attempt; the result is only in the log.
    Failed,
}

/// Waits between attempts to store a result while the database is down.
#[cfg(not(test))]
const STORE_RETRIES_MS: [u64; 4] = [500, 1_500, 4_000, 10_000];
#[cfg(test)]
const STORE_RETRIES_MS: [u64; 4] = [1, 1, 1, 1];

/// Store an outcome, retrying for about 15 s if the database is briefly down.
async fn store(st: &AppState, job: &Job, o: &Outcome) -> Stored {
    let mut waits = STORE_RETRIES_MS.iter();
    loop {
        match st.db.finish_job_if(&job.id, jobs::RUNNING, o).await {
            Ok(true) => return Stored::Saved,
            Ok(false) => return Stored::AlreadyFinished,
            Err(e) => match waits.next() {
                Some(ms) => {
                    tracing::warn!(job_id = %job.id, error = %e, retry_in_ms = ms, "could not store scan result; retrying");
                    tokio::time::sleep(Duration::from_millis(*ms)).await;
                }
                None => {
                    tracing::error!(event = "scan.store_failed", job_id = %job.id, error = %e, "could not store scan result");
                    return Stored::Failed;
                }
            },
        }
    }
}

/// Store the outcome of a RUNNING job, then log every result line, record
/// metrics and call the webhook. A job someone else already finished is left
/// alone. `ep` names where it ran (endpoint or agent) for logs.
pub async fn finish(st: &AppState, job: &Job, ep: &str, o: Outcome) -> Stored {
    let stored = store(st, job, &o).await;
    if stored == Stored::AlreadyFinished {
        tracing::warn!(job_id = %job.id, "job already finished; result ignored");
        return stored;
    }
    // Still log below: logs are the alert path even when the database is down.
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
            tracing::error!(event = "scan.failed", job_id = %job.id, kind = %job.kind, endpoint = ep, scan_target = %job.target, code, reason = o.error_message.as_deref().unwrap_or(""), "scan failed");
        }
        _ => {
            tracing::info!(event = "scan.finished", job_id = %job.id, kind = %job.kind, endpoint = ep, scan_target = %job.target, verdict = o.verdict, files = o.files_scanned, detections = o.detections.len(), errors = o.errors.len(), "scan finished");
        }
    }
    let secs = job
        .started_at
        .map(|s| (crate::db::now_ms() - s) as f64 / 1000.0);
    st.metrics.record(job, &o, secs);
    st.notifier.notify(event("scan.finished", job, ep, &o));
    if stored == Stored::Saved && !o.detections.is_empty() && job.kind != crate::quarantine::KIND {
        crate::quarantine::auto(st, &job.id).await;
    }
    stored
}

/// Finishes an upload job if its request is dropped (client disconnect)
/// before the scan ends, so it never stays RUNNING until a restart.
pub struct UploadGuard {
    st: Arc<AppState>,
    job: Option<Job>,
    ep: String,
}

impl UploadGuard {
    pub fn new(st: &Arc<AppState>, job: &Job, ep: &str) -> Self {
        Self {
            st: st.clone(),
            job: Some(job.clone()),
            ep: ep.to_owned(),
        }
    }

    /// Store the real outcome; the guard then has nothing left to do.
    pub async fn finish(mut self, o: Outcome) -> Stored {
        let Some(job) = self.job.clone() else {
            return Stored::AlreadyFinished;
        };
        // Disarm only once stored: if this is dropped midway, Drop still finishes the job.
        let r = finish(&self.st, &job, &self.ep, o).await;
        self.job = None;
        r
    }
}

impl Drop for UploadGuard {
    fn drop(&mut self) {
        let Some(job) = self.job.take() else {
            return;
        };
        let st = self.st.clone();
        let ep = std::mem::take(&mut self.ep);
        // Only possible inside the runtime that ran the request.
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                tracing::warn!(job_id = %job.id, "upload request ended before the scan finished");
                let o = failure(SCAN_FAILED, "The upload was interrupted.");
                finish(&st, &job, &ep, o).await;
            });
        }
    }
}

/// The webhook view of a finished job.
pub fn event(name: &'static str, job: &Job, endpoint: &str, o: &Outcome) -> crate::webhook::Event {
    let mut found: Vec<String> = o.detections.values().flatten().cloned().collect();
    found.sort();
    found.dedup();
    crate::webhook::Event {
        event: name,
        job_id: job.id.clone(),
        kind: job.kind.clone(),
        target: job.target.clone(),
        endpoint: endpoint.to_owned(),
        submitted_by: job.submitted_by.clone(),
        verdict: o.verdict.to_owned(),
        found_viruses: found,
        detections: o.detections.clone(),
        files_scanned: o.files_scanned,
        file_errors: o.errors.len(),
        error_code: o.error_code.map(str::to_owned),
        error: o.error_message.clone(),
        finished_at: crate::timefmt::rfc3339(crate::db::now_ms()),
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
    /// Stops a running local job when it is cancelled.
    stops: std::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<()>>>,
}

impl Runner {
    pub fn new(concurrency: usize) -> Self {
        Self {
            wake: Notify::new(),
            permits: Arc::new(Semaphore::new(concurrency.max(1))),
            stops: std::sync::Mutex::default(),
        }
    }

    /// Stop a running local job; true if one was running.
    pub fn stop(&self, id: &str) -> bool {
        match self.stops.lock().ok().and_then(|mut g| g.remove(id)) {
            Some(tx) => tx.send(()).is_ok(),
            None => false,
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
    crate::quarantine::spawn_settler(st.clone());
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
                let (tx, rx) = tokio::sync::oneshot::channel();
                if let Ok(mut g) = st.runner.stops.lock() {
                    g.insert(id.clone(), tx);
                }
                let st = st.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        () = run(st.clone(), id.clone(), permit) => {}
                        Ok(()) = rx => tracing::info!(job_id = %id, "cancelled scan stopped"),
                    }
                    if let Ok(mut g) = st.runner.stops.lock() {
                        g.remove(&id);
                    }
                });
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
        KIND_PATH | KIND_WATCH => {
            run_path(&st, &job).await;
        }
        other => {
            let o = failure(SCAN_FAILED, "This job type cannot be run.");
            tracing::error!(job_id = %id, kind = other, "unknown job kind");
            finish(&st, &job, "-", o).await;
        }
    }
}

async fn run_path(st: &AppState, job: &Job) -> Stored {
    let Some(ep) = pick_endpoint(st, job.endpoint_id).await else {
        return finish(
            st,
            job,
            "-",
            failure(CONFIGURATION_UNAVAILABLE, "No enabled clamd endpoint."),
        )
        .await;
    };
    // A watched file whose name is not UTF-8: its exact bytes are in the key.
    let raw = if job.kind == KIND_WATCH {
        crate::watch::raw_path(&job.target)
    } else {
        None
    };
    // Re-check at use time: the tree may have changed since submission.
    let resolved = match &raw {
        Some(p) => resolve_os_path(&st.cfg.scan_roots, p).await,
        None => resolve_path(&st.cfg.scan_roots, &job.target).await,
    };
    let path = match resolved {
        Ok(p) => p,
        Err(m) => return finish(st, job, &ep.name, failure(POLICY_REJECTED, m)).await,
    };
    let Ok(addr) = ep.parsed() else {
        return finish(
            st,
            job,
            &ep.name,
            failure(CONFIGURATION_UNAVAILABLE, "Endpoint address is invalid."),
        )
        .await;
    };
    // Watched files: remember size and mtime as seen before the scan.
    let seen = if job.kind == KIND_WATCH {
        tokio::fs::metadata(&path)
            .await
            .ok()
            .map(|m| crate::watch::stamp(&m))
    } else {
        None
    };
    let result = if raw.is_some() {
        // clamd's reply names files as text; stream the file so the name never matters.
        stream_file(st, addr, &path, &job.target).await
    } else {
        st.clamd(addr).multiscan(&path).await
    };
    let o = match result {
        Ok(report) => outcome(report),
        Err(clamd::Error::StreamTooLarge(_)) => failure(
            LIMIT_EXCEEDED,
            "The file is larger than CLAMD_MAX_STREAM_MB.",
        ),
        Err(e) => {
            tracing::warn!(job_id = %job.id, endpoint = %ep.name, error = %e, "clamd path scan failed");
            failure(SCAN_FAILED, "clamd did not complete the scan.")
        }
    };
    if let Some((mtime, size)) = seen {
        crate::watch::record(st, &job.target, mtime, size, &o).await;
    }
    finish(st, job, &ep.name, o).await
}

/// Scan one file by streaming it; results are named `display`.
async fn stream_file(
    st: &AppState,
    addr: clamd::Endpoint,
    path: &Path,
    display: &str,
) -> Result<clamd::ScanReport, clamd::Error> {
    let f = tokio::fs::File::open(path)
        .await
        .map_err(clamd::Error::Io)?;
    let mut r = st
        .clamd(addr)
        .instream(tokio::io::BufReader::new(f))
        .await?;
    for d in &mut r.detections {
        d.path = display.to_owned();
    }
    for e in &mut r.errors {
        e.path = display.to_owned();
    }
    Ok(r)
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
    async fn finish_reports_whether_the_result_was_saved() {
        use clap::Parser;
        let cli = crate::config::Cli::parse_from(["palisade"]);
        let db = crate::db::Db::open("sqlite::memory:", 1).await.expect("db");
        let st = AppState::new(cli.config.clone(), db);
        let new = || jobs::NewJob {
            kind: KIND_PATH,
            target: "/d",
            endpoint_id: None,
            schedule_id: None,
            agent_id: None,
            submitted_by: None,
            transport: "UI",
            running: true,
        };
        let job = st.db.create_job(new()).await.expect("job");
        let ok = || outcome(report(&[], &[], 1));
        assert_eq!(finish(&st, &job, "-", ok()).await, Stored::Saved);
        assert_eq!(finish(&st, &job, "-", ok()).await, Stored::AlreadyFinished);
        // Database gone: every retry fails, and the caller is told so (an agent then resends).
        let job = st.db.create_job(new()).await.expect("job");
        st.db.close().await;
        assert_eq!(finish(&st, &job, "-", ok()).await, Stored::Failed);
    }

    #[tokio::test]
    async fn paths_stay_inside_roots() {
        let base = std::env::temp_dir().join(format!("palisade-roots-{}", crate::db::new_id()));
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
