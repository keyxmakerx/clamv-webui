//! Canary files: decoys that nobody should touch. Any access raises an alert
//! (an ERROR log line, an audit entry and the webhook).

use std::path::PathBuf;
use std::sync::Arc;

use crate::app::AppState;
use crate::db::audit::AuditEntry;
use crate::webhook::Event;

/// Report a touched canary. `where_` is this host or the agent's name.
pub async fn tripped(st: &AppState, where_: &str, path: &str, what: &str) {
    tracing::error!(
        event = "canary.tripped",
        endpoint = %where_,
        path = %path,
        what = %what,
        "canary file touched"
    );
    st.db
        .audit(AuditEntry {
            action: "CANARY_TRIPPED",
            outcome: "ALERT",
            details: Some(format!("{where_}: {path} {what}")),
            transport: Some("CANARY"),
            ..Default::default()
        })
        .await;
    st.notifier.notify(Event {
        event: "canary.tripped",
        job_id: String::new(),
        kind: "CANARY".into(),
        target: path.into(),
        endpoint: where_.into(),
        submitted_by: None,
        verdict: "ALERT".into(),
        found_viruses: Vec::new(),
        detections: Default::default(),
        files_scanned: 0,
        file_errors: 0,
        error_code: None,
        error: Some(what.into()),
        finished_at: crate::timefmt::rfc3339(crate::db::now_ms()),
    });
}

/// Warn about canaries that scans would open (and so trip).
pub fn check_placement(
    files: &[PathBuf],
    scanned: &[PathBuf],
    conf: Option<&crate::clamdconf::ConfFile>,
) {
    for f in files {
        let inside = scanned.iter().any(|r| f.starts_with(r));
        let excluded = conf.is_some_and(|c| c.excluded(&f.to_string_lossy()));
        if inside && !excluded {
            tracing::warn!(
                event = "canary.scanned",
                path = %f.display(),
                "canary is inside a scanned folder, so scans will trip it; add an ExcludePath or move it"
            );
        }
    }
}

/// Watch CANARY_FILES on this host.
pub fn spawn(st: Arc<AppState>) {
    let files = st.cfg.canary_files.clone();
    if files.is_empty() {
        return;
    }
    let conf = st
        .clamd_conf
        .load(st.cfg.clamd_conf_file.as_deref())
        .ok()
        .flatten();
    check_placement(&files, &st.cfg.scan_roots, conf.as_deref());
    let mut rx = match crate::fsevents::canaries(files) {
        Ok(rx) => rx,
        Err(e) => {
            tracing::error!(event = "canary.unavailable", error = %e, "canary files cannot be watched");
            return;
        }
    };
    let host = hostname();
    tokio::spawn(async move {
        while let Some((p, what)) = rx.recv().await {
            tripped(&st, &host, &p.to_string_lossy(), what).await;
        }
    });
}

/// This machine's name, for alerts.
pub fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "server".into())
}
