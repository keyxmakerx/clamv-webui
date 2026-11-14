//! AIDE and rkhunter results. Each host runs them on its own timer; the
//! server and agents read their report files (mounted read-only), and every
//! new run is stored, logged and, when it found something, alerted.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::db::audit::AuditEntry;
use crate::webhook::Event;

pub const AIDE: &str = "aide";
pub const RKHUNTER: &str = "rkhunter";
const MAX_FINDINGS: usize = 200;
const TAIL_BYTES: u64 = 2 * 1024 * 1024;

/// One run of one tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub tool: String,
    /// When the report file was last written (unix ms).
    pub ran_at: i64,
    pub ok: bool,
    pub summary: String,
    #[serde(default)]
    pub findings: Vec<String>,
}

impl Report {
    /// Cap sizes and strip control characters from what a host sent.
    pub fn cleaned(mut self) -> Option<Self> {
        if self.tool != AIDE && self.tool != RKHUNTER {
            return None;
        }
        let clean = |s: &str, n: usize| -> String {
            s.chars().filter(|c| !c.is_control()).take(n).collect()
        };
        self.summary = clean(&self.summary, 500);
        self.findings = self
            .findings
            .iter()
            .take(MAX_FINDINGS)
            .map(|f| clean(f, 1000))
            .collect();
        Some(self)
    }
}

/// The last run in an AIDE `--check` log.
pub fn parse_aide(text: &str, ran_at: i64) -> Option<Report> {
    let start = text
        .rfind("Start timestamp:")
        .or_else(|| text.rfind("AIDE found"))
        .or_else(|| text.rfind("AIDE, version"))?;
    let run = &text[start..];
    if run.contains("found NO differences") {
        return Some(Report {
            tool: AIDE.into(),
            ran_at,
            ok: true,
            summary: "no changes".into(),
            findings: Vec::new(),
        });
    }
    if !run.contains("found differences") {
        return None;
    }
    let count = |label: &str| -> u64 {
        run.lines()
            .find_map(|l| l.trim().strip_prefix(label))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    };
    let (added, removed, changed) = (
        count("Added entries:"),
        count("Removed entries:"),
        count("Changed entries:"),
    );
    let mut findings = Vec::new();
    let mut section = "";
    for l in run.lines() {
        let t = l.trim();
        match t {
            "Added entries:" => section = "added",
            "Removed entries:" => section = "removed",
            "Changed entries:" => section = "changed",
            "Detailed information about changes:" => section = "",
            _ => {}
        }
        // 0.16: "changed: /etc/passwd"; 0.17+: "f   ...    .C... : /etc/passwd".
        let entry = t.split_once(": /").and_then(|(kind, p)| {
            if matches!(kind, "added" | "removed" | "changed") {
                Some((kind.to_owned(), format!("/{p}")))
            } else if !section.is_empty() {
                Some((section.to_owned(), format!("/{p}")))
            } else {
                None
            }
        });
        if let Some((k, p)) = entry
            && findings.len() < MAX_FINDINGS
        {
            findings.push(format!("{k}: {p}"));
        }
    }
    Some(Report {
        tool: AIDE.into(),
        ran_at,
        ok: false,
        summary: format!("{added} added, {removed} removed, {changed} changed"),
        findings,
    })
}

/// The last run in an rkhunter log.
pub fn parse_rkhunter(text: &str, ran_at: i64) -> Option<Report> {
    let start = text.rfind("Rootkit Hunter version").unwrap_or(0);
    let run = &text[start..];
    if !run.contains("Rootkit Hunter") && !run.contains("rkhunter") {
        return None;
    }
    // Lines look like "[03:00:12] Warning: ...".
    let strip = |l: &str| -> String {
        let l = l.trim();
        match l.strip_prefix('[').and_then(|r| r.split_once(']')) {
            Some((_, rest)) => rest.trim().to_owned(),
            None => l.to_owned(),
        }
    };
    let lines: Vec<String> = run.lines().map(strip).collect();
    let findings: Vec<String> = lines
        .iter()
        .filter(|l| l.starts_with("Warning:"))
        .take(MAX_FINDINGS)
        .map(|l| l.trim_start_matches("Warning:").trim().to_owned())
        .collect();
    let num = |label: &str| -> Option<u64> {
        lines
            .iter()
            .find_map(|l| l.strip_prefix(label))
            .and_then(|v| v.trim().trim_start_matches(':').trim().parse().ok())
    };
    let rootkits = num("Possible rootkits");
    let suspect = num("Suspect files");
    let mut summary = if findings.is_empty() {
        "no warnings".to_owned()
    } else {
        format!("{} warning(s)", findings.len())
    };
    if let Some(r) = rootkits {
        summary.push_str(&format!(", possible rootkits: {r}"));
    }
    if let Some(s) = suspect {
        summary.push_str(&format!(", suspect files: {s}"));
    }
    Some(Report {
        tool: RKHUNTER.into(),
        ran_at,
        ok: findings.is_empty() && rootkits.unwrap_or(0) == 0,
        summary,
        findings,
    })
}

/// Read the tail of a report file and parse it, with the file's mtime.
pub fn read(tool: &str, path: &Path) -> Option<Report> {
    use std::io::{Read, Seek, SeekFrom};
    let meta = std::fs::metadata(path).ok()?;
    let ran_at = meta
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())?;
    let mut f = std::fs::File::open(path).ok()?;
    f.seek(SeekFrom::Start(meta.len().saturating_sub(TAIL_BYTES)))
        .ok()?;
    let mut buf = Vec::new();
    f.take(TAIL_BYTES).read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    match tool {
        AIDE => parse_aide(&text, ran_at),
        _ => parse_rkhunter(&text, ran_at),
    }
}

/// Check the report files every few minutes and hand over each new run.
pub fn watch<F, Fut>(
    sources: Vec<(&'static str, PathBuf)>,
    mut seen: Vec<(String, i64)>,
    mut sink: F,
) where
    F: FnMut(Report) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let sources: Vec<_> = sources
        .into_iter()
        .filter(|(_, p)| !p.as_os_str().is_empty())
        .collect();
    if sources.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        loop {
            tick.tick().await;
            for (tool, path) in &sources {
                let (t, p) = (*tool, path.clone());
                let Ok(Some(r)) = tokio::task::spawn_blocking(move || read(t, &p)).await else {
                    continue;
                };
                if seen.iter().any(|(k, at)| k == tool && *at == r.ran_at) {
                    continue;
                }
                seen.retain(|(k, _)| k != tool);
                seen.push(((*tool).to_owned(), r.ran_at));
                sink(r).await;
            }
        }
    });
}

/// Store a run, log it and alert on findings. `agent` None is this server.
pub async fn record(st: &AppState, agent: Option<i64>, host: &str, r: Report) {
    match st.db.add_integrity_report(agent, &r).await {
        Ok(true) => {}
        Ok(false) => return, // already have this run
        Err(e) => {
            tracing::warn!(error = %e, "could not store integrity report");
            return;
        }
    }
    if r.ok {
        tracing::info!(event = "integrity.clean", host = %host, tool = %r.tool, summary = %r.summary, "integrity check clean");
        return;
    }
    tracing::warn!(event = "integrity.findings", host = %host, tool = %r.tool, summary = %r.summary, first = r.findings.first().map_or("", String::as_str), "integrity check found changes");
    st.db
        .audit(AuditEntry {
            action: "INTEGRITY_FINDINGS",
            outcome: "ALERT",
            details: Some(format!("{host}: {} {}", r.tool, r.summary)),
            transport: Some("INTEGRITY"),
            ..Default::default()
        })
        .await;
    st.notifier.notify(Event {
        event: "integrity.findings",
        job_id: String::new(),
        kind: r.tool.to_ascii_uppercase(),
        target: r.summary.clone(),
        endpoint: host.into(),
        submitted_by: None,
        verdict: "ALERT".into(),
        found_viruses: Vec::new(),
        detections: Default::default(),
        files_scanned: 0,
        file_errors: 0,
        error_code: None,
        error: Some(
            r.findings
                .iter()
                .take(10)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        finished_at: crate::timefmt::rfc3339(r.ran_at),
    });
}

/// Watch this server's AIDE and rkhunter reports.
pub fn spawn(st: Arc<AppState>) {
    let sources = sources(&st.cfg);
    let host = crate::canary::hostname();
    tokio::spawn(async move {
        let seen = st.db.latest_integrity_runs(None).await.unwrap_or_default();
        let st2 = st.clone();
        watch(sources, seen, move |r| {
            let (st, host) = (st2.clone(), host.clone());
            async move { record(&st, None, &host, r).await }
        });
    });
}

pub fn sources(cfg: &crate::config::Config) -> Vec<(&'static str, PathBuf)> {
    vec![
        (AIDE, cfg.aide_log.clone()),
        (RKHUNTER, cfg.rkhunter_log.clone()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const AIDE_017: &str = "Start timestamp: 2026-11-10 03:00:01 +0000 (AIDE 0.17.4)\n\
AIDE found NO differences between database and filesystem. Looks okay!!\n\
Start timestamp: 2026-11-11 03:00:01 +0000 (AIDE 0.17.4)\n\
AIDE found differences between database and filesystem!!\n\n\
Summary:\n  Total number of entries:\t41012\n  Added entries:\t\t1\n  Removed entries:\t\t0\n  Changed entries:\t\t2\n\n\
---------------------------------------------------\nAdded entries:\n---------------------------------------------------\n\n\
f++++++++++++++++: /etc/cron.d/backdoor\n\n\
---------------------------------------------------\nChanged entries:\n---------------------------------------------------\n\n\
f   ...    .C... : /usr/bin/sshd\nf   ...    .C... : /etc/passwd\n\n\
---------------------------------------------------\nDetailed information about changes:\n---------------------------------------------------\n\n\
File: /usr/bin/sshd\n  SHA256    : abc | def\n";

    #[test]
    fn aide_last_run_with_entries() {
        let r = parse_aide(AIDE_017, 5).expect("report");
        assert!(!r.ok);
        assert_eq!(r.summary, "1 added, 0 removed, 2 changed");
        assert_eq!(
            r.findings,
            vec![
                "added: /etc/cron.d/backdoor",
                "changed: /usr/bin/sshd",
                "changed: /etc/passwd"
            ]
        );
        let clean = parse_aide("Start timestamp: x\nAIDE found NO differences between database and filesystem. Looks okay!!\n", 1).expect("r");
        assert!(clean.ok);
        let old = parse_aide(
            "AIDE found differences between database and filesystem!!\nchanged: /etc/hosts\n",
            1,
        )
        .expect("r");
        assert_eq!(old.findings, vec!["changed: /etc/hosts"]);
        assert!(parse_aide("nothing here", 1).is_none());
    }

    #[test]
    fn rkhunter_warnings_and_summary() {
        let log = "[ Rootkit Hunter version 1.4.6 ]\n[03:00:10] Checking /usr/bin/ssh [ OK ]\n\
[03:00:12] Warning: The file properties have changed:\n[03:00:12]          File: /usr/bin/ssh\n\
[03:01:40] Warning: Hidden file found: /dev/.blk\n[03:02:00] System checks summary\n\
[03:02:00] Suspect files: 2\n[03:02:00] Possible rootkits: 0\n";
        let r = parse_rkhunter(log, 9).expect("report");
        assert!(!r.ok);
        assert_eq!(
            r.findings,
            vec![
                "The file properties have changed:",
                "Hidden file found: /dev/.blk"
            ]
        );
        assert_eq!(
            r.summary,
            "2 warning(s), possible rootkits: 0, suspect files: 2"
        );
        let ok = parse_rkhunter(
            "[ Rootkit Hunter version 1.4.6 ]\n[03:02:00] Possible rootkits: 0\n",
            1,
        )
        .expect("r");
        assert!(ok.ok);
    }
}
