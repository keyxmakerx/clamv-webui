//! Falco intake. Falco writes one JSON alert per line (json_output with
//! file_output); the server and agents follow that file, read-only, and
//! report each alert. Error and worse also go out as notifications.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::webhook::Event;

/// Most alerts read from the file per pass; the rest wait for the next one.
const MAX_BATCH: usize = 200;
/// One notification per rule per host per this long.
const NOTIFY_COOLDOWN: Duration = Duration::from_secs(600);

/// One Falco alert as a host reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub at: i64,
    pub priority: String,
    pub rule: String,
    pub output: String,
    #[serde(default)]
    pub container: Option<String>,
}

const PRIORITIES: [&str; 8] = [
    "debug",
    "informational",
    "notice",
    "warning",
    "error",
    "critical",
    "alert",
    "emergency",
];

/// 0 (debug) to 7 (emergency); unknown names count as warning.
pub fn rank(p: &str) -> usize {
    let p = p.to_ascii_lowercase();
    let p = if p == "info" {
        "informational".to_owned()
    } else {
        p
    };
    PRIORITIES.iter().position(|x| *x == p).unwrap_or(3)
}

impl Alert {
    /// Cap sizes and strip control characters from what a host sent.
    pub fn cleaned(mut self) -> Self {
        let clean = |s: &str, n: usize| -> String {
            s.chars().filter(|c| !c.is_control()).take(n).collect()
        };
        self.priority = PRIORITIES[rank(&self.priority)].to_owned();
        self.rule = clean(&self.rule, 255);
        self.output = clean(&self.output, 2000);
        self.container = self
            .container
            .as_deref()
            .map(|c| clean(c, 255))
            .filter(|c| !c.is_empty());
        self
    }
}

#[derive(Deserialize)]
struct Raw {
    #[serde(default)]
    output: String,
    #[serde(default)]
    priority: String,
    #[serde(default)]
    rule: String,
    #[serde(default)]
    time: String,
    #[serde(default)]
    output_fields: serde_json::Map<String, serde_json::Value>,
}

/// One line of Falco's JSON output.
pub fn parse_line(line: &str) -> Option<Alert> {
    let r: Raw = serde_json::from_str(line.trim()).ok()?;
    if r.rule.is_empty() {
        return None;
    }
    let at = crate::timefmt::parse_rfc3339(&r.time).unwrap_or_else(crate::db::now_ms);
    let field = |k: &str| {
        r.output_fields
            .get(k)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    };
    let container = field("container.name")
        .filter(|n| n != "host" && !n.is_empty())
        .or_else(|| field("container.id").filter(|n| n != "host" && !n.is_empty()));
    Some(
        Alert {
            at,
            priority: r.priority,
            rule: r.rule,
            output: r.output,
            container,
        }
        .cleaned(),
    )
}

/// Follow `path` from its current end, handing over batches of alerts at or
/// above `min_rank`. Copes with rotation and truncation.
pub fn follow<F, Fut>(path: PathBuf, min_rank: usize, mut sink: F)
where
    F: FnMut(Vec<Alert>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    if path.as_os_str().is_empty() {
        return;
    }
    tokio::spawn(async move {
        // Start at the end: old alerts were seen when they happened, or are history.
        let mut pos: Option<(u64, u64)> = None; // (inode or 0, offset)
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        let mut carry = String::new();
        loop {
            tick.tick().await;
            let p = path.clone();
            let prev = pos;
            let read = tokio::task::spawn_blocking(move || read_new(&p, prev)).await;
            let Ok(Some((next, text))) = read else {
                continue;
            };
            let first = pos.is_none();
            pos = Some(next);
            if first {
                continue;
            }
            carry.push_str(&text);
            let Some(cut) = carry.rfind('\n') else {
                continue;
            };
            let lines: String = carry.drain(..=cut).collect();
            let mut batch: Vec<Alert> = lines
                .lines()
                .filter_map(parse_line)
                .filter(|a| rank(&a.priority) >= min_rank)
                .collect();
            while !batch.is_empty() {
                let rest = batch.split_off(batch.len().min(MAX_BATCH));
                sink(std::mem::replace(&mut batch, rest)).await;
            }
        }
    });
}

/// New bytes since `prev`; the first call only records the end of the file.
fn read_new(path: &std::path::Path, prev: Option<(u64, u64)>) -> Option<((u64, u64), String)> {
    use std::io::{Read, Seek, SeekFrom};
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    let ino = std::os::unix::fs::MetadataExt::ino(&meta);
    #[cfg(not(unix))]
    let ino = 0;
    let len = meta.len();
    let start = match prev {
        None => return Some(((ino, len), String::new())),
        Some((i, off)) if i == ino && off <= len => off,
        _ => 0, // rotated or truncated: read the new file from the top
    };
    let mut f = std::fs::File::open(path).ok()?;
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::new();
    // At most 4 MiB a pass, so a flood cannot hold memory.
    f.take(4 * 1024 * 1024).read_to_end(&mut buf).ok()?;
    let read = buf.len() as u64;
    Some((
        (ino, start + read),
        String::from_utf8_lossy(&buf).into_owned(),
    ))
}

/// Per-host, per-rule notification throttle.
#[derive(Default)]
pub struct Throttle(std::sync::Mutex<HashMap<(Option<i64>, String), Instant>>);

impl Throttle {
    fn allow(&self, host: Option<i64>, rule: &str) -> bool {
        let Ok(mut m) = self.0.lock() else {
            return true;
        };
        if m.len() > 5000 {
            m.retain(|_, t| t.elapsed() < NOTIFY_COOLDOWN);
        }
        let k = (host, rule.to_owned());
        if m.get(&k).is_some_and(|t| t.elapsed() < NOTIFY_COOLDOWN) {
            return false;
        }
        m.insert(k, Instant::now());
        true
    }
}

/// Store, log and (Error or worse) notify. `agent` None is this server.
pub async fn record(st: &AppState, agent: Option<i64>, host: &str, alerts: Vec<Alert>) {
    for a in alerts {
        if let Err(e) = st.db.add_falco_event(agent, &a).await {
            tracing::warn!(error = %e, "could not store Falco alert");
        }
        let loud = rank(&a.priority) >= rank("error");
        if loud {
            tracing::error!(event = "falco.alert", host = %host, priority = %a.priority, rule = %a.rule, container = a.container.as_deref().unwrap_or("-"), output = %a.output, "Falco alert");
        } else {
            tracing::warn!(event = "falco.alert", host = %host, priority = %a.priority, rule = %a.rule, container = a.container.as_deref().unwrap_or("-"), output = %a.output, "Falco alert");
        }
        if loud && st.falco_throttle.allow(agent, &a.rule) {
            st.notifier.notify(Event {
                event: "falco.alert",
                job_id: String::new(),
                kind: a.priority.to_ascii_uppercase(),
                target: a.rule.clone(),
                endpoint: host.into(),
                submitted_by: None,
                verdict: "ALERT".into(),
                found_viruses: Vec::new(),
                detections: Default::default(),
                files_scanned: 0,
                file_errors: 0,
                error_code: None,
                error: Some(a.output.clone()),
                finished_at: crate::timefmt::rfc3339(a.at),
            });
        }
    }
}

/// Follow this server's Falco output.
pub fn spawn(st: Arc<AppState>) {
    let path = st.cfg.falco_events.clone();
    let min = rank(&st.cfg.falco_min_priority);
    let host = crate::canary::hostname();
    follow(path, min, move |batch| {
        let (st, host) = (st.clone(), host.clone());
        async move { record(&st, None, &host, batch).await }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_falco_json() {
        let line = r#"{"hostname":"nas","output":"10:00:00.0: Warning Shell spawned in a container (user=root container=plex)","priority":"Warning","rule":"Terminal shell in container","source":"syscall","tags":["container","shell"],"time":"2026-11-14T10:00:00.123456789Z","output_fields":{"container.id":"abc123","container.name":"plex","user.name":"root"}}"#;
        let a = parse_line(line).expect("alert");
        assert_eq!(a.rule, "Terminal shell in container");
        assert_eq!(a.priority, "warning");
        assert_eq!(a.container.as_deref(), Some("plex"));
        assert!(a.at > 1_700_000_000_000);
        assert!(parse_line("not json").is_none());
        assert!(parse_line(r#"{"output":"x"}"#).is_none());
        assert!(rank("Critical") > rank("error") && rank("Notice") < rank("warning"));
    }

    #[tokio::test]
    async fn follows_new_lines_only_and_survives_rotation() {
        let d = std::env::temp_dir().join(format!("clamv-falco-{}", crate::db::new_id()));
        std::fs::create_dir_all(&d).expect("mkdir");
        let f = d.join("events.json");
        let line = |rule: &str, p: &str| {
            format!(
                "{{\"rule\":\"{rule}\",\"priority\":\"{p}\",\"output\":\"o\",\"time\":\"2026-11-14T10:00:00Z\"}}\n"
            )
        };
        std::fs::write(&f, line("old", "Error")).expect("write");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        follow(f.clone(), rank("warning"), move |b| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(b);
            }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut s = std::fs::read_to_string(&f).expect("read");
        s.push_str(&line("noise", "Notice"));
        s.push_str(&line("shell", "Warning"));
        std::fs::write(&f, s).expect("append");
        let b = tokio::time::timeout(Duration::from_secs(12), rx.recv())
            .await
            .expect("batch")
            .expect("some");
        assert_eq!(
            b.iter().map(|a| a.rule.as_str()).collect::<Vec<_>>(),
            vec!["shell"]
        );
        // Rotation: a new, shorter file.
        std::fs::remove_file(&f).expect("rm");
        std::fs::write(&f, line("after", "Critical")).expect("write");
        let b = tokio::time::timeout(Duration::from_secs(12), rx.recv())
            .await
            .expect("batch")
            .expect("some");
        assert_eq!(b[0].rule, "after");
        let _ = std::fs::remove_dir_all(&d);
    }
}
