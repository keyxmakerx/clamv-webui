//! Canary files: decoys that nobody should touch. Any access raises an alert
//! (an ERROR log line, an audit entry and the webhook).
//!
//! Each host watches CANARY_FILES plus the canaries an admin added for it in
//! the UI. Where auditd logs a `clamv_canary` rule, the alert names who did it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};

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

/// One managed canary as a host receives it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spec {
    pub path: String,
    /// Write a decoy when the file does not exist (never overwrites).
    #[serde(default)]
    pub create: bool,
}

/// The audit rule key the alert enrichment looks for.
pub const AUDIT_KEY: &str = "clamv_canary";
const AUDIT_LOG: &str = "/var/log/audit/audit.log";

/// The auditd rule an admin adds on the host for one canary.
pub fn audit_rule(path: &str) -> String {
    format!("-w {path} -p rwxa -k {AUDIT_KEY}")
}

/// A canary path an admin may add: absolute, plain, not a directory marker.
pub fn valid_path(p: &str) -> Result<(), &'static str> {
    if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
        return Err("The path is too long or holds control characters.");
    }
    if !p.starts_with('/') || p.ends_with('/') {
        return Err("Use an absolute path to a file, such as /srv/share/passwords.xlsx.");
    }
    if p.split('/').any(|seg| seg == ".." || seg == ".") {
        return Err("The path may not contain . or .. parts.");
    }
    Ok(())
}

/// Write a plausible decoy if nothing is there yet. Never overwrites.
fn ensure_decoy(path: &Path) {
    if path.symlink_metadata().is_ok() {
        return;
    }
    let body =
        b"# Accounts\nservice,user,password\nbackup-nas,admin,Winter2024!\nvpn,ops,changeme-7731\n";
    let r = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, body));
    match r {
        Ok(()) => {
            tracing::info!(event = "canary.created", path = %path.display(), "decoy file written")
        }
        Err(e) => {
            tracing::warn!(event = "canary.create_failed", path = %path.display(), error = %e, "decoy file could not be written")
        }
    }
}

/// Whether each canary exists as a regular file (so it can be watched).
fn armed_states(files: &[PathBuf]) -> BTreeMap<String, bool> {
    files
        .iter()
        .map(|f| {
            let ok = f.symlink_metadata().is_ok_and(|m| m.is_file());
            (f.to_string_lossy().into_owned(), ok)
        })
        .collect()
}

/// Watches fixed files plus a changing list. Hits arrive as `(path, what)`;
/// `states` holds whether each file could be watched.
/// Path → whether it could be watched.
pub type States = Arc<Mutex<BTreeMap<String, bool>>>;

pub struct Runner {
    pub hits: mpsc::Receiver<(String, String)>,
    pub states: States,
}

type Hits = mpsc::Receiver<(PathBuf, &'static str)>;

/// Write requested decoys, record states and start watching the files.
fn arm(fixed: &[PathBuf], list: &[Spec], states: &States) -> (Vec<PathBuf>, Option<Hits>) {
    let mut files = fixed.to_vec();
    for s in list {
        let p = PathBuf::from(&s.path);
        if s.create {
            ensure_decoy(&p);
        }
        if !files.contains(&p) {
            files.push(p);
        }
    }
    if let Ok(mut g) = states.lock() {
        *g = armed_states(&files);
    }
    if files.is_empty() {
        return (files, None);
    }
    match crate::fsevents::canaries(files.clone()) {
        Ok(rx) => (files, Some(rx)),
        Err(e) => {
            tracing::error!(event = "canary.unavailable", error = %e, "canary files cannot be watched");
            (files, None)
        }
    }
}

/// Must be called inside a Tokio runtime. The first list is armed before this returns.
pub fn run(fixed: Vec<PathBuf>, mut specs: watch::Receiver<Vec<Spec>>) -> Runner {
    let (tx, hits) = mpsc::channel(64);
    let states: States = Arc::new(Mutex::new(BTreeMap::new()));
    let st = states.clone();
    let first = specs.borrow_and_update().clone();
    let (mut files, mut rx) = arm(&fixed, &first, &st);
    tokio::spawn(async move {
        loop {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            tick.tick().await;
            loop {
                tokio::select! {
                    hit = async { match rx.as_mut() { Some(r) => r.recv().await, None => std::future::pending().await } } => {
                        let Some((p, what)) = hit else { rx = None; continue };
                        let path = p.to_string_lossy().into_owned();
                        let what = match who_touched(&path).await {
                            Some(w) => format!("{what} by {w}"),
                            None => what.to_owned(),
                        };
                        if tx.send((path, what)).await.is_err() {
                            return;
                        }
                    }
                    ch = specs.changed() => {
                        if ch.is_err() { return; }
                        break;
                    }
                    _ = tick.tick() => {
                        if let Ok(mut g) = st.lock() {
                            *g = armed_states(&files);
                        }
                    }
                }
            }
            let list = specs.borrow_and_update().clone();
            drop(rx.take());
            let (fixed, st2) = (fixed.clone(), st.clone());
            let Ok((f, r)) = tokio::task::spawn_blocking(move || arm(&fixed, &list, &st2)).await
            else {
                return;
            };
            files = f;
            rx = r;
        }
    });
    Runner { hits, states }
}

/// Who touched `path`, from auditd records tagged with AUDIT_KEY, if readable.
async fn who_touched(path: &str) -> Option<String> {
    if std::fs::metadata(AUDIT_LOG).is_err() {
        return None;
    }
    // auditd writes asynchronously; give it a moment.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(AUDIT_LOG).ok()?;
        let len = f.metadata().ok()?.len();
        f.seek(SeekFrom::Start(len.saturating_sub(512 * 1024)))
            .ok()?;
        let mut buf = Vec::new();
        f.take(512 * 1024).read_to_end(&mut buf).ok()?;
        audit_actor(&String::from_utf8_lossy(&buf), &path)
    })
    .await
    .ok()
    .flatten()
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!(" {key}=");
    let start = line.find(&pat)? + pat.len();
    let rest = &line[start..];
    let v = if let Some(r) = rest.strip_prefix('"') {
        &r[..r.find('"')?]
    } else {
        rest.split(' ').next()?
    };
    Some(v)
}

/// `msg=audit(1700000000.123:456)` → `456`.
fn serial(line: &str) -> Option<&str> {
    let s = line.split("msg=audit(").nth(1)?;
    let s = &s[..s.find(')')?];
    s.split(':').nth(1)
}

/// The newest SYSCALL with our key whose PATH record names `path`:
/// "`/usr/bin/cat` (uid 1000, login uid 1000, pid 4242)".
pub fn audit_actor(log: &str, path: &str) -> Option<String> {
    let quoted = format!("name=\"{path}\"");
    let serials: Vec<&str> = log
        .lines()
        .filter(|l| l.starts_with("type=PATH") && l.contains(&quoted))
        .filter_map(serial)
        .collect();
    let line = log.lines().rev().find(|l| {
        l.starts_with("type=SYSCALL")
            && field(l, "key").is_some_and(|k| k == AUDIT_KEY)
            && serial(l).is_some_and(|s| serials.contains(&s))
    })?;
    let exe = field(line, "exe").unwrap_or("?");
    let uid = field(line, "uid").unwrap_or("?");
    let auid = field(line, "auid").unwrap_or("?");
    let pid = field(line, "pid").unwrap_or("?");
    let mut out = format!("{exe} (uid {uid}");
    if auid != "4294967295" && auid != "unset" {
        out.push_str(&format!(", login uid {auid}"));
    }
    out.push_str(&format!(", pid {pid})"));
    Some(out.chars().take(200).collect())
}

/// This server's managed canaries, published to its runner.
pub struct Central {
    pub specs: watch::Sender<Vec<Spec>>,
    pub states: Mutex<Option<States>>,
}

impl Default for Central {
    fn default() -> Self {
        Self {
            specs: watch::channel(Vec::new()).0,
            states: Mutex::new(None),
        }
    }
}

impl Central {
    /// Whether this server could watch `path`, if it has looked yet.
    pub fn armed(&self, path: &str) -> Option<bool> {
        let g = self.states.lock().ok()?;
        let s = g.as_ref()?.lock().ok()?;
        s.get(path).copied()
    }
}

/// Reload this server's canaries from the database into the runner.
pub async fn reload(st: &AppState) {
    match st.db.host_canaries(None).await {
        Ok(list) => {
            let specs: Vec<Spec> = list
                .into_iter()
                .map(|c| Spec {
                    path: c.path,
                    create: c.create_file,
                })
                .collect();
            st.canaries.specs.send_if_modified(|cur| {
                let changed = *cur != specs;
                if changed {
                    *cur = specs;
                }
                changed
            });
        }
        Err(e) => tracing::warn!(error = %e, "could not load canaries"),
    }
}

/// Watch CANARY_FILES and this server's managed canaries.
pub fn spawn(st: Arc<AppState>) {
    let files = st.cfg.canary_files.clone();
    let conf = st
        .clamd_conf
        .load(st.cfg.clamd_conf_file.as_deref())
        .ok()
        .flatten();
    check_placement(&files, &st.cfg.scan_roots, conf.as_deref());
    let mut r = run(files, st.canaries.specs.subscribe());
    if let Ok(mut g) = st.canaries.states.lock() {
        *g = Some(r.states.clone());
    }
    let host = hostname();
    tokio::spawn(async move {
        reload(&st).await;
        while let Some((p, what)) = r.hits.recv().await {
            let _ = st.db.canary_tripped(None, &p).await;
            tripped(&st, &host, &p, &what).await;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_records_name_the_actor() {
        let log = "type=SYSCALL msg=audit(1700000000.100:41): arch=c000003e syscall=257 success=yes exit=3 pid=999 auid=4294967295 uid=0 comm=\"cron\" exe=\"/usr/sbin/cron\" key=\"other\"\n\
type=SYSCALL msg=audit(1700000001.200:42): arch=c000003e syscall=257 success=yes exit=3 ppid=1 pid=4242 auid=1000 uid=1000 gid=1000 comm=\"cat\" exe=\"/usr/bin/cat\" key=\"clamv_canary\"\n\
type=CWD msg=audit(1700000001.200:42): cwd=\"/home/u\"\n\
type=PATH msg=audit(1700000001.200:42): item=0 name=\"/srv/share/passwords.xlsx\" inode=12 nametype=NORMAL\n";
        assert_eq!(
            audit_actor(log, "/srv/share/passwords.xlsx").as_deref(),
            Some("/usr/bin/cat (uid 1000, login uid 1000, pid 4242)")
        );
        assert_eq!(audit_actor(log, "/other"), None);
    }

    #[test]
    fn paths_are_checked() {
        assert!(valid_path("/srv/share/passwords.xlsx").is_ok());
        assert!(valid_path("relative.txt").is_err());
        assert!(valid_path("/srv/../etc/shadow").is_err());
        assert!(valid_path("/srv/dir/").is_err());
        assert!(valid_path("/srv/a\nb").is_err());
    }

    #[tokio::test]
    async fn runner_follows_list_changes_and_creates_decoys() {
        let d = std::env::temp_dir().join(format!("clamv-canary-run-{}", crate::db::new_id()));
        std::fs::create_dir_all(&d).expect("mkdir");
        let f = d.join("keys.txt");
        let (tx, rx) = watch::channel(Vec::new());
        let mut r = run(Vec::new(), rx);
        tx.send_replace(vec![Spec {
            path: f.to_string_lossy().into_owned(),
            create: true,
        }]);
        for _ in 0..50 {
            if r.states
                .lock()
                .expect("lock")
                .get(f.to_str().expect("utf8"))
                == Some(&true)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(f.is_file(), "decoy written");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = std::fs::read(&f).expect("read");
        let (p, what) = tokio::time::timeout(Duration::from_secs(5), r.hits.recv())
            .await
            .expect("hit")
            .expect("open");
        assert_eq!(p, f.to_string_lossy());
        assert!(what.starts_with("opened"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
