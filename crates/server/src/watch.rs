//! Watched folders: new or changed files become WATCH jobs.
//!
//! A file is recorded only after its scan finishes (N6). Failed scans are
//! retried after an hour; files over clamd's limits are not retried until
//! they change. Files still being written (changed in the last minute) wait.
//! Symlinks are not followed.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::app::AppState;
use crate::db::jobs::{self, NewJob, Outcome};
use crate::db::now_ms;
use crate::scan;

const SETTLE_MS: i64 = 60_000;
const RETRY_ERROR_MS: i64 = 3_600_000;
const MAX_NEW_PER_PASS: usize = 200;
const MAX_DEPTH: usize = 8;
const MAX_ENTRIES: usize = 200_000;

/// Verdicts kept in processed_files.
pub const SEEN_BASELINE: &str = "BASELINE";
pub const SEEN_LIMIT: &str = "LIMIT";

/// Files known to be handled, so unchanged files cost no database query.
#[derive(Default)]
pub struct Watcher {
    known: Mutex<HashMap<String, (i64, i64)>>,
}

impl Watcher {
    fn is_known(&self, path: &str, stamp: (i64, i64)) -> bool {
        self.known
            .lock()
            .map(|m| m.get(path) == Some(&stamp))
            .unwrap_or(false)
    }

    fn remember(&self, path: &str, stamp: (i64, i64)) {
        if let Ok(mut m) = self.known.lock() {
            m.insert(path.to_owned(), stamp);
        }
    }
}

/// (mtime ms, size) of a file.
pub fn stamp(m: &std::fs::Metadata) -> (i64, i64) {
    let mtime = m
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    (mtime, i64::try_from(m.len()).unwrap_or(i64::MAX))
}

/// Marks a watched file whose name is not UTF-8. Its key is the readable
/// (lossy) path, this mark, then the exact path bytes in hex. Walked paths
/// never contain `//`, so a key cannot collide with a real file's path.
pub const RAW_MARK: &str = "//raw:";

/// Key for a non-UTF-8 path.
pub fn raw_key(p: &Path) -> String {
    #[cfg(unix)]
    let bytes = std::os::unix::ffi::OsStrExt::as_bytes(p.as_os_str()).to_vec();
    #[cfg(not(unix))]
    let bytes = p.to_string_lossy().into_owned().into_bytes();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}{RAW_MARK}{hex}", p.to_string_lossy())
}

/// The exact path behind a `raw_key`, if `target` is one.
pub fn raw_path(target: &str) -> Option<PathBuf> {
    let (_, hex) = target.rsplit_once(RAW_MARK)?;
    if hex.len() % 2 != 0 {
        return None;
    }
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Some(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
    }
    #[cfg(not(unix))]
    {
        String::from_utf8(bytes).ok().map(PathBuf::from)
    }
}

/// Regular files under `root`, depth-limited, without following symlinks.
pub fn walk(root: &Path) -> Vec<(String, (i64, i64))> {
    let mut out = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    let mut seen = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            seen += 1;
            if seen > MAX_ENTRIES {
                tracing::warn!(event = "watch.truncated", root = %root.display(), limit = MAX_ENTRIES, "watched folder has too many entries; the rest are skipped");
                return out;
            }
            let Ok(ft) = entry.file_type() else { continue };
            let path = entry.path();
            if ft.is_dir() && depth < MAX_DEPTH {
                stack.push((path, depth + 1));
            } else if ft.is_file()
                && let Ok(m) = entry.metadata()
            {
                // Names that are not UTF-8 are scanned too (streamed to clamd).
                let key = path.to_str().map_or_else(|| raw_key(&path), str::to_owned);
                out.push((key, stamp(&m)));
            }
        }
    }
    out
}

/// Store the result of a WATCH scan.
pub async fn record(st: &AppState, path: &str, mtime: i64, size: i64, o: &Outcome) {
    let verdict = match (o.verdict, o.error_code) {
        (_, Some(scan::LIMIT_EXCEEDED)) => SEEN_LIMIT,
        (v, _) => v,
    };
    if let Err(e) = st.db.record_processed(path, mtime, size, verdict).await {
        tracing::warn!(error = %e, path = %path, "could not record watched file");
    } else if verdict != jobs::ERROR {
        st.watcher.remember(path, (mtime, size));
    }
}

pub fn spawn(st: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(st.cfg.watch_poll_secs.max(10)));
        loop {
            tick.tick().await;
            pass(&st).await;
        }
    });
}

/// One look at every enabled watched folder. Returns how many jobs were queued.
pub async fn pass(st: &AppState) -> usize {
    let Ok(watches) = st.db.list_watches().await else {
        return 0;
    };
    let watches: Vec<_> = watches.into_iter().filter(|w| w.enabled).collect();
    if watches.is_empty() {
        return 0;
    }
    let inflight: HashSet<String> = st
        .db
        .active_watch_targets()
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();
    let now = now_ms();
    let mut queued = 0;
    'outer: for w in watches {
        let root = match scan::resolve_path(&st.cfg.scan_roots, &w.path).await {
            Ok(r) => r,
            Err(_) => {
                tracing::warn!(event = "watch.path_rejected", path = %w.path, "watched folder is missing or outside SCAN_ROOTS");
                continue;
            }
        };
        let Some(ep) = scan::pick_endpoint(st, w.endpoint_id).await else {
            tracing::warn!(event = "watch.no_endpoint", path = %w.path, "no enabled clamd endpoint for watched folder");
            continue;
        };
        let files = tokio::task::spawn_blocking(move || walk(&root))
            .await
            .unwrap_or_default();
        for (path, stamp) in files {
            if queued >= MAX_NEW_PER_PASS {
                tracing::info!(
                    event = "watch.backlog",
                    "more new files waiting; continuing next pass"
                );
                break 'outer;
            }
            if inflight.contains(&path)
                || now - stamp.0 < SETTLE_MS
                || st.watcher.is_known(&path, stamp)
            {
                continue;
            }
            match st.db.processed(&path).await {
                Ok(Some(p)) if (p.modified_ms, p.size_bytes) == stamp => {
                    if p.verdict != jobs::ERROR {
                        st.watcher.remember(&path, stamp);
                        continue;
                    }
                    if now - p.processed_at < RETRY_ERROR_MS {
                        continue;
                    }
                }
                Ok(_) => {}
                Err(_) => continue,
            }
            let job = st
                .db
                .create_job(NewJob {
                    kind: scan::KIND_WATCH,
                    target: &path,
                    endpoint_id: Some(ep.id),
                    schedule_id: None,
                    agent_id: None,
                    submitted_by: Some("watcher"),
                    transport: "WATCH",
                    running: false,
                })
                .await;
            match job {
                Ok(_) => queued += 1,
                Err(e) => tracing::warn!(error = %e, path = %path, "could not queue watched file"),
            }
        }
    }
    if queued > 0 {
        tracing::info!(
            event = "watch.queued",
            jobs = queued,
            "new or changed files queued"
        );
        st.runner.poke();
    }
    queued
}

/// Mark every file now in `root` as handled, so only later changes are scanned.
pub async fn baseline(st: &AppState, root: PathBuf) -> usize {
    let files = tokio::task::spawn_blocking(move || walk(&root))
        .await
        .unwrap_or_default();
    let mut n = 0;
    for (path, (m, s)) in files {
        if st
            .db
            .record_processed(&path, m, s, SEEN_BASELINE)
            .await
            .is_ok()
        {
            st.watcher.remember(&path, (m, s));
            n += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn non_utf8_names_are_walked_and_round_trip() {
        use std::os::unix::ffi::OsStrExt;
        let dir = std::env::temp_dir().join(format!("clamv-raw-{}", crate::db::new_id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let bad = dir.join(std::ffi::OsStr::from_bytes(b"bad\xff.exe"));
        std::fs::write(&bad, b"x").expect("write");
        std::fs::write(dir.join("ok.txt"), b"x").expect("write");
        let found = walk(&dir);
        assert_eq!(found.len(), 2);
        let key = found
            .iter()
            .map(|(k, _)| k)
            .find(|k| k.contains(RAW_MARK))
            .expect("raw key");
        assert!(
            key.starts_with(dir.to_str().expect("utf8")),
            "folder prefix kept"
        );
        assert_eq!(raw_path(key).as_deref(), Some(bad.as_path()));
        assert_eq!(raw_path("/data/plain.txt"), None);
        assert_eq!(raw_path("/data/x//raw:zz"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
