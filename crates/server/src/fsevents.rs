//! Event-driven file watching (Linux inotify), shared by the server and agents.
//!
//! `files` reports regular files once they are written or moved in, after a
//! short quiet period. `canaries` reports any access to decoy files. Watching
//! a file never opens it, so the watcher itself cannot trip a canary.
//! Elsewhere both return an error and callers fall back to polling.

use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::mpsc;

/// A written file is reported after this long without further writes.
pub const QUIET: Duration = Duration::from_secs(2);
const MAX_WATCHES: usize = 100_000;
const MAX_DEPTH: usize = 16;
/// One alert per canary per this long.
const CANARY_COOLDOWN: Duration = Duration::from_secs(60);

#[cfg(target_os = "linux")]
mod imp {
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    use inotify::{Inotify, WatchDescriptor, WatchMask, Watches};
    use tokio::sync::mpsc;
    use tokio_stream_shim::next;

    use super::{CANARY_COOLDOWN, MAX_DEPTH, MAX_WATCHES, QUIET};

    mod tokio_stream_shim {
        use std::future::poll_fn;
        use std::pin::Pin;

        use futures_core::Stream;

        pub async fn next<S: Stream + Unpin>(s: &mut S) -> Option<S::Item> {
            poll_fn(|cx| Pin::new(&mut *s).poll_next(cx)).await
        }
    }

    fn dir_mask() -> WatchMask {
        WatchMask::CLOSE_WRITE
            | WatchMask::MOVED_TO
            | WatchMask::CREATE
            | WatchMask::DELETE_SELF
            | WatchMask::MOVE_SELF
            | WatchMask::DONT_FOLLOW
            | WatchMask::ONLYDIR
    }

    /// Watch `dir` and its subfolders; return the regular files already inside when `list` is set.
    fn add_tree(
        w: &mut Watches,
        dirs: &mut HashMap<WatchDescriptor, PathBuf>,
        dir: &Path,
        list: bool,
        found: &mut Vec<PathBuf>,
    ) {
        let mut stack = vec![(dir.to_path_buf(), 0usize)];
        while let Some((d, depth)) = stack.pop() {
            if dirs.len() >= MAX_WATCHES {
                tracing::warn!(
                    event = "realtime.limit",
                    limit = MAX_WATCHES,
                    "too many folders to watch; the rest rely on polling"
                );
                return;
            }
            match w.add(&d, dir_mask()) {
                Ok(wd) => {
                    dirs.insert(wd, d.clone());
                }
                Err(e) => {
                    tracing::warn!(event = "realtime.watch_failed", path = %d.display(), error = %e, "cannot watch folder (raise fs.inotify.max_user_watches?)");
                    continue;
                }
            }
            let Ok(rd) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in rd.flatten() {
                let Ok(ft) = e.file_type() else { continue };
                if ft.is_dir() && depth < MAX_DEPTH {
                    stack.push((e.path(), depth + 1));
                } else if list && ft.is_file() {
                    found.push(e.path());
                }
            }
        }
    }

    pub fn files(roots: Vec<PathBuf>) -> std::io::Result<mpsc::Receiver<PathBuf>> {
        let ino = Inotify::init()?;
        let (tx, rx) = mpsc::channel(4096);
        let mut stream = ino.into_event_stream(vec![0u8; 64 * 1024])?;
        let mut w = stream.watches();
        let mut dirs = HashMap::new();
        for r in &roots {
            add_tree(&mut w, &mut dirs, r, false, &mut Vec::new());
        }
        tokio::spawn(async move {
            let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
            let mut tick = tokio::time::interval(QUIET / 2);
            loop {
                tokio::select! {
                    ev = next(&mut stream) => {
                        let Some(Ok(ev)) = ev else { break };
                        let ev: inotify::Event<OsString> = ev;
                        if ev.mask.contains(inotify::EventMask::Q_OVERFLOW) {
                            tracing::warn!(event = "realtime.overflow", "file events were lost; the next poll catches up");
                            continue;
                        }
                        if ev.mask.contains(inotify::EventMask::IGNORED) {
                            dirs.remove(&ev.wd);
                            continue;
                        }
                        let (Some(dir), Some(name)) = (dirs.get(&ev.wd).cloned(), ev.name) else { continue };
                        let path = dir.join(name);
                        if ev.mask.contains(inotify::EventMask::ISDIR) {
                            if ev.mask.intersects(inotify::EventMask::CREATE | inotify::EventMask::MOVED_TO) {
                                // A new folder may already hold files (moved in, or written before the watch).
                                let mut found = Vec::new();
                                add_tree(&mut w, &mut dirs, &path, true, &mut found);
                                for f in found {
                                    pending.insert(f, Instant::now());
                                }
                            }
                        } else if ev.mask.intersects(inotify::EventMask::CLOSE_WRITE | inotify::EventMask::MOVED_TO) {
                            pending.insert(path, Instant::now());
                        }
                    }
                    _ = tick.tick() => {
                        let ready: Vec<PathBuf> = pending
                            .iter()
                            .filter(|(_, t)| t.elapsed() >= QUIET)
                            .map(|(p, _)| p.clone())
                            .collect();
                        for p in ready {
                            pending.remove(&p);
                            if tx.send(p).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        });
        Ok(rx)
    }

    fn canary_mask() -> WatchMask {
        WatchMask::OPEN
            | WatchMask::ACCESS
            | WatchMask::MODIFY
            | WatchMask::ATTRIB
            | WatchMask::DELETE_SELF
            | WatchMask::MOVE_SELF
            | WatchMask::DONT_FOLLOW
    }

    fn what(m: inotify::EventMask) -> &'static str {
        use inotify::EventMask as M;
        if m.contains(M::DELETE_SELF) {
            "deleted"
        } else if m.contains(M::MOVE_SELF) {
            "moved"
        } else if m.contains(M::MODIFY) {
            "modified"
        } else if m.contains(M::ATTRIB) {
            "permissions or times changed"
        } else {
            "opened"
        }
    }

    pub fn canaries(
        files: Vec<PathBuf>,
    ) -> std::io::Result<mpsc::Receiver<(PathBuf, &'static str)>> {
        let ino = Inotify::init()?;
        let (tx, rx) = mpsc::channel(256);
        let mut stream = ino.into_event_stream(vec![0u8; 16 * 1024])?;
        let mut w = stream.watches();
        let mut by_wd: HashMap<WatchDescriptor, PathBuf> = HashMap::new();
        let arm = |w: &mut Watches, by_wd: &mut HashMap<WatchDescriptor, PathBuf>, f: &PathBuf| {
            if by_wd.values().any(|p| p == f) {
                return;
            }
            match w.add(f, canary_mask()) {
                Ok(wd) => {
                    by_wd.insert(wd, f.clone());
                    tracing::info!(event = "canary.armed", path = %f.display(), "canary file armed");
                }
                Err(e) => {
                    tracing::warn!(event = "canary.missing", path = %f.display(), error = %e, "canary file cannot be watched")
                }
            }
        };
        for f in &files {
            arm(&mut w, &mut by_wd, f);
        }
        tokio::spawn(async move {
            let mut last: HashMap<PathBuf, Instant> = HashMap::new();
            let mut rearm = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tokio::select! {
                    ev = next(&mut stream) => {
                        let Some(Ok(ev)) = ev else { break };
                        let ev: inotify::Event<OsString> = ev;
                        if ev.mask.contains(inotify::EventMask::IGNORED) {
                            by_wd.remove(&ev.wd);
                            continue;
                        }
                        let Some(path) = by_wd.get(&ev.wd).cloned() else { continue };
                        let quiet = last.get(&path).is_none_or(|t| t.elapsed() >= CANARY_COOLDOWN);
                        if quiet {
                            last.insert(path.clone(), Instant::now());
                            if tx.send((path, what(ev.mask))).await.is_err() {
                                return;
                            }
                        }
                    }
                    // The list changed and the caller dropped us.
                    () = tx.closed() => return,
                    // A deleted or replaced canary is armed again once it is back.
                    _ = rearm.tick() => {
                        for f in &files {
                            if f.exists() {
                                arm(&mut w, &mut by_wd, f);
                            }
                        }
                    }
                }
            }
        });
        Ok(rx)
    }
}

/// Regular files written or moved in under `roots`, each reported after `QUIET`.
pub fn files(roots: Vec<PathBuf>) -> std::io::Result<mpsc::Receiver<PathBuf>> {
    #[cfg(target_os = "linux")]
    {
        imp::files(roots)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = roots;
        Err(std::io::Error::other("real-time watching needs Linux"))
    }
}

/// Any access to one of `files`: `(path, what happened)`, at most once a minute per file.
pub fn canaries(files: Vec<PathBuf>) -> std::io::Result<mpsc::Receiver<(PathBuf, &'static str)>> {
    #[cfg(target_os = "linux")]
    {
        imp::canaries(files)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = files;
        Err(std::io::Error::other("canary files need Linux"))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("clamv-{tag}-{}", crate::db::new_id()));
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    #[tokio::test]
    async fn written_files_and_new_folders_are_reported() {
        let d = tmp("fsev");
        let mut rx = files(vec![d.clone()]).expect("watch");
        std::fs::write(d.join("a.bin"), b"x").expect("write");
        let got = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("event");
        assert_eq!(got, Some(d.join("a.bin")));
        // A folder created later is watched too.
        std::fs::create_dir(d.join("sub")).expect("mkdir");
        tokio::time::sleep(Duration::from_millis(300)).await;
        std::fs::write(d.join("sub").join("b.bin"), b"y").expect("write");
        let got = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("event");
        assert_eq!(got, Some(d.join("sub").join("b.bin")));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn opening_a_canary_is_reported_once() {
        let d = tmp("canary");
        let f = d.join("passwords.kdbx");
        std::fs::write(&f, b"decoy").expect("write");
        let mut rx = canaries(vec![f.clone()]).expect("watch");
        let _ = std::fs::read(&f).expect("read");
        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("event");
        assert_eq!(got, Some((f.clone(), "opened")));
        let _ = std::fs::read(&f).expect("read");
        assert!(
            tokio::time::timeout(Duration::from_millis(500), rx.recv())
                .await
                .is_err(),
            "cooldown"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
