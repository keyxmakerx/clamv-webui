//! Quarantine: move an infected file out of a scan root into a locked folder, and
//! put it back or delete it later. Off until QUARANTINE_DIR is set. A file moves only
//! when clamd still finds it infected at that moment, only from inside SCAN_ROOTS,
//! and only after a full, verified copy; restoring or deleting needs a passkey.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::app::AppState;
use crate::db::quarantine as q;

pub const KIND: &str = "QUARANTINE";
pub const OFF: &str = "QUARANTINE_OFF";
pub const NOT_INFECTED: &str = "QUARANTINE_NOT_INFECTED";
pub const READ_ONLY: &str = "QUARANTINE_READ_ONLY";
pub const EXISTS: &str = "QUARANTINE_EXISTS";
pub const REJECTED: &str = "QUARANTINE_REJECTED";
pub const FAILED: &str = "QUARANTINE_FAILED";

/// Step-up actions, confirmed with a passkey like host baseline changes.
pub const RESTORE: &str = "quarantine.restore";
pub const DELETE: &str = "quarantine.delete";

pub fn message(code: &str) -> &'static str {
    match code {
        OFF => "Quarantine is off on that host; set QUARANTINE_DIR.",
        NOT_INFECTED => "clamd no longer finds that file infected, so it was left where it is.",
        READ_ONLY => {
            "The file's folder is mounted read-only, so it cannot be moved; mount that scan root read-write to quarantine from it."
        }
        EXISTS => "Something already exists at the original path, so nothing was restored.",
        REJECTED => "That path is not a regular file inside the host's scan roots.",
        crate::agent::policy::REFUSED => {
            "That agent's host does not allow quarantine; add it to AGENT_ALLOW on the agent."
        }
        crate::agent::policy::RATE_LIMITED => {
            "That agent refused: too many quarantines in the last hour."
        }
        _ => "The quarantine step failed; see the host's log.",
    }
}

/// What the server asks a host to do, as a QUARANTINE job target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Op {
    Move { id: String, path: String },
    Restore { id: String, path: String },
    Delete { id: String },
}

/// What a host reports back about a moved file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Held {
    pub sha256: String,
    pub size: i64,
}

/// Ids name the stored copies, so they must be plain ids.
fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

fn stored(dir: &Path, id: &str) -> Option<PathBuf> {
    valid_id(id).then(|| dir.join(format!("{id}.quarantined")))
}

/// Copy `from` to a new file `to` with `mode`, returning its sha256 and size.
async fn copy_new(from: &Path, to: &Path, mode: u32) -> std::io::Result<Held> {
    let mut src = tokio::fs::File::open(from).await?;
    let mut dst = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(to)
        .await?;
    let mut h = Sha256::new();
    let mut size: i64 = 0;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        dst.write_all(&buf[..n]).await?;
        size += i64::try_from(n).unwrap_or(0);
    }
    dst.sync_all().await?;
    Ok(Held {
        sha256: h.finalize().iter().map(|b| format!("{b:02x}")).collect(),
        size,
    })
}

/// Move one infected file into `dir`. clamd must still find it infected.
pub async fn move_in(
    clamd: &clamd::Client,
    roots: &[PathBuf],
    dir: Option<&Path>,
    id: &str,
    path: &str,
) -> Result<Held, &'static str> {
    let dir = dir.filter(|d| d.is_dir()).ok_or(OFF)?;
    let dest = stored(dir, id).ok_or(REJECTED)?;
    let real = crate::scan::resolve_path(roots, path)
        .await
        .map_err(|_| REJECTED)?;
    let meta = tokio::fs::symlink_metadata(&real)
        .await
        .map_err(|_| REJECTED)?;
    if !meta.is_file() {
        return Err(REJECTED);
    }
    let f = tokio::fs::File::open(&real).await.map_err(|_| REJECTED)?;
    match clamd.instream(f).await {
        Ok(r) if !r.detections.is_empty() => {}
        Ok(_) => return Err(NOT_INFECTED),
        Err(_) => return Err(FAILED),
    }
    // Refuse early when the file cannot be removed, before copying a large file for nothing.
    let parent = real.parent().ok_or(REJECTED)?;
    if tokio::fs::metadata(parent)
        .await
        .map(|m| m.permissions().readonly())
        .unwrap_or(true)
    {
        return Err(READ_ONLY);
    }
    let held = copy_new(&real, &dest, 0o400).await.map_err(|e| {
        tracing::warn!(event = "quarantine.copy_failed", error = %e, "copy into quarantine failed");
        FAILED
    })?;
    if let Err(e) = tokio::fs::remove_file(&real).await {
        let _ = tokio::fs::remove_file(&dest).await;
        return Err(match e.raw_os_error() {
            Some(30) | Some(13) | Some(1) => READ_ONLY,
            _ => FAILED,
        });
    }
    Ok(held)
}

/// Put a held file back at its original path, only if nothing is there now.
pub async fn restore(
    roots: &[PathBuf],
    dir: Option<&Path>,
    id: &str,
    path: &str,
) -> Result<(), &'static str> {
    let dir = dir.filter(|d| d.is_dir()).ok_or(OFF)?;
    let from = stored(dir, id).ok_or(REJECTED)?;
    let p = Path::new(path);
    let (Some(parent), Some(name)) = (p.parent(), p.file_name()) else {
        return Err(REJECTED);
    };
    let parent = crate::scan::resolve_os_path(roots, parent)
        .await
        .map_err(|_| REJECTED)?;
    let to = parent.join(name);
    if tokio::fs::symlink_metadata(&to).await.is_ok() {
        return Err(EXISTS);
    }
    copy_new(&from, &to, 0o640)
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => EXISTS,
            _ if matches!(e.raw_os_error(), Some(30) | Some(13) | Some(1)) => READ_ONLY,
            _ => FAILED,
        })?;
    let _ = tokio::fs::remove_file(&from).await;
    Ok(())
}

/// Delete a held copy for good. Already gone counts as done.
pub async fn delete(dir: Option<&Path>, id: &str) -> Result<(), &'static str> {
    let dir = dir.filter(|d| d.is_dir()).ok_or(OFF)?;
    let f = stored(dir, id).ok_or(REJECTED)?;
    match tokio::fs::remove_file(&f).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(FAILED),
    }
}

// ---- the server's side ----

async fn central_clamd(st: &AppState) -> Option<clamd::Client> {
    let ep = st.db.default_endpoint().await.ok().flatten()?;
    Some(st.clamd(ep.parsed().ok()?))
}

async fn queue(st: &AppState, agent: i64, op: &Op, by: &str) -> Result<String, String> {
    let target = serde_json::to_string(op).map_err(|_| "Service unavailable.".to_owned())?;
    let job = st
        .db
        .create_job(crate::db::jobs::NewJob {
            kind: KIND,
            target: &target,
            endpoint_id: None,
            schedule_id: None,
            agent_id: Some(agent),
            submitted_by: Some(by),
            transport: "UI",
            running: false,
        })
        .await
        .map_err(|_| "Service unavailable.".to_owned())?;
    st.agents.poke();
    Ok(job.id)
}

/// Quarantine the file behind a detection. Returns the new entry's id.
pub async fn start(st: &AppState, detection: i64, by: &str) -> Result<String, String> {
    let d = st
        .db
        .detection(detection)
        .await
        .map_err(|_| "Service unavailable.".to_owned())?
        .ok_or_else(|| "Unknown detection.".to_owned())?;
    if d.path.contains(crate::watch::RAW_MARK) {
        return Err(
            "That file's name is not readable text, so clamv cannot address it for quarantine."
                .into(),
        );
    }
    if d.agent_id.is_none() && st.cfg.quarantine_dir.is_none() {
        return Err(message(OFF).into());
    }
    let item = st
        .db
        .create_quarantine(d.agent_id, &d.path, &d.signature, by)
        .await
        .map_err(|_| "Service unavailable.".to_owned())?
        .ok_or_else(|| "That file is already in quarantine or on its way.".to_owned())?;
    let host = host_name(st, d.agent_id).await;
    tracing::warn!(event = "quarantine.requested", host = %host, path = %d.path, signature = %d.signature, by, "quarantine requested");
    match d.agent_id {
        Some(a) => {
            let job = queue(
                st,
                a,
                &Op::Move {
                    id: item.id.clone(),
                    path: d.path.clone(),
                },
                by,
            )
            .await?;
            let _ = st.db.set_quarantine_job(&item.id, &job).await;
        }
        None => {
            let r = match central_clamd(st).await {
                Some(c) => {
                    move_in(
                        &c,
                        &st.cfg.scan_roots,
                        st.cfg.quarantine_dir.as_deref(),
                        &item.id,
                        &item.original_path,
                    )
                    .await
                }
                None => Err(FAILED),
            };
            let failed = r.as_ref().err().copied();
            record_move(st, &item, None, r, by).await;
            if let Some(c) = failed {
                return Err(message(c).to_owned());
            }
        }
    }
    Ok(item.id)
}

async fn host_name(st: &AppState, agent: Option<i64>) -> String {
    match agent {
        None => crate::canary::hostname(),
        Some(id) => st
            .db
            .agent(id)
            .await
            .ok()
            .flatten()
            .map_or_else(|| format!("agent {id}"), |a| a.name),
    }
}

async fn record_move(
    st: &AppState,
    item: &q::Item,
    agent: Option<i64>,
    r: Result<Held, &str>,
    by: &str,
) {
    let host = host_name(st, agent.or(item.agent_id)).await;
    match r {
        Ok(h) => {
            tracing::warn!(event = "quarantine.moved", host = %host, path = %item.original_path, sha256 = %h.sha256, size = h.size, "infected file moved into quarantine");
            let _ = st
                .db
                .set_quarantine_state(&item.id, q::HELD, None, Some((&h.sha256, h.size)), by)
                .await;
        }
        Err(code) => {
            tracing::warn!(event = "quarantine.failed", host = %host, path = %item.original_path, code, "file not quarantined");
            let _ = st
                .db
                .set_quarantine_state(&item.id, q::FAILED, Some(code), None, by)
                .await;
        }
    }
}

/// Restore or delete a held file; called after a passkey confirmation.
pub async fn confirm(
    st: &Arc<AppState>,
    action: &str,
    id: &str,
    by: &str,
) -> Result<String, String> {
    let item = st
        .db
        .quarantine_item(id)
        .await
        .map_err(|_| "Service unavailable.".to_owned())?
        .filter(|i| i.state == q::HELD)
        .ok_or_else(|| "That file is not in quarantine.".to_owned())?;
    let host = host_name(st, item.agent_id).await;
    let (op, state) = match action {
        RESTORE => (
            Op::Restore {
                id: item.id.clone(),
                path: item.original_path.clone(),
            },
            q::RESTORED,
        ),
        DELETE => (
            Op::Delete {
                id: item.id.clone(),
            },
            q::DELETED,
        ),
        _ => return Err("Unknown action.".into()),
    };
    match item.agent_id {
        Some(a) => {
            let job = queue(st, a, &op, by).await?;
            let _ = st.db.set_quarantine_job(&item.id, &job).await;
            tracing::warn!(event = "quarantine.confirmed", host = %host, path = %item.original_path, action, by, "quarantine change sent with a passkey");
            Ok(format!(
                "Sent to {host}; the list updates when it reports back."
            ))
        }
        None => {
            let dir = st.cfg.quarantine_dir.as_deref();
            let r = match &op {
                Op::Restore { id, path } => restore(&st.cfg.scan_roots, dir, id, path).await,
                Op::Delete { id } => delete(dir, id).await,
                Op::Move { .. } => Err(REJECTED),
            };
            r.map_err(|c| message(c).to_owned())?;
            let _ = st
                .db
                .set_quarantine_state(&item.id, state, None, None, by)
                .await;
            tracing::warn!(event = if state == q::RESTORED { "quarantine.restored" } else { "quarantine.deleted" }, host = %host, path = %item.original_path, by, "quarantine change made with a passkey");
            Ok(if state == q::RESTORED {
                format!("Restored {}.", item.original_path)
            } else {
                "Deleted the quarantined copy for good.".to_owned()
            })
        }
    }
}

/// An agent finished a QUARANTINE job: bring the entry up to date.
pub async fn agent_result(
    st: &AppState,
    agent: i64,
    target: &str,
    held: Option<Held>,
    failure: Option<&str>,
) {
    let Ok(op) = serde_json::from_str::<Op>(target) else {
        return;
    };
    let id = match &op {
        Op::Move { id, .. } | Op::Restore { id, .. } | Op::Delete { id } => id,
    };
    let Ok(Some(item)) = st.db.quarantine_item(id).await else {
        return;
    };
    if item.agent_id != Some(agent) {
        return;
    }
    let by = format!("agent:{agent}");
    match (op, failure) {
        (Op::Move { .. }, None) => {
            record_move(st, &item, Some(agent), Ok(held.unwrap_or_default()), &by).await
        }
        (Op::Move { .. }, Some(c)) => {
            record_move(st, &item, Some(agent), Err(clean_code(c)), &by).await
        }
        (Op::Restore { .. }, None) => {
            let _ = st
                .db
                .set_quarantine_state(&item.id, q::RESTORED, None, None, &by)
                .await;
        }
        (Op::Delete { .. }, None) => {
            let _ = st
                .db
                .set_quarantine_state(&item.id, q::DELETED, None, None, &by)
                .await;
        }
        // A failed restore or delete leaves the file held; the error shows on the job.
        (_, Some(c)) => {
            tracing::warn!(event = "quarantine.failed", agent, path = %item.original_path, code = clean_code(c), "quarantine change failed on the agent");
        }
    }
}

fn clean_code(c: &str) -> &'static str {
    [
        OFF,
        NOT_INFECTED,
        READ_ONLY,
        EXISTS,
        REJECTED,
        crate::agent::policy::REFUSED,
        crate::agent::policy::RATE_LIMITED,
    ]
    .into_iter()
    .find(|k| *k == c)
    .unwrap_or(FAILED)
}

/// With QUARANTINE_AUTO, quarantine each new detection from a finished job.
pub async fn auto(st: &AppState, job_id: &str) {
    if !st.cfg.quarantine_auto {
        return;
    }
    for d in st.db.detections_for_job(job_id).await.unwrap_or_default() {
        if let Err(e) = start(st, d.id, "auto").await {
            tracing::warn!(event = "quarantine.auto_skipped", path = %d.path, reason = %e, "automatic quarantine skipped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_round_trip_and_ids_are_plain() {
        let op = Op::Move {
            id: "0190a1b2-c3d4".into(),
            path: "/data/x.exe".into(),
        };
        let s = serde_json::to_string(&op).expect("json");
        assert_eq!(serde_json::from_str::<Op>(&s).expect("op"), op);
        assert!(valid_id("0190a1b2-c3d4"));
        assert!(!valid_id("../../etc/passwd"));
        assert!(!valid_id(""));
        assert!(stored(Path::new("/q"), "a/b").is_none());
    }

    #[tokio::test]
    async fn restore_and_delete_stay_in_bounds() {
        let base = std::env::temp_dir().join(format!("clamv-q-{}", crate::db::new_id()));
        let root = base.join("root");
        let qdir = base.join("q");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&qdir).expect("q");
        std::fs::write(qdir.join("abc.quarantined"), b"X5O").expect("held");
        let roots = vec![root.clone()];
        // Nothing outside the roots.
        assert_eq!(
            restore(&roots, Some(&qdir), "abc", "/etc/x").await,
            Err(REJECTED)
        );
        // Not over an existing file.
        std::fs::write(root.join("x.exe"), b"new").expect("new");
        let target = root.join("x.exe").display().to_string();
        assert_eq!(
            restore(&roots, Some(&qdir), "abc", &target).await,
            Err(EXISTS)
        );
        std::fs::remove_file(root.join("x.exe")).expect("rm");
        assert_eq!(restore(&roots, Some(&qdir), "abc", &target).await, Ok(()));
        assert_eq!(std::fs::read(root.join("x.exe")).expect("back"), b"X5O");
        assert!(!qdir.join("abc.quarantined").exists());
        assert_eq!(delete(Some(&qdir), "abc").await, Ok(()));
        assert_eq!(delete(None, "abc").await, Err(OFF));
        let _ = std::fs::remove_dir_all(&base);
    }
}
