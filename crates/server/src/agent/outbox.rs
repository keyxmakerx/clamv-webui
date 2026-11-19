//! Results and events the agent has not delivered yet.
//!
//! Everything the agent sends goes through here, in order. While the server is
//! away items wait, in memory or, with `AGENT_QUEUE_DIR`, as one file each so
//! they survive an agent restart. The queue is bounded; when full the oldest
//! item is dropped and logged, so the agent's own log stays the full record.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use super::proto::{AgentEvent, ResultRequest};

/// Most items held at once.
pub const MAX_ITEMS: usize = 5_000;
/// Most bytes held at once (sum of the JSON bodies); well under the agent compose mem_limit of 256m.
pub const MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "to", rename_all = "lowercase")]
pub enum Item {
    /// A finished job, for `/agent/v1/jobs/{id}/result`.
    Result { job: String, body: ResultRequest },
    /// Something seen on this host, for `/agent/v1/events`.
    Event { body: AgentEvent },
}

impl Item {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Result { .. } => "result",
            Self::Event { .. } => "event",
        }
    }
}

struct Held {
    seq: u64,
    bytes: usize,
    /// The JSON body, kept encoded so memory use is what was counted.
    json: Vec<u8>,
}

pub struct Outbox {
    dir: Option<PathBuf>,
    q: Mutex<(VecDeque<Held>, usize, u64)>,
    pub ready: Notify,
}

impl Outbox {
    /// Open the queue; items left in `dir` by an earlier run are loaded in order.
    pub fn open(dir: Option<PathBuf>) -> anyhow::Result<Self> {
        let mut q = VecDeque::new();
        let mut bytes = 0;
        let mut next = 0;
        if let Some(d) = &dir {
            std::fs::create_dir_all(d)
                .map_err(|e| anyhow::anyhow!("cannot use AGENT_QUEUE_DIR {}: {e}", d.display()))?;
            let mut found: Vec<(u64, PathBuf)> = std::fs::read_dir(d)?
                .filter_map(Result::ok)
                .filter_map(|e| {
                    let p = e.path();
                    let seq = p
                        .file_name()?
                        .to_str()?
                        .strip_suffix(".json")?
                        .parse::<u64>()
                        .ok()?;
                    Some((seq, p))
                })
                .collect();
            found.sort();
            for (seq, p) in found {
                match std::fs::read(&p) {
                    Ok(json) if serde_json::from_slice::<Item>(&json).is_ok() => {
                        bytes += json.len();
                        next = seq + 1;
                        q.push_back(Held {
                            seq,
                            bytes: json.len(),
                            json,
                        });
                    }
                    _ => {
                        tracing::warn!(event = "agent.queue_unreadable", file = %p.display(), "skipping an unreadable queued item");
                        let _ = std::fs::remove_file(&p);
                    }
                }
            }
            if !q.is_empty() {
                tracing::info!(
                    event = "agent.queue_loaded",
                    items = q.len(),
                    "unsent results from the last run will be sent"
                );
            }
        }
        Ok(Self {
            dir,
            q: Mutex::new((q, bytes, next)),
            ready: Notify::new(),
        })
    }

    pub fn len(&self) -> usize {
        self.q.lock().map_or(0, |g| g.0.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn file(dir: &Path, seq: u64) -> PathBuf {
        dir.join(format!("{seq:020}.json"))
    }

    /// Queue an item; the oldest ones go if the queue is full.
    pub fn push(&self, item: &Item) {
        let Ok(json) = serde_json::to_vec(item) else {
            return;
        };
        let Ok(mut g) = self.q.lock() else {
            return;
        };
        let seq = g.2;
        g.2 += 1;
        if let Some(d) = &self.dir
            && let Err(e) = write_private(&Self::file(d, seq), &json)
        {
            // Memory still holds it; only a restart would lose it.
            tracing::warn!(event = "agent.queue_write_failed", error = %e, "could not write a queued item to AGENT_QUEUE_DIR");
        }
        g.1 += json.len();
        g.0.push_back(Held {
            seq,
            bytes: json.len(),
            json,
        });
        while g.0.len() > MAX_ITEMS || (g.1 > MAX_BYTES && g.0.len() > 1) {
            let Some(old) = g.0.pop_front() else { break };
            g.1 -= old.bytes;
            self.remove_file(old.seq);
            let what = serde_json::from_slice::<Item>(&old.json)
                .map(|i| match i {
                    Item::Result { job, .. } => format!("result for job {job}"),
                    Item::Event { .. } => "event".to_owned(),
                })
                .unwrap_or_default();
            tracing::error!(event = "agent.result_lost", item = %what, "send queue full; dropped the oldest unsent item");
        }
        drop(g);
        self.ready.notify_one();
    }

    /// The oldest item and its sequence number, without removing it.
    pub fn peek(&self) -> Option<(u64, Item)> {
        let g = self.q.lock().ok()?;
        let h = g.0.front()?;
        serde_json::from_slice(&h.json).ok().map(|i| (h.seq, i))
    }

    /// Remove the item `seq` once it was delivered (or refused for good).
    pub fn done(&self, seq: u64) {
        let Ok(mut g) = self.q.lock() else {
            return;
        };
        if g.0.front().is_some_and(|h| h.seq == seq)
            && let Some(h) = g.0.pop_front()
        {
            g.1 -= h.bytes;
            drop(g);
            self.remove_file(seq);
        }
    }

    fn remove_file(&self, seq: u64) {
        if let Some(d) = &self.dir {
            let _ = std::fs::remove_file(Self::file(d, seq));
        }
    }
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    std::fs::write(&tmp, data)?;
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(n: usize) -> Item {
        Item::Event {
            body: AgentEvent::Canary {
                path: format!("/c/{n}"),
                what: "open".into(),
            },
        }
    }

    #[test]
    fn items_survive_a_restart_in_order() {
        let dir = std::env::temp_dir().join(format!("clamv-q-{}", crate::db::new_id()));
        let q = Outbox::open(Some(dir.clone())).expect("open");
        q.push(&ev(1));
        q.push(&Item::Result {
            job: "j2".into(),
            body: ResultRequest::default(),
        });
        let (s1, _) = q.peek().expect("first");
        q.done(s1);
        drop(q);
        let q = Outbox::open(Some(dir.clone())).expect("reopen");
        assert_eq!(q.len(), 1);
        match q.peek() {
            Some((_, Item::Result { job, .. })) => assert_eq!(job, "j2"),
            _ => panic!("expected the result"),
        }
        q.push(&ev(3));
        let (s, _) = q.peek().expect("next");
        q.done(s);
        assert!(matches!(q.peek(), Some((_, Item::Event { .. }))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_full_queue_drops_the_oldest() {
        let q = Outbox::open(None).expect("open");
        for i in 0..MAX_ITEMS + 3 {
            q.push(&ev(i));
        }
        assert_eq!(q.len(), MAX_ITEMS);
        match q.peek() {
            Some((
                _,
                Item::Event {
                    body: AgentEvent::Canary { path, .. },
                },
            )) => {
                assert_eq!(path, "/c/3")
            }
            _ => panic!("expected an event"),
        }
    }
}
