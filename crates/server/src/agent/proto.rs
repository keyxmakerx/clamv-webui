//! Wire format between agent and server. Bump `PROTOCOL` when a job kind or field is added.

use serde::{Deserialize, Serialize};

/// 2: agents list the job kinds they run, the server can cancel running jobs.
pub const PROTOCOL: u32 = 2;
/// Oldest agent protocol the server still talks to.
pub const MIN_PROTOCOL: u32 = 1;

/// Job kinds a protocol-1 agent runs (it does not list them).
pub const LEGACY_KINDS: [&str; 5] = [
    crate::scan::KIND_PATH,
    crate::schedule::KIND_CONTROL,
    crate::hostchecks::KIND,
    crate::firewall::KIND,
    crate::quarantine::KIND,
];

/// Job kinds this build's agent runs.
pub const KINDS: [&str; 5] = LEGACY_KINDS;

/// Failure code from an agent that does not know a job kind.
pub const UNSUPPORTED: &str = "AGENT_UNSUPPORTED";

/// Entries kept from one report; the rest are dropped with a note.
const MAX_ENTRIES: usize = 20_000;
/// The server refuses agent bodies over 32 MiB; agents trim reports to this first.
pub const MAX_BODY: usize = 24 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct PollRequest {
    pub protocol: u32,
    pub version: String,
    #[serde(default)]
    pub clamd_version: Option<String>,
    #[serde(default)]
    pub roots: Vec<String>,
    /// Jobs the agent can run at once.
    pub slots: u32,
    /// Jobs it can take now.
    pub free: u32,
    /// Ids of jobs it is running.
    #[serde(default)]
    pub running: Vec<String>,
    /// Hold the request open until work arrives.
    #[serde(default)]
    pub wait: bool,
    /// Whether each canary could be watched, by path.
    #[serde(default)]
    pub canaries: Vec<CanaryState>,
    /// Which clamv host-check units this host has, read every few minutes.
    #[serde(default)]
    pub host_checks: Option<crate::hostchecks::UnitStates>,
    /// Job kinds this agent runs (protocol 2+).
    #[serde(default)]
    pub kinds: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryState {
    pub path: String,
    pub armed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PollResponse {
    pub jobs: Vec<Assignment>,
    /// The canaries an admin set for this agent (on top of its CANARY_FILES).
    #[serde(default)]
    pub canaries: Option<Vec<crate::canary::Spec>>,
    /// Running jobs to stop at once: cancelled on the server.
    #[serde(default)]
    pub cancel: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assignment {
    pub id: String,
    pub kind: String,
    pub target: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub ok: u64,
    #[serde(default)]
    pub detections: Vec<Entry>,
    #[serde(default)]
    pub errors: Vec<Entry>,
}

/// `text` is the signature for a detection and the reason for an error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub path: String,
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Failure {
    pub code: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ResultRequest {
    #[serde(default)]
    pub report: Option<Report>,
    #[serde(default)]
    pub failure: Option<Failure>,
    /// A file this job moved into quarantine.
    #[serde(default)]
    pub quarantine: Option<crate::quarantine::Held>,
}

/// Something the agent saw on its own: a real-time scan or a touched canary.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AgentEvent {
    Scan {
        path: String,
        #[serde(default)]
        report: Option<Report>,
        #[serde(default)]
        failure: Option<Failure>,
    },
    Canary {
        path: String,
        what: String,
    },
    /// Falco alerts from the agent's host.
    Falco {
        alerts: Vec<crate::falco::Alert>,
    },
    /// A new AIDE or rkhunter run on the agent's host.
    Integrity {
        report: crate::integrity::Report,
    },
    /// What the host's firewall snapshot unit wrote.
    Firewall {
        snapshot: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorBody<'a> {
    pub error: &'a str,
}

pub fn clean(s: &str, n: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(n).collect()
}

impl Report {
    pub fn from_clamd(r: clamd::ScanReport) -> Self {
        Self {
            ok: r.ok,
            detections: r
                .detections
                .into_iter()
                .map(|d| Entry {
                    path: d.path,
                    text: d.signature,
                })
                .collect(),
            errors: r
                .errors
                .into_iter()
                .map(|e| Entry {
                    path: e.path,
                    text: e.message,
                })
                .collect(),
        }
    }

    /// Trim to what the server accepts: detections are kept first, then errors, with a note for the rest.
    pub fn fit(&mut self, max_bytes: usize) {
        let size = |e: &Entry| e.path.len() + e.text.len() + 32;
        for e in self.detections.iter_mut().chain(self.errors.iter_mut()) {
            e.path = clean(&e.path, 4096);
            e.text = clean(&e.text, 512);
        }
        let mut budget = max_bytes.saturating_sub(4096);
        let mut dropped = 0usize;
        let mut keep = |list: &mut Vec<Entry>| {
            let mut n = 0;
            for e in list.iter() {
                let s = size(e);
                if n >= MAX_ENTRIES || s > budget {
                    break;
                }
                budget -= s;
                n += 1;
            }
            dropped += list.len() - n;
            list.truncate(n);
        };
        keep(&mut self.detections);
        keep(&mut self.errors);
        if dropped > 0 {
            self.errors.push(Entry {
                path: String::new(),
                text: format!(
                    "{dropped} more result line(s) were dropped by the agent; its log has them all."
                ),
            });
        }
    }

    /// Back to a clamd report, with sizes bounded: the agent is trusted to scan, not to fill the database.
    pub fn into_report(self) -> clamd::ScanReport {
        let dropped = self.detections.len().saturating_sub(MAX_ENTRIES)
            + self.errors.len().saturating_sub(MAX_ENTRIES);
        let mut errors: Vec<clamd::FileError> = self
            .errors
            .into_iter()
            .take(MAX_ENTRIES)
            .map(|e| clamd::FileError {
                path: clean(&e.path, 4096),
                message: clean(&e.text, 512),
            })
            .collect();
        if dropped > 0 {
            errors.push(clamd::FileError {
                path: String::new(),
                message: format!("{dropped} more result line(s) were dropped."),
            });
        }
        clamd::ScanReport {
            ok: self.ok,
            detections: self
                .detections
                .into_iter()
                .take(MAX_ENTRIES)
                .map(|d| clamd::Detection {
                    path: clean(&d.path, 4096),
                    signature: clean(&d.text, 256),
                })
                .collect(),
            errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_fit_the_server_limit() {
        let mut r = Report {
            ok: 3,
            detections: vec![Entry {
                path: "/d/x".into(),
                text: "Eicar".into(),
            }],
            errors: (0..50_000)
                .map(|i| Entry {
                    path: format!("/d/{i}/{}", "p".repeat(400)),
                    text: "Permission denied".into(),
                })
                .collect(),
        };
        r.fit(1024 * 1024);
        let body = serde_json::to_vec(&r).expect("json");
        assert!(body.len() < 1024 * 1024, "{}", body.len());
        assert_eq!(r.detections.len(), 1, "detections kept first");
        assert!(
            r.errors
                .last()
                .is_some_and(|e| e.text.contains("dropped by the agent"))
        );
    }

    #[test]
    fn reports_are_bounded_and_cleaned() {
        let r = Report {
            ok: 1,
            detections: vec![Entry {
                path: "/d/a\u{1b}[31m".into(),
                text: "X".repeat(1000),
            }],
            errors: (0..MAX_ENTRIES + 5)
                .map(|i| Entry {
                    path: format!("/d/{i}"),
                    text: "e".into(),
                })
                .collect(),
        }
        .into_report();
        assert_eq!(r.detections[0].path, "/d/a[31m");
        assert_eq!(r.detections[0].signature.len(), 256);
        assert_eq!(r.errors.len(), MAX_ENTRIES + 1);
        assert!(
            r.errors
                .last()
                .is_some_and(|e| e.message.starts_with("5 more"))
        );
    }
}
