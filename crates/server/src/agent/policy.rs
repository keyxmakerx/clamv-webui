//! What this agent host lets the server have it do. Set on the agent host
//! itself (AGENT_ALLOW or AGENT_ALLOW_FILE), never from the server, so a
//! compromised server cannot widen it. Every action is rate-limited and logged here.

use std::collections::BTreeSet;
use std::time::Duration;

use crate::auth::ratelimit::RateLimit;

pub const REFUSED: &str = "AGENT_REFUSED";
pub const RATE_LIMITED: &str = "AGENT_RATE_LIMITED";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Perm {
    Scan,
    Canaries,
    /// Read-only checks: run AIDE or rkhunter, read the firewall.
    Checks,
    /// Switch or reschedule the daily timers.
    Timers,
    /// Accept an AIDE baseline or update rkhunter's properties.
    Baseline,
    /// Apply or remove clamv's firewall table.
    Firewall,
    Quarantine,
}

pub const ALL: [Perm; 7] = [
    Perm::Scan,
    Perm::Canaries,
    Perm::Checks,
    Perm::Timers,
    Perm::Baseline,
    Perm::Firewall,
    Perm::Quarantine,
];

impl Perm {
    pub fn name(self) -> &'static str {
        match self {
            Perm::Scan => "scan",
            Perm::Canaries => "canaries",
            Perm::Checks => "checks",
            Perm::Timers => "timers",
            Perm::Baseline => "baseline",
            Perm::Firewall => "firewall",
            Perm::Quarantine => "quarantine",
        }
    }

    /// Most actions of this kind per hour.
    fn per_hour(self) -> u32 {
        match self {
            Perm::Scan => 600,
            Perm::Canaries => 60,
            Perm::Checks => 60,
            Perm::Timers => 20,
            Perm::Baseline => 4,
            Perm::Firewall => 6,
            Perm::Quarantine => 120,
        }
    }
}

/// Parse a comma or newline separated list; `all` turns everything on.
pub fn parse(items: &[String]) -> Result<BTreeSet<Perm>, String> {
    let mut out = BTreeSet::new();
    for raw in items.iter().flat_map(|s| s.split([',', '\n'])) {
        let w = raw.trim().to_ascii_lowercase();
        if w.is_empty() || w.starts_with('#') {
            continue;
        }
        if w == "all" {
            out.extend(ALL);
            continue;
        }
        match ALL.iter().find(|p| p.name() == w) {
            Some(p) => {
                out.insert(*p);
            }
            None => return Err(format!("unknown AGENT_ALLOW entry {w:?}")),
        }
    }
    Ok(out)
}

/// Which permission a job needs; None for a kind this agent does not know.
pub fn classify(kind: &str, target: &str) -> Option<Perm> {
    match kind {
        crate::scan::KIND_PATH | crate::schedule::KIND_CONTROL => Some(Perm::Scan),
        crate::hostchecks::KIND if crate::hostchecks::parse_timer_target(target).is_some() => {
            Some(Perm::Timers)
        }
        crate::hostchecks::KIND => Some(match crate::hostchecks::check_action(target) {
            Some(a) if a.passkey => Perm::Baseline,
            Some(a) if a.name.contains(".timer") => Perm::Timers,
            _ => Perm::Checks,
        }),
        crate::firewall::KIND => Some(match serde_json::from_str::<crate::firewall::Op>(target) {
            Ok(crate::firewall::Op::Snapshot) | Err(_) => Perm::Checks,
            Ok(_) => Perm::Firewall,
        }),
        crate::quarantine::KIND => Some(Perm::Quarantine),
        _ => None,
    }
}

pub struct Policy {
    allowed: BTreeSet<Perm>,
    limits: Vec<(Perm, RateLimit)>,
}

impl Policy {
    pub fn new(allowed: BTreeSet<Perm>) -> Self {
        Self {
            allowed,
            limits: ALL
                .iter()
                .map(|p| (*p, RateLimit::new(p.per_hour(), Duration::from_secs(3600))))
                .collect(),
        }
    }

    pub fn allows(&self, p: Perm) -> bool {
        self.allowed.contains(&p)
    }

    pub fn names(&self) -> String {
        self.allowed
            .iter()
            .map(|p| p.name())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Ok to run, or the job error code that refuses it.
    pub fn admit(&self, p: Perm) -> Result<(), &'static str> {
        if !self.allows(p) {
            return Err(REFUSED);
        }
        match self.limits.iter().find(|(q, _)| *q == p) {
            Some((_, l)) if !l.allow(p.name()) => Err(RATE_LIMITED),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_read_only() {
        let p = parse(&["scan,canaries,checks".into()]).expect("parse");
        assert!(p.contains(&Perm::Scan) && !p.contains(&Perm::Firewall));
        assert_eq!(parse(&["all".into()]).expect("all").len(), ALL.len());
        assert!(parse(&["scan,root".into()]).is_err());
        assert_eq!(
            parse(&["# comment\nscan\n\nfirewall".into()])
                .expect("file")
                .len(),
            2
        );
    }

    #[test]
    fn jobs_need_the_right_permission() {
        assert_eq!(classify("HOSTCHECK", "aide.check"), Some(Perm::Checks));
        assert_eq!(classify("HOSTCHECK", "aide.accept"), Some(Perm::Baseline));
        assert_eq!(classify("HOSTCHECK", "aide.timer.on"), Some(Perm::Timers));
        assert_eq!(
            classify("HOSTCHECK", "aide.timer.at 03:30"),
            Some(Perm::Timers)
        );
        assert_eq!(
            classify("FIREWALL", r#"{"op":"snapshot"}"#),
            Some(Perm::Checks)
        );
        assert_eq!(
            classify("FIREWALL", r#"{"op":"remove"}"#),
            Some(Perm::Firewall)
        );
        assert_eq!(classify("NOPE", ""), None);
    }

    #[test]
    fn refuses_and_limits() {
        let p = Policy::new(parse(&["checks,baseline".into()]).expect("p"));
        assert_eq!(p.admit(Perm::Firewall), Err(REFUSED));
        for _ in 0..4 {
            assert_eq!(p.admit(Perm::Baseline), Ok(()));
        }
        assert_eq!(p.admit(Perm::Baseline), Err(RATE_LIMITED));
        assert_eq!(p.admit(Perm::Checks), Ok(()));
    }
}
