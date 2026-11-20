//! Host firewall. Palisade reads each host's rules through a fixed snapshot unit,
//! shows who owns them (Docker, CrowdSec, ufw, firewalld...), and writes only
//! its own nftables table, `inet palisade`, through a fixed apply unit that checks
//! the plan in an empty network namespace and rolls back unless Palisade confirms
//! it can still reach the host. See examples/host-checks.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::app::AppState;

pub const KIND: &str = "FIREWALL";
pub const MAX_RULES: usize = 50;
pub const MAX_SOURCES: usize = 16;
/// Bytes of snapshot kept per host.
pub const MAX_SNAPSHOT: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Only `allow` may reach `port`; everyone else is dropped. An empty list closes the port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub port: u16,
    pub proto: Proto,
    #[serde(default)]
    pub allow: Vec<String>,
}

/// Check rules and put them in a stable order.
pub fn check(mut rules: Vec<Rule>) -> Result<Vec<Rule>, String> {
    if rules.len() > MAX_RULES {
        return Err(format!("At most {MAX_RULES} ports per host."));
    }
    for r in &mut rules {
        if r.port == 0 {
            return Err("Port must be 1 to 65535.".into());
        }
        if r.allow.len() > MAX_SOURCES {
            return Err(format!("At most {MAX_SOURCES} sources per port."));
        }
        let mut clean = Vec::new();
        for s in &r.allow {
            let s = s.trim();
            if s.is_empty() {
                continue;
            }
            crate::webhook::Cidr::parse(s)?;
            let (ip, bits) = s.split_once('/').unwrap_or((s, ""));
            let ip: IpAddr = ip.parse().map_err(|_| format!("bad source {s:?}"))?;
            let canon = if bits.is_empty() {
                ip.to_string()
            } else {
                format!("{ip}/{bits}")
            };
            if !clean.contains(&canon) {
                clean.push(canon);
            }
        }
        clean.sort();
        r.allow = clean;
    }
    rules.sort_by_key(|r| (r.port, r.proto.as_str()));
    rules.dedup_by_key(|r| (r.port, r.proto));
    Ok(rules)
}

/// The inside of `table inet palisade`, exactly as written to plan.nft.
pub fn body(rules: &[Rule]) -> String {
    let mut s = String::from(
        "  chain input {\n    type filter hook input priority -5; policy accept;\n    ct state established,related accept\n    iif \"lo\" accept\n",
    );
    for r in rules {
        let p = r.proto.as_str();
        let (v4, v6): (Vec<&String>, Vec<&String>) = r.allow.iter().partition(|a| !a.contains(':'));
        if !v4.is_empty() {
            s.push_str(&format!(
                "    {p} dport {} ip saddr {{ {} }} accept\n",
                r.port,
                v4.iter().map(|x| x.as_str()).collect::<Vec<_>>().join(", ")
            ));
        }
        if !v6.is_empty() {
            s.push_str(&format!(
                "    {p} dport {} ip6 saddr {{ {} }} accept\n",
                r.port,
                v6.iter().map(|x| x.as_str()).collect::<Vec<_>>().join(", ")
            ));
        }
        s.push_str(&format!("    {p} dport {} drop\n", r.port));
    }
    s.push_str("  }\n");
    s
}

pub fn hash(body: &str) -> String {
    Sha256::digest(body.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Who manages a table or chain, from its name.
pub fn owner(family: &str, table: &str, chains: &[String]) -> &'static str {
    let any = |p: &str| chains.iter().any(|c| c.starts_with(p));
    match (family, table) {
        ("inet", "palisade") => "palisade",
        (_, t) if t.starts_with("crowdsec") => "CrowdSec",
        (_, "firewalld") => "firewalld",
        _ if any("CROWDSEC") => "CrowdSec",
        _ if any("DOCKER") => "Docker",
        _ if any("ufw") => "ufw",
        _ if any("f2b-") => "fail2ban",
        _ if any("KUBE-") || any("cali-") => "Kubernetes",
        _ if any("LIBVIRT") => "libvirt",
        _ => "host",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub family: String,
    pub name: String,
    pub owner: &'static str,
    pub chains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listen {
    pub proto: String,
    pub addr: String,
    pub port: u16,
    pub process: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyStatus {
    /// applied, pending, rolled_back, refused, failed or removed.
    pub state: String,
    pub at: i64,
    pub hash: String,
    /// nft, ufw or firewalld: the tool the host wrote through; empty when not said.
    pub via: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snapshot {
    pub nft: bool,
    pub tables: Vec<Table>,
    pub legacy_rules: usize,
    pub ufw: String,
    pub firewalld: String,
    pub selinux: String,
    pub listening: Vec<Listen>,
    pub status: Option<ApplyStatus>,
}

fn sections(raw: &str) -> HashMap<&str, Vec<&str>> {
    let mut out: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut cur = "";
    for line in raw.lines() {
        if let Some(name) = line.strip_prefix("### ") {
            cur = name.trim();
            out.entry(cur).or_default();
        } else if !cur.is_empty() {
            out.entry(cur).or_default().push(line);
        }
    }
    out
}

/// `0.0.0.0:22`, `[::]:8080`, `*:53`, `127.0.0.53%lo:53` → (address, port).
fn split_addr(s: &str) -> Option<(String, u16)> {
    let (a, p) = s.rsplit_once(':')?;
    let port = p.parse().ok()?;
    let a = a.trim_start_matches('[').trim_end_matches(']');
    let a = a.split('%').next().unwrap_or(a);
    Some((a.to_owned(), port))
}

pub fn parse(raw: &str) -> Snapshot {
    let sec = sections(raw);
    let mut snap = Snapshot::default();
    if let Some(lines) = sec.get("nft") {
        snap.nft = true;
        let mut cur: Option<Table> = None;
        for l in lines {
            let t = l.trim();
            if let Some(rest) = t.strip_prefix("table ") {
                if let Some(done) = cur.take() {
                    snap.tables.push(done);
                }
                let mut it = rest.trim_end_matches('{').split_whitespace();
                if let (Some(f), Some(n)) = (it.next(), it.next()) {
                    cur = Some(Table {
                        family: crate::agent::proto::clean(f, 16),
                        name: crate::agent::proto::clean(n, 64),
                        owner: "host",
                        chains: Vec::new(),
                    });
                }
            } else if let Some(rest) = t.strip_prefix("chain ")
                && let Some(c) = cur.as_mut()
                && c.chains.len() < 200
            {
                c.chains.push(crate::agent::proto::clean(
                    rest.trim_end_matches('{').trim(),
                    64,
                ));
            }
        }
        if let Some(done) = cur.take() {
            snap.tables.push(done);
        }
        for t in &mut snap.tables {
            t.owner = owner(&t.family, &t.name, &t.chains);
        }
    }
    snap.legacy_rules = sec
        .get("iptables-legacy")
        .map_or(0, |l| l.iter().filter(|x| x.starts_with("-A ")).count());
    let first = |k: &str| {
        sec.get(k)
            .and_then(|l| l.iter().find(|x| !x.trim().is_empty()))
            .map(|s| crate::agent::proto::clean(s.trim(), 80))
            .unwrap_or_default()
    };
    snap.ufw = first("ufw")
        .strip_prefix("Status: ")
        .map(str::to_owned)
        .unwrap_or_else(|| first("ufw"));
    snap.firewalld = first("firewalld");
    snap.selinux = first("selinux");
    if let Some(lines) = sec.get("listening") {
        for l in lines.iter().take(500) {
            let f: Vec<&str> = l.split_whitespace().collect();
            // Netid State Recv-Q Send-Q Local Peer [Process]
            if f.len() < 5 {
                continue;
            }
            let Some((addr, port)) = split_addr(f[4]) else {
                continue;
            };
            let process = f
                .get(6..)
                .map(|p| p.join(" "))
                .and_then(|p| {
                    p.split("((\"")
                        .nth(1)
                        .and_then(|x| x.split('"').next())
                        .map(str::to_owned)
                })
                .unwrap_or_default();
            let item = Listen {
                proto: crate::agent::proto::clean(f[0], 8),
                addr: crate::agent::proto::clean(&addr, 64),
                port,
                process: crate::agent::proto::clean(&process, 64),
            };
            if !snap
                .listening
                .iter()
                .any(|x| x.proto == item.proto && x.port == item.port && x.addr == item.addr)
            {
                snap.listening.push(item);
            }
        }
        snap.listening.sort_by_key(|l| (l.port, l.proto.clone()));
    }
    if let Some(l) = sec.get("status").and_then(|l| l.first()) {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 3 {
            snap.status = Some(ApplyStatus {
                state: crate::agent::proto::clean(f[0], 16),
                at: f[1].parse::<i64>().unwrap_or(0) * 1000,
                hash: crate::agent::proto::clean(f[2], 64),
                via: f
                    .get(3)
                    .filter(|v| matches!(**v, "nft" | "ufw" | "firewalld"))
                    .map(|v| (*v).to_owned())
                    .unwrap_or_default(),
            });
        }
    }
    snap
}

impl Snapshot {
    /// The tool the host's apply unit will write through: an active ufw, a running firewalld, else nftables.
    pub fn backend(&self) -> &'static str {
        if self.ufw == "active" {
            "ufw"
        } else if self.firewalld == "running" {
            "firewalld"
        } else {
            "nftables"
        }
    }
}

/// Is this listener reachable from outside (not loopback)?
pub fn exposed(l: &Listen) -> bool {
    match l.addr.parse::<IpAddr>() {
        Ok(ip) => !ip.is_loopback(),
        Err(_) => true,
    }
}

// ---- what a host does (this server, or an agent) ----

/// What the server asks an agent to do, as a job target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Op {
    Snapshot,
    Apply { rules: Vec<Rule> },
    Remove,
}

fn unit(name: &str) -> &'static crate::hostchecks::Action {
    crate::hostchecks::action(name).unwrap_or(&crate::hostchecks::ACTIONS[0])
}

/// Run the snapshot unit and read what it wrote.
pub async fn snapshot(dir: &Path) -> Result<String, crate::hostchecks::RunError> {
    let file = dir.join("snapshot.txt");
    let before = std::fs::metadata(&file).and_then(|m| m.modified()).ok();
    crate::hostchecks::run(unit("firewall.snapshot")).await?;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let now = std::fs::metadata(&file).and_then(|m| m.modified()).ok();
        if now.is_some() && now != before {
            break;
        }
    }
    read_snapshot(dir).ok_or_else(|| crate::hostchecks::RunError {
        code: crate::hostchecks::FAILED,
        message: "the snapshot unit wrote nothing".into(),
    })
}

pub fn read_snapshot(dir: &Path) -> Option<String> {
    use std::io::Read;
    let f = std::fs::File::open(dir.join("snapshot.txt")).ok()?;
    let mut s = Vec::new();
    f.take(MAX_SNAPSHOT as u64).read_to_end(&mut s).ok()?;
    let mut out = String::from_utf8_lossy(&s).into_owned();
    // The apply status is read here, unprivileged: the root snapshot unit reads nothing from this folder.
    if let Ok(f) = std::fs::File::open(dir.join("status")) {
        let mut st = String::new();
        if f.take(200).read_to_string(&mut st).is_ok() {
            out.push_str("\n### status\n");
            out.push_str(st.lines().next().unwrap_or_default());
            out.push('\n');
        }
    }
    Some(out)
}

/// Write the plan for the apply unit and start it. Returns the hash to confirm.
pub async fn apply(dir: &Path, rules: Vec<Rule>) -> Result<String, crate::hostchecks::RunError> {
    let rules = check(rules).map_err(|m| crate::hostchecks::RunError {
        code: crate::hostchecks::FAILED,
        message: m,
    })?;
    let b = body(&rules);
    let io = |e: std::io::Error| crate::hostchecks::RunError {
        code: crate::hostchecks::FAILED,
        message: format!("cannot write the plan to {}: {e}", dir.display()),
    };
    let tmp = dir.join(".plan.nft.tmp");
    std::fs::write(&tmp, &b).map_err(io)?;
    std::fs::rename(&tmp, dir.join("plan.nft")).map_err(io)?;
    let _ = std::fs::remove_file(dir.join("confirm"));
    crate::hostchecks::run(unit("firewall.apply")).await?;
    Ok(hash(&b))
}

/// Whether the apply unit has loaded this plan and now waits for a confirmation.
/// Confirming earlier would prove nothing about the new rules.
pub fn waiting(dir: &Path, hash: &str) -> bool {
    std::fs::read_to_string(dir.join("status")).is_ok_and(|s| {
        let f: Vec<&str> = s.split_whitespace().collect();
        f.len() >= 3 && f[0] == "pending" && f[2] == hash
    })
}

/// Tell the waiting apply unit that Palisade still reaches this host.
pub fn confirm(dir: &Path, hash: &str) {
    let tmp = dir.join(".confirm.tmp");
    if std::fs::write(&tmp, hash).is_ok() {
        let _ = std::fs::rename(&tmp, dir.join("confirm"));
    }
}

pub async fn remove() -> Result<(), crate::hostchecks::RunError> {
    crate::hostchecks::run(unit("firewall.remove")).await
}

// ---- the server's view ----

/// Latest snapshot per host (None is this server), with when it arrived.
#[derive(Default)]
pub struct Snapshots {
    raw: Mutex<HashMap<Option<i64>, (String, i64)>>,
    /// This server's apply waiting for an admin's browser to come back: (hash, user, started).
    pub pending: Mutex<Option<(String, String, i64)>>,
}

impl Snapshots {
    pub fn set(&self, host: Option<i64>, mut raw: String) {
        if raw.len() > MAX_SNAPSHOT {
            let mut cut = MAX_SNAPSHOT;
            while !raw.is_char_boundary(cut) {
                cut -= 1;
            }
            raw.truncate(cut);
        }
        if let Ok(mut g) = self.raw.lock() {
            g.insert(host, (raw, crate::db::now_ms()));
        }
    }

    pub fn get(&self, host: Option<i64>) -> Option<(Snapshot, i64)> {
        let g = self.raw.lock().ok()?;
        let (raw, at) = g.get(&host)?;
        Some((parse(raw), *at))
    }
}

/// Shared with the host's firewall units, which use this fixed path too.
pub const DIR: &str = "/var/lib/palisade/firewall";

pub fn dir() -> &'static Path {
    Path::new(DIR)
}

/// Refresh this server's snapshot.
pub async fn refresh_here(st: &AppState) -> Result<(), crate::hostchecks::RunError> {
    let raw = snapshot(dir()).await?;
    st.firewalls.set(None, raw);
    Ok(())
}

/// Every 15 minutes, read this server's firewall when the folder is mounted.
pub fn spawn(st: Arc<AppState>) {
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(900));
        loop {
            t.tick().await;
            if dir().is_dir()
                && let Err(e) = refresh_here(&st).await
            {
                tracing::debug!(error = %e.message, "firewall snapshot failed");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &str = "### nft
table ip filter {
\tchain DOCKER {
\t}
\tchain DOCKER-USER {
\t}
\tchain INPUT {
\t\ttype filter hook input priority filter; policy accept;
\t}
}
table ip crowdsec {
\tchain crowdsec-chain-input {
\t}
}
table inet firewalld {
\tchain filter_INPUT {
\t}
}
table inet palisade {
\tchain input {
\t}
}
### iptables-legacy
-A INPUT -j ACCEPT
### ufw
Status: inactive
### firewalld
running
### selinux
Enforcing
### listening
tcp   LISTEN 0      4096         0.0.0.0:22        0.0.0.0:*    users:((\"sshd\",pid=812,fd=3))
tcp   LISTEN 0      4096       127.0.0.1:631       0.0.0.0:*    users:((\"cupsd\",pid=900,fd=7))
tcp   LISTEN 0      4096            [::]:8080         [::]:*    users:((\"docker-proxy\",pid=1,fd=4))
udp   UNCONN 0      0      127.0.0.53%lo:53        0.0.0.0:*    users:((\"systemd-resolve\",pid=5,fd=13))
### status
rolled_back 1763100000 abc123
";

    #[test]
    fn snapshots_are_read_with_owners() {
        let s = parse(RAW);
        let owners: Vec<(&str, &str)> = s
            .tables
            .iter()
            .map(|t| (t.name.as_str(), t.owner))
            .collect();
        assert_eq!(
            owners,
            vec![
                ("filter", "Docker"),
                ("crowdsec", "CrowdSec"),
                ("firewalld", "firewalld"),
                ("palisade", "palisade")
            ]
        );
        assert_eq!(s.legacy_rules, 1);
        assert_eq!(s.ufw, "inactive");
        assert_eq!(s.firewalld, "running");
        assert_eq!(s.selinux, "Enforcing");
        assert_eq!(s.listening.len(), 4);
        assert_eq!(s.listening[0].process, "sshd");
        assert_eq!(s.listening[3].addr, "::");
        assert!(exposed(&s.listening[0]) && !exposed(&s.listening[2]));
        let st = s.status.expect("status");
        assert_eq!(
            (st.state.as_str(), st.at),
            ("rolled_back", 1_763_100_000_000)
        );
    }

    #[test]
    fn plans_are_checked_and_written_only_as_our_table() {
        let rules = check(vec![
            Rule {
                port: 8080,
                proto: Proto::Tcp,
                allow: vec![
                    "100.82.0.0/16".into(),
                    " fd00::/8 ".into(),
                    "100.82.0.0/16".into(),
                ],
            },
            Rule {
                port: 22,
                proto: Proto::Tcp,
                allow: vec![],
            },
        ])
        .expect("ok");
        assert_eq!(rules[0].port, 22);
        assert_eq!(rules[1].allow, vec!["100.82.0.0/16", "fd00::/8"]);
        let b = body(&rules);
        assert!(b.contains("tcp dport 8080 ip saddr { 100.82.0.0/16 } accept"));
        assert!(b.contains("tcp dport 8080 ip6 saddr { fd00::/8 } accept"));
        assert!(b.contains("tcp dport 22 drop"));
        assert!(b.contains("policy accept;"));
        // The host-side apply script refuses these words; the generator never emits them.
        for w in ["table", "ruleset", "include", "flush", "delete", "add "] {
            assert!(!b.contains(w), "{w}");
        }
        assert_eq!(hash(&b).len(), 64);
        // The apply script accepts only these line shapes; the generator must stay inside them.
        let script = include_str!("../../../examples/host-checks/firewall-apply");
        let allowed = script
            .lines()
            .find_map(|l| l.strip_prefix("allowed='"))
            .and_then(|l| l.strip_suffix('\''))
            .expect("allowed pattern");
        let re = regex::Regex::new(allowed).expect("regex");
        let wide = check(vec![Rule {
            port: 65535,
            proto: Proto::Udp,
            allow: vec![
                "::ffff:10.1.2.3".into(),
                "2001:db8::/32".into(),
                "10.0.0.1".into(),
            ],
        }])
        .expect("ok");
        for l in b
            .lines()
            .chain(body(&wide).lines())
            .chain(body(&[]).lines())
        {
            assert!(re.is_match(l), "the apply script would refuse {l:?}");
        }
        assert!(!re.is_match("    tcp dport 22 redirect to :2222"));
        assert!(!re.is_match("    type nat hook prerouting priority -100; policy accept;"));
        assert!(
            check(vec![Rule {
                port: 0,
                proto: Proto::Tcp,
                allow: vec![]
            }])
            .is_err()
        );
        assert!(
            check(vec![Rule {
                port: 1,
                proto: Proto::Udp,
                allow: vec!["10.0.0.0/33".into()]
            }])
            .is_err()
        );
        assert!(
            check(vec![Rule {
                port: 1,
                proto: Proto::Udp,
                allow: vec!["x; flush ruleset".into()]
            }])
            .is_err()
        );
    }

    #[test]
    fn ops_round_trip() {
        let op = Op::Apply {
            rules: vec![Rule {
                port: 80,
                proto: Proto::Tcp,
                allow: vec![],
            }],
        };
        let s = serde_json::to_string(&op).expect("json");
        assert_eq!(serde_json::from_str::<Op>(&s).expect("op"), op);
        assert_eq!(
            serde_json::from_str::<Op>(r#"{"op":"snapshot"}"#).expect("op"),
            Op::Snapshot
        );
    }
}
