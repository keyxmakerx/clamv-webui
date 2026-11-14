//! Coverage: which threats each host is protected against, this server and
//! every agent alike. Threat rows on top, host cards below.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;

use super::endpoints::{self, Status};
use super::session::Auth;
use super::{Nav, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::db::now_ms;
use crate::db::stats::HostActivity;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/coverage", get(page))
}

const DAY: i64 = 86_400_000;
const WEEK: i64 = 7 * DAY;

#[derive(Clone)]
pub struct Cell {
    /// ok, warn, off or soon.
    pub state: &'static str,
    pub text: String,
}

fn cell(state: &'static str, text: impl Into<String>) -> Cell {
    Cell {
        state,
        text: text.into(),
    }
}

pub struct Threat {
    pub name: &'static str,
    pub what: &'static str,
    pub cells: Vec<Cell>,
}

pub struct Host {
    pub name: String,
    pub role: &'static str,
    pub online: bool,
    pub seen: String,
    pub version: String,
    pub roots: String,
    pub on: usize,
    pub of: usize,
    pub items: Vec<(&'static str, Cell)>,
}

#[derive(Template)]
#[template(path = "coverage.html")]
struct CoveragePage {
    nav: Nav,
    hosts: Vec<Host>,
    threats: Vec<Threat>,
}

const THREATS: [(&str, &str); 8] = [
    (
        "Malware in stored files",
        "A scanner is up and has scanned this host in the last week.",
    ),
    (
        "Malware as files arrive",
        "New files are scanned the moment they are written.",
    ),
    (
        "Ransomware and snooping",
        "Canary files are armed, so touching them alerts at once.",
    ),
    (
        "A broken or tampered scanner",
        "The EICAR check passed in the last week.",
    ),
    (
        "Outdated signatures",
        "Signatures are less than two days old.",
    ),
    (
        "Rootkits and changed system files",
        "AIDE and rkhunter results reach this console.",
    ),
    (
        "Suspicious behaviour at runtime",
        "Falco alerts reach this console.",
    ),
    (
        "Exposed services",
        "The host firewall is known and planned from here.",
    ),
];

fn ago(now: i64, t: i64) -> String {
    let h = (now - t).max(0) / 3_600_000;
    if h < 1 {
        "under an hour ago".into()
    } else if h < 48 {
        format!("{h} h ago")
    } else {
        format!("{} days ago", h / 24)
    }
}

fn last(act: &[HostActivity], agent: Option<i64>, kinds: &[&str]) -> Option<i64> {
    act.iter()
        .filter(|a| a.agent_id == agent && kinds.contains(&a.kind.as_str()))
        .map(|a| a.last)
        .max()
}

fn signatures(version: Option<&str>, now: i64) -> Cell {
    let Some(v) = version else {
        return cell("off", "version unknown");
    };
    let (_, _, time) = crate::api::split_version(v);
    match time.as_deref().and_then(crate::timefmt::parse_clamd_date) {
        Some(t) if now - t <= 2 * DAY => cell("ok", format!("updated {}", ago(now, t))),
        Some(t) if now - t <= WEEK => cell("warn", format!("updated {}", ago(now, t))),
        Some(t) => cell("off", format!("updated {}", ago(now, t))),
        None => cell("off", "version unknown"),
    }
}

fn canaries(armed: usize, missing: usize) -> Cell {
    match (armed, missing) {
        (0, 0) => cell("off", "no canaries"),
        (a, 0) => cell("ok", format!("{a} armed")),
        (0, m) => cell("warn", format!("{m} missing")),
        (a, m) => cell("warn", format!("{a} armed, {m} missing")),
    }
}

fn control(controls: &[(Option<i64>, String, i64)], agent: Option<i64>, now: i64) -> Cell {
    match controls.iter().find(|c| c.0 == agent) {
        Some((_, v, at)) if v == crate::db::jobs::OK && now - at <= WEEK => {
            cell("ok", format!("passed {}", ago(now, *at)))
        }
        Some((_, v, at)) if v == crate::db::jobs::OK => {
            cell("warn", format!("last passed {}", ago(now, *at)))
        }
        Some((_, _, at)) => cell("warn", format!("failed {}", ago(now, *at))),
        None => cell("off", "no EICAR check scheduled"),
    }
}

fn soon(i: usize) -> Cell {
    match i {
        5 => cell("soon", "AIDE and rkhunter come next"),
        6 => cell("soon", "Falco intake comes next"),
        _ => cell("soon", "planned after this release"),
    }
}

fn host(
    name: String,
    role: &'static str,
    online: bool,
    seen: String,
    version: String,
    roots: String,
    cells: Vec<Cell>,
) -> Host {
    let counted: Vec<&Cell> = cells.iter().filter(|c| c.state != "soon").collect();
    Host {
        name,
        role,
        online,
        seen,
        version,
        roots,
        on: counted.iter().filter(|c| c.state == "ok").count(),
        of: counted.len(),
        items: THREATS.iter().map(|t| t.0).zip(cells).collect(),
    }
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Viewer) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let now = now_ms();
    let act = st
        .db
        .host_activity(now - 30 * DAY)
        .await
        .unwrap_or_default();
    let controls = st
        .db
        .recent_controls(now - 30 * DAY)
        .await
        .unwrap_or_default();
    let all_canaries = st.db.list_canaries().await.unwrap_or_default();
    let agents = st.db.list_agents().await.unwrap_or_default();
    let watches = st.db.list_watches().await.unwrap_or_default();

    // This server: its own clamd endpoints, folders and canaries.
    let eps = endpoints::probe_all(&st, st.db.list_endpoints().await.unwrap_or_default()).await;
    let up: Vec<&str> = eps
        .iter()
        .filter(|e| e.enabled)
        .filter_map(|e| match &e.status {
            Status::Up(v) => Some(v.as_str()),
            _ => None,
        })
        .collect();
    let scanned = last(
        &act,
        None,
        &[
            crate::scan::KIND_PATH,
            crate::scan::KIND_UPLOAD,
            crate::scan::KIND_WATCH,
        ],
    );
    let stored = match (up.is_empty(), scanned) {
        (true, _) => cell("off", "no clamd endpoint answers"),
        (false, Some(t)) if now - t <= WEEK => cell("ok", format!("scanned {}", ago(now, t))),
        (false, Some(t)) => cell("warn", format!("last scan {}", ago(now, t))),
        (false, None) => cell("warn", "no scans in 30 days"),
    };
    let live_watches = watches.iter().filter(|w| w.enabled).count();
    let arrive = if !st.cfg.watch_realtime {
        cell("off", "WATCH_REALTIME is off")
    } else if live_watches == 0 && st.cfg.realtime_paths.is_empty() {
        cell("off", "no watched folders")
    } else {
        cell(
            "ok",
            format!(
                "{} folder(s) watched",
                live_watches.max(st.cfg.realtime_paths.len())
            ),
        )
    };
    let mut armed = 0;
    let mut missing = 0;
    let mut central_paths: Vec<String> = st
        .cfg
        .canary_files
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    central_paths.extend(
        all_canaries
            .iter()
            .filter(|c| c.agent_id.is_none())
            .map(|c| c.path.clone()),
    );
    for p in &central_paths {
        match st.canaries.armed(p) {
            Some(true) => armed += 1,
            _ => missing += 1,
        }
    }
    let mut cells = vec![
        stored,
        arrive,
        canaries(armed, missing),
        control(&controls, None, now),
        up.iter()
            .map(|v| signatures(Some(v), now))
            .max_by_key(|c| match c.state {
                "ok" => 2,
                "warn" => 1,
                _ => 0,
            })
            .unwrap_or_else(|| cell("off", "no clamd endpoint answers")),
    ];
    cells.extend((5..THREATS.len()).map(soon));
    let mut hosts = vec![host(
        crate::canary::hostname(),
        "this server",
        true,
        "now".into(),
        up.first()
            .map(|v| crate::api::split_version(v).0)
            .unwrap_or_default(),
        st.cfg
            .scan_roots
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", "),
        cells,
    )];

    // Every agent, from what it last reported.
    for a in &agents {
        let online = crate::agent::is_online(a, now);
        let id = Some(a.id);
        let scanned = last(&act, id, &[crate::scan::KIND_PATH, crate::scan::KIND_WATCH]);
        let stored = match (a.enabled, online, scanned) {
            (false, _, _) => cell("off", "agent disabled"),
            (_, false, _) => cell("off", "agent offline"),
            (_, true, Some(t)) if now - t <= WEEK => cell("ok", format!("scanned {}", ago(now, t))),
            (_, true, Some(t)) => cell("warn", format!("last scan {}", ago(now, t))),
            (_, true, None) => cell("warn", "no scans in 30 days"),
        };
        let arrive = match last(&act, id, &[crate::scan::KIND_WATCH]) {
            Some(t) if now - t <= WEEK => cell("ok", format!("last file {}", ago(now, t))),
            Some(t) => cell("warn", format!("last file {}", ago(now, t))),
            None => cell("off", "no real-time results"),
        };
        let mine: Vec<_> = all_canaries.iter().filter(|c| c.agent_id == id).collect();
        let armed = mine.iter().filter(|c| c.armed == Some(true)).count();
        let mut cells = vec![
            stored,
            arrive,
            canaries(armed, mine.len() - armed),
            control(&controls, id, now),
            if online {
                signatures(a.clamd_version.as_deref(), now)
            } else {
                cell("off", "agent offline")
            },
        ];
        cells.extend((5..THREATS.len()).map(soon));
        hosts.push(host(
            a.name.clone(),
            "agent",
            online && a.enabled,
            a.last_seen_at
                .map_or_else(|| "never".into(), |t| ago(now, t)),
            a.version.clone().unwrap_or_default(),
            a.roots.join(", "),
            cells,
        ));
    }

    let threats = THREATS
        .iter()
        .enumerate()
        .map(|(i, (name, what))| Threat {
            name,
            what,
            cells: hosts.iter().map(|h| h.items[i].1.clone()).collect(),
        })
        .collect();
    render(
        axum::http::StatusCode::OK,
        &CoveragePage {
            nav: Nav::new("coverage", &s, &u),
            hosts,
            threats,
        },
    )
}
