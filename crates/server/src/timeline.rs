//! One timeline across sensors: ClamAV detections, canary hits, AIDE and
//! rkhunter findings and Falco alerts. Events on the same host from two or
//! more different sensors within an hour of each other form an incident,
//! which is logged and notified once.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use crate::app::AppState;
use crate::db::audit::AuditEntry;
use crate::webhook::Event;

pub const WINDOW_MS: i64 = 3_600_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub at: i64,
    pub host: String,
    /// ClamAV, Canary, Integrity or Falco.
    pub sensor: &'static str,
    pub title: String,
    pub detail: String,
    pub href: String,
}

#[derive(Debug, Clone)]
pub struct Incident {
    pub host: String,
    pub first: i64,
    pub last: i64,
    pub sensors: Vec<&'static str>,
    pub items: Vec<Item>,
}

impl Incident {
    /// Stable id: host and first event time.
    pub fn key(&self) -> String {
        format!("{}|{}", self.host, self.first)
    }

    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = self
            .items
            .iter()
            .map(|i| format!("{}: {}", i.sensor, i.title))
            .collect();
        parts.dedup();
        let n = parts.len();
        let mut s = parts.into_iter().take(5).collect::<Vec<_>>().join("; ");
        if n > 5 {
            s.push_str(&format!("; and {} more", n - 5));
        }
        s
    }
}

/// Everything every sensor saw since `since`, newest first.
pub async fn collect(st: &AppState, since: i64) -> Vec<Item> {
    let agents = st.db.list_agents().await.unwrap_or_default();
    let server = crate::canary::hostname();
    let host = |id: Option<i64>| {
        id.map_or_else(
            || server.clone(),
            |id| {
                agents
                    .iter()
                    .find(|a| a.id == id)
                    .map_or_else(|| format!("agent {id}"), |a| a.name.clone())
            },
        )
    };
    let mut out = Vec::new();
    let f = crate::db::stats::DetectionFilter {
        since: Some(since),
        ..Default::default()
    };
    for d in st.db.list_detections(&f, 0, 2000).await.unwrap_or_default() {
        out.push(Item {
            at: d.found_at,
            host: host(d.agent_id),
            sensor: "ClamAV",
            title: d.signature,
            detail: d
                .path
                .split(crate::watch::RAW_MARK)
                .next()
                .unwrap_or(&d.path)
                .to_owned(),
            href: format!("/jobs/{}", d.job_id),
        });
    }
    for (at, details) in st
        .db
        .audit_by_action("CANARY_TRIPPED", since)
        .await
        .unwrap_or_default()
    {
        let (h, rest) = details.split_once(": ").unwrap_or(("?", details.as_str()));
        out.push(Item {
            at,
            host: h.to_owned(),
            sensor: "Canary",
            title: "canary touched".into(),
            detail: rest.to_owned(),
            href: "/admin/canaries".into(),
        });
    }
    for r in st.db.recent_integrity(500).await.unwrap_or_default() {
        if r.report.ok || r.report.ran_at < since {
            continue;
        }
        out.push(Item {
            at: r.report.ran_at,
            host: host(r.agent_id),
            sensor: "Integrity",
            title: format!("{} found changes", r.report.tool),
            detail: r.report.summary,
            href: "/integrity".into(),
        });
    }
    for a in st.db.falco_since(since, 2000).await.unwrap_or_default() {
        out.push(Item {
            at: a.alert.at,
            host: host(a.agent_id),
            sensor: "Falco",
            title: a.alert.rule,
            detail: a.alert.output,
            href: "/integrity".into(),
        });
    }
    out.sort_by_key(|i| std::cmp::Reverse(i.at));
    out
}

/// Chains of events on one host, each within WINDOW_MS of the previous,
/// that involve at least two different sensors. Newest first.
pub fn incidents(items: &[Item]) -> Vec<Incident> {
    let mut by_host: BTreeMap<&str, Vec<&Item>> = BTreeMap::new();
    for i in items {
        by_host.entry(i.host.as_str()).or_default().push(i);
    }
    let mut out = Vec::new();
    for (host, mut list) in by_host {
        list.sort_by_key(|i| i.at);
        let mut chain: Vec<&Item> = Vec::new();
        let mut flush = |chain: &mut Vec<&Item>| {
            let mut sensors: Vec<&'static str> = chain.iter().map(|i| i.sensor).collect();
            sensors.sort_unstable();
            sensors.dedup();
            if sensors.len() >= 2 {
                out.push(Incident {
                    host: host.to_owned(),
                    first: chain[0].at,
                    last: chain[chain.len() - 1].at,
                    sensors,
                    items: chain.iter().map(|i| (*i).clone()).collect(),
                });
            }
            chain.clear();
        };
        for i in list {
            if chain.last().is_some_and(|p| i.at - p.at > WINDOW_MS) {
                flush(&mut chain);
            }
            chain.push(i);
        }
        flush(&mut chain);
    }
    out.sort_by_key(|i| std::cmp::Reverse(i.last));
    out
}

/// Every 5 minutes: find new incidents in the last few hours, log and notify once.
pub fn spawn(st: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        loop {
            tick.tick().await;
            check(&st).await;
        }
    });
}

pub async fn check(st: &AppState) {
    let now = crate::db::now_ms();
    let items = collect(st, now - 4 * WINDOW_MS).await;
    let seen: Vec<String> = st
        .db
        .audit_by_action("INCIDENT", now - 30 * 86_400_000)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(_, d)| d.split(' ').next().unwrap_or_default().to_owned())
        .collect();
    for inc in incidents(&items) {
        let key = inc.key();
        if seen.contains(&key) {
            continue;
        }
        let summary = inc.summary();
        tracing::error!(event = "incident.correlated", host = %inc.host, sensors = %inc.sensors.join("+"), events = inc.items.len(), summary = %summary, "events from several sensors on one host within an hour");
        st.db
            .audit(AuditEntry {
                action: "INCIDENT",
                outcome: "ALERT",
                details: Some(format!("{key} {}", inc.sensors.join("+"))),
                transport: Some("TIMELINE"),
                ..Default::default()
            })
            .await;
        st.notifier.notify(Event {
            event: "incident.correlated",
            job_id: String::new(),
            kind: inc.sensors.join("+").to_ascii_uppercase(),
            target: summary,
            endpoint: inc.host.clone(),
            submitted_by: None,
            verdict: "ALERT".into(),
            found_viruses: Vec::new(),
            detections: Default::default(),
            files_scanned: 0,
            file_errors: 0,
            error_code: None,
            error: None,
            finished_at: crate::timefmt::rfc3339(inc.last),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(at: i64, host: &str, sensor: &'static str) -> Item {
        Item {
            at,
            host: host.into(),
            sensor,
            title: format!("{sensor} event"),
            detail: String::new(),
            href: String::new(),
        }
    }

    #[test]
    fn two_sensors_within_an_hour_on_one_host() {
        let m = 60_000;
        let items = vec![
            item(0, "nas", "ClamAV"),
            item(50 * m, "nas", "Falco"), // joins: different sensor, 50 min later
            item(100 * m, "nas", "Falco"), // chain continues (50 min after previous)
            item(400 * m, "nas", "ClamAV"), // alone
            item(10 * m, "edge", "Falco"), // other host, same sensor twice
            item(20 * m, "edge", "Falco"),
            item(30 * m, "vps", "Canary"),
            item(95 * m, "vps", "Integrity"), // 65 min later: too far
        ];
        let inc = incidents(&items);
        assert_eq!(inc.len(), 1);
        assert_eq!(inc[0].host, "nas");
        assert_eq!(inc[0].sensors, vec!["ClamAV", "Falco"]);
        assert_eq!(inc[0].items.len(), 3);
        assert_eq!(inc[0].key(), "nas|0");
    }
}
