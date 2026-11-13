//! Prometheus metrics with the Java names, so existing dashboards and alert
//! rules keep working. clamd is sampled in the background, never per scrape.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::app::AppState;
use crate::db::jobs;

pub const MAX_SLOTS: usize = 12;
const KINDS: [&str; 4] = ["upload", "path", "watch", "control"];
const VERDICTS: [&str; 3] = ["ok", "virus_found", "error"];
const BUCKETS: [f64; 14] = [
    0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0, 3600.0,
];
/// Signature labels are capped so a malware storm cannot blow up cardinality.
const MAX_SIGNATURES: usize = 500;
const SAMPLE_SECS: u64 = 30;
const STALE_SAMPLE_SECS: i64 = 120;
const STALE_SIGNATURE_SECS: i64 = 7 * 24 * 3600;

#[derive(Default, Clone)]
struct Hist {
    counts: [u64; BUCKETS.len()],
    count: u64,
    sum: f64,
}

#[derive(Default)]
struct Counters {
    scans: BTreeMap<(String, String), u64>,
    completed: BTreeMap<(String, String), u64>,
    detections: u64,
    failures: BTreeMap<&'static str, u64>,
    signatures: BTreeMap<String, u64>,
    durations: BTreeMap<String, Hist>,
}

/// One sampled clamd endpoint.
#[derive(Default, Clone)]
struct Slot {
    name: String,
    available: bool,
    last_success: i64,
    live: Option<f64>,
    idle: Option<f64>,
    busy: Option<f64>,
    max: Option<f64>,
    queue: Option<f64>,
    pools: Option<f64>,
    pools_used: Option<f64>,
    pools_total: Option<f64>,
    db_version: Option<f64>,
    db_time: Option<i64>,
    version: [Option<f64>; 3],
}

/// One endpoint's latest sample, formatted for display.
pub struct ClamdStatus {
    pub name: String,
    pub available: bool,
    pub sampled: String,
    pub threads: String,
    pub busy_pct: u8,
    pub queue: String,
    pub memory: String,
    pub version: String,
    pub database: String,
    pub database_age: String,
    pub stale: bool,
}

pub struct Metrics {
    counters: Mutex<Counters>,
    slots: Mutex<Vec<Slot>>,
}

impl Default for Metrics {
    fn default() -> Self {
        let mut c = Counters::default();
        // Zeroes before the first scan give rate() a baseline, as in Java.
        for k in KINDS {
            for v in VERDICTS {
                c.scans.insert((k.into(), v.into()), 0);
            }
            c.durations.insert(k.into(), Hist::default());
        }
        c.signatures.insert("unknown".into(), 0);
        Self {
            counters: Mutex::new(c),
            slots: Mutex::new(Vec::new()),
        }
    }
}

fn failure_reason(message: &str) -> &'static str {
    let m = message.to_ascii_lowercase();
    if m.contains("timeout") || m.contains("timed out") {
        "TIMEOUT"
    } else if m.contains("connect") || m.contains("refused") || m.contains("unreachable") {
        "CONNECTION"
    } else if m.contains("path") || m.contains("permission") || m.contains("denied") {
        "PATH_OR_PERMISSION"
    } else if m.contains("unsupported") {
        "UNSUPPORTED"
    } else {
        "OTHER"
    }
}

impl Metrics {
    /// Count a finished job. `seconds` is run time, excluding queue time.
    pub fn record(&self, job: &jobs::Job, o: &jobs::Outcome, seconds: Option<f64>) {
        let Ok(mut c) = self.counters.lock() else {
            return;
        };
        let kind = job.kind.to_ascii_lowercase();
        *c.scans
            .entry((kind.clone(), o.verdict.to_ascii_lowercase()))
            .or_default() += 1;
        *c.completed
            .entry((job.kind.clone(), o.verdict.to_owned()))
            .or_default() += 1;
        if o.verdict == jobs::VIRUS_FOUND {
            c.detections += 1;
            let mut sigs: Vec<&String> = o.detections.values().flatten().collect();
            sigs.sort();
            sigs.dedup();
            if sigs.is_empty() {
                *c.signatures.entry("unknown".into()).or_default() += 1;
            }
            for s in sigs {
                let key = if c.signatures.contains_key(s) || c.signatures.len() < MAX_SIGNATURES {
                    s.clone()
                } else {
                    "other".into()
                };
                *c.signatures.entry(key).or_default() += 1;
            }
        }
        if o.verdict == jobs::ERROR {
            let r = failure_reason(o.error_message.as_deref().unwrap_or(""));
            *c.failures.entry(r).or_default() += 1;
        }
        if let Some(s) = seconds.filter(|s| s.is_finite() && *s >= 0.0) {
            let h = c.durations.entry(kind).or_default();
            h.count += 1;
            h.sum += s;
            if let Some(i) = BUCKETS.iter().position(|b| s <= *b) {
                h.counts[i] += 1;
            }
        }
    }

    fn set_slots(&self, slots: Vec<Slot>) {
        if let Ok(mut g) = self.slots.lock() {
            *g = slots;
        }
    }

    fn slot_snapshot(&self) -> Vec<Slot> {
        self.slots.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// The latest clamd samples for the status page.
    pub fn clamd_status(&self) -> Vec<ClamdStatus> {
        let now = crate::db::now_ms() / 1000;
        let f = |v: Option<f64>| v.map_or_else(|| "?".to_owned(), |x| num(Some(x)));
        let mb = |v: Option<f64>| {
            v.map_or_else(|| "?".to_owned(), |b| format!("{:.1} MiB", b / 1_048_576.0))
        };
        self.slot_snapshot()
            .into_iter()
            .map(|s| ClamdStatus {
                name: s.name.clone(),
                available: s.available,
                sampled: if s.last_success == 0 {
                    "never".into()
                } else {
                    format!("{} s ago", now - s.last_success)
                },
                threads: format!(
                    "{} live, {} busy, {} idle, max {}",
                    f(s.live),
                    f(s.busy),
                    f(s.idle),
                    f(s.max)
                ),
                busy_pct: match (s.busy, s.max) {
                    (Some(b), Some(m)) if m > 0.0 => {
                        ((b / m) * 100.0).round().clamp(0.0, 100.0) as u8
                    }
                    _ => 0,
                },
                queue: f(s.queue),
                memory: format!("{} of {}", mb(s.pools_used), mb(s.pools_total)),
                version: match s.version {
                    [Some(a), Some(b), c] => {
                        format!("{}.{}.{}", a as i64, b as i64, c.map_or(0, |x| x as i64))
                    }
                    _ => "?".into(),
                },
                database: s.db_version.map_or_else(|| "?".into(), |v| num(Some(v))),
                database_age: s.db_time.map_or_else(
                    || "?".into(),
                    |t| {
                        let h = (now - t).max(0) / 3600;
                        if h < 48 {
                            format!("{h} h")
                        } else {
                            format!("{} days", h / 24)
                        }
                    },
                ),
                stale: s.db_time.is_some_and(|t| now - t > STALE_SIGNATURE_SECS),
            })
            .collect()
    }
}

fn esc(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn num(v: Option<f64>) -> String {
    match v {
        Some(x) if x.is_finite() => {
            if x.fract() == 0.0 && x.abs() < 1e15 {
                format!("{}", x as i64)
            } else {
                format!("{x}")
            }
        }
        _ => "NaN".into(),
    }
}

struct Out(String);

impl Out {
    fn head(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.0, "# HELP {name} {help}\n# TYPE {name} {kind}");
    }
    fn line(&mut self, name: &str, labels: &[(&str, &str)], v: &str) {
        self.0.push_str(name);
        if !labels.is_empty() {
            self.0.push('{');
            for (i, (k, val)) in labels.iter().enumerate() {
                if i > 0 {
                    self.0.push(',');
                }
                let _ = write!(self.0, "{k}=\"{}\"", esc(val));
            }
            self.0.push('}');
        }
        let _ = writeln!(self.0, " {v}");
    }
}

/// Render the exposition text.
pub async fn render(st: &AppState) -> String {
    let mut o = Out(String::with_capacity(8192));
    let now = crate::db::now_ms() / 1000;
    {
        let c = st
            .metrics
            .counters
            .lock()
            .map(|g| Counters {
                scans: g.scans.clone(),
                completed: g.completed.clone(),
                detections: g.detections,
                failures: g.failures.clone(),
                signatures: g.signatures.clone(),
                durations: g.durations.clone(),
            })
            .unwrap_or_default();
        o.head("clamav_scans_total", "counter", "Completed scan jobs");
        for ((t, v), n) in &c.scans {
            o.line(
                "clamav_scans_total",
                &[("type", t), ("verdict", v)],
                &n.to_string(),
            );
        }
        o.head(
            "clamav_scan_completed_total",
            "counter",
            "Completed scan jobs by type and verdict",
        );
        for ((t, v), n) in &c.completed {
            o.line(
                "clamav_scan_completed_total",
                &[("type", t), ("verdict", v)],
                &n.to_string(),
            );
        }
        o.head(
            "clamav_scan_detections_total",
            "counter",
            "Scan jobs that found malware",
        );
        o.line(
            "clamav_scan_detections_total",
            &[],
            &c.detections.to_string(),
        );
        o.head(
            "clamav_scan_failures_total",
            "counter",
            "Scan jobs that failed",
        );
        for (r, n) in &c.failures {
            o.line(
                "clamav_scan_failures_total",
                &[("reason", r)],
                &n.to_string(),
            );
        }
        o.head(
            "clamav_viruses_detected_total",
            "counter",
            "Signature detections from completed scans",
        );
        for (s, n) in &c.signatures {
            o.line(
                "clamav_viruses_detected_total",
                &[("signature", s)],
                &n.to_string(),
            );
        }
        o.head(
            "clamav_scan_duration_seconds",
            "histogram",
            "Scan execution duration, excluding queue time",
        );
        for (t, h) in &c.durations {
            let mut acc = 0;
            for (b, n) in BUCKETS.iter().zip(h.counts) {
                acc += n;
                o.line(
                    "clamav_scan_duration_seconds_bucket",
                    &[("type", t), ("le", &num(Some(*b)))],
                    &acc.to_string(),
                );
            }
            o.line(
                "clamav_scan_duration_seconds_bucket",
                &[("type", t), ("le", "+Inf")],
                &h.count.to_string(),
            );
            o.line(
                "clamav_scan_duration_seconds_sum",
                &[("type", t)],
                &format!("{}", h.sum),
            );
            o.line(
                "clamav_scan_duration_seconds_count",
                &[("type", t)],
                &h.count.to_string(),
            );
        }
    }
    // Unknown counts must not look like zero during a database outage.
    let (pending, running, db_up) = match st.db.count_active_jobs().await {
        Ok((q, r)) => (q, r, 1),
        Err(_) => (-1, -1, 0),
    };
    let cap = st.cfg.scan_concurrency.max(1);
    for (name, help, v) in [
        ("clamav_scan_jobs_pending", "Queued scan jobs", pending),
        ("clamav_scan_jobs_running", "Running scan jobs", running),
        (
            "clamav_scan_workers_busy",
            "Path scan workers in use",
            st.runner.busy(cap) as i64,
        ),
        (
            "clamav_scan_workers_capacity",
            "Path scan workers",
            cap as i64,
        ),
        (
            "clamav_scan_workers_queued",
            "Jobs waiting in memory for a worker",
            0,
        ),
        (
            "clamav_scan_database_available",
            "1 when the database answers",
            db_up,
        ),
    ] {
        o.head(name, "gauge", help);
        o.line(name, &[], &v.to_string());
    }
    let slots = st.metrics.slot_snapshot();
    type Get = fn(&Slot, i64) -> Option<f64>;
    let gauges: &[(&str, &str, Get)] = &[
        (
            "clamav_clamd_endpoint_configured",
            "1 for a sampled endpoint slot",
            |_, _| Some(1.0),
        ),
        (
            "clamav_clamd_endpoint_available",
            "1 when the last clamd sample succeeded",
            |s, _| Some(f64::from(u8::from(s.available))),
        ),
        (
            "clamav_clamd_endpoint_stale",
            "1 when the last good sample is older than 2 minutes",
            |s, now| {
                Some(f64::from(u8::from(
                    !s.available || s.last_success == 0 || now - s.last_success > STALE_SAMPLE_SECS,
                )))
            },
        ),
        (
            "clamav_clamd_sample_age",
            "Seconds since the last good sample",
            |s, now| (s.last_success > 0).then(|| (now - s.last_success) as f64),
        ),
        ("clamav_threads_live", "clamd live threads", |s, _| s.live),
        ("clamav_threads_idle", "clamd idle threads", |s, _| s.idle),
        ("clamav_threads_busy", "clamd busy threads", |s, _| s.busy),
        ("clamav_threads_max", "clamd max threads", |s, _| s.max),
        ("clamav_queue_items", "clamd queued items", |s, _| s.queue),
        ("clamav_clamd_pools", "clamd memory pools", |s, _| s.pools),
        (
            "clamav_pools_used_bytes",
            "clamd pool memory used",
            |s, _| s.pools_used,
        ),
        (
            "clamav_pools_total_bytes",
            "clamd pool memory total",
            |s, _| s.pools_total,
        ),
        (
            "clamav_database_version",
            "Signature database version",
            |s, _| s.db_version,
        ),
        (
            "clamav_database_timestamp",
            "Signature database build time, Unix seconds",
            |s, _| s.db_time.map(|t| t as f64),
        ),
        (
            "clamav_database_age",
            "Signature database age in seconds",
            |s, now| s.db_time.map(|t| (now - t).max(0) as f64),
        ),
        (
            "clamav_clamd_version_major",
            "clamd major version",
            |s, _| s.version[0],
        ),
        (
            "clamav_clamd_version_minor",
            "clamd minor version",
            |s, _| s.version[1],
        ),
        (
            "clamav_clamd_version_patch",
            "clamd patch version",
            |s, _| s.version[2],
        ),
    ];
    for (name, help, get) in gauges {
        o.head(name, "gauge", help);
        for (i, s) in slots.iter().enumerate() {
            o.line(name, &[("slot", &i.to_string())], &num(get(s, now)));
        }
    }
    // Compatibility aliases from the Java build.
    for (alias, name) in [
        ("clamav_clamd_threads_live", "live"),
        ("clamav_clamd_threads_busy", "busy"),
        ("clamav_clamd_threads_max", "max"),
        ("clamav_clamd_queue_items", "queue"),
        ("clamav_clamd_database_version", "db"),
    ] {
        o.head(alias, "gauge", "Alias kept for older dashboards");
        for (i, s) in slots.iter().enumerate() {
            let v = match name {
                "live" => s.live,
                "busy" => s.busy,
                "max" => s.max,
                "queue" => s.queue,
                _ => s.db_version,
            };
            o.line(alias, &[("slot", &i.to_string())], &num(v));
        }
    }
    o.head(
        "clamav_clamd_endpoint_info",
        "gauge",
        "Endpoint name for each slot",
    );
    for (i, s) in slots.iter().enumerate() {
        o.line(
            "clamav_clamd_endpoint_info",
            &[("slot", &i.to_string()), ("endpoint", &s.name)],
            "1",
        );
    }
    o.0
}

/// clamd prints memory as e.g. `565.123M`; K, M, G and T are powers of 1024.
fn memory_bytes(v: &str) -> Option<f64> {
    let v = v.trim();
    let v = v
        .strip_suffix("iB")
        .or_else(|| v.strip_suffix('B'))
        .unwrap_or(v);
    let (n, pow) = match v.chars().last()? {
        'K' | 'k' => (&v[..v.len() - 1], 1),
        'M' | 'm' => (&v[..v.len() - 1], 2),
        'G' | 'g' => (&v[..v.len() - 1], 3),
        'T' | 't' => (&v[..v.len() - 1], 4),
        _ => (v, 0),
    };
    let x: f64 = n.trim().parse().ok()?;
    let b = (x * 1024f64.powi(pow)).round();
    (b.is_finite() && b >= 0.0).then_some(b)
}

fn version_parts(engine: &str) -> [Option<f64>; 3] {
    let digits: String = engine
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut it = digits.split('.').map(|p| p.parse::<f64>().ok());
    [
        it.next().flatten(),
        it.next().flatten(),
        it.next().flatten(),
    ]
}

async fn sample(st: &AppState, ep: &crate::db::endpoints::Endpoint, prev: Option<&Slot>) -> Slot {
    let mut s = Slot {
        name: ep.name.clone(),
        last_success: prev.map_or(0, |p| p.last_success),
        ..Slot::default()
    };
    let Ok(addr) = ep.parsed() else {
        return s;
    };
    let c = st.clamd(addr);
    let got = tokio::time::timeout(Duration::from_secs(5), async {
        let stats = c.stats().await?;
        let version = c.version().await?;
        Ok::<_, clamd::Error>((stats, version))
    })
    .await;
    let Ok(Ok((stats, version))) = got else {
        return s;
    };
    let p = crate::api::parse_stats(&stats);
    let f = |v: &serde_json::Value| v.as_f64();
    s.live = f(&p["threads"]["live"]);
    s.idle = f(&p["threads"]["idle"]);
    s.max = f(&p["threads"]["max"]);
    s.busy = s.live.zip(s.idle).map(|(l, i)| (l - i).max(0.0));
    s.queue = f(&p["queue"]["items"]);
    s.pools = f(&p["pools"]);
    s.pools_used = p["memory"]["pools_used"].as_str().and_then(memory_bytes);
    s.pools_total = p["memory"]["pools_total"].as_str().and_then(memory_bytes);
    let (engine, db, time) = crate::api::split_version(&version);
    s.version = version_parts(&engine);
    s.db_version = db.and_then(|d| d.parse().ok());
    s.db_time = time
        .as_deref()
        .and_then(crate::timefmt::parse_clamd_date)
        .map(|t| t / 1000);
    s.available = true;
    s.last_success = crate::db::now_ms() / 1000;
    s
}

/// Sample enabled endpoints every 30 s. State changes are logged, since logs are the alert path.
pub fn spawn(st: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(SAMPLE_SECS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut prev: BTreeMap<String, Slot> = BTreeMap::new();
        loop {
            tick.tick().await;
            let Ok(mut eps) = st.db.list_endpoints().await else {
                continue;
            };
            eps.retain(|e| e.enabled);
            eps.sort_by_key(|e| e.id);
            eps.truncate(MAX_SLOTS);
            let mut slots = Vec::with_capacity(eps.len());
            let mut next = BTreeMap::new();
            for ep in &eps {
                let old = prev.get(&ep.name);
                let s = sample(&st, ep, old).await;
                transitions(old, &s);
                next.insert(ep.name.clone(), s.clone());
                slots.push(s);
            }
            st.metrics.set_slots(slots);
            prev = next;
        }
    });
}

fn transitions(old: Option<&Slot>, s: &Slot) {
    let was_up = old.is_none_or(|o| o.available);
    if was_up && !s.available {
        tracing::warn!(event = "clamd.unreachable", endpoint = %s.name, "clamd stopped answering");
    } else if !was_up && s.available {
        tracing::info!(event = "clamd.recovered", endpoint = %s.name, "clamd is answering again");
    }
    let now = crate::db::now_ms() / 1000;
    let stale = |x: &Slot| x.db_time.is_some_and(|t| now - t > STALE_SIGNATURE_SECS);
    if stale(s) && !old.is_some_and(stale) {
        let hours = s.db_time.map_or(0, |t| (now - t) / 3600);
        tracing::warn!(event = "clamd.signatures_stale", endpoint = %s.name, age_hours = hours, "clamd signatures are stale");
    }
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/metrics", get(scrape))
        .route("/actuator/prometheus", get(scrape))
}

/// Bearer METRICS_TOKEN; without one configured the endpoint does not exist.
async fn scrape(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(want) = st.cfg.metrics_token() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let got = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    let ok: bool = Sha256::digest(got.as_bytes())
        .ct_eq(&Sha256::digest(want.as_bytes()))
        .into();
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "unauthorized",
        )
            .into_response();
    }
    (
        [
            (
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        render(&st).await,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_and_version_parsing() {
        assert_eq!(memory_bytes("1.000M"), Some(1_048_576.0));
        assert_eq!(memory_bytes("2K"), Some(2048.0));
        assert_eq!(memory_bytes("12"), Some(12.0));
        assert_eq!(memory_bytes("N/A"), None);
        assert_eq!(
            version_parts("ClamAV 1.4.2"),
            [Some(1.0), Some(4.0), Some(2.0)]
        );
        assert_eq!(version_parts("ClamAV 1.5"), [Some(1.0), Some(5.0), None]);
    }

    #[test]
    fn reasons_and_escaping() {
        assert_eq!(failure_reason("clamd connection refused"), "CONNECTION");
        assert_eq!(failure_reason("Timed out"), "TIMEOUT");
        assert_eq!(esc("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
        assert_eq!(num(None), "NaN");
        assert_eq!(num(Some(3.0)), "3");
        assert_eq!(num(Some(0.5)), "0.5");
    }
}
