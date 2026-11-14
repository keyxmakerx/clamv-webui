//! CrowdSec console: overview with an attack map, alerts and decisions, and
//! bans added or removed by admins.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;
use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use serde::Deserialize;

use super::admin::{admin_post, audit, fmt_ts};
use super::session::Auth;
use super::{Nav, RequestInfo, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::crowdsec::{Alert, Decision};
use crate::db::sessions::Session;
use crate::db::users::User;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/crowdsec", get(overview))
        .route("/crowdsec/alerts", get(alerts))
        .route("/crowdsec/decisions", get(decisions).post(add))
        .route("/crowdsec/decisions/{id}/delete", post(delete))
        .route("/crowdsec/decisions/remove", post(remove_value))
        .route("/crowdsec/refresh", post(refresh))
}

const PAGE: usize = 100;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// `3h 12m`, `6d 2h`, `45s`.
pub fn span(ms: i64) -> String {
    let s = ms.max(0) / 1000;
    let (d, h, m) = (s / 86_400, s % 86_400 / 3600, s % 3600 / 60);
    match (d, h, m) {
        (0, 0, 0) => format!("{s}s"),
        (0, 0, m) => format!("{m}m"),
        (0, h, m) => format!("{h}h {m}m"),
        (d, h, _) => format!("{d}d {h}h"),
    }
}

// ---- search ----

#[derive(Debug, Clone, PartialEq, Eq)]
struct Term {
    neg: bool,
    field: Option<String>,
    exact: bool,
    val: String,
}

/// `ssh  ip:1.2.3  country=NL  -machine:edge  "http probing"`
fn parse_search(q: &str) -> Vec<Term> {
    let mut out = Vec::new();
    let mut chars = q.chars().peekable();
    while chars.peek().is_some() {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let mut tok = String::new();
        let mut quoted = false;
        while let Some(&c) = chars.peek() {
            if c == '"' {
                quoted = !quoted;
                chars.next();
                continue;
            }
            if c.is_whitespace() && !quoted {
                break;
            }
            tok.push(c);
            chars.next();
        }
        if tok.is_empty() {
            continue;
        }
        let (neg, rest) = match tok.strip_prefix('-') {
            Some(r) if !r.is_empty() => (true, r.to_owned()),
            _ => (false, tok.clone()),
        };
        let split = rest.find([':', '=']).filter(|&i| {
            i > 0
                && matches!(
                    &rest[..i],
                    "ip" | "scenario"
                        | "country"
                        | "as"
                        | "machine"
                        | "origin"
                        | "type"
                        | "sim"
                        | "scope"
                )
        });
        let t = match split {
            Some(i) => Term {
                neg,
                field: Some(rest[..i].to_owned()),
                exact: rest[i..].starts_with('='),
                val: rest[i + 1..].to_lowercase(),
            },
            None => Term {
                neg,
                field: None,
                exact: false,
                val: rest.to_lowercase(),
            },
        };
        if out.len() < 20 {
            out.push(t);
        }
    }
    out
}

fn hit(hay: &str, t: &Term) -> bool {
    let hay = hay.to_lowercase();
    if t.exact {
        hay == t.val
    } else {
        hay.contains(&t.val)
    }
}

fn alert_matches(a: &Alert, terms: &[Term]) -> bool {
    terms.iter().all(|t| {
        let m = match t.field.as_deref() {
            None => [
                a.scenario.as_str(),
                a.value.as_str(),
                a.message.as_str(),
                a.as_name.as_str(),
                a.machine.as_str(),
                a.country.as_str(),
            ]
            .iter()
            .any(|h| hit(h, t)),
            Some("ip") => hit(&a.value, t),
            Some("scenario") => hit(&a.scenario, t),
            Some("country") => hit(&a.country, t),
            Some("as") => hit(&a.as_name, t) || hit(&a.as_number, t),
            Some("machine") => hit(&a.machine, t),
            Some("scope") => hit(&a.scope, t),
            Some("sim") => (t.val == "yes" || t.val == "true") == a.simulated,
            Some("origin") => a.decisions.iter().any(|d| hit(&d.origin, t)),
            Some("type") => a.decisions.iter().any(|d| hit(&d.kind, t)),
            Some(_) => true,
        };
        m != t.neg
    })
}

fn decision_matches(d: &Decision, a: Option<&Alert>, terms: &[Term]) -> bool {
    terms.iter().all(|t| {
        let m = match t.field.as_deref() {
            None => [d.value.as_str(), d.scenario.as_str(), d.origin.as_str()]
                .iter()
                .any(|h| hit(h, t)),
            Some("ip") => hit(&d.value, t),
            Some("scenario") => hit(&d.scenario, t),
            Some("origin") => hit(&d.origin, t),
            Some("type") => hit(&d.kind, t),
            Some("scope") => hit(&d.scope, t),
            Some("sim") => (t.val == "yes" || t.val == "true") == d.simulated,
            Some("country") => a.is_some_and(|a| hit(&a.country, t)),
            Some("as") => a.is_some_and(|a| hit(&a.as_name, t) || hit(&a.as_number, t)),
            Some("machine") => a.is_some_and(|a| hit(&a.machine, t)),
            Some(_) => true,
        };
        m != t.neg
    })
}

fn range_ms(range: &str, lookback: i64) -> (i64, &'static str) {
    let (ms, r) = match range {
        "1h" => (3_600_000, "1h"),
        "24h" => (86_400_000, "24h"),
        "30d" => (30 * 86_400_000, "30d"),
        _ => (7 * 86_400_000, "7d"),
    };
    (ms.min(lookback), r)
}

#[derive(Deserialize, Default)]
pub struct Q {
    q: Option<String>,
    range: Option<String>,
    page: Option<usize>,
    expired: Option<String>,
    all: Option<String>,
}

// ---- charts and map ----

/// Alerts per hour (24 h or less) or per day, as bars that link to the alerts page.
fn bars(alerts: &[Alert], since: i64, now: i64, offset_ms: i64, range: &str) -> String {
    const W: f64 = 520.0;
    const H: f64 = 240.0;
    const PAD_L: f64 = 36.0;
    const PAD_B: f64 = 22.0;
    let hourly = now - since <= 86_400_000;
    let bucket = if hourly { 3_600_000 } else { 86_400_000 };
    let first = (since + offset_ms) - (since + offset_ms).rem_euclid(bucket) - offset_ms;
    let count = usize::try_from((now - first) / bucket + 1)
        .unwrap_or(1)
        .clamp(1, 800);
    let mut n = vec![0i64; count];
    let mut sim = vec![0i64; count];
    for a in alerts {
        if let Ok(i) = usize::try_from((a.created_at - first) / bucket)
            && i < count
        {
            n[i] += 1;
            if a.simulated {
                sim[i] += 1;
            }
        }
    }
    let max = n.iter().copied().max().unwrap_or(0).max(1);
    let step = [
        1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 5000, 10_000,
    ]
    .into_iter()
    .find(|s| max <= s * 4)
    .unwrap_or(max / 4 + 1);
    let top = step * ((max + step - 1) / step).max(1);
    let plot_h = H - PAD_B - 8.0;
    #[allow(clippy::cast_precision_loss)]
    let y = |v: i64| 8.0 + plot_h - (v as f64 / top as f64) * plot_h;
    #[allow(clippy::cast_precision_loss)]
    let bw = (W - PAD_L - 24.0) / count as f64;
    let mut s = String::new();
    let _ = write!(
        s,
        r#"<svg class="chart" viewBox="0 0 {W} {H}" role="img" aria-label="CrowdSec alerts over time">"#
    );
    let mut v = 0;
    while v <= top {
        let yy = y(v);
        let _ = write!(
            s,
            r#"<line class="chart-grid" x1="{PAD_L}" x2="{W}" y1="{yy:.1}" y2="{yy:.1}"/><text class="chart-axis" x="{:.1}" y="{:.1}" text-anchor="end">{v}</text>"#,
            PAD_L - 6.0,
            yy + 4.0
        );
        v += step;
    }
    let every = (count / 8).max(1);
    for i in 0..count {
        let start = first + i64::try_from(i).unwrap_or(0) * bucket;
        #[allow(clippy::cast_precision_loss)]
        let x = PAD_L + i as f64 * bw + bw * 0.12;
        let w = (bw * 0.76).max(1.0);
        let label = super::charts::label(start, offset_ms, hourly);
        let tip = format!("{label}: {} alert(s), {} simulated", n[i], sim[i]);
        let _ = write!(
            s,
            r#"<a href="/crowdsec/alerts?range={range}" aria-label="{t}"><title>{t}</title><rect class="chart-hit" x="{x:.1}" y="8" width="{w:.1}" height="{plot_h:.1}"/>"#,
            t = esc(&tip)
        );
        let real = n[i] - sim[i];
        if real > 0 {
            let y1 = y(real);
            let _ = write!(
                s,
                r#"<rect class="bar-hit" x="{x:.1}" y="{y1:.1}" width="{w:.1}" height="{:.1}" rx="2"/>"#,
                y(0) - y1
            );
        }
        if sim[i] > 0 {
            let y1 = y(n[i]);
            let _ = write!(
                s,
                r#"<rect class="bar-ok" x="{x:.1}" y="{y1:.1}" width="{w:.1}" height="{:.1}" rx="2"/>"#,
                y(real) - y1
            );
        }
        s.push_str("</a>");
        if i % every == 0 {
            let _ = write!(
                s,
                r#"<text class="chart-axis" x="{:.1}" y="{:.1}" text-anchor="middle">{}</text>"#,
                x + w / 2.0,
                H - 6.0,
                esc(&label)
            );
        }
    }
    s.push_str("</svg>");
    s
}

/// Equirectangular world (lat 90 to -60) with one dot per place, sized by alerts.
fn map(alerts: &[Alert], banned: &std::collections::HashSet<String>) -> String {
    // (lat, lon) rounded to a degree → (alerts, banned, country, a source)
    let mut spots: BTreeMap<(i64, i64), (usize, bool, String)> = BTreeMap::new();
    for a in alerts {
        let (Some(lat), Some(lon)) = (a.lat, a.lon) else {
            continue;
        };
        #[allow(clippy::cast_possible_truncation)]
        let key = (lat.round() as i64, lon.round() as i64);
        let e = spots.entry(key).or_insert((0, false, a.country.clone()));
        e.0 += 1;
        e.1 |= banned.contains(&a.value);
    }
    let mut s = String::from(
        r#"<svg class="attack-map" viewBox="0 0 360 150" role="img" aria-label="Where attacks came from"><image class="map-land" href="/images/world.svg" x="0" y="0" width="360" height="150"/>"#,
    );
    let mut list: Vec<_> = spots.into_iter().collect();
    list.sort_by_key(|(_, (n, _, _))| *n);
    for ((lat, lon), (n, ban, cn)) in list {
        #[allow(clippy::cast_precision_loss)]
        let (x, y) = ((lon + 180) as f64, (90 - lat) as f64);
        if !(0.0..=150.0).contains(&y) {
            continue;
        }
        #[allow(clippy::cast_precision_loss)]
        let r = (1.1 + (n as f64).sqrt() * 0.7).min(7.0);
        let tip = format!(
            "{}: {n} alert(s){}",
            if cn.is_empty() { "unknown" } else { &cn },
            if ban { ", banned now" } else { "" }
        );
        let href = if cn.is_empty() {
            "/crowdsec/alerts".to_owned()
        } else {
            format!("/crowdsec/alerts?q=country%3D{}", enc(&cn))
        };
        let _ = write!(
            s,
            r#"<a href="{href}" aria-label="{t}"><title>{t}</title><circle class="map-dot{}" cx="{x:.1}" cy="{y:.1}" r="{r:.2}"/></a>"#,
            if ban { " map-dot-ban" } else { "" },
            t = esc(&tip)
        );
    }
    s.push_str("</svg>");
    s
}

pub struct Top {
    label: String,
    count: usize,
    max: usize,
    href: String,
}

fn top(items: impl Iterator<Item = String>, field: &str, range: &str, n: usize) -> Vec<Top> {
    let mut m: HashMap<String, usize> = HashMap::new();
    for i in items.filter(|s| !s.is_empty()) {
        *m.entry(i).or_default() += 1;
    }
    let mut v: Vec<(String, usize)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(n);
    let max = v.first().map_or(1, |x| x.1);
    v.into_iter()
        .map(|(label, count)| Top {
            href: format!(
                "/crowdsec/alerts?range={range}&q={}",
                enc(&format!("{field}=\"{label}\""))
            ),
            label,
            count,
            max,
        })
        .collect()
}

// ---- pages ----

pub struct Kpi {
    label: &'static str,
    value: String,
    tone: &'static str,
    href: String,
}

pub struct AlertRow {
    id: i64,
    at: String,
    source: String,
    scope: String,
    country: String,
    as_name: String,
    scenario: String,
    machine: String,
    simulated: bool,
    events: i64,
    message: String,
    meta: Vec<(String, String)>,
    decisions: Vec<DecisionRow>,
}

pub struct DecisionRow {
    id: i64,
    value: String,
    scope: String,
    kind: String,
    origin: String,
    scenario: String,
    left: String,
    active: bool,
    simulated: bool,
    country: String,
    machine: String,
    dupes: usize,
}

fn decision_row(d: &Decision, a: Option<&Alert>, now: i64) -> DecisionRow {
    DecisionRow {
        id: d.id,
        value: d.value.clone(),
        scope: d.scope.clone(),
        kind: d.kind.clone(),
        origin: d.origin.clone(),
        scenario: d.scenario.clone(),
        left: if d.until > now {
            span(d.until - now)
        } else {
            format!("ended {} ago", span(now - d.until))
        },
        active: d.until > now,
        simulated: d.simulated,
        country: a.map(|a| a.country.clone()).unwrap_or_default(),
        machine: a.map(|a| a.machine.clone()).unwrap_or_default(),
        dupes: 0,
    }
}

fn alert_row(a: &Alert, now: i64) -> AlertRow {
    AlertRow {
        id: a.id,
        at: fmt_ts(a.created_at),
        source: a.value.clone(),
        scope: a.scope.clone(),
        country: a.country.clone(),
        as_name: a.as_name.clone(),
        scenario: a.scenario.clone(),
        machine: a.machine.clone(),
        simulated: a.simulated,
        events: a.events,
        message: a.message.clone(),
        meta: a.meta.clone(),
        decisions: a
            .decisions
            .iter()
            .map(|d| decision_row(d, Some(a), now))
            .collect(),
    }
}

#[derive(Template)]
#[template(path = "crowdsec.html")]
struct OverviewPage {
    nav: Nav,
    status: crate::crowdsec::Status,
    last_ok: String,
    range: &'static str,
    kpis: Vec<Kpi>,
    chart: String,
    map: String,
    countries: Vec<Top>,
    scenarios: Vec<Top>,
    asns: Vec<Top>,
    machines: Vec<Top>,
    sources: Vec<Top>,
    recent: Vec<AlertRow>,
}

impl OverviewPage {
    fn tops(&self) -> [(&'static str, &[Top]); 5] {
        [
            ("Countries", &self.countries),
            ("Scenarios", &self.scenarios),
            ("Autonomous systems", &self.asns),
            ("Targets (machines)", &self.machines),
            ("Top sources", &self.sources),
        ]
    }
}

fn last_ok(st: &crate::crowdsec::Status) -> String {
    st.last_ok
        .map(|t| span(crate::db::now_ms() - t))
        .unwrap_or_default()
}

async fn overview(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    headers: HeaderMap,
    Query(q): Query<Q>,
) -> Response {
    let (s, u) = match auth.require(Role::Operator) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let c = &st.crowdsec;
    let now = crate::db::now_ms();
    let (len, range) = range_ms(q.range.as_deref().unwrap_or("7d"), c.lookback_ms());
    let since = now - len;
    let list = c.alerts(since, |_| true);
    let active = c.active();
    let banned: std::collections::HashSet<String> =
        active.iter().map(|d| d.value.clone()).collect();
    let sources: std::collections::HashSet<&str> = list.iter().map(|a| a.value.as_str()).collect();
    let countries: std::collections::HashSet<&str> = list
        .iter()
        .map(|a| a.country.as_str())
        .filter(|c| !c.is_empty())
        .collect();
    let sim = list.iter().filter(|a| a.simulated).count();
    let kpis = vec![
        Kpi {
            label: "Alerts",
            value: list.len().to_string(),
            tone: if list.is_empty() { "ok" } else { "warn" },
            href: format!("/crowdsec/alerts?range={range}"),
        },
        Kpi {
            label: "Active decisions",
            value: active.len().to_string(),
            tone: "",
            href: "/crowdsec/decisions".into(),
        },
        Kpi {
            label: "Attacking sources",
            value: sources.len().to_string(),
            tone: "",
            href: String::new(),
        },
        Kpi {
            label: "Countries",
            value: countries.len().to_string(),
            tone: "",
            href: String::new(),
        },
        Kpi {
            label: "Simulated",
            value: sim.to_string(),
            tone: "",
            href: format!("/crowdsec/alerts?range={range}&q=sim%3Ayes"),
        },
    ];
    let status = c.status();
    render(
        StatusCode::OK,
        &OverviewPage {
            nav: Nav::new("crowdsec", &s, &u),
            last_ok: last_ok(&status),
            status,
            range,
            chart: bars(&list, since, now, super::tz_offset_ms(&headers), range),
            map: map(&list, &banned),
            countries: top(list.iter().map(|a| a.country.clone()), "country", range, 8),
            scenarios: top(
                list.iter().map(|a| a.scenario.clone()),
                "scenario",
                range,
                8,
            ),
            asns: top(list.iter().map(|a| a.as_name.clone()), "as", range, 8),
            machines: top(list.iter().map(|a| a.machine.clone()), "machine", range, 8),
            sources: top(list.iter().map(|a| a.value.clone()), "ip", range, 8),
            recent: list.iter().take(8).map(|a| alert_row(a, now)).collect(),
            kpis,
        },
    )
}

pub struct Facet {
    label: String,
    count: usize,
    href: String,
}

#[derive(Template)]
#[template(path = "crowdsec_alerts.html")]
struct AlertsPage {
    nav: Nav,
    status: crate::crowdsec::Status,
    q: String,
    range: &'static str,
    total: usize,
    rows: Vec<AlertRow>,
    page: usize,
    pages: usize,
    scenario_facets: Vec<Facet>,
    country_facets: Vec<Facet>,
    machine_facets: Vec<Facet>,
    writable: bool,
}

impl AlertsPage {
    fn facet_groups(&self) -> [(&'static str, &[Facet]); 3] {
        [
            ("Scenario", &self.scenario_facets),
            ("Country", &self.country_facets),
            ("Target", &self.machine_facets),
        ]
    }

    fn link(&self, page: usize) -> String {
        format!(
            "/crowdsec/alerts?range={}&q={}&page={page}",
            self.range,
            enc(&self.q)
        )
    }
}

fn facets(
    list: &[Alert],
    f: impl Fn(&Alert) -> &str,
    field: &str,
    q: &str,
    range: &str,
) -> Vec<Facet> {
    top(list.iter().map(|a| f(a).to_owned()), field, range, 8)
        .into_iter()
        .map(|t| Facet {
            href: format!(
                "/crowdsec/alerts?range={range}&q={}",
                enc(format!("{q} {field}=\"{}\"", t.label).trim())
            ),
            label: t.label,
            count: t.count,
        })
        .collect()
}

async fn alerts(State(st): State<Arc<AppState>>, auth: Auth, Query(q): Query<Q>) -> Response {
    let (s, u) = match auth.require(Role::Operator) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let c = &st.crowdsec;
    let now = crate::db::now_ms();
    let (len, range) = range_ms(q.range.as_deref().unwrap_or("7d"), c.lookback_ms());
    let text: String = q.q.unwrap_or_default().chars().take(512).collect();
    let terms = parse_search(&text);
    let list = c.alerts(now - len, |a| alert_matches(a, &terms));
    let pages = list.len().div_ceil(PAGE).max(1);
    let page = q.page.unwrap_or(0).min(pages - 1);
    let rows = list
        .iter()
        .skip(page * PAGE)
        .take(PAGE)
        .map(|a| alert_row(a, now))
        .collect();
    let nav = Nav::new("crowdsec", &s, &u);
    let writable = nav.is_admin && !st.cfg.crowdsec_read_only;
    render(
        StatusCode::OK,
        &AlertsPage {
            scenario_facets: facets(&list, |a| &a.scenario, "scenario", &text, range),
            country_facets: facets(&list, |a| &a.country, "country", &text, range),
            machine_facets: facets(&list, |a| &a.machine, "machine", &text, range),
            nav,
            status: c.status(),
            total: list.len(),
            q: text,
            range,
            rows,
            page,
            pages,
            writable,
        },
    )
}

#[derive(Template)]
#[template(path = "crowdsec_decisions.html")]
struct DecisionsPage {
    nav: Nav,
    status: crate::crowdsec::Status,
    q: String,
    expired: bool,
    all: bool,
    rows: Vec<DecisionRow>,
    total: usize,
    writable: bool,
    durations: Vec<(&'static str, &'static str)>,
}

async fn decisions(State(st): State<Arc<AppState>>, auth: Auth, Query(q): Query<Q>) -> Response {
    let (s, u) = match auth.require(Role::Operator) {
        Ok(x) => x,
        Err(r) => return r,
    };
    show_decisions(&st, Nav::new("crowdsec", &s, &u), &q)
}

fn show_decisions(st: &AppState, nav: Nav, q: &Q) -> Response {
    let c = &st.crowdsec;
    let now = crate::db::now_ms();
    let text: String = q.q.clone().unwrap_or_default().chars().take(512).collect();
    let terms = parse_search(&text);
    let expired = q.expired.as_deref() == Some("1");
    let all = q.all.as_deref() == Some("1");
    let list = if expired { c.expired() } else { c.active() };
    let mut rows: Vec<DecisionRow> = Vec::new();
    let mut seen: HashMap<(String, String), usize> = HashMap::new();
    for d in &list {
        let a = c.alert(d.alert_id);
        if !decision_matches(d, a.as_ref(), &terms) {
            continue;
        }
        // Longest first, so the first of a value and type is the one that counts.
        let key = (d.value.clone(), d.kind.clone());
        if !all && let Some(&i) = seen.get(&key) {
            rows[i].dupes += 1;
            continue;
        }
        seen.insert(key, rows.len());
        rows.push(decision_row(d, a.as_ref(), now));
        if rows.len() >= 2000 {
            break;
        }
    }
    let writable = nav.is_admin && !st.cfg.crowdsec_read_only && c.configured();
    let status = if nav.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    render(
        status,
        &DecisionsPage {
            nav,
            status: c.status(),
            q: text,
            expired,
            all,
            total: rows.len(),
            rows,
            writable,
            durations: vec![
                ("1h", "1 hour"),
                ("4h", "4 hours"),
                ("24h", "1 day"),
                ("7d", "7 days"),
                ("30d", "30 days"),
                ("365d", "1 year"),
            ],
        },
    )
}

fn result(
    st: &AppState,
    s: &Session,
    me: &User,
    error: Option<String>,
    ok: Option<String>,
) -> Response {
    let mut nav = Nav::new("crowdsec", s, me);
    nav.error = error;
    nav.success = ok;
    show_decisions(st, nav, &Q::default())
}

#[derive(Deserialize)]
struct AddForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    value: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    duration: String,
    #[serde(default)]
    custom: String,
    #[serde(default)]
    reason: String,
}

async fn add(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Form(f): Form<AddForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let duration = if f.custom.trim().is_empty() {
        f.duration.as_str()
    } else {
        f.custom.as_str()
    };
    let ban =
        match crate::crowdsec::check_ban(&f.value, &f.kind, duration, &f.reason, Some(info.ip)) {
            Ok(b) => b,
            Err(m) => return result(&st, &s, &me, Some(m), None),
        };
    if let Err(e) = st.crowdsec.ban(&ban, &me.username).await {
        return result(&st, &s, &me, Some(format!("CrowdSec refused: {e}")), None);
    }
    tracing::warn!(event = "crowdsec.ban", user = %me.username, value = %ban.value, kind = %ban.kind, duration = %ban.duration, reason = %ban.reason, "CrowdSec decision added");
    audit(
        &st,
        &me,
        &info,
        "CROWDSEC_BAN",
        format!(
            "{} {} {} ({})",
            ban.kind, ban.value, ban.duration, ban.reason
        ),
    )
    .await;
    crate::crowdsec::tick(&st, false).await;
    result(
        &st,
        &s,
        &me,
        None,
        Some(format!(
            "{} on {} for {}.",
            ban.kind, ban.value, ban.duration
        )),
    )
}

#[derive(Deserialize)]
struct PlainForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    value: String,
}

async fn delete(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<i64>,
    Form(f): Form<PlainForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let what = st
        .crowdsec
        .active()
        .into_iter()
        .find(|d| d.id == id)
        .map_or_else(
            || format!("decision {id}"),
            |d| format!("{} {}", d.kind, d.value),
        );
    match st.crowdsec.unban(id).await {
        Ok(n) => {
            tracing::warn!(event = "crowdsec.unban", user = %me.username, decision = id, what = %what, deleted = n, "CrowdSec decision removed");
            audit(&st, &me, &info, "CROWDSEC_UNBAN", format!("{what} (#{id})")).await;
            crate::crowdsec::tick(&st, false).await;
            result(&st, &s, &me, None, Some(format!("Removed {what}.")))
        }
        Err(e) => result(&st, &s, &me, Some(format!("CrowdSec refused: {e}")), None),
    }
}

async fn remove_value(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Form(f): Form<PlainForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let value = f.value.trim().to_owned();
    match st.crowdsec.unban_value(&value).await {
        Ok(n) => {
            tracing::warn!(event = "crowdsec.unban", user = %me.username, value = %value, deleted = n, "CrowdSec decisions removed");
            audit(
                &st,
                &me,
                &info,
                "CROWDSEC_UNBAN",
                format!("all on {value} ({n})"),
            )
            .await;
            crate::crowdsec::tick(&st, false).await;
            result(
                &st,
                &s,
                &me,
                None,
                Some(format!("Removed {n} decision(s) on {value}.")),
            )
        }
        Err(e) => result(&st, &s, &me, Some(format!("CrowdSec refused: {e}")), None),
    }
}

async fn refresh(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    Form(f): Form<PlainForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    crate::crowdsec::tick(&st, true).await;
    let status = st.crowdsec.status();
    match status.error {
        Some(e) if !status.up => result(&st, &s, &me, Some(format!("Refresh failed: {e}")), None),
        _ => result(&st, &s, &me, None, Some("Re-read the LAPI.".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_terms() {
        let t = parse_search(r#"ssh  ip:1.2  country=NL -machine:edge "http probing" bogus:x"#);
        assert_eq!(t.len(), 6);
        assert_eq!(t[1].field.as_deref(), Some("ip"));
        assert!(t[2].exact);
        assert!(t[3].neg);
        assert_eq!(t[4].val, "http probing");
        assert_eq!(t[5].field, None);
        let a = Alert {
            scenario: "crowdsecurity/ssh-bf".into(),
            value: "1.2.3.4".into(),
            country: "NL".into(),
            machine: "nas".into(),
            ..Alert::default()
        };
        assert!(alert_matches(
            &a,
            &parse_search("ssh ip:1.2 country=nl -machine:edge")
        ));
        assert!(!alert_matches(&a, &parse_search("country=n")));
        assert!(!alert_matches(&a, &parse_search("-machine:nas")));
        assert!(alert_matches(&a, &parse_search("sim:no")));
    }

    #[test]
    fn spans() {
        assert_eq!(span(45_000), "45s");
        assert_eq!(span(5 * 60_000), "5m");
        assert_eq!(span(3 * 3_600_000 + 12 * 60_000), "3h 12m");
        assert_eq!(span(6 * 86_400_000 + 2 * 3_600_000), "6d 2h");
    }
}
