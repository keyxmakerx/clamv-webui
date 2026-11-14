//! CrowdSec console. clamv signs in to a Local API as a watcher (a machine
//! added with `cscli machines add`), keeps the last week of alerts and every
//! active decision in memory, and adds or removes bans when an admin asks.
//! Nothing is stored in the database, so a restart re-reads the LAPI.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde_json::{Value, json};

use crate::app::AppState;
use crate::config::Config;
use crate::webhook::Event;

/// Alerts kept in memory at most; the oldest go first.
pub const MAX_ALERTS: usize = 20_000;
/// Event metadata pairs kept per alert.
const MAX_META: usize = 40;
const TICK: Duration = Duration::from_secs(60);
/// A full re-read drops alerts deleted on the LAPI side.
const FULL_EVERY: u32 = 60;
/// Failed refreshes in a row before the LAPI counts as down.
const DOWN_AFTER: u32 = 3;

#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub id: i64,
    pub alert_id: i64,
    pub origin: String,
    /// ban, captcha, throttle...
    pub kind: String,
    pub scope: String,
    pub value: String,
    pub scenario: String,
    /// Unix ms when it ends.
    pub until: i64,
    pub simulated: bool,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Alert {
    pub id: i64,
    pub created_at: i64,
    pub scenario: String,
    pub message: String,
    /// The watcher that raised it, usually the host name.
    pub machine: String,
    pub events: i64,
    pub simulated: bool,
    pub scope: String,
    pub value: String,
    pub as_name: String,
    pub as_number: String,
    pub country: String,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub decisions: Vec<Decision>,
    pub meta: Vec<(String, String)>,
}

impl Alert {
    /// Where it came from: an IP, a range, or whatever the scope names.
    pub fn source(&self) -> &str {
        &self.value
    }
}

#[derive(Debug, Clone, Default)]
pub struct Status {
    pub configured: bool,
    pub up: bool,
    pub last_ok: Option<i64>,
    pub error: Option<String>,
    pub read_only: bool,
    pub url: String,
}

#[derive(Default)]
struct Snapshot {
    alerts: BTreeMap<i64, Alert>,
    /// Active decisions by id, from the last active-decisions read.
    active: BTreeMap<i64, Decision>,
    status: Status,
    failures: u32,
    /// Whether "down" was already logged and notified.
    told_down: bool,
}

struct Lapi {
    base: url::Url,
    machine: String,
    password: String,
    include_capi: bool,
    lookback_h: u32,
    client: reqwest::Client,
}

#[derive(Default)]
pub struct Console {
    lapi: Option<Lapi>,
    read_only: bool,
    snap: RwLock<Snapshot>,
    token: Mutex<Option<(String, i64)>>,
    /// Serialises refreshes so a ban and the timer don't race.
    busy: tokio::sync::Mutex<u32>,
}

/// Go duration (`3h59m12.5s`, `-1m`, `150ms`) to milliseconds.
pub fn parse_go_duration(s: &str) -> Option<i64> {
    let s = s.trim();
    let (neg, mut rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s),
    };
    if rest.is_empty() {
        return None;
    }
    let mut total = 0f64;
    while !rest.is_empty() {
        let n = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let num: f64 = rest[..n].parse().ok()?;
        rest = &rest[n..];
        let u = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let mult = match &rest[..u] {
            "h" => 3_600_000.0,
            "m" => 60_000.0,
            "s" => 1_000.0,
            "ms" => 1.0,
            "us" | "µs" => 0.001,
            "ns" => 0.000_001,
            _ => return None,
        };
        rest = &rest[u..];
        total += num * mult;
    }
    #[allow(clippy::cast_possible_truncation)]
    let ms = total.round() as i64;
    Some(if neg { -ms } else { ms })
}

fn text(v: &Value, n: usize) -> String {
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
    };
    s.chars()
        .filter(|c| !c.is_control() && !crate::webhook::is_bidi_control(*c))
        .take(n)
        .collect()
}

fn decision(v: &Value, alert_id: i64, now: i64) -> Option<Decision> {
    let id = v["id"].as_i64()?;
    let until = v["until"]
        .as_str()
        .and_then(crate::timefmt::parse_rfc3339)
        .or_else(|| {
            v["duration"]
                .as_str()
                .and_then(parse_go_duration)
                .map(|d| now + d)
        })
        .unwrap_or(now);
    Some(Decision {
        id,
        alert_id,
        origin: text(&v["origin"], 64),
        kind: text(&v["type"], 32),
        scope: text(&v["scope"], 32),
        value: text(&v["value"], 128),
        scenario: text(&v["scenario"], 256),
        until,
        simulated: v["simulated"].as_bool().unwrap_or(false),
    })
}

/// One alert from `GET /v1/alerts`; anything malformed is skipped.
pub fn parse_alert(v: &Value, now: i64) -> Option<Alert> {
    let id = v["id"].as_i64()?;
    let src = &v["source"];
    let mut meta: Vec<(String, String)> = Vec::new();
    let pairs = v["meta"].as_array().into_iter().flatten().chain(
        v["events"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|e| e["meta"].as_array().into_iter().flatten()),
    );
    for m in pairs {
        let k = text(&m["key"], 64);
        let val = text(&m["value"], 512);
        if k.is_empty() || val.is_empty() || meta.iter().any(|(a, b)| *a == k && *b == val) {
            continue;
        }
        if meta.len() >= MAX_META {
            break;
        }
        meta.push((k, val));
    }
    let value = match text(&src["value"], 128) {
        v if v.is_empty() => text(&src["ip"], 128),
        v => v,
    };
    Some(Alert {
        id,
        created_at: v["created_at"]
            .as_str()
            .and_then(crate::timefmt::parse_rfc3339)
            .or_else(|| {
                v["start_at"]
                    .as_str()
                    .and_then(crate::timefmt::parse_rfc3339)
            })
            .unwrap_or(now),
        scenario: text(&v["scenario"], 256),
        message: text(&v["message"], 512),
        machine: text(&v["machine_id"], 128),
        events: v["events_count"].as_i64().unwrap_or(0),
        simulated: v["simulated"].as_bool().unwrap_or(false),
        scope: text(&src["scope"], 32),
        value,
        as_name: text(&src["as_name"], 128),
        as_number: text(&src["as_number"], 16),
        country: text(&src["cn"], 8).to_ascii_uppercase(),
        lat: src["latitude"]
            .as_f64()
            .filter(|x| x.is_finite() && x.abs() <= 90.0),
        lon: src["longitude"]
            .as_f64()
            .filter(|x| x.is_finite() && x.abs() <= 180.0),
        decisions: v["decisions"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| decision(d, id, now))
            .collect(),
        meta,
    })
}

/// What a ban request becomes once checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ban {
    pub scope: &'static str,
    pub value: String,
    pub kind: String,
    /// Go duration, e.g. `4h`.
    pub duration: String,
    pub reason: String,
}

/// Check an admin's ban form. `me` is the admin's own address, which is refused.
pub fn check_ban(
    value: &str,
    kind: &str,
    duration: &str,
    reason: &str,
    me: Option<IpAddr>,
) -> Result<Ban, String> {
    let value = value.trim();
    let (scope, net, bits) = if value.contains('/') {
        let c = crate::webhook::Cidr::parse(value)?;
        let (ip, bits) = value.split_once('/').unwrap_or((value, ""));
        let ip: IpAddr = ip.parse().map_err(|_| format!("bad range {value:?}"))?;
        let bits: u8 = bits.parse().map_err(|_| format!("bad range {value:?}"))?;
        let min = if ip.is_ipv4() { 8 } else { 32 };
        if bits < min {
            return Err(format!(
                "{value} is too wide; use /{min} or narrower so one click can't cut off most of the internet."
            ));
        }
        if me.is_some_and(|m| c.contains(m)) {
            return Err(format!(
                "{value} contains your own address; you would lock yourself out."
            ));
        }
        ("Range", ip, bits)
    } else {
        let ip: IpAddr = value
            .parse()
            .map_err(|_| format!("{value:?} is not an IP address or range."))?;
        if me == Some(ip) {
            return Err("That is your own address; you would lock yourself out.".into());
        }
        ("Ip", ip, if ip.is_ipv4() { 32 } else { 128 })
    };
    if net.is_loopback() || net.is_unspecified() || net.is_multicast() {
        return Err(format!("{value} cannot be banned."));
    }
    let kind = match kind.trim() {
        "" | "ban" => "ban",
        "captcha" => "captcha",
        _ => return Err("Type must be ban or captcha.".into()),
    };
    let d = duration.trim().to_ascii_lowercase();
    let (n, unit) = d.split_at(d.len().saturating_sub(1));
    let n: u32 = n
        .parse()
        .map_err(|_| "Duration looks like 30m, 4h or 7d.".to_owned())?;
    let hours = match unit {
        "m" if (1..=525_600).contains(&n) => None,
        "h" if (1..=8_760).contains(&n) => Some(n),
        "d" if (1..=365).contains(&n) => Some(n * 24),
        _ => return Err("Duration looks like 30m, 4h or 7d, at most a year.".into()),
    };
    let duration = hours.map_or_else(|| format!("{n}m"), |h| format!("{h}h"));
    let reason: String = reason
        .chars()
        .filter(|c| !c.is_control() && !crate::webhook::is_bidi_control(*c))
        .take(120)
        .collect::<String>()
        .trim()
        .to_owned();
    if reason.is_empty() {
        return Err("Say why, so the next person knows.".into());
    }
    let value = if scope == "Range" {
        format!("{net}/{bits}")
    } else {
        net.to_string()
    };
    Ok(Ban {
        scope,
        value,
        kind: kind.to_owned(),
        duration,
        reason,
    })
}

impl Console {
    pub fn from_config(cfg: &Config) -> anyhow::Result<Self> {
        let Some(raw) = cfg.crowdsec_lapi_url.as_deref().map(str::trim) else {
            return Ok(Self::default());
        };
        if raw.is_empty() {
            return Ok(Self::default());
        }
        let mut base = url::Url::parse(raw)
            .map_err(|e| anyhow::anyhow!("CROWDSEC_LAPI_URL is not a URL: {e}"))?;
        if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
            anyhow::bail!("CROWDSEC_LAPI_URL must be http:// or https:// with a host");
        }
        if !base.username().is_empty() || base.password().is_some() {
            anyhow::bail!("CROWDSEC_LAPI_URL must not carry credentials; use CROWDSEC_PASSWORD");
        }
        if !base.path().ends_with('/') {
            let p = format!("{}/", base.path());
            base.set_path(&p);
        }
        let password = match &cfg.crowdsec_password_file {
            Some(p) => std::fs::read_to_string(p).map_err(|e| {
                anyhow::anyhow!("cannot read CROWDSEC_PASSWORD_FILE {}: {e}", p.display())
            })?,
            None => cfg.crowdsec_password.clone().unwrap_or_default(),
        }
        .trim_end_matches(['\r', '\n'])
        .to_owned();
        let machine = cfg.crowdsec_machine_id.trim().to_owned();
        if machine.is_empty() || password.is_empty() {
            anyhow::bail!("CROWDSEC_LAPI_URL needs CROWDSEC_MACHINE_ID and CROWDSEC_PASSWORD");
        }
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("clamv-webui/", env!("CARGO_PKG_VERSION")))
            .tls_backend_preconfigured(crate::webhook::client_tls(cfg.crowdsec_ca_file.as_deref())?)
            .build()?;
        Ok(Self {
            lapi: Some(Lapi {
                base,
                machine,
                password,
                include_capi: cfg.crowdsec_include_capi,
                lookback_h: cfg.crowdsec_lookback_hours.clamp(1, 720),
                client,
            }),
            read_only: cfg.crowdsec_read_only,
            snap: RwLock::new(Snapshot {
                status: Status {
                    configured: true,
                    read_only: cfg.crowdsec_read_only,
                    url: raw.to_owned(),
                    ..Status::default()
                },
                ..Snapshot::default()
            }),
            ..Self::default()
        })
    }

    pub fn configured(&self) -> bool {
        self.lapi.is_some()
    }

    pub fn status(&self) -> Status {
        self.snap
            .read()
            .map(|s| s.status.clone())
            .unwrap_or_default()
    }

    pub fn lookback_ms(&self) -> i64 {
        self.lapi.as_ref().map_or(168, |l| i64::from(l.lookback_h)) * 3_600_000
    }

    /// Alerts since `since`, newest first, that `keep` accepts.
    pub fn alerts(&self, since: i64, keep: impl Fn(&Alert) -> bool) -> Vec<Alert> {
        let Ok(s) = self.snap.read() else {
            return Vec::new();
        };
        let mut v: Vec<Alert> = s
            .alerts
            .values()
            .rev()
            .filter(|a| a.created_at >= since && keep(a))
            .cloned()
            .collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        v
    }

    pub fn alert(&self, id: i64) -> Option<Alert> {
        self.snap.read().ok()?.alerts.get(&id).cloned()
    }

    /// Active decisions, longest-lasting first.
    pub fn active(&self) -> Vec<Decision> {
        let now = crate::db::now_ms();
        let Ok(s) = self.snap.read() else {
            return Vec::new();
        };
        let mut v: Vec<Decision> = s
            .active
            .values()
            .filter(|d| d.until > now)
            .cloned()
            .collect();
        v.sort_by_key(|d| std::cmp::Reverse(d.until));
        v
    }

    /// Decisions that ended within the look-back window, newest first.
    pub fn expired(&self) -> Vec<Decision> {
        let now = crate::db::now_ms();
        let Ok(s) = self.snap.read() else {
            return Vec::new();
        };
        let mut v: Vec<Decision> = s
            .alerts
            .values()
            .flat_map(|a| a.decisions.iter())
            .filter(|d| d.until <= now && !s.active.contains_key(&d.id))
            .cloned()
            .collect();
        v.sort_by_key(|d| std::cmp::Reverse(d.until));
        v.dedup_by_key(|d| d.id);
        v
    }

    fn url(&self, path: &str) -> anyhow::Result<url::Url> {
        let l = self
            .lapi
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("CrowdSec is not configured"))?;
        Ok(l.base.join(path)?)
    }

    async fn login(&self) -> anyhow::Result<String> {
        let l = self
            .lapi
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("CrowdSec is not configured"))?;
        let r = l
            .client
            .post(self.url("v1/watchers/login")?)
            .json(&json!({"machine_id": l.machine, "password": l.password, "scenarios": []}))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("{}", e.without_url()))?;
        let code = r.status();
        if code == reqwest::StatusCode::UNAUTHORIZED || code == reqwest::StatusCode::FORBIDDEN {
            anyhow::bail!(
                "the LAPI refused machine {:?}; check CROWDSEC_PASSWORD and run cscli machines validate",
                l.machine
            );
        }
        if !code.is_success() {
            anyhow::bail!("login: HTTP {}", code.as_u16());
        }
        let v: Value = r.json().await.map_err(|e| anyhow::anyhow!("login: {e}"))?;
        let token = v["token"]
            .as_str()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| anyhow::anyhow!("login: no token in the answer"))?
            .to_owned();
        let exp = v["expire"]
            .as_str()
            .and_then(crate::timefmt::parse_rfc3339)
            .unwrap_or_else(|| crate::db::now_ms() + 30 * 60_000);
        if let Ok(mut g) = self.token.lock() {
            *g = Some((token.clone(), exp));
        }
        Ok(token)
    }

    async fn token(&self) -> anyhow::Result<String> {
        let now = crate::db::now_ms();
        let cached = self
            .token
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .filter(|(_, exp)| *exp > now + 60_000);
        match cached {
            Some((t, _)) => Ok(t),
            None => self.login().await,
        }
    }

    fn forget_token(&self) {
        if let Ok(mut g) = self.token.lock() {
            *g = None;
        }
    }

    /// One authenticated call; a 401 signs in again once.
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> anyhow::Result<Value> {
        let l = self
            .lapi
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("CrowdSec is not configured"))?;
        for attempt in 0..2 {
            let token = self.token().await?;
            let mut u = self.url(path)?;
            if !query.is_empty() {
                u.query_pairs_mut()
                    .extend_pairs(query.iter().map(|(k, v)| (*k, v.as_str())));
            }
            let mut req = l.client.request(method.clone(), u).bearer_auth(&token);
            if let Some(b) = body {
                req = req.json(b);
            }
            let r = req
                .send()
                .await
                .map_err(|e| anyhow::anyhow!("{}", e.without_url()))?;
            let code = r.status();
            if code == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
                self.forget_token();
                continue;
            }
            if code == reqwest::StatusCode::FORBIDDEN {
                anyhow::bail!("the LAPI refused this ({path}): HTTP 403");
            }
            if !code.is_success() {
                anyhow::bail!("{path}: HTTP {}", code.as_u16());
            }
            let bytes = r
                .bytes()
                .await
                .map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
            if bytes.is_empty() {
                return Ok(Value::Null);
            }
            return serde_json::from_slice(&bytes).map_err(|e| anyhow::anyhow!("{path}: {e}"));
        }
        anyhow::bail!("{path}: signed out twice")
    }

    async fn fetch_alerts(&self, extra: &[(&str, String)]) -> anyhow::Result<Vec<Alert>> {
        let l = self
            .lapi
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("CrowdSec is not configured"))?;
        let mut q: Vec<(&str, String)> = vec![
            ("limit", MAX_ALERTS.to_string()),
            ("simulated", "true".into()),
            ("include_capi", l.include_capi.to_string()),
        ];
        q.extend_from_slice(extra);
        let v = self
            .call(reqwest::Method::GET, "v1/alerts", &q, None)
            .await?;
        let now = crate::db::now_ms();
        Ok(v.as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| parse_alert(a, now))
            .collect())
    }

    /// Read new alerts and every active decision. `full` re-reads the whole window.
    async fn sync(&self, full: bool) -> anyhow::Result<()> {
        let lookback_h = self.lapi.as_ref().map_or(168, |l| l.lookback_h);
        let now = crate::db::now_ms();
        let last_ok = self.status().last_ok;
        let since = match (full, last_ok) {
            (false, Some(t)) => format!("{}s", (now - t) / 1000 + 300),
            _ => format!("{lookback_h}h"),
        };
        let fresh = self.fetch_alerts(&[("since", since)]).await?;
        let active = self
            .fetch_alerts(&[("has_active_decision", "true".into())])
            .await?;
        let cutoff = now - i64::from(lookback_h) * 3_600_000;
        let Ok(mut s) = self.snap.write() else {
            anyhow::bail!("state lock poisoned");
        };
        if full || last_ok.is_none() {
            s.alerts.clear();
        }
        s.active = active
            .iter()
            .flat_map(|a| a.decisions.iter())
            .filter(|d| d.until > now)
            .map(|d| (d.id, d.clone()))
            .collect();
        for a in fresh.into_iter().chain(active) {
            s.alerts.insert(a.id, a);
        }
        let keep: HashSet<i64> = s.active.values().map(|d| d.alert_id).collect();
        s.alerts
            .retain(|id, a| a.created_at >= cutoff || keep.contains(id));
        while s.alerts.len() > MAX_ALERTS {
            let Some(oldest) = s.alerts.keys().find(|id| !keep.contains(id)).copied() else {
                break;
            };
            s.alerts.remove(&oldest);
        }
        Ok(())
    }

    /// Refresh now and record the outcome. Returns whether the LAPI just went down or came back.
    pub async fn refresh(&self, full: bool) -> Option<bool> {
        self.lapi.as_ref()?;
        let mut n = self.busy.lock().await;
        let full = full || *n % FULL_EVERY == 0;
        *n = n.wrapping_add(1);
        let r = self.sync(full).await;
        let Ok(mut s) = self.snap.write() else {
            return None;
        };
        match r {
            Ok(()) => {
                s.failures = 0;
                s.status.up = true;
                s.status.error = None;
                s.status.last_ok = Some(crate::db::now_ms());
                if s.told_down {
                    s.told_down = false;
                    return Some(true);
                }
                None
            }
            Err(e) => {
                s.failures = s.failures.saturating_add(1);
                s.status.error = Some(e.to_string());
                if s.failures >= DOWN_AFTER || s.status.last_ok.is_none() {
                    s.status.up = false;
                    if !s.told_down {
                        s.told_down = true;
                        return Some(false);
                    }
                }
                None
            }
        }
    }

    fn writable(&self) -> anyhow::Result<()> {
        if self.lapi.is_none() {
            anyhow::bail!("CrowdSec is not configured.");
        }
        if self.read_only {
            anyhow::bail!("CROWDSEC_READ_ONLY is on.");
        }
        Ok(())
    }

    /// Add a decision the way `cscli decisions add` does: a manual alert carrying it.
    pub async fn ban(&self, b: &Ban, by: &str) -> anyhow::Result<()> {
        self.writable()?;
        let now = crate::timefmt::rfc3339(crate::db::now_ms());
        let scenario = format!(
            "manual '{}' from clamv-webui user {by}: {}",
            b.kind, b.reason
        );
        let body = json!([{
            "scenario": scenario,
            "scenario_hash": "",
            "scenario_version": "",
            "message": scenario,
            "events_count": 1,
            "start_at": now,
            "stop_at": now,
            "capacity": 0,
            "leakspeed": "0",
            "simulated": false,
            "remediation": true,
            "events": [],
            "source": {"scope": b.scope, "value": b.value},
            "decisions": [{
                "duration": b.duration,
                "origin": "cscli",
                "scenario": scenario,
                "scope": b.scope,
                "type": b.kind,
                "value": b.value,
            }],
        }]);
        self.call(reqwest::Method::POST, "v1/alerts", &[], Some(&body))
            .await?;
        Ok(())
    }

    /// Remove one decision. Returns how many the LAPI deleted.
    pub async fn unban(&self, id: i64) -> anyhow::Result<u64> {
        self.writable()?;
        let v = self
            .call(
                reqwest::Method::DELETE,
                &format!("v1/decisions/{id}"),
                &[],
                None,
            )
            .await?;
        Ok(deleted(&v))
    }

    /// Remove every decision on one IP or range.
    pub async fn unban_value(&self, value: &str) -> anyhow::Result<u64> {
        self.writable()?;
        let value = value.trim();
        let key = if value.contains('/') {
            crate::webhook::Cidr::parse(value).map_err(|e| anyhow::anyhow!(e))?;
            "range"
        } else {
            value
                .parse::<IpAddr>()
                .map_err(|_| anyhow::anyhow!("{value:?} is not an IP address or range"))?;
            "ip"
        };
        let v = self
            .call(
                reqwest::Method::DELETE,
                "v1/decisions",
                &[(key, value.to_owned())],
                None,
            )
            .await?;
        Ok(deleted(&v))
    }
}

fn deleted(v: &Value) -> u64 {
    v["nbDeleted"]
        .as_u64()
        .or_else(|| v["nbDeleted"].as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0)
}

fn lapi_event(up: bool, url: &str, error: Option<String>) -> Event {
    Event {
        event: if up {
            "crowdsec.lapi_up"
        } else {
            "crowdsec.lapi_down"
        },
        job_id: String::new(),
        kind: "CROWDSEC".into(),
        target: url.to_owned(),
        endpoint: crate::canary::hostname(),
        submitted_by: None,
        verdict: if up { "OK" } else { "ALERT" }.into(),
        found_viruses: Vec::new(),
        detections: Default::default(),
        files_scanned: 0,
        file_errors: 0,
        error_code: None,
        error,
        finished_at: crate::timefmt::rfc3339(crate::db::now_ms()),
    }
}

/// Refresh, then log and notify when the LAPI goes down or comes back.
pub async fn tick(st: &AppState, full: bool) {
    let Some(change) = st.crowdsec.refresh(full).await else {
        return;
    };
    let s = st.crowdsec.status();
    if change {
        tracing::info!(event = "crowdsec.lapi_up", url = %s.url, "CrowdSec LAPI reachable again");
    } else {
        tracing::error!(event = "crowdsec.lapi_down", url = %s.url, error = s.error.as_deref().unwrap_or("-"), "CrowdSec LAPI unreachable");
    }
    st.notifier.notify(lapi_event(change, &s.url, s.error));
}

pub fn spawn(st: Arc<AppState>) {
    if !st.crowdsec.configured() {
        return;
    }
    tokio::spawn(async move {
        let mut t = tokio::time::interval(TICK);
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            t.tick().await;
            tick(&st, false).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_durations() {
        assert_eq!(parse_go_duration("3h59m12.5s"), Some(14_352_500));
        assert_eq!(parse_go_duration("-1m"), Some(-60_000));
        assert_eq!(parse_go_duration("150ms"), Some(150));
        assert_eq!(parse_go_duration("4h"), Some(14_400_000));
        assert_eq!(parse_go_duration(""), None);
        assert_eq!(parse_go_duration("4d"), None);
        assert_eq!(parse_go_duration("h"), None);
    }

    #[test]
    fn alerts_parse_leniently() {
        let v: Value = serde_json::from_str(
            r#"{"id":7,"scenario":"crowdsecurity/ssh-bf","machine_id":"nas","created_at":"2026-11-14T10:00:00Z",
            "events_count":6,"simulated":false,"message":"Ip 1.2.3.4 performed ssh-bf\u202e",
            "source":{"scope":"Ip","value":"1.2.3.4","as_name":"EVIL","as_number":"666","cn":"nl","latitude":52.3,"longitude":4.9},
            "decisions":[{"id":11,"origin":"crowdsec","type":"ban","scope":"Ip","value":"1.2.3.4","duration":"3h59m","scenario":"crowdsecurity/ssh-bf"},{"bad":1}],
            "events":[{"meta":[{"key":"service","value":"ssh"},{"key":"service","value":"ssh"},{"key":"user","value":"root"}]}]}"#,
        )
        .expect("json");
        let a = parse_alert(&v, 1000).expect("alert");
        assert_eq!(a.id, 7);
        assert_eq!(a.country, "NL");
        assert_eq!(a.machine, "nas");
        assert!(!a.message.contains('\u{202e}'));
        assert_eq!(a.decisions.len(), 1);
        assert_eq!(a.decisions[0].until, 1000 + 239 * 60_000);
        assert_eq!(
            a.meta,
            vec![
                ("service".to_owned(), "ssh".to_owned()),
                ("user".to_owned(), "root".to_owned())
            ]
        );
        assert!(parse_alert(&json!({"scenario": "x"}), 0).is_none());
    }

    #[test]
    fn bans_are_checked() {
        let me: IpAddr = "100.82.0.9".parse().expect("ip");
        let b = check_ban(" 1.2.3.4 ", "", "7d", "brute force", Some(me)).expect("ok");
        assert_eq!(
            (
                b.scope,
                b.value.as_str(),
                b.kind.as_str(),
                b.duration.as_str()
            ),
            ("Ip", "1.2.3.4", "ban", "168h")
        );
        assert_eq!(
            check_ban("10.1.0.0/16", "captcha", "30m", "x", None)
                .expect("ok")
                .duration,
            "30m"
        );
        for (v, d, r) in [
            ("100.82.0.9", "4h", "x"),
            ("100.82.0.0/16", "4h", "x"),
            ("127.0.0.1", "4h", "x"),
            ("0.0.0.0/0", "4h", "x"),
            ("1.0.0.0/4", "4h", "x"),
            ("nope", "4h", "x"),
            ("1.2.3.4", "4w", "x"),
            ("1.2.3.4", "400d", "x"),
            ("1.2.3.4", "4h", "  "),
        ] {
            assert!(
                check_ban(v, "ban", d, r, Some(me)).is_err(),
                "{v} {d} {r:?}"
            );
        }
        assert!(check_ban("1.2.3.4", "drop", "4h", "x", None).is_err());
    }
}
