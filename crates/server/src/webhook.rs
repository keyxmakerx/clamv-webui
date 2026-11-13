//! Outgoing webhook for finished scans. Every request is pinned to addresses
//! checked against the SSRF policy, redirects are off and the URL is never logged.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::Url;
use serde::Serialize;
use tokio::sync::mpsc;

use crate::config::{Config, WebhookEvents};
use crate::db::jobs;

const QUEUE: usize = 100;
const WORKERS: usize = 2;
const ATTEMPTS: u32 = 3;

/// What a webhook call reports. Field names follow the Java payload.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub event: &'static str,
    pub job_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub target: String,
    pub endpoint: String,
    pub submitted_by: Option<String>,
    pub verdict: String,
    pub found_viruses: Vec<String>,
    pub detections: BTreeMap<String, Vec<String>>,
    pub files_scanned: i64,
    pub file_errors: usize,
    pub error_code: Option<String>,
    pub error: Option<String>,
    pub finished_at: String,
}

impl Event {
    /// Detections, failures, unscannable files and anything that is not a plain finish.
    pub fn is_alert(&self) -> bool {
        self.event != "scan.finished" || self.verdict != jobs::OK || self.file_errors > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cidr {
    net: IpAddr,
    bits: u8,
}

impl Cidr {
    fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (ip, bits) = match s.split_once('/') {
            Some((ip, b)) => (ip, Some(b)),
            None => (s, None),
        };
        let net: IpAddr = ip.parse().map_err(|_| format!("bad CIDR {s:?}"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let bits = match bits {
            Some(b) => b
                .parse::<u8>()
                .ok()
                .filter(|b| *b <= max)
                .ok_or_else(|| format!("bad CIDR {s:?}"))?,
            None => max,
        };
        Ok(Self { net, bits })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, canonical(ip)) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.bits)).unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.bits))
                    .unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

/// Check one CIDR or address for the settings page.
pub fn parse_cidr(s: &str) -> Result<(), String> {
    Cidr::parse(s).map(|_| ())
}

/// IPv4-mapped IPv6 addresses are judged as IPv4.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

fn v4_special(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_unspecified()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_documentation()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 100 && (64..128).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
}

fn v6_special(a: Ipv6Addr) -> bool {
    let s = a.segments();
    a.is_loopback()
        || a.is_unspecified()
        || a.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        // NAT64 well-known prefix: judge the embedded IPv4 address.
        || (s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0]
            && v4_special(Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8)))
}

/// Cloud metadata services, refused even with WEBHOOK_ALLOW_PRIVATE.
fn metadata(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(a) => a == Ipv4Addr::new(169, 254, 169, 254),
        IpAddr::V6(a) => a == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254),
    }
}

#[derive(Debug, Clone)]
struct Policy {
    allow_private: bool,
    cidrs: Vec<Cidr>,
}

impl Policy {
    fn permits(&self, ip: IpAddr) -> bool {
        if self.cidrs.iter().any(|c| c.contains(ip)) {
            return true;
        }
        let special = match canonical(ip) {
            IpAddr::V4(a) => v4_special(a),
            IpAddr::V6(a) => v6_special(a),
        };
        !special || (self.allow_private && !metadata(ip))
    }
}

#[derive(Debug, Clone)]
pub struct Target {
    url: Url,
    discord: bool,
    policy: Policy,
}

impl Target {
    /// None when no webhook is configured; an error for a bad URL or CIDR.
    pub fn from_config(cfg: &Config) -> anyhow::Result<Option<Self>> {
        let raw = match &cfg.webhook_url_file {
            Some(p) => std::fs::read_to_string(p)
                .map_err(|e| anyhow::anyhow!("cannot read WEBHOOK_URL_FILE {}: {e}", p.display()))?
                .trim()
                .to_owned(),
            None => cfg
                .webhook_url
                .clone()
                .unwrap_or_default()
                .trim()
                .to_owned(),
        };
        if raw.is_empty() {
            return Ok(None);
        }
        // The URL may hold a token, so errors never quote it.
        let url =
            Url::parse(&raw).map_err(|_| anyhow::anyhow!("WEBHOOK_URL is not a valid URL"))?;
        if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
            anyhow::bail!("WEBHOOK_URL must be an http or https URL with a host");
        }
        if !url.username().is_empty() || url.password().is_some() {
            anyhow::bail!("WEBHOOK_URL must not contain credentials");
        }
        let cidrs = cfg
            .webhook_allowed_cidrs
            .iter()
            .filter(|c| !c.trim().is_empty())
            .map(|c| Cidr::parse(c))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("WEBHOOK_ALLOWED_CIDRS: {e}"))?;
        let discord = matches!(
            url.host_str(),
            Some("discord.com" | "discordapp.com" | "canary.discord.com" | "ptb.discord.com")
        ) && url.path().starts_with("/api/webhooks/");
        Ok(Some(Self {
            url,
            discord,
            policy: Policy {
                allow_private: cfg.webhook_allow_private,
                cidrs,
            },
        }))
    }

    pub fn host(&self) -> String {
        self.url.host_str().unwrap_or("").to_owned()
    }

    pub fn is_discord(&self) -> bool {
        self.discord
    }

    /// Resolve and check every address; all must pass so DNS cannot mix in a private one.
    async fn addrs(&self) -> Result<Vec<SocketAddr>, String> {
        let port = self.url.port_or_known_default().unwrap_or(443);
        let addrs: Vec<SocketAddr> = match self.url.host() {
            Some(url::Host::Ipv4(a)) => vec![SocketAddr::new(IpAddr::V4(a), port)],
            Some(url::Host::Ipv6(a)) => vec![SocketAddr::new(IpAddr::V6(a), port)],
            Some(url::Host::Domain(d)) => {
                tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((d, port)))
                    .await
                    .map_err(|_| "DNS lookup timed out".to_owned())?
                    .map_err(|e| format!("DNS lookup failed: {e}"))?
                    .collect()
            }
            None => Vec::new(),
        };
        if addrs.is_empty() {
            return Err("host has no addresses".into());
        }
        if let Some(bad) = addrs.iter().find(|a| !self.policy.permits(a.ip())) {
            return Err(format!(
                "address {} is not allowed; add it to WEBHOOK_ALLOWED_CIDRS",
                bad.ip()
            ));
        }
        Ok(addrs)
    }

    fn body(&self, e: &Event) -> serde_json::Value {
        if self.discord {
            serde_json::json!({ "content": discord_text(e), "allowed_mentions": { "parse": [] } })
        } else {
            serde_json::to_value(e).unwrap_or_default()
        }
    }

    async fn deliver(&self, e: &Event) -> Result<(), String> {
        let addrs = self.addrs().await?;
        let mut b = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("clamv-webui/", env!("CARGO_PKG_VERSION")))
            .tls_backend_preconfigured(tls());
        if let Some(d) = self.url.domain() {
            b = b.resolve_to_addrs(d, &addrs);
        }
        let client = b.build().map_err(|e| format!("client: {e}"))?;
        let body = self.body(e);
        let mut last = String::new();
        for attempt in 1..=ATTEMPTS {
            if attempt > 1 {
                tokio::time::sleep(Duration::from_secs(if attempt == 2 { 1 } else { 5 })).await;
            }
            match client.post(self.url.clone()).json(&body).send().await {
                Ok(r) if r.status().is_success() => return Ok(()),
                Ok(r) => {
                    let s = r.status();
                    last = format!("HTTP {}", s.as_u16());
                    if !(s.is_server_error() || s.as_u16() == 429) {
                        break;
                    }
                }
                // Strip the URL from transport errors.
                Err(err) => last = err.without_url().to_string(),
            }
        }
        Err(last)
    }
}

fn tls() -> rustls::ClientConfig {
    client_tls(None).unwrap_or_else(|_| client_tls_roots(webpki_roots_store()))
}

fn webpki_roots_store() -> rustls::RootCertStore {
    rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

fn client_tls_roots(roots: rustls::RootCertStore) -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Client TLS with the public web roots plus an optional PEM bundle.
pub(crate) fn client_tls(
    extra_ca: Option<&std::path::Path>,
) -> anyhow::Result<rustls::ClientConfig> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let mut roots = webpki_roots_store();
    if let Some(p) = extra_ca {
        let mut n = 0;
        for c in CertificateDer::pem_file_iter(p)
            .map_err(|e| anyhow::anyhow!("cannot read CA file {}: {e}", p.display()))?
        {
            let c = c.map_err(|e| anyhow::anyhow!("bad certificate in {}: {e}", p.display()))?;
            roots
                .add(c)
                .map_err(|e| anyhow::anyhow!("bad certificate in {}: {e}", p.display()))?;
            n += 1;
        }
        if n == 0 {
            anyhow::bail!("no certificates in {}", p.display());
        }
    }
    Ok(client_tls_roots(roots))
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_owned()
    } else {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

fn discord_text(e: &Event) -> String {
    let clean = |s: &str| s.replace('`', "'");
    let head = match (e.event, e.verdict.as_str()) {
        ("test", _) => "Test message from clamv-webui.".to_owned(),
        ("canary.tripped", _) => format!(
            "**Canary file touched** on `{}`: `{}` ({}). Someone may be inside.",
            clean(&e.endpoint),
            clean(&e.target),
            e.error.as_deref().unwrap_or("accessed")
        ),
        ("eicar.control_failed", _) => format!(
            "**EICAR check failed** on `{}`: scan results cannot be trusted.",
            clean(&e.endpoint)
        ),
        (_, jobs::VIRUS_FOUND) => format!(
            "**Malware found** by `{}` ({} scan of `{}`):",
            clean(&e.endpoint),
            e.kind,
            clean(&e.target)
        ),
        (_, jobs::ERROR) => format!(
            "**Scan failed** on `{}` ({} scan of `{}`)",
            clean(&e.endpoint),
            e.kind,
            clean(&e.target)
        ),
        _ => format!(
            "Scan finished on `{}` ({} scan of `{}`): {}, {} file(s)",
            clean(&e.endpoint),
            e.kind,
            clean(&e.target),
            e.verdict,
            e.files_scanned
        ),
    };
    let mut lines = vec![head];
    for (path, sigs) in e.detections.iter().take(10) {
        lines.push(format!(
            "- `{}` in `{}`",
            clean(&sigs.join(", ")),
            clean(path)
        ));
    }
    if e.detections.len() > 10 {
        lines.push(format!("- and {} more", e.detections.len() - 10));
    }
    if e.file_errors > 0 {
        lines.push(format!(
            "{} file(s) could not be fully scanned.",
            e.file_errors
        ));
    }
    if let Some(m) = &e.error {
        lines.push(format!("Reason: {}", clean(m)));
    }
    if !e.job_id.is_empty() {
        lines.push(format!("Job `{}`", e.job_id));
    }
    clip(&lines.join("\n"), 1900)
}

#[derive(Debug, Clone)]
pub struct Delivery {
    pub at: i64,
    pub ok: bool,
    pub detail: String,
}

/// Queues events for a small worker pool so scans never wait on the network.
pub struct Notifier {
    target: Option<Target>,
    events: WebhookEvents,
    tx: mpsc::Sender<Event>,
    rx: Mutex<Option<mpsc::Receiver<Event>>>,
    last: Mutex<Option<Delivery>>,
}

impl Notifier {
    pub fn new(cfg: &Config) -> Self {
        let target = Target::from_config(cfg).unwrap_or_else(|e| {
            tracing::error!(event = "webhook.config_invalid", error = %e, "webhook disabled");
            None
        });
        let (tx, rx) = mpsc::channel(QUEUE);
        Self {
            target,
            events: cfg.webhook_events,
            tx,
            rx: Mutex::new(Some(rx)),
            last: Mutex::new(None),
        }
    }

    pub fn target(&self) -> Option<&Target> {
        self.target.as_ref()
    }

    pub fn events(&self) -> WebhookEvents {
        self.events
    }

    pub fn last(&self) -> Option<Delivery> {
        self.last.lock().ok().and_then(|g| g.clone())
    }

    pub fn notify(&self, e: Event) {
        if self.target.is_none() || (self.events == WebhookEvents::Alerts && !e.is_alert()) {
            return;
        }
        if self.tx.try_send(e).is_err() {
            tracing::warn!(
                event = "webhook.dropped",
                "webhook queue full; event dropped"
            );
        }
    }

    /// Send a test event now and report the result.
    pub async fn test(&self) -> Result<(), String> {
        let Some(t) = &self.target else {
            return Err("No webhook is configured.".into());
        };
        let e = Event {
            event: "test",
            job_id: String::new(),
            kind: "TEST".into(),
            target: String::new(),
            endpoint: String::new(),
            submitted_by: None,
            verdict: jobs::OK.into(),
            found_viruses: Vec::new(),
            detections: BTreeMap::new(),
            files_scanned: 0,
            file_errors: 0,
            error_code: None,
            error: None,
            finished_at: crate::timefmt::rfc3339(crate::db::now_ms()),
        };
        let r = t.deliver(&e).await;
        self.record(t, &e, &r);
        r
    }

    fn record(&self, t: &Target, e: &Event, r: &Result<(), String>) {
        match r {
            Ok(()) => {
                tracing::info!(event = "webhook.delivered", host = %t.host(), webhook_event = e.event, job_id = %e.job_id, "webhook delivered");
            }
            Err(m) => {
                tracing::error!(event = "webhook.failed", host = %t.host(), webhook_event = e.event, job_id = %e.job_id, reason = %m, "webhook delivery failed");
            }
        }
        if let Ok(mut g) = self.last.lock() {
            *g = Some(Delivery {
                at: crate::db::now_ms(),
                ok: r.is_ok(),
                detail: r.as_ref().err().cloned().unwrap_or_default(),
            });
        }
    }
}

/// Start the delivery workers.
pub fn spawn(st: Arc<crate::app::AppState>) {
    let Some(rx) = st.notifier.rx.lock().ok().and_then(|mut g| g.take()) else {
        return;
    };
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    for _ in 0..WORKERS {
        let (st, rx) = (st.clone(), rx.clone());
        tokio::spawn(async move {
            loop {
                let Some(e) = rx.lock().await.recv().await else {
                    return;
                };
                if let Some(t) = st.notifier.target() {
                    let r = t.deliver(&e).await;
                    st.notifier.record(t, &e, &r);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(private: bool, cidrs: &[&str]) -> Policy {
        Policy {
            allow_private: private,
            cidrs: cidrs
                .iter()
                .map(|c| Cidr::parse(c).expect("cidr"))
                .collect(),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn blocks_private_ranges_by_default() {
        let p = policy(false, &[]);
        for a in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.82.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
        ] {
            assert!(!p.permits(ip(a)), "{a}");
        }
        for a in [
            "1.1.1.1",
            "162.159.135.232",
            "2606:4700::1111",
            "64:ff9b::101:101",
        ] {
            assert!(p.permits(ip(a)), "{a}");
        }
    }

    #[test]
    fn allowlist_and_private_switch() {
        let p = policy(false, &["100.82.0.0/16"]);
        assert!(p.permits(ip("100.82.4.5")));
        assert!(!p.permits(ip("100.83.0.1")));
        let p = policy(true, &[]);
        assert!(p.permits(ip("192.168.1.1")));
        assert!(!p.permits(ip("169.254.169.254")), "metadata stays blocked");
        let p = policy(false, &["169.254.169.254"]);
        assert!(p.permits(ip("169.254.169.254")), "explicit allow wins");
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("nope").is_err());
        assert!(
            Cidr::parse("0.0.0.0/0")
                .expect("all")
                .contains(ip("8.8.8.8"))
        );
    }

    #[test]
    fn discord_text_is_clipped_and_mention_safe() {
        let mut d = BTreeMap::new();
        for i in 0..50 {
            d.insert(
                format!("/data/{}/`x`", "a".repeat(80) + &i.to_string()),
                vec!["Eicar".into()],
            );
        }
        let e = Event {
            event: "scan.finished",
            job_id: "j".into(),
            kind: "PATH".into(),
            target: "/data".into(),
            endpoint: "default".into(),
            submitted_by: None,
            verdict: jobs::VIRUS_FOUND.into(),
            found_viruses: vec!["Eicar".into()],
            detections: d,
            files_scanned: 50,
            file_errors: 0,
            error_code: None,
            error: None,
            finished_at: String::new(),
        };
        assert!(e.is_alert());
        let t = discord_text(&e);
        assert!(t.chars().count() <= 1900);
        assert!(t.contains("and 40 more"));
        assert!(!t.contains("`x`"));
    }
}
