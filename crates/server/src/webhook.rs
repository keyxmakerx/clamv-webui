//! Outgoing alerts: plain JSON webhooks, Discord, Slack/Mattermost, ntfy and Gotify.
//! Every request is pinned to addresses checked against the SSRF policy,
//! redirects are off and the URL is never logged.

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
/// Most destinations one instance sends to.
pub const MAX_TARGETS: usize = 5;

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
pub struct Cidr {
    net: IpAddr,
    bits: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, String> {
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

    pub fn contains(&self, ip: IpAddr) -> bool {
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

/// How a destination wants the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Discord,
    Slack,
    Ntfy,
    Gotify,
}

impl Format {
    pub fn label(self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Discord => "Discord",
            Self::Slack => "Slack / Mattermost",
            Self::Ntfy => "ntfy",
            Self::Gotify => "Gotify",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Target {
    url: Url,
    format: Format,
    policy: Policy,
}

impl Target {
    /// Every configured destination (none when unset); an error for a bad URL or CIDR.
    pub fn from_config(cfg: &Config) -> anyhow::Result<Vec<Self>> {
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
        let cidrs = cfg
            .webhook_allowed_cidrs
            .iter()
            .filter(|c| !c.trim().is_empty())
            .map(|c| Cidr::parse(c))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("WEBHOOK_ALLOWED_CIDRS: {e}"))?;
        let policy = Policy {
            allow_private: cfg.webhook_allow_private,
            cidrs,
        };
        let parts: Vec<&str> = raw
            .split([',', '\n'])
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .collect();
        if parts.len() > MAX_TARGETS {
            anyhow::bail!("WEBHOOK_URL: at most {MAX_TARGETS} destinations");
        }
        parts
            .iter()
            .enumerate()
            .map(|(i, p)| {
                Self::parse(p, policy.clone())
                    .map_err(|e| anyhow::anyhow!("WEBHOOK_URL destination {}: {e}", i + 1))
            })
            .collect()
    }

    /// `https://…` (JSON, or Discord by host), or `ntfy+`, `gotify+`, `slack+`, `json+` in front.
    fn parse(raw: &str, policy: Policy) -> anyhow::Result<Self> {
        let (forced, rest) = match raw.split_once('+') {
            Some((p, rest)) if rest.starts_with("http") && !p.contains(':') => {
                let f = match p.to_ascii_lowercase().as_str() {
                    "ntfy" => Format::Ntfy,
                    "gotify" => Format::Gotify,
                    "slack" | "mattermost" => Format::Slack,
                    "discord" => Format::Discord,
                    "json" => Format::Json,
                    _ => anyhow::bail!("unknown prefix; use ntfy+, gotify+, slack+ or json+"),
                };
                (Some(f), rest)
            }
            _ => (None, raw),
        };
        // The URL may hold a token, so errors never quote it.
        let url = Url::parse(rest).map_err(|_| anyhow::anyhow!("not a valid URL"))?;
        if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
            anyhow::bail!("must be an http or https URL with a host");
        }
        if !url.username().is_empty() || url.password().is_some() {
            anyhow::bail!("must not contain credentials");
        }
        let discord = matches!(
            url.host_str(),
            Some("discord.com" | "discordapp.com" | "canary.discord.com" | "ptb.discord.com")
        ) && url.path().starts_with("/api/webhooks/");
        let format = forced.unwrap_or(if discord {
            Format::Discord
        } else {
            Format::Json
        });
        if format == Format::Ntfy
            && url
                .path_segments()
                .and_then(|mut s| s.next_back())
                .is_none_or(str::is_empty)
        {
            anyhow::bail!("an ntfy URL ends with the topic, e.g. ntfy+https://ntfy.sh/my-topic");
        }
        if format == Format::Gotify && !url.query_pairs().any(|(k, _)| k == "token") {
            anyhow::bail!("a Gotify URL needs ?token=<app token>");
        }
        Ok(Self {
            url,
            format,
            policy,
        })
    }

    pub fn host(&self) -> String {
        self.url.host_str().unwrap_or("").to_owned()
    }

    pub fn format(&self) -> Format {
        self.format
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

    /// Where to POST and what JSON to send.
    fn request(&self, e: &Event) -> (Url, serde_json::Value) {
        let sev = severity(e);
        match self.format {
            Format::Json => (
                self.url.clone(),
                serde_json::to_value(e).unwrap_or_default(),
            ),
            Format::Discord => (
                self.url.clone(),
                serde_json::json!({ "content": discord_text(e), "allowed_mentions": { "parse": [] } }),
            ),
            Format::Slack => (
                self.url.clone(),
                // Slack reads <…> as links and mentions, so escape as its docs require.
                serde_json::json!({ "text": discord_text(e)
                    .replace("**", "*")
                    .replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;") }),
            ),
            Format::Gotify => {
                let mut u = self.url.clone();
                u.set_path(&format!(
                    "{}/message",
                    self.url
                        .path()
                        .trim_end_matches('/')
                        .trim_end_matches("/message")
                ));
                (
                    u,
                    serde_json::json!({
                        "title": title(e),
                        "message": body_text(e),
                        "priority": gotify_priority(sev),
                        "extras": { "client::display": { "contentType": "text/markdown" } },
                    }),
                )
            }
            Format::Ntfy => {
                // JSON publishing goes to the server root with the topic in the body,
                // which keeps non-ASCII titles out of headers.
                let mut u = self.url.clone();
                let mut segs: Vec<String> = self
                    .url
                    .path_segments()
                    .map(|s| s.map(str::to_owned).collect())
                    .unwrap_or_default();
                let topic = segs.pop().unwrap_or_default();
                u.set_path(&format!("{}/", segs.join("/")));
                (
                    u,
                    serde_json::json!({
                        "topic": topic,
                        "title": title(e),
                        "message": body_text(e),
                        "priority": sev,
                        "tags": [tag(e)],
                        "markdown": true,
                    }),
                )
            }
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
        let (url, body) = self.request(e);
        let mut last = String::new();
        for attempt in 1..=ATTEMPTS {
            if attempt > 1 {
                tokio::time::sleep(Duration::from_secs(if attempt == 2 { 1 } else { 5 })).await;
            }
            match client.post(url.clone()).json(&body).send().await {
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

/// 1 (min) to 5 (urgent), on ntfy's scale.
fn severity(e: &Event) -> u8 {
    match (e.event, e.verdict.as_str()) {
        ("canary.tripped", _) => 5,
        ("eicar.control_failed", _) | (_, jobs::VIRUS_FOUND) => 4,
        ("test", _) | (_, jobs::ERROR) => 3,
        _ if e.file_errors > 0 => 3,
        _ => 2,
    }
}

fn gotify_priority(sev: u8) -> u8 {
    match sev {
        5 => 10,
        4 => 8,
        3 => 5,
        _ => 2,
    }
}

fn tag(e: &Event) -> &'static str {
    match severity(e) {
        5 => "rotating_light",
        4 => "biohazard",
        3 => "warning",
        _ => "white_check_mark",
    }
}

/// One line for a notification title.
fn title(e: &Event) -> String {
    let t = match (e.event, e.verdict.as_str()) {
        ("test", _) => "Test from clamv-webui".to_owned(),
        ("canary.tripped", _) => format!("Canary file touched on {}", e.endpoint),
        ("eicar.control_failed", _) => format!("EICAR check failed on {}", e.endpoint),
        (_, jobs::VIRUS_FOUND) => format!("Malware found on {}", e.endpoint),
        (_, jobs::ERROR) => format!("Scan failed on {}", e.endpoint),
        _ => format!("Scan finished on {}", e.endpoint),
    };
    clip(
        &t.chars()
            .map(|c| if is_bidi_control(c) { '\u{FFFD}' } else { c })
            .collect::<String>(),
        120,
    )
}

/// The chat text without its first line, which the title already says.
fn body_text(e: &Event) -> String {
    let full = discord_text(e);
    match full.split_once('\n') {
        Some((_, rest)) if !rest.trim().is_empty() => rest.to_owned(),
        _ => full.replace("**", ""),
    }
}

/// Bidirectional overrides can make `evil\u{202E}fdp.exe` read as `evil.exe.pdf`.
pub fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{200E}' | '\u{200F}' | '\u{061C}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

fn discord_text(e: &Event) -> String {
    let clean = |s: &str| {
        s.chars()
            .map(|c| if is_bidi_control(c) { '\u{FFFD}' } else { c })
            .collect::<String>()
            .replace('`', "'")
    };
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
    targets: Vec<Target>,
    events: WebhookEvents,
    ignore: Vec<String>,
    tx: mpsc::Sender<Event>,
    rx: Mutex<Option<mpsc::Receiver<Event>>>,
    last: Mutex<Vec<Option<Delivery>>>,
}

impl Notifier {
    pub fn new(cfg: &Config) -> Self {
        let targets = Target::from_config(cfg).unwrap_or_else(|e| {
            tracing::error!(event = "webhook.config_invalid", error = %e, "webhook disabled");
            Vec::new()
        });
        let (tx, rx) = mpsc::channel(QUEUE);
        Self {
            last: Mutex::new(vec![None; targets.len()]),
            targets,
            events: cfg.webhook_events,
            ignore: cfg
                .webhook_ignore_signatures
                .iter()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            tx,
            rx: Mutex::new(Some(rx)),
        }
    }

    pub fn targets(&self) -> &[Target] {
        &self.targets
    }

    /// Signature prefixes that never raise a notification on their own.
    pub fn ignored(&self) -> &[String] {
        &self.ignore
    }

    /// A detection whose every signature is on the ignore list, with nothing else wrong.
    fn muted(&self, e: &Event) -> bool {
        e.event == "scan.finished"
            && e.verdict == jobs::VIRUS_FOUND
            && e.file_errors == 0
            && !e.found_viruses.is_empty()
            && e.found_viruses.iter().all(|v| {
                let v = v.to_ascii_lowercase();
                self.ignore.iter().any(|p| v.starts_with(p.as_str()))
            })
    }

    pub fn events(&self) -> WebhookEvents {
        self.events
    }

    /// The latest delivery to any destination.
    pub fn last(&self) -> Option<Delivery> {
        self.last
            .lock()
            .ok()
            .and_then(|g| g.iter().flatten().max_by_key(|d| d.at).cloned())
    }

    /// The latest delivery per destination, in configured order.
    pub fn last_each(&self) -> Vec<Option<Delivery>> {
        self.last.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn notify(&self, e: Event) {
        if self.targets.is_empty() || (self.events == WebhookEvents::Alerts && !e.is_alert()) {
            return;
        }
        if self.muted(&e) {
            tracing::info!(event = "webhook.muted", job_id = %e.job_id, "detection matches WEBHOOK_IGNORE_SIGNATURES; not sent");
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
        if self.targets.is_empty() {
            return Err("No webhook is configured.".into());
        }
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
        let mut errs = Vec::new();
        for (i, t) in self.targets.iter().enumerate() {
            let r = t.deliver(&e).await;
            self.record(i, t, &e, &r);
            if let Err(m) = r {
                errs.push(if self.targets.len() > 1 {
                    format!("{} ({}): {m}", t.host(), t.format.label())
                } else {
                    m
                });
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("; "))
        }
    }

    fn record(&self, i: usize, t: &Target, e: &Event, r: &Result<(), String>) {
        match r {
            Ok(()) => {
                tracing::info!(event = "webhook.delivered", host = %t.host(), webhook_event = e.event, job_id = %e.job_id, "webhook delivered");
            }
            Err(m) => {
                tracing::error!(event = "webhook.failed", host = %t.host(), webhook_event = e.event, job_id = %e.job_id, reason = %m, "webhook delivery failed");
            }
        }
        let Ok(mut g) = self.last.lock() else { return };
        if let Some(slot) = g.get_mut(i) {
            *slot = Some(Delivery {
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
                for (i, t) in st.notifier.targets().iter().enumerate() {
                    let r = t.deliver(&e).await;
                    st.notifier.record(i, t, &e, &r);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

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

    fn hit(sigs: &[&str]) -> Event {
        let mut d = BTreeMap::new();
        d.insert(
            "/data/tv/x.mkv".to_owned(),
            sigs.iter().map(|s| (*s).to_owned()).collect(),
        );
        Event {
            event: "scan.finished",
            job_id: "j".into(),
            kind: "WATCH".into(),
            target: "/data/tv/x.mkv".into(),
            endpoint: "nas".into(),
            submitted_by: None,
            verdict: jobs::VIRUS_FOUND.into(),
            found_viruses: sigs.iter().map(|s| (*s).to_owned()).collect(),
            detections: d,
            files_scanned: 1,
            file_errors: 0,
            error_code: None,
            error: None,
            finished_at: String::new(),
        }
    }

    fn target(raw: &str) -> anyhow::Result<Target> {
        Target::parse(raw, policy(false, &[]))
    }

    #[test]
    fn formats_from_prefix_and_host() {
        assert_eq!(
            target("https://hooks.example/x").expect("t").format,
            Format::Json
        );
        assert_eq!(
            target("https://discord.com/api/webhooks/1/abc")
                .expect("t")
                .format,
            Format::Discord
        );
        assert_eq!(
            target("ntfy+https://ntfy.sh/alerts").expect("t").format,
            Format::Ntfy
        );
        assert_eq!(
            target("slack+https://chat.example/hooks/x")
                .expect("t")
                .format,
            Format::Slack
        );
        assert!(target("ntfy+https://ntfy.sh/").is_err(), "topic needed");
        assert!(target("gotify+https://g.example/").is_err(), "token needed");
        assert!(target("smtp+https://x.example/").is_err());
        let err = target("gotify+https://u:secret@g.example/?token=t").expect_err("creds");
        assert!(!err.to_string().contains("secret"));
    }

    #[test]
    fn ntfy_and_gotify_requests() {
        let e = hit(&["Win.Trojan.Agent"]);
        let (u, b) = target("ntfy+https://ntfy.example/sub/alerts?auth=abc")
            .expect("t")
            .request(&e);
        assert_eq!(u.as_str(), "https://ntfy.example/sub/?auth=abc");
        assert_eq!(b["topic"], "alerts");
        assert_eq!(b["priority"], 4);
        assert_eq!(b["title"], "Malware found on nas");
        assert!(
            b["message"]
                .as_str()
                .is_some_and(|m| m.contains("Win.Trojan.Agent"))
        );
        let (u, b) = target("gotify+https://g.example/?token=t")
            .expect("t")
            .request(&e);
        assert_eq!(u.as_str(), "https://g.example/message?token=t");
        assert_eq!(b["priority"], 8);
        let (_, b) = target("slack+https://chat.example/h")
            .expect("t")
            .request(&hit(&["<!channel>"]));
        assert!(
            b["text"]
                .as_str()
                .is_some_and(|t| !t.contains("<!channel>"))
        );
        let (_, b) = target("slack+https://chat.example/h")
            .expect("t")
            .request(&e);
        assert!(
            b["text"]
                .as_str()
                .is_some_and(|t| t.starts_with("*Malware found*"))
        );
    }

    #[test]
    fn ignored_signatures_mute_only_pure_matches() {
        let cfg = crate::config::Cli::try_parse_from([
            "clamv-webui",
            "--webhook-url",
            "https://hooks.example/x",
            "--webhook-ignore-signatures",
            "PUA.,Heuristics.Encrypted",
        ])
        .expect("parse")
        .config;
        let n = Notifier::new(&cfg);
        assert!(n.muted(&hit(&["PUA.Win.Packer"])));
        assert!(n.muted(&hit(&["pua.x", "Heuristics.Encrypted.Zip"])));
        assert!(!n.muted(&hit(&["PUA.Win.Packer", "Win.Trojan.Agent"])));
        let mut failed = hit(&["PUA.Win.Packer"]);
        failed.file_errors = 1;
        assert!(!n.muted(&failed));
    }

    #[test]
    fn several_destinations_capped() {
        let parse = |u: &str| {
            let c = crate::config::Cli::try_parse_from(["clamv-webui", "--webhook-url", u])
                .expect("parse")
                .config;
            Target::from_config(&c)
        };
        let two = parse("https://a.example/x, ntfy+https://ntfy.sh/t").expect("two");
        assert_eq!(two.len(), 2);
        assert!(parse(&["https://a.example/x"; 6].join(",")).is_err());
        assert!(parse("").expect("none").is_empty());
    }
}
