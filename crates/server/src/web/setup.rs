//! Setup: what works on this server, what is missing, and the exact compose
//! lines that fix each missing thing. The same guides feed the "not set up
//! yet" panels on feature pages. Checks read state that is already there
//! (cached probes, config, files); the one network call, the clamd probe, is
//! short, so the page never hangs.

use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use askama::Template;
use axum::Router;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use serde::Deserialize;

use super::admin::admin_post;
use super::endpoints::{self, Status};
use super::session::Auth;
use super::{Nav, error_page, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::config::Config;
use crate::db::now_ms;
use crate::db::users::User;

pub fn routes() -> Router<Arc<AppState>> {
    // The router is built once at start, so this is the server's start time.
    STARTED.get_or_init(now_ms);
    Router::new()
        .route("/admin/setup", get(page))
        .route("/admin/setup/dismiss", post(dismiss))
}

static STARTED: OnceLock<i64> = OnceLock::new();

/// clamd that never answered since start counts as still starting for this long.
const STARTING_MS: i64 = 20 * 60_000;
const CLAMD_PROBE: Duration = Duration::from_secs(2);
const FS_PROBE: Duration = Duration::from_secs(1);
const DOCS: &str = "https://github.com/keyxmakerx/palisade/blob/main/docs/";
const DISMISSED: &str = "ui.setup_dismissed.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Required,
    Recommended,
    Optional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Ok,
    Attention,
    Off,
    Broken,
    /// Working on it by itself (signatures downloading, LAPI connecting).
    Pending,
    /// A reminder, never a problem.
    Note,
}

impl Health {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Attention => "needs attention",
            Self::Off => "not set up (optional)",
            Self::Broken => "broken",
            Self::Pending => "in progress",
            Self::Note => "reminder",
        }
    }

    pub fn badge(self) -> &'static str {
        match self {
            Self::Ok => "badge-ok",
            Self::Attention => "badge-warn",
            Self::Off => "badge-muted",
            Self::Broken => "badge-danger",
            Self::Pending => "badge-info",
            Self::Note => "badge-muted",
        }
    }

    /// The Setup row's state class (`is-…`), for its status icon and edge colour.
    pub fn tone(self) -> &'static str {
        match self {
            Self::Ok | Self::Note => "is-done",
            Self::Attention => "is-warn",
            Self::Off => "is-off",
            Self::Broken => "is-danger",
            Self::Pending => "is-pending",
        }
    }

    /// The Font Awesome icon for the Setup row's status.
    pub fn icon(self) -> &'static str {
        match self {
            Self::Ok => "fa-check",
            Self::Note => "fa-info",
            Self::Attention => "fa-exclamation",
            Self::Off => "fa-minus",
            Self::Broken => "fa-times",
            Self::Pending => "fa-hourglass-half",
        }
    }

    /// Needs the operator to do something.
    pub fn needs_action(self) -> bool {
        matches!(self, Self::Attention | Self::Broken)
    }
}

/// What a capability gives you and how to turn it on.
pub struct Guide {
    /// Anchor on the Setup page.
    pub key: &'static str,
    pub title: &'static str,
    /// One sentence: what it gives you.
    pub gives: &'static str,
    /// The compose service the lines go into.
    pub service: &'static str,
    /// `environment:` lines, each with a one-line comment.
    pub env: &'static [&'static str],
    /// `volumes:` lines, each with a one-line comment.
    pub volumes: &'static [&'static str],
    /// Steps outside compose: (text, command or path shown as code).
    pub steps: &'static [(&'static str, &'static str)],
    /// The page in this app that does it: (path, link text).
    pub page: Option<(&'static str, &'static str)>,
    /// Docs file and anchor under docs/.
    pub docs: &'static str,
}

impl Guide {
    /// Lines to paste under the service in docker-compose.yml.
    pub fn compose(&self) -> String {
        let mut out = String::new();
        if !self.env.is_empty() {
            out.push_str("    environment:\n");
            for l in self.env {
                out.push_str("      ");
                out.push_str(l);
                out.push('\n');
            }
        }
        if !self.volumes.is_empty() {
            out.push_str("    volumes:\n");
            for l in self.volumes {
                out.push_str("      - ");
                out.push_str(l);
                out.push('\n');
            }
        }
        out.trim_end().to_owned()
    }

    pub fn docs_url(&self) -> String {
        format!("{DOCS}{}", self.docs)
    }
}

pub const GUIDES: &[Guide] = &[
    Guide {
        key: "clamd",
        title: "Virus scanner (clamd)",
        gives: "Scans uploads, folders and schedules; nothing else here scans without it.",
        service: "palisade",
        env: &["CLAMD_ENDPOINT: tcp://clamav:3310  # the clamav service in the same compose file"],
        volumes: &[],
        steps: &[
            (
                "Keep the clamav service from the default compose file running. Its first start downloads about 300 MB of signatures, which takes a few minutes.",
                "",
            ),
            (
                "It turns healthy once clamd answers; to watch the download:",
                "docker compose logs -f clamav",
            ),
        ],
        page: Some(("/admin/endpoints", "clamd endpoints")),
        docs: "CONFIGURATION.md#clamd-and-scanning",
    },
    Guide {
        key: "signatures",
        title: "Signature updates",
        gives: "Fresh signatures catch new malware; freshclam in the clamav container updates them several times a day.",
        service: "clamav",
        env: &[],
        volumes: &["clamav-db:/var/lib/clamav  # keeps signatures across restarts"],
        steps: &[
            (
                "The clamav container needs outbound HTTPS to database.clamav.net.",
                "",
            ),
            (
                "Old signatures mean freshclam keeps failing; its log says why:",
                "docker compose logs clamav",
            ),
        ],
        page: Some(("/clamd", "clamd status")),
        docs: "CONFIGURATION.md#clamd-and-scanning",
    },
    Guide {
        key: "scan-roots",
        title: "Folders to scan",
        gives: "Path scans, schedules and watched folders work only inside SCAN_ROOTS; uploads work without it.",
        service: "palisade",
        env: &["SCAN_ROOTS: /scan  # comma-separated folders inside the container"],
        volumes: &[
            "/srv/files:/scan:ro  # the host folder to scan; mount it the same way in the clamav service",
        ],
        steps: &[
            (
                "clamd opens the files itself, so mount the same host folder at the same path in the clamav service too.",
                "",
            ),
            ("Read-only (:ro) is enough unless you use quarantine.", ""),
        ],
        page: Some(("/scan", "Scan")),
        docs: "CONFIGURATION.md#clamd-and-scanning",
    },
    Guide {
        key: "data-dir",
        title: "Data folder",
        gives: "Holds the database, the key that encrypts 2FA secrets, and the TLS certificate.",
        service: "palisade",
        env: &[],
        volumes: &[
            "palisade-data:/app/data  # named volume; starts owned by UID 10001, no chown needed",
        ],
        steps: &[
            (
                "Also declare it at the bottom of the compose file, under volumes:",
                "palisade-data:",
            ),
            (
                "Keeping a host folder instead? Give it to the container's user:",
                "sudo chown -R 10001:10001 ./data",
            ),
        ],
        page: None,
        docs: "CONFIGURATION.md#core",
    },
    Guide {
        key: "admin",
        title: "Admin sign-in",
        gives: "The first admin account starts with a one-time password that must be replaced.",
        service: "palisade",
        env: &[],
        volumes: &[],
        steps: &[
            (
                "Sign in as admin and choose your own password; Palisade then deletes",
                "DATA_DIR/bootstrap-admin-password",
            ),
            (
                "Copy the one-time password to the host without printing it, then open ./admin-password:",
                "docker compose cp palisade:/app/data/bootstrap-admin-password ./admin-password",
            ),
            (
                "Delete ./admin-password once you have signed in. BOOTSTRAP_ADMIN_PASSWORD_FILE only matters on the very first start.",
                "",
            ),
        ],
        page: Some(("/account/password", "Change password")),
        docs: "SECURITY.md#admins-and-tokens",
    },
    Guide {
        key: "2fa",
        title: "Two-factor sign-in for admins",
        gives: "An authenticator app or passkey stops a leaked password from opening the console.",
        service: "palisade",
        env: &[
            "REQUIRE_ADMIN_2FA: \"true\"  # admins must add a second factor before using the app",
        ],
        volumes: &[],
        steps: &[(
            "Each admin adds an authenticator app or passkey under Account security.",
            "",
        )],
        page: Some(("/account/security", "Account security")),
        docs: "SECURITY.md#admins-and-tokens",
    },
    Guide {
        key: "https",
        title: "HTTPS",
        gives: "Passkeys and remote agents need HTTPS, and it keeps passwords off the wire.",
        service: "palisade",
        env: &[
            "TLS_SELF_SIGNED: \"true\"  # HTTPS with a certificate kept in DATA_DIR/tls",
            "TLS_SELF_SIGNED_NAMES: palisade.lan,192.168.1.10  # the names and IPs you open it by",
        ],
        volumes: &[],
        steps: &[(
            "Behind a reverse proxy instead: let the proxy do HTTPS and set PUBLIC_URL and TRUSTED_PROXIES (see Public address).",
            "",
        )],
        page: None,
        docs: "REVERSE_PROXY.md#what-the-app-needs",
    },
    Guide {
        key: "public-url",
        title: "Public address",
        gives: "Passkeys are bound to one host name; PUBLIC_URL fixes it and refuses requests for other names.",
        service: "palisade",
        env: &[
            "PUBLIC_URL: https://palisade.example.com  # the address users open",
            "ALLOWED_HOSTS: palisade.lan  # other names that may open it; passkeys still use PUBLIC_URL's",
            "TRUSTED_PROXIES: 172.16.0.0/12  # your reverse proxy, so its X-Forwarded-Proto is believed",
        ],
        volumes: &[],
        steps: &[],
        page: None,
        docs: "REVERSE_PROXY.md#what-the-app-needs",
    },
    Guide {
        key: "schedules",
        title: "Scheduled scans",
        gives: "A nightly scan of your folders catches what slipped in during the day.",
        service: "palisade",
        env: &[],
        volumes: &[],
        steps: &[(
            "Add a schedule, e.g. every night at 03:00 over your scan root, with the EICAR check on.",
            "",
        )],
        page: Some(("/admin/schedules", "Add a schedule")),
        docs: "CONFIGURATION.md#clamd-and-scanning",
    },
    Guide {
        key: "alerts",
        title: "Alerts",
        gives: "Detections, failed scans and canary hits reach your phone or chat instead of waiting here.",
        service: "palisade",
        env: &[
            "WEBHOOK_URL_FILE: /run/secrets/webhook_url  # file with up to 5 comma-separated URLs",
        ],
        volumes: &[
            "./secrets/webhook_url:/run/secrets/webhook_url:ro  # keeps the URL out of the compose file",
        ],
        steps: &[
            (
                "Put the URL in that file (readable by UID 10001). Discord is detected; prefix ntfy+, gotify+ or slack+ for those.",
                "./secrets/webhook_url",
            ),
            (
                "A destination on your LAN also needs WEBHOOK_ALLOWED_CIDRS.",
                "",
            ),
        ],
        page: Some(("/admin/integrations", "Send a test message")),
        docs: "CONFIGURATION.md#alerts-webhook-ntfy-gotify-slack-discord",
    },
    Guide {
        key: "quarantine",
        title: "Quarantine",
        gives: "Moves infected files out of reach and keeps a locked copy you can restore.",
        service: "palisade",
        env: &[
            "QUARANTINE_DIR: /app/data/quarantine  # where infected files are moved; created on start",
        ],
        volumes: &["/srv/files:/scan  # scan roots must be read-write (no :ro) to move files out"],
        steps: &[(
            "Files Palisade cannot delete stay put; on the host, give the scan folder to UID 10001:",
            "sudo chown -R 10001 /srv/files",
        )],
        page: Some(("/admin/quarantine", "Quarantine")),
        docs: "CONFIGURATION.md#quarantine",
    },
    Guide {
        key: "crowdsec",
        title: "CrowdSec",
        gives: "See CrowdSec's alerts and decisions here, and ban or unban addresses.",
        service: "palisade",
        env: &[
            "CROWDSEC_LAPI_URL: http://crowdsec:8080  # your CrowdSec Local API",
            "CROWDSEC_PASSWORD_FILE: /run/secrets/crowdsec_pw  # the watcher password",
        ],
        volumes: &["./secrets/crowdsec_pw:/run/secrets/crowdsec_pw:ro  # readable by UID 10001"],
        steps: &[
            (
                "Easiest: start from docker-compose.full.yml, which runs CrowdSec and registers the watcher for you.",
                "",
            ),
            (
                "Your own CrowdSec container: make a random password file, then give CrowdSec the same file and set AGENT_USERNAME=palisade and AGENT_PASSWORD from it, as docker-compose.full.yml does.",
                "(umask 077; mkdir -p secrets; openssl rand -hex 24 > secrets/crowdsec_pw)",
            ),
            (
                "To hide the ban and unban buttons, also set",
                "CROWDSEC_READ_ONLY: \"true\"",
            ),
        ],
        page: Some(("/crowdsec", "CrowdSec")),
        docs: "CONFIGURATION.md#crowdsec",
    },
    Guide {
        key: "integrity",
        title: "AIDE and rkhunter reports",
        gives: "Rootkit and changed-system-file findings from this host, read from their logs.",
        service: "palisade",
        env: &[],
        volumes: &[
            "/var/log/aide:/var/log/aide:ro  # AIDE --check output (AIDE_LOG)",
            "/var/log/rkhunter.log:/var/log/rkhunter.log:ro  # rkhunter log (RKHUNTER_LOG)",
        ],
        steps: &[(
            "Install aide and rkhunter on the host; their daily runs write those logs.",
            "",
        )],
        page: Some(("/integrity", "Host checks")),
        docs: "CONFIGURATION.md#managed-host-checks-and-firewall",
    },
    Guide {
        key: "host-setup",
        title: "Managed host checks and firewall",
        gives: "Start AIDE and rkhunter and manage the firewall from here, without root in the container.",
        service: "palisade",
        env: &[],
        volumes: &[
            "/run/dbus/system_bus_socket:/run/dbus/system_bus_socket:ro  # lets Palisade start its fixed host units",
            "/var/lib/palisade/firewall:/var/lib/palisade/firewall  # firewall snapshots and plans",
            "/var/lib/palisade/timers:/var/lib/palisade/timers  # daily check times",
        ],
        steps: &[(
            "Once, on the host, install the units and the polkit rule:",
            "docker run --rm --user 0 -v /:/host ghcr.io/keyxmakerx/palisade:latest host-setup",
        )],
        page: Some(("/admin/firewall", "Firewall")),
        docs: "CONFIGURATION.md#managed-host-checks-and-firewall",
    },
    Guide {
        key: "falco",
        title: "Falco runtime alerts",
        gives: "Suspicious behaviour on this host (shells in containers, odd file access) shows up within seconds.",
        service: "palisade",
        env: &[],
        volumes: &["/var/log/falco:/var/log/falco:ro  # Falco's JSON alerts (FALCO_EVENTS)"],
        steps: &[(
            "In falco.yaml set json_output: true and file_output to",
            "/var/log/falco/events.json",
        )],
        page: Some(("/integrity", "Host checks")),
        docs: "CONFIGURATION.md#managed-host-checks-and-firewall",
    },
    Guide {
        key: "canaries",
        title: "Canary files",
        gives: "Decoy files that alert the moment anything opens them: an early sign of ransomware or snooping.",
        service: "palisade",
        env: &[],
        volumes: &["/srv/share:/srv/share  # the folder that holds the decoys, at the same path"],
        steps: &[
            (
                "Add a decoy next to what it guards, outside scanned folders (scans open every file).",
                "",
            ),
            (
                "Mount that folder read-write if Palisade should write the decoy for you.",
                "",
            ),
        ],
        page: Some(("/admin/canaries", "Add a canary")),
        docs: "CONFIGURATION.md#agents",
    },
    Guide {
        key: "auditd",
        title: "Who touched a canary (auditd)",
        gives: "Names the program and user behind a canary hit.",
        service: "palisade",
        env: &[],
        volumes: &["/var/log/audit:/var/log/audit:ro  # auditd log"],
        steps: &[
            (
                "Add one auditd rule per canary on the host; the Canaries page shows each rule.",
                "",
            ),
            (
                "auditd's log is root-only by default: set log_group in auditd.conf to a group UID 10001 is in.",
                "",
            ),
        ],
        page: Some(("/admin/canaries", "Canaries")),
        docs: "CONFIGURATION.md#agents",
    },
    Guide {
        key: "watch",
        title: "Watched folders",
        gives: "New files are scanned the moment they are written.",
        service: "palisade",
        env: &[],
        volumes: &[],
        steps: &[("Add a folder inside SCAN_ROOTS.", "")],
        page: Some(("/admin/watch", "Watch a folder")),
        docs: "CONFIGURATION.md#clamd-and-scanning",
    },
    Guide {
        key: "metrics",
        title: "Prometheus metrics",
        gives: "Scan, detection and clamd metrics for Prometheus and the bundled Grafana dashboard.",
        service: "palisade",
        env: &[
            "METRICS_TOKEN_FILE: /run/secrets/metrics_token  # 16+ random characters; Prometheus sends it as a Bearer token",
        ],
        volumes: &[
            "./secrets/metrics_token:/run/secrets/metrics_token:ro  # readable by UID 10001",
        ],
        steps: &[(
            "Make the token file:",
            "openssl rand -hex 24 > secrets/metrics_token",
        )],
        page: Some(("/admin/integrations", "Grafana and Prometheus files")),
        docs: "CONFIGURATION.md#metrics",
    },
    Guide {
        key: "sso",
        title: "Single sign-on (OIDC or LDAP)",
        gives: "Sign in with your existing accounts; roles come from your groups.",
        service: "palisade",
        env: &[
            "OIDC_ISSUER: https://auth.example.com/realms/main  # your provider",
            "OIDC_CLIENT_ID: palisade  # the client registered there",
            "OIDC_CLIENT_SECRET_FILE: /run/secrets/oidc_secret  # its secret",
            "OIDC_REDIRECT_URI: https://palisade.example.com/login/oauth2/code/clamav  # register this at the provider",
            "OIDC_ADMIN_GROUPS: palisade-admins  # groups that become admins",
        ],
        volumes: &["./secrets/oidc_secret:/run/secrets/oidc_secret:ro  # readable by UID 10001"],
        steps: &[(
            "For LDAP instead set LDAP_URL, LDAP_BIND_DN, LDAP_BIND_PASSWORD_FILE, LDAP_USER_BASE and LDAP_ADMIN_GROUPS.",
            "",
        )],
        page: None,
        docs: "CONFIGURATION.md#oidc-single-sign-on",
    },
    Guide {
        key: "agents",
        title: "Remote agents",
        gives: "Scan, watch and check other machines from this console.",
        service: "palisade",
        env: &["TLS_SELF_SIGNED: \"true\"  # agents connect over HTTPS only"],
        volumes: &[],
        steps: &[("Add an agent; the page shows what to run on that host.", "")],
        page: Some(("/admin/agents", "Add an agent")),
        docs: "CONFIGURATION.md#agents",
    },
    Guide {
        key: "backups",
        title: "Backups",
        gives: "The data folder holds everything Palisade knows; without secret.key, stored 2FA secrets cannot be read.",
        service: "palisade",
        env: &[],
        volumes: &[],
        steps: &[
            (
                "Copy the data folder (./data with the default compose) to your backups regularly.",
                "",
            ),
            (
                "With an external DATABASE_URL, back that database up as well.",
                "",
            ),
        ],
        page: None,
        docs: "ARCHITECTURE.md#data",
    },
];

/// Shown if a template names a guide that does not exist (a test keeps that from happening).
const UNKNOWN: Guide = Guide {
    key: "",
    title: "This feature",
    gives: "",
    service: "palisade",
    env: &[],
    volumes: &[],
    steps: &[],
    page: None,
    docs: "CONFIGURATION.md",
};

/// The guide for `key`, for templates' "not set up yet" panels.
pub fn guide(key: &str) -> &'static Guide {
    GUIDES.iter().find(|g| g.key == key).unwrap_or(&UNKNOWN)
}

pub struct Row {
    pub guide: &'static Guide,
    pub group: Group,
    pub health: Health,
    /// What was found, one or two sentences.
    pub detail: String,
}

impl Row {
    /// What a dismissal remembers about this row.
    fn token(&self) -> String {
        format!("{}:{:?}", self.guide.key, self.health)
    }
}

pub struct Report {
    pub rows: Vec<Row>,
}

impl Report {
    fn core(&self) -> impl Iterator<Item = &Row> {
        self.rows.iter().filter(|r| r.group != Group::Optional)
    }

    /// Required and recommended rows the operator has to act on.
    pub fn attention(&self) -> Vec<&Row> {
        self.core().filter(|r| r.health.needs_action()).collect()
    }

    /// Required and recommended rows that are not done yet, still-starting ones
    /// included, as `key:state` so a hidden "in progress" never hides a later "broken".
    pub fn incomplete(&self) -> Vec<String> {
        self.core()
            .filter(|r| r.health.needs_action() || r.health == Health::Pending)
            .map(Row::token)
            .collect()
    }

    pub fn pending(&self) -> bool {
        self.rows.iter().any(|r| r.health == Health::Pending)
    }
}

/// File-system facts for the checks, gathered off the request path: a hung mount never
/// stalls a page, and no request ever drives a file-system call.
#[derive(Clone)]
pub struct FsFacts {
    data_dir: (Health, String),
    backups: (Health, String),
    /// The one-time admin password file, while it exists.
    pub bootstrap_file: Option<String>,
    falco: (Health, String),
    audit: (Health, String),
    integrity: (Health, String),
}

impl FsFacts {
    fn checking() -> Self {
        let c = || (Health::Pending, "Checking...".to_owned());
        Self {
            data_dir: c(),
            backups: c(),
            bootstrap_file: None,
            falco: c(),
            audit: c(),
            integrity: c(),
        }
    }

    /// Read everything once. Blocking: call it from a thread or `spawn_blocking`.
    pub fn gather(cfg: &Config) -> Self {
        let boot = crate::auth::bootstrap::file(&cfg.data_dir);
        Self {
            data_dir: data_dir(&cfg.data_dir),
            backups: backups(cfg),
            bootstrap_file: boot.is_file().then(|| boot.display().to_string()),
            falco: readable_file(&cfg.falco_events, "FALCO_EVENTS"),
            audit: readable_file(Path::new(crate::canary::AUDIT_LOG), "the auditd log"),
            integrity: integrity(cfg),
        }
    }
}

/// The latest `FsFacts`, refreshed in the background.
pub struct FsCache(std::sync::RwLock<FsFacts>);

impl FsCache {
    /// Gather once at start, giving up after two seconds (rows then say "Checking...").
    pub fn new(cfg: &Config) -> Self {
        let c = cfg.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(FsFacts::gather(&c));
        });
        let first = rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|_| FsFacts::checking());
        Self(std::sync::RwLock::new(first))
    }

    pub fn get(&self) -> FsFacts {
        self.0
            .read()
            .map(|f| f.clone())
            .unwrap_or_else(|_| FsFacts::checking())
    }

    fn set(&self, f: FsFacts) {
        if let Ok(mut g) = self.0.write() {
            *g = f;
        }
    }

    /// The one-time password file was just removed.
    pub fn bootstrap_removed(&self) {
        if let Ok(mut g) = self.0.write() {
            g.bootstrap_file = None;
        }
    }
}

/// Gather again now (a few seconds at most) and keep the result.
pub async fn refresh_fs(st: &AppState) {
    let c = st.cfg.clone();
    let job = tokio::task::spawn_blocking(move || FsFacts::gather(&c));
    if let Ok(Ok(f)) = tokio::time::timeout(Duration::from_secs(5), job).await {
        st.setup_fs.set(f);
    }
}

/// Keep `FsFacts` fresh while the server runs.
pub fn spawn_fs_refresh(st: Arc<AppState>) {
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(15));
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            t.tick().await;
            refresh_fs(&st).await;
        }
    });
}

/// What the check knows about the request it answers.
pub struct Ctx {
    /// Host header as sent.
    pub host: Option<String>,
    /// Came over HTTPS (TLS here, or a trusted proxy said so).
    pub https: bool,
    /// Probe clamd; otherwise only the last background sample is used.
    pub probe: bool,
}

fn row(key: &str, group: Group, state: Health, detail: impl Into<String>) -> Row {
    Row {
        guide: guide(key),
        group,
        health: state,
        detail: detail.into(),
    }
}

/// Run every check. Each one is bounded; nothing here waits on a slow service for long.
pub async fn evaluate(st: &AppState, ctx: &Ctx) -> Report {
    use Group::{Optional, Recommended, Required};
    let now = now_ms();
    let (clamd_state, clamd_detail, sigs) = clamd(st, ctx.probe, now).await;
    let mut rows = vec![row("clamd", Required, clamd_state, clamd_detail)];
    let (s, d) = signatures(&sigs, clamd_state, now);
    rows.push(row("signatures", Required, s, d));
    let (s, d) = scan_roots(st).await;
    rows.push(row("scan-roots", Required, s, d));
    let fs = st.setup_fs.get();
    let (s, d) = fs.data_dir.clone();
    rows.push(row("data-dir", Required, s, d));
    let admins = st.db.list_users().await.unwrap_or_default();
    let (s, d) = admin(st, &fs, &admins);
    rows.push(row("admin", Required, s, d));

    let (s, d) = two_factor(st, &admins).await;
    rows.push(row("2fa", Recommended, s, d));
    let (s, d) = https(st, ctx);
    rows.push(row("https", Recommended, s, d));
    let (s, d) = public_url(st, ctx);
    rows.push(row("public-url", Recommended, s, d));
    let (s, d) = schedules(st).await;
    rows.push(row("schedules", Recommended, s, d));
    let (s, d) = alerts(st);
    rows.push(row("alerts", Recommended, s, d));
    let (s, d) = fs.backups.clone();
    rows.push(row("backups", Recommended, s, d));

    let (s, d) = quarantine(st);
    rows.push(row("quarantine", Optional, s, d));
    let (s, d) = crowdsec(st);
    rows.push(row("crowdsec", Optional, s, d));
    let (s, d) = fs.integrity.clone();
    rows.push(row("integrity", Optional, s, d));
    let (s, d) = host_setup(st);
    rows.push(row("host-setup", Optional, s, d));
    let (s, d) = fs.falco.clone();
    rows.push(row("falco", Optional, s, d));
    let (s, d) = canaries(st).await;
    rows.push(row("canaries", Optional, s, d));
    let (s, d) = fs.audit.clone();
    rows.push(row("auditd", Optional, s, d));
    let (s, d) = watch(st).await;
    rows.push(row("watch", Optional, s, d));
    let (s, d) = metrics(st);
    rows.push(row("metrics", Optional, s, d));
    let (s, d) = sso(st);
    rows.push(row("sso", Optional, s, d));
    let (s, d) = agents(st, ctx, now).await;
    rows.push(row("agents", Optional, s, d));
    Report { rows }
}

/// What is known about the signatures: the VERSION reply, or only the sampler's "stale" flag.
pub enum Sigs {
    Version(String),
    Sampled { stale: bool },
    Unknown,
}

async fn clamd(st: &AppState, probe: bool, now: i64) -> (Health, String, Sigs) {
    let ep = match st.db.default_endpoint().await {
        Ok(Some(ep)) => ep,
        Ok(None) => {
            return (
                Health::Broken,
                "No enabled default clamd endpoint. Add one, or enable and mark one as default, under clamd endpoints.".into(),
                Sigs::Unknown,
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "setup: endpoint lookup failed");
            return (
                Health::Broken,
                "The database did not answer the endpoint lookup; see the server log.".into(),
                Sigs::Unknown,
            );
        }
    };
    // The background sampler's last word on this endpoint (every 30 s).
    let sampled = st
        .metrics
        .clamd_status()
        .into_iter()
        .find(|c| c.name == ep.name);
    let answered_before = sampled.as_ref().is_some_and(|c| c.sampled != "never");
    let status = if probe {
        match tokio::time::timeout(CLAMD_PROBE, endpoints::probe(st, &ep)).await {
            Ok(s) => s,
            Err(_) => Status::Down("timed out".into()),
        }
    } else {
        match &sampled {
            Some(c) if c.available => Status::Up(String::new()),
            _ => Status::Down("not sampled yet".into()),
        }
    };
    match status {
        Status::Up(v) => {
            let text = if v.is_empty() {
                format!("clamd at {} answers.", ep.address)
            } else {
                format!(
                    "clamd at {} answers: {}.",
                    ep.address,
                    crate::api::split_version(&v).0
                )
            };
            let sigs = if v.is_empty() {
                Sigs::Sampled {
                    stale: sampled.as_ref().is_some_and(|c| c.stale),
                }
            } else {
                Sigs::Version(v)
            };
            (Health::Ok, text, sigs)
        }
        Status::Disabled => (
            Health::Broken,
            format!("The default endpoint {} is disabled.", ep.name),
            Sigs::Unknown,
        ),
        Status::Down(why) => {
            let started = STARTED.get().copied().unwrap_or(now);
            if !answered_before && now - started < STARTING_MS {
                (
                    Health::Pending,
                    format!(
                        "clamd at {} is not answering yet. On a first start it is still downloading signatures (about 300 MB, a few minutes); this page checks again by itself.",
                        ep.address
                    ),
                    Sigs::Unknown,
                )
            } else {
                (
                    Health::Broken,
                    format!(
                        "clamd at {} is not answering ({why}). Check that the clamav container is running and healthy.",
                        ep.address
                    ),
                    Sigs::Unknown,
                )
            }
        }
    }
}

fn signatures(sigs: &Sigs, clamd: Health, now: i64) -> (Health, String) {
    let v = match sigs {
        Sigs::Version(v) => v,
        Sigs::Sampled { stale: true } => {
            return (
                Health::Broken,
                "Signatures are over a week old: freshclam is not updating them.".into(),
            );
        }
        Sigs::Sampled { stale: false } => {
            return (Health::Ok, "Signatures are under a week old.".into());
        }
        Sigs::Unknown if clamd == Health::Ok => {
            return (Health::Pending, "Shown on the next check.".into());
        }
        Sigs::Unknown => return (Health::Pending, "Shown once clamd answers.".into()),
    };
    let (_, db, time) = crate::api::split_version(v);
    let db = db.map(|d| format!(" (database {d})")).unwrap_or_default();
    match time.as_deref().and_then(crate::timefmt::parse_clamd_date) {
        Some(t) => {
            let h = (now - t).max(0) / 3_600_000;
            let age = if h < 48 {
                format!("{h} h")
            } else {
                format!("{} days", h / 24)
            };
            if h <= 48 {
                (Health::Ok, format!("Signatures are {age} old{db}."))
            } else if h <= 168 {
                (
                    Health::Attention,
                    format!("Signatures are {age} old{db}; freshclam should update them daily."),
                )
            } else {
                (
                    Health::Broken,
                    format!("Signatures are {age} old{db}: freshclam is not updating them."),
                )
            }
        }
        None => (
            Health::Attention,
            "clamd did not say how old its signatures are.".into(),
        ),
    }
}

/// Exists, is a directory, and can be listed. Bounded, since a dead network mount can hang.
async fn probe_dir(p: &Path) -> Result<(), String> {
    let p = p.to_path_buf();
    let job = tokio::task::spawn_blocking(move || {
        let m = std::fs::metadata(&p).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => "does not exist in the container".to_owned(),
            std::io::ErrorKind::PermissionDenied => "is not readable by UID 10001".to_owned(),
            _ => format!("cannot be read ({e})"),
        })?;
        if !m.is_dir() {
            return Err("is not a folder".into());
        }
        std::fs::read_dir(&p).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => "is not readable by UID 10001".to_owned(),
            _ => format!("cannot be listed ({e})"),
        })?;
        Ok(())
    });
    match tokio::time::timeout(FS_PROBE, job).await {
        Ok(Ok(r)) => r,
        _ => Err("did not answer within a second (a hung network mount?)".into()),
    }
}

async fn scan_roots(st: &AppState) -> (Health, String) {
    let roots = &st.cfg.scan_roots;
    if roots.is_empty() {
        return (
            Health::Attention,
            "SCAN_ROOTS is not set, so path scans, schedules and watched folders are off. Uploads still work.".into(),
        );
    }
    let mut bad = Vec::new();
    for r in roots {
        if let Err(why) = probe_dir(r).await {
            bad.push(format!("{} {why}", r.display()));
        }
    }
    if !bad.is_empty() {
        return (
            Health::Broken,
            format!("{}. Mount the host folder there.", bad.join("; ")),
        );
    }
    let list = roots
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    // clamd opens files by path itself; the last path scan shows whether it sees the same folders.
    let last = st
        .db
        .list_jobs(
            &crate::db::jobs::JobFilter {
                kind: Some(crate::scan::KIND_PATH.into()),
                status: Some(crate::db::jobs::FINISHED.into()),
                ..Default::default()
            },
            0,
            5,
        )
        .await
        .map(|(j, _)| j)
        .unwrap_or_default()
        .into_iter()
        .find(|j| j.agent_id.is_none());
    let blind = last.as_ref().is_some_and(|j| {
        j.files_scanned == 0
            && j.errors.iter().any(|e| {
                let m = e.message.to_ascii_lowercase();
                m.contains("lstat") || m.contains("no such file")
            })
    });
    match last {
        Some(_) if blind => (
            Health::Attention,
            format!(
                "{list} readable here, but clamd could not find the files in the last path scan. Mount the same host folder at the same path in the clamav service."
            ),
        ),
        Some(j) => (
            Health::Ok,
            format!(
                "{list} readable; clamd read {} file(s) there in the last path scan.",
                j.files_scanned
            ),
        ),
        None => (
            Health::Ok,
            format!("{list} readable. Run one path scan to confirm clamd sees the same folders."),
        ),
    }
}

fn data_dir(dir: &Path) -> (Health, String) {
    let shown = dir.display().to_string();
    let probe = dir.join(".setup-write-test");
    let r = std::fs::write(&probe, b"");
    let _ = std::fs::remove_file(&probe);
    match r {
        Ok(()) => (Health::Ok, format!("{shown} is writable.")),
        Err(e) => (
            Health::Broken,
            format!(
                "{shown} is not writable ({e}); new settings, sessions and keys cannot be saved."
            ),
        ),
    }
}

fn admin(st: &AppState, fs: &FsFacts, users: &[User]) -> (Health, String) {
    let mut issues = Vec::new();
    if let Some(f) = fs.bootstrap_file.as_deref() {
        issues.push(format!("The one-time password file {f} is still there"));
    }
    if users
        .iter()
        .any(|u| u.username == "admin" && u.enabled && u.must_change_password)
    {
        issues.push("admin still has its one-time password".into());
    }
    if st.cfg.bootstrap_admin_password.is_some() {
        issues.push(
            "BOOTSTRAP_ADMIN_PASSWORD is still set; it is only read on the first start".into(),
        );
    }
    if issues.is_empty() {
        (Health::Ok, "admin has its own password.".into())
    } else {
        (Health::Attention, format!("{}.", issues.join("; ")))
    }
}

async fn two_factor(st: &AppState, users: &[User]) -> (Health, String) {
    let mut without = Vec::new();
    let mut local = 0;
    for u in users
        .iter()
        .filter(|u| u.enabled && u.role == Role::Admin && !u.is_external())
    {
        local += 1;
        if matches!(st.db.mfa_methods(&u.id).await, Ok((false, 0))) {
            without.push(u.username.clone());
        }
    }
    let required = if st.cfg.require_admin_2fa {
        " REQUIRE_ADMIN_2FA is on."
    } else {
        ""
    };
    if local == 0 {
        (
            Health::Ok,
            "No admin signs in with a local password.".into(),
        )
    } else if without.is_empty() {
        (
            Health::Ok,
            format!("Every admin has an authenticator app or passkey.{required}"),
        )
    } else {
        (
            Health::Attention,
            format!(
                "Signs in with a password only: {}.{required}",
                without.join(", ")
            ),
        )
    }
}

fn https(st: &AppState, ctx: &Ctx) -> (Health, String) {
    if st.cfg.tls_self_signed {
        (
            Health::Ok,
            "Palisade serves HTTPS with its self-signed certificate.".into(),
        )
    } else if st.cfg.tls_enabled() {
        (
            Health::Ok,
            "Palisade serves HTTPS with TLS_CERT_FILE.".into(),
        )
    } else if ctx.https {
        (
            Health::Ok,
            "Your reverse proxy serves HTTPS and Palisade trusts it.".into(),
        )
    } else {
        (
            Health::Attention,
            "This page came over plain HTTP. Passkeys and remote agents need HTTPS.".into(),
        )
    }
}

/// The name part of a Host header.
fn host_name(host: &str) -> &str {
    let name = if host.starts_with('[') {
        host.split(']')
            .next()
            .map_or(host, |s| s.trim_start_matches('['))
    } else {
        host.rsplit_once(':').map_or(host, |(n, _)| n)
    };
    name.trim_end_matches('.')
}

fn public_url(st: &AppState, ctx: &Ctx) -> (Health, String) {
    let here = ctx.host.as_deref().map(host_name).unwrap_or("");
    let Some(u) = &st.cfg.public_url else {
        let named = if here.is_empty() {
            String::new()
        } else {
            format!(" ({here})")
        };
        return (
            Health::Off,
            format!(
                "PUBLIC_URL is not set. Passkeys bind to the name you use now{named}; set it if you reach Palisade by more than one name."
            ),
        );
    };
    let public = u.host_str().unwrap_or("").trim_matches(['[', ']']);
    if u.scheme() == "https" && !st.cfg.tls_enabled() && st.trusted_proxies.is_empty() {
        return (
            Health::Broken,
            format!(
                "PUBLIC_URL is {u} but Palisade serves plain HTTP and trusts no proxy. Set TRUSTED_PROXIES to your reverse proxy's address."
            ),
        );
    }
    if !here.is_empty() && !here.eq_ignore_ascii_case(public) {
        return (
            Health::Attention,
            format!(
                "You opened this page as {here}, but PUBLIC_URL is {u}. Passkeys only work at {public}."
            ),
        );
    }
    let extra = st
        .cfg
        .allowed_hosts
        .iter()
        .filter(|h| !h.trim().is_empty())
        .count();
    let also = if extra > 0 {
        format!(" ALLOWED_HOSTS adds {extra} more name(s).")
    } else {
        String::new()
    };
    (Health::Ok, format!("{u}.{also}"))
}

async fn schedules(st: &AppState) -> (Health, String) {
    let list = st.db.list_schedules().await.unwrap_or_default();
    let on = list.iter().filter(|s| s.enabled).count();
    if on == 0 {
        let needs = if st.cfg.scan_roots.is_empty() {
            " Set SCAN_ROOTS first."
        } else {
            ""
        };
        let what = if list.is_empty() {
            "No scheduled scans yet"
        } else {
            "Every schedule is paused"
        };
        (
            Health::Attention,
            format!("{what}; add a nightly scan of your folders.{needs}"),
        )
    } else {
        (Health::Ok, format!("{on} schedule(s) on."))
    }
}

fn alerts(st: &AppState) -> (Health, String) {
    let targets = st.notifier.targets();
    if targets.is_empty() {
        return (
            Health::Attention,
            "No alert destination; detections only show up on this console.".into(),
        );
    }
    let failed: Vec<String> = targets
        .iter()
        .zip(st.notifier.last_each())
        .filter_map(|(t, d)| match d {
            Some(d) if !d.ok => Some(format!("{}: {}", t.host(), d.detail)),
            _ => None,
        })
        .collect();
    if failed.is_empty() {
        (
            Health::Ok,
            format!(
                "{} destination(s) set; full URLs stay secret.",
                targets.len()
            ),
        )
    } else {
        (
            Health::Broken,
            format!("The last delivery failed ({}).", failed.join("; ")),
        )
    }
}

fn backups(cfg: &Config) -> (Health, String) {
    let mut names: Vec<String> = std::fs::read_dir(&cfg.data_dir)
        .map(|it| {
            it.filter_map(Result::ok)
                .filter_map(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    if n.starts_with('.') {
                        return None;
                    }
                    let dir = e.file_type().is_ok_and(|t| t.is_dir());
                    Some(if dir { format!("{n}/") } else { n })
                })
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names.truncate(12);
    let holds = if names.is_empty() {
        String::new()
    } else {
        format!(" It holds {}.", names.join(", "))
    };
    let db = if cfg.database_url.is_some() || cfg.database_url_file.is_some() {
        " The database is external: back it up too."
    } else {
        ""
    };
    (
        Health::Note,
        format!("Back up {} regularly.{holds}{db}", cfg.data_dir.display()),
    )
}

fn quarantine(st: &AppState) -> (Health, String) {
    match &st.cfg.quarantine_dir {
        None => (Health::Off, "QUARANTINE_DIR is not set.".into()),
        Some(d) if d.is_dir() => (
            Health::Ok,
            format!(
                "Infected files go to {}{}.",
                d.display(),
                if st.cfg.quarantine_auto {
                    ", every new detection on its own"
                } else {
                    ""
                }
            ),
        ),
        Some(d) => (
            Health::Broken,
            format!(
                "QUARANTINE_DIR {} does not exist or is not a folder; create it, owned by UID 10001.",
                d.display()
            ),
        ),
    }
}

fn crowdsec(st: &AppState) -> (Health, String) {
    let url_set = st
        .cfg
        .crowdsec_lapi_url
        .as_deref()
        .is_some_and(|u| !u.trim().is_empty());
    if !st.crowdsec.configured() {
        return if url_set {
            (
                Health::Broken,
                "CROWDSEC_LAPI_URL is set but the rest is missing or invalid (it needs CROWDSEC_PASSWORD_FILE); the server log says which (crowdsec.config_invalid).".into(),
            )
        } else {
            (Health::Off, "CROWDSEC_LAPI_URL is not set.".into())
        };
    }
    let s = st.crowdsec.status();
    if s.up {
        (Health::Ok, format!("The LAPI at {} answers.", s.url))
    } else if let Some(e) = s.error {
        (
            Health::Broken,
            format!(
                "The LAPI at {} failed: {e}. Check the URL and that the watcher password matches cscli machines add.",
                s.url
            ),
        )
    } else {
        (Health::Pending, format!("Connecting to {}.", s.url))
    }
}

/// A mounted log or file Palisade reads.
fn readable_file(p: &Path, what: &str) -> (Health, String) {
    match std::fs::File::open(p).map_err(|e| e.kind()) {
        Ok(_) => (Health::Ok, format!("Reading {}.", p.display())),
        Err(std::io::ErrorKind::NotFound) => (
            Health::Off,
            format!("Nothing mounted at {} ({what}).", p.display()),
        ),
        Err(std::io::ErrorKind::PermissionDenied) => (
            Health::Broken,
            format!("{} is mounted but UID 10001 may not read it.", p.display()),
        ),
        Err(_) => (Health::Broken, format!("{} cannot be read.", p.display())),
    }
}

fn integrity(cfg: &Config) -> (Health, String) {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    let mut paths = Vec::new();
    for (tool, p) in crate::integrity::sources(cfg) {
        paths.push(p.display().to_string());
        match readable_file(&p, tool) {
            (Health::Ok, _) => ok.push(tool),
            (Health::Off, _) => {}
            (_, d) => bad.push(d),
        }
    }
    if !bad.is_empty() {
        (Health::Broken, bad.join(" "))
    } else if ok.is_empty() {
        (
            Health::Off,
            format!("No report mounted at {}.", paths.join(" or ")),
        )
    } else {
        (Health::Ok, format!("Reading {} reports.", ok.join(" and ")))
    }
}

fn host_setup(st: &AppState) -> (Health, String) {
    let bus = Path::new("/run/dbus/system_bus_socket").exists();
    let fw = crate::firewall::dir().is_dir();
    let units = st.host_units.get(None).map(|(u, _)| u);
    match (bus, fw, units) {
        (false, false, _) => (
            Health::Off,
            "Neither the system D-Bus socket nor the firewall folder is mounted.".into(),
        ),
        (_, _, Some(u)) if u.error.is_some() => (
            Health::Broken,
            format!(
                "The host units did not answer: {}",
                u.error.unwrap_or_default()
            ),
        ),
        (true, true, Some(u)) if u.installed() => (
            Health::Ok,
            "Host units installed; D-Bus and the firewall folder are mounted.".into(),
        ),
        (true, _, Some(u)) if !u.installed() => (
            Health::Attention,
            "D-Bus is mounted but the host units are not installed; run host-setup on the host."
                .into(),
        ),
        (true, false, _) => (
            Health::Attention,
            "D-Bus is mounted but /var/lib/palisade/firewall is not.".into(),
        ),
        (false, true, _) => (
            Health::Attention,
            "The firewall folder is mounted but /run/dbus/system_bus_socket is not.".into(),
        ),
        _ => (
            Health::Pending,
            "Waiting for the first look at the host units.".into(),
        ),
    }
}

async fn canaries(st: &AppState) -> (Health, String) {
    let all = st.db.list_canaries().await.unwrap_or_default();
    let mut paths: Vec<String> = st
        .cfg
        .canary_files
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    paths.extend(
        all.iter()
            .filter(|c| c.agent_id.is_none())
            .map(|c| c.path.clone()),
    );
    let on_agents = all.iter().filter(|c| c.agent_id.is_some()).count();
    if paths.is_empty() && on_agents == 0 {
        return (Health::Off, "No canary files yet.".into());
    }
    let missing: Vec<&String> = paths
        .iter()
        .filter(|p| st.canaries.armed(p) == Some(false))
        .collect();
    let agents = if on_agents > 0 {
        format!(" {on_agents} more on agents.")
    } else {
        String::new()
    };
    if missing.is_empty() {
        (
            Health::Ok,
            format!("{} armed on this server.{agents}", paths.len()),
        )
    } else {
        (
            Health::Broken,
            format!(
                "Missing on this server, so nothing guards it: {}.{agents}",
                missing
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    }
}

async fn watch(st: &AppState) -> (Health, String) {
    let on = st
        .db
        .list_watches()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|w| w.enabled)
        .count();
    match (on, st.cfg.watch_realtime) {
        (0, _) => (Health::Off, "No watched folders.".into()),
        (n, true) => (
            Health::Ok,
            format!("{n} folder(s) watched; new files are scanned as they are written."),
        ),
        (n, false) => (
            Health::Ok,
            format!(
                "{n} folder(s) checked every {} s (WATCH_REALTIME is off).",
                st.cfg.watch_poll_secs
            ),
        ),
    }
}

fn metrics(st: &AppState) -> (Health, String) {
    if st.cfg.metrics_token().is_some() {
        (
            Health::Ok,
            "/metrics is on; Prometheus needs the token.".into(),
        )
    } else {
        (Health::Off, "/metrics is off until a token is set.".into())
    }
}

fn sso(st: &AppState) -> (Health, String) {
    let oidc_set = st
        .cfg
        .oidc_issuer
        .as_deref()
        .is_some_and(|v| !v.trim().is_empty());
    let ldap_set = st
        .cfg
        .ldap_url
        .as_deref()
        .is_some_and(|v| !v.trim().is_empty());
    let mut on = Vec::new();
    let mut bad = Vec::new();
    match (&st.oidc, oidc_set) {
        (Some(o), _) => on.push(format!("OIDC ({})", o.label())),
        (None, true) => {
            bad.push("OIDC_ISSUER is set but OIDC is off: a setting is missing or invalid (oidc.config_invalid in the server log)")
        }
        _ => {}
    }
    match (&st.ldap, ldap_set) {
        (Some(_), _) => on.push("LDAP".to_owned()),
        (None, true) => {
            bad.push("LDAP_URL is set but LDAP is off: a setting is missing or invalid (ldap.config_invalid in the server log)")
        }
        _ => {}
    }
    if !bad.is_empty() {
        (Health::Broken, format!("{}.", bad.join("; ")))
    } else if on.is_empty() {
        (Health::Off, "Local accounts only.".into())
    } else {
        (Health::Ok, format!("{} sign-in is on.", on.join(" and ")))
    }
}

async fn agents(st: &AppState, ctx: &Ctx, now: i64) -> (Health, String) {
    let list = st.db.list_agents().await.unwrap_or_default();
    if list.is_empty() {
        return (Health::Off, "No agents yet.".into());
    }
    let enabled: Vec<_> = list.iter().filter(|a| a.enabled).collect();
    let offline: Vec<&str> = enabled
        .iter()
        .filter(|a| !crate::agent::is_online(a, now))
        .map(|a| a.name.as_str())
        .collect();
    let plain = if st.cfg.tls_enabled() || ctx.https {
        ""
    } else {
        " This server serves plain HTTP, so agents need AGENT_ALLOW_PLAINTEXT."
    };
    if offline.is_empty() {
        (
            Health::Ok,
            format!(
                "{} of {} agent(s) online.{plain}",
                enabled.len(),
                list.len()
            ),
        )
    } else {
        (
            Health::Attention,
            format!(
                "Offline: {}. Check that the agent container runs and can reach this server.{plain}",
                offline.join(", ")
            ),
        )
    }
}

// ---- dismissal and landing ----

fn dismissed_key(user: &User) -> String {
    format!("{DISMISSED}{}", user.id)
}

async fn dismissed(st: &AppState, user: &User) -> Vec<String> {
    st.db
        .setting(&dismissed_key(user))
        .await
        .ok()
        .flatten()
        .map(|v| v.split(',').map(str::to_owned).collect())
        .unwrap_or_default()
}

/// The dashboard banner: how many required or recommended things need attention.
pub struct Banner {
    pub count: usize,
    pub titles: String,
}

impl Banner {
    pub fn text(&self) -> String {
        match self.count {
            1 => "1 thing needs attention".into(),
            n => format!("{n} things need attention"),
        }
    }
}

/// For admins only; None when nothing new needs attention since they hid it.
pub async fn banner(st: &AppState, user: &User, ctx: &Ctx) -> Option<Banner> {
    if !user.role.allows(Role::Admin) {
        return None;
    }
    let report = evaluate(st, ctx).await;
    let rows = report.attention();
    if rows.is_empty() {
        return None;
    }
    let hidden = dismissed(st, user).await;
    if rows.iter().all(|r| hidden.contains(&r.token())) {
        return None;
    }
    Some(Banner {
        count: rows.len(),
        titles: rows
            .iter()
            .map(|r| r.guide.title)
            .collect::<Vec<_>>()
            .join(", "),
    })
}

/// Where an admin lands after signing in: Setup while it is not done and not hidden.
pub async fn land_on_setup(st: &AppState, user: &User) -> bool {
    if user.role != Role::Admin {
        return false;
    }
    let ctx = Ctx {
        host: st
            .cfg
            .public_url
            .as_ref()
            .and_then(|u| u.host_str().map(str::to_owned)),
        // No request headers here: a trusted proxy in front of an https PUBLIC_URL counts as HTTPS.
        https: st.cfg.tls_enabled()
            || (!st.trusted_proxies.is_empty()
                && st
                    .cfg
                    .public_url
                    .as_ref()
                    .is_some_and(|u| u.scheme() == "https")),
        probe: false,
    };
    let report = evaluate(st, &ctx).await;
    let open = report.incomplete();
    if open.is_empty() {
        return false;
    }
    let hidden = dismissed(st, user).await;
    !open.iter().all(|k| hidden.contains(k))
}

/// The request's own view, for the checks that depend on it.
pub fn ctx_of(st: &AppState, h: &HeaderMap, probe: bool) -> Ctx {
    Ctx {
        host: h
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(255).collect()),
        https: st.cfg.tls_enabled() || super::session::forwarded_https(st, h),
        probe,
    }
}

// ---- page ----

#[derive(Template)]
#[template(path = "setup.html")]
struct SetupPage {
    nav: Nav,
    report: Report,
    attention: usize,
    ok: usize,
    off: usize,
}

impl SetupPage {
    fn group(&self, g: &str) -> Vec<&Row> {
        let want = match g {
            "required" => Group::Required,
            "recommended" => Group::Recommended,
            _ => Group::Optional,
        };
        self.report
            .rows
            .iter()
            .filter(|r| r.group == want)
            .collect()
    }

    /// Rows in group `g` that need nothing more (working, or only a reminder).
    fn done(&self, g: &str) -> usize {
        self.group(g)
            .iter()
            .filter(|r| matches!(r.health, Health::Ok | Health::Note))
            .count()
    }

    /// Required and recommended rows: (done, total), for the progress bar.
    fn progress(&self) -> (usize, usize) {
        let done = self.done("required") + self.done("recommended");
        let total = self.group("required").len() + self.group("recommended").len();
        (done, total)
    }
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth, headers: HeaderMap) -> Response {
    let (s, u) = match auth.require(Role::Admin) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let report = evaluate(&st, &ctx_of(&st, &headers, true)).await;
    let attention = report.attention().len();
    let ok = report
        .rows
        .iter()
        .filter(|r| r.health == Health::Ok)
        .count();
    let off = report
        .rows
        .iter()
        .filter(|r| r.health == Health::Off)
        .count();
    render(
        StatusCode::OK,
        &SetupPage {
            nav: Nav::new("setup", &s, &u),
            report,
            attention,
            ok,
            off,
        },
    )
}

#[derive(Deserialize)]
struct DismissForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    next: String,
}

/// Hide the banner and the sign-in landing until something new needs attention.
async fn dismiss(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    headers: HeaderMap,
    Form(f): Form<DismissForm>,
) -> Response {
    let (s, u) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let report = evaluate(&st, &ctx_of(&st, &headers, true)).await;
    let keys = report.incomplete().join(",");
    if let Err(e) = st
        .db
        .set_setting(&dismissed_key(&u), &keys, Some(&u.username))
        .await
    {
        tracing::error!(error = %e, "setup: saving the dismissal failed");
        return error_page(
            StatusCode::SERVICE_UNAVAILABLE,
            "Could not save that: the database did not answer. Try again in a moment.",
        );
    }
    let to = if f.next == "setup" {
        "/admin/setup"
    } else {
        "/dashboard"
    };
    super::ux::back(
        &s,
        to,
        None,
        Some("Hidden until something new needs attention. Setup under Administration still lists everything.".into()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_guide_is_unique_and_short() {
        let mut keys = std::collections::HashSet::new();
        for g in GUIDES {
            assert!(keys.insert(g.key), "duplicate {}", g.key);
            for l in g.env.iter().chain(g.volumes) {
                assert!(!l.contains('\n'), "{}: one line each", g.key);
                assert!(
                    l.contains("  # "),
                    "{}: every line has a comment: {l}",
                    g.key
                );
            }
            assert!(g.docs.contains(".md"), "{}", g.key);
        }
    }

    /// Templates only name guides that exist.
    #[test]
    fn templates_name_real_guides() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/templates");
        for e in std::fs::read_dir(dir).expect("templates") {
            let text = std::fs::read_to_string(e.expect("entry").path()).expect("read");
            for part in text.split("setup::guide(\"").skip(1) {
                let key = part.split('"').next().expect("key");
                assert!(GUIDES.iter().any(|g| g.key == key), "unknown guide {key}");
            }
        }
    }

    #[test]
    fn compose_lines_fit_under_the_service() {
        let c = guide("crowdsec").compose();
        assert!(c.starts_with("    environment:\n      CROWDSEC_LAPI_URL: "));
        assert!(c.contains("\n    volumes:\n      - ./secrets/crowdsec_pw:"));
        assert!(guide("schedules").compose().is_empty());
        assert_eq!(guide("nope").title, "This feature");
    }

    #[test]
    fn signature_age_thresholds() {
        let v = Sigs::Version("ClamAV 1.4.0/27000/Thu Nov 12 09:00:00 2026".into());
        let t = crate::timefmt::parse_clamd_date("Thu Nov 12 09:00:00 2026").expect("date");
        let at = |h: i64| t + h * 3_600_000;
        assert_eq!(signatures(&v, Health::Ok, at(3)).0, Health::Ok);
        assert_eq!(signatures(&v, Health::Ok, at(100)).0, Health::Attention);
        assert_eq!(signatures(&v, Health::Ok, at(400)).0, Health::Broken);
        assert_eq!(
            signatures(&Sigs::Unknown, Health::Pending, at(0)).0,
            Health::Pending
        );
        assert_eq!(
            signatures(&Sigs::Sampled { stale: true }, Health::Ok, at(0)).0,
            Health::Broken
        );
    }

    #[test]
    fn host_names_drop_the_port() {
        assert_eq!(host_name("nas:8080"), "nas");
        assert_eq!(host_name("[::1]:8443"), "::1");
        assert_eq!(host_name("palisade.lan."), "palisade.lan");
    }
}
