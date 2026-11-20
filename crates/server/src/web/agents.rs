//! Admin page for remote agents. A token is shown once, with steps and a ready compose file.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use serde::Deserialize;

use super::admin::{admin_post, audit, fmt_ts};
use super::session::Auth;
use super::{Nav, RequestInfo, error_page, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::db::now_ms;
use crate::db::sessions::Session;
use crate::db::users::User;

const MAX_AGENTS: usize = 100;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin/agents", get(page).post(create))
        .route("/admin/agents/{id}/enabled", post(toggle))
        .route("/admin/agents/{id}/rotate", post(rotate))
        .route("/admin/agents/{id}/delete", post(delete))
        .route("/admin/agents/{id}/rename", post(rename))
}

pub struct AgentRow {
    id: i64,
    name: String,
    prefix: String,
    enabled: bool,
    state: &'static str,
    last_seen: String,
    ip: String,
    version: String,
    clamd: String,
    roots: Vec<String>,
    slots: i64,
    queued: usize,
    running: usize,
    /// Why the agent is refused, e.g. "update the agent".
    hint: String,
    /// The latest problem seen with it (when, then what to do), or empty.
    problem: String,
}

/// Shown once after creating an agent or rotating its token.
pub struct Enroll {
    name: String,
    secret: String,
    /// True after "New token": only the token file changes on the agent host.
    rotated: bool,
    /// The agent's AGENT_SERVER_URL is https://; plain http:// fails unless the host allows it.
    https: bool,
    /// The compose file for the agent host, ready to save.
    compose: String,
    /// The same with AGENT_ALLOW_PLAINTEXT, offered only when the address is plain http://.
    plaintext_compose: String,
    /// The compose pins this server's own certificate.
    pinned: bool,
}

/// What an agent host can let the server do (AGENT_ALLOW), in form order:
/// (name, what it allows, on by default). The defaults match the agent's own.
pub const ALLOW_CHOICES: [(&str, &str, bool); 7] = [
    (
        "scan",
        "Scan folders (path scans, schedules, real-time)",
        true,
    ),
    (
        "canaries",
        "Watch canary files and write decoys inside CANARY_DIRS",
        true,
    ),
    (
        "checks",
        "Read-only checks: run AIDE or rkhunter, read the firewall",
        true,
    ),
    ("timers", "Switch the daily AIDE and rkhunter timers", false),
    (
        "baseline",
        "Accept a new AIDE baseline or rkhunter properties",
        false,
    ),
    (
        "firewall",
        "Apply or remove Palisade's firewall table",
        false,
    ),
    ("quarantine", "Move infected files into quarantine", false),
];

/// The folder an agent scans unless the form names another.
const DEFAULT_FOLDER: &str = "/data";

#[derive(Template)]
#[template(path = "admin_agents.html")]
struct AgentsPage {
    nav: Nav,
    rows: Vec<AgentRow>,
    enroll: Option<Enroll>,
    /// Set when the self-signed certificate was replaced recently: pinned agents need the new fingerprint.
    cert_changed: Option<crate::tls::Replaced>,
    /// Prefilled address agents use to reach this server.
    server: String,
    /// Neither this server nor PUBLIC_URL is HTTPS, so agents cannot connect as they are.
    no_https: bool,
    allow_choices: &'static [(&'static str, &'static str, bool)],
    default_folder: &'static str,
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth, headers: HeaderMap) -> Response {
    let (s, u) = match auth.require(Role::Admin) {
        Ok(x) => x,
        Err(r) => return r,
    };
    show(&st, &headers, Nav::new("agents", &s, &u), None).await
}

async fn show(st: &AppState, h: &HeaderMap, nav: Nav, enroll: Option<Enroll>) -> Response {
    let Ok(list) = st.db.list_agents().await else {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    let now = now_ms();
    let mut rows = Vec::with_capacity(list.len());
    for a in list {
        let queued = st
            .db
            .agent_jobs(a.id, crate::db::jobs::QUEUED)
            .await
            .map_or(0, |l| l.len());
        let running = st
            .db
            .agent_jobs(a.id, crate::db::jobs::RUNNING)
            .await
            .map_or(0, |l| l.len());
        let hint = st.agents.version_hint(a.id).unwrap_or_default();
        let state = if !a.enabled {
            "disabled"
        } else if !hint.is_empty() {
            "version mismatch"
        } else if a.last_seen_at.is_none() {
            "never connected"
        } else if crate::agent::is_online(&a, now) {
            "online"
        } else {
            "offline"
        };
        rows.push(AgentRow {
            id: a.id,
            name: a.name,
            prefix: a.prefix,
            enabled: a.enabled,
            state,
            last_seen: a.last_seen_at.map_or_else(|| "never".into(), fmt_ts),
            problem: st
                .agents
                .last_problem(a.id)
                .map(|(at, what)| format!("{}: {what}", fmt_ts(at)))
                .unwrap_or_default(),
            ip: a.last_ip.unwrap_or_default(),
            version: a.version.unwrap_or_default(),
            clamd: a.clamd_version.unwrap_or_else(|| "unknown".into()),
            roots: a.roots,
            slots: a.slots,
            queued,
            running,
            hint,
        });
    }
    let status = if nav.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    let cert_changed = if st.cfg.tls_enabled() {
        crate::tls::recently_replaced(&st.cfg)
    } else {
        None
    };
    let server = server_url(st, h);
    render(
        status,
        &AgentsPage {
            nav,
            rows,
            enroll,
            cert_changed,
            no_https: !server.starts_with("https://"),
            server,
            allow_choices: &ALLOW_CHOICES,
            default_folder: DEFAULT_FOLDER,
        },
    )
}

async fn result(
    st: &AppState,
    s: &Session,
    me: &User,
    error: Option<String>,
    success: Option<String>,
    enroll: Option<(Enroll, &HeaderMap)>,
) -> Response {
    // A new token is shown once, on this response; it is never kept for a redirect.
    let Some((enroll, h)) = enroll else {
        return super::ux::back(s, "/admin/agents", error, success);
    };
    let mut nav = Nav::new("agents", s, me);
    nav.error = error;
    nav.success = success;
    show(st, h, nav, Some(enroll)).await
}

/// A server address that drops into the agent's compose file as is: http(s),
/// a host, no credentials, query or fragment, and only plain URL characters.
fn clean_server_url(raw: &str) -> Option<String> {
    let u = url::Url::parse(raw.trim()).ok()?;
    if !matches!(u.scheme(), "http" | "https")
        || u.host_str().is_none_or(str::is_empty)
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return None;
    }
    let s = if u.path() == "/" {
        u.as_str().trim_end_matches('/')
    } else {
        u.as_str()
    };
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || ".-:[]/_~".contains(c))
        .then(|| s.to_owned())
}

/// The address agents should use: PUBLIC_URL when set, else what the browser used to reach us.
fn server_url(st: &AppState, h: &HeaderMap) -> String {
    let tls = st.cfg.tls_enabled();
    if let Some(mut u) = st.cfg.public_url.clone() {
        if tls {
            let _ = u.set_scheme("https");
        }
        if let Some(s) = clean_server_url(u.as_str()) {
            return s;
        }
    }
    let scheme = if tls { "https" } else { "http" };
    let host = h
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .filter(|v| {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c))
        })
        .unwrap_or("SERVER:8080");
    format!("{scheme}://{host}")
}

/// A folder for SCAN_ROOTS and the volume lines: absolute, plain characters only.
fn clean_folder(raw: &str) -> Option<String> {
    let f = raw.trim();
    let f = if f.len() > 1 {
        f.trim_end_matches('/')
    } else {
        f
    };
    let ok = f.starts_with('/')
        && f.len() > 1
        && f.len() <= 255
        && !f.split('/').any(|p| p == "..")
        && f.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c));
    ok.then(|| f.to_owned())
}

/// What the operator picked in the Add agent form.
pub struct Choices {
    server: String,
    folder: String,
    allow: Vec<&'static str>,
}

impl Choices {
    fn defaults(server: String) -> Self {
        Self {
            server,
            folder: DEFAULT_FOLDER.to_owned(),
            allow: ALLOW_CHOICES.iter().filter(|c| c.2).map(|c| c.0).collect(),
        }
    }

    fn allows(&self, name: &str) -> bool {
        self.allow.contains(&name)
    }
}

/// The agent host's compose file: the agent, and a clamd that sees the same folder.
fn compose(c: &Choices, fingerprint: Option<&str>, plaintext: bool) -> String {
    let folder = &c.folder;
    let mut env = vec![format!(
        "      AGENT_SERVER_URL: {}  # how this host reaches the server",
        c.server
    )];
    if let Some(fp) = fingerprint {
        env.push(format!(
            "      AGENT_SERVER_FINGERPRINT: {fp}  # pins the server's certificate"
        ));
    }
    if plaintext {
        env.push(
            "      AGENT_ALLOW_PLAINTEXT: \"true\"  # token and results unencrypted; private VPN or mesh only"
                .to_owned(),
        );
    }
    env.push("      AGENT_TOKEN_FILE: /run/secrets/agent_token".to_owned());
    env.push(format!(
        "      AGENT_ALLOW: {}  # what this host lets the server do",
        c.allow.join(",")
    ));
    env.push("      CLAMD_ENDPOINT: tcp://clamav:3310  # the clamd below".to_owned());
    env.push(format!(
        "      SCAN_ROOTS: {folder}  # folders the agent may scan; clamd sees the same path"
    ));
    let quarantine = c.allows("quarantine");
    if quarantine {
        env.push("      QUARANTINE_DIR: /quarantine  # where infected files are moved".to_owned());
    }
    let mut vols = vec![if quarantine {
        format!("      - {folder}:{folder}  # read-write so infected files can be moved")
    } else {
        format!("      - {folder}:{folder}:ro")
    }];
    if quarantine {
        vols.push("      - ./quarantine:/quarantine  # mkdir quarantine; chown 10001".to_owned());
    }
    if c.allows("checks") {
        vols.push(
            "      # - /var/log/aide:/var/log/aide:ro  # if AIDE runs on this host".to_owned(),
        );
        vols.push(
            "      # - /var/log/rkhunter.log:/var/log/rkhunter.log:ro  # if rkhunter runs on this host"
                .to_owned(),
        );
    }
    if c.allows("timers") || c.allows("baseline") || c.allows("firewall") {
        vols.push(
            "      - /run/dbus/system_bus_socket:/run/dbus/system_bus_socket:ro  # run host-setup on this host first"
                .to_owned(),
        );
    }
    if c.allows("firewall") {
        vols.push("      - /var/lib/palisade/firewall:/var/lib/palisade/firewall".to_owned());
    }
    if c.allows("timers") {
        vols.push("      - /var/lib/palisade/timers:/var/lib/palisade/timers".to_owned());
    }
    format!(
        "services:
  palisade-agent:
    image: ghcr.io/keyxmakerx/palisade:latest
    command: agent
    restart: unless-stopped
    depends_on:
      - clamav
    environment:
{env}
    secrets:
      - agent_token
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    volumes:
{vols}

  clamav:
    image: clamav/clamav:latest  # first start downloads signatures (a few minutes)
    restart: unless-stopped
    volumes:
      - clamav-db:/var/lib/clamav
      - {folder}:{folder}:ro

secrets:
  agent_token:
    file: ./agent_token  # made in the steps above

volumes:
  clamav-db:
",
        env = env.join("\n"),
        vols = vols.join("\n"),
    )
}

fn enroll(st: &AppState, name: String, secret: String, c: &Choices, rotated: bool) -> Enroll {
    let https = c.server.starts_with("https://");
    let fingerprint = if https && st.cfg.tls_enabled() {
        crate::tls::files(&st.cfg)
            .ok()
            .and_then(|(c, _)| crate::tls::fingerprint(&c))
    } else {
        None
    };
    Enroll {
        name,
        secret,
        rotated,
        https,
        compose: compose(c, fingerprint.as_deref(), false),
        plaintext_compose: if https {
            String::new()
        } else {
            compose(c, None, true)
        },
        pinned: fingerprint.is_some(),
    }
}

#[derive(Deserialize)]
struct CreateForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    name: String,
}

/// The Add agent form; a list of pairs keeps the repeated `allow` boxes.
fn parse_create(
    st: &AppState,
    h: &HeaderMap,
    f: &[(String, String)],
) -> Result<(String, Choices), String> {
    let get = |k: &str| {
        f.iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.trim())
            .unwrap_or("")
    };
    let name = get("name").to_owned();
    if !valid_agent_name(&name) {
        return Err("Names are 1 to 64 letters, digits, dots, dashes or underscores.".into());
    }
    let server = match get("server") {
        "" => server_url(st, h),
        raw => clean_server_url(raw).ok_or(
            "Server address: give an http:// or https:// address like https://192.168.1.10:8080, without a user name or ?query.",
        )?,
    };
    let folder = match get("folder") {
        "" => DEFAULT_FOLDER.to_owned(),
        raw => clean_folder(raw).ok_or(
            "Folder to scan: give an absolute path like /srv/media, using letters, digits, / . _ - only.",
        )?,
    };
    let mut allow: Vec<&'static str> = Vec::new();
    for (_, v) in f.iter().filter(|(k, _)| k == "allow") {
        let Some(c) = ALLOW_CHOICES.iter().find(|c| c.0 == v.as_str()) else {
            return Err("Unknown permission.".into());
        };
        if !allow.contains(&c.0) {
            allow.push(c.0);
        }
    }
    // A form without the boxes at all (an older page or a script) gets the defaults.
    if allow.is_empty() && get("choices").is_empty() {
        allow = Choices::defaults(String::new()).allow;
    }
    if allow.is_empty() {
        return Err("Tick at least one thing the agent may do; most agents need Scan.".into());
    }
    // Keep the form's order so the compose line reads the same every time.
    allow.sort_by_key(|n| ALLOW_CHOICES.iter().position(|c| c.0 == *n));
    Ok((
        name,
        Choices {
            server,
            folder,
            allow,
        },
    ))
}

async fn create(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    headers: HeaderMap,
    Form(f): Form<Vec<(String, String)>>,
) -> Response {
    let csrf = f
        .iter()
        .find(|(k, _)| k == "_csrf")
        .map(|(_, v)| v.as_str());
    let (s, me) = match admin_post(auth, csrf) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let (name, choices) = match parse_create(&st, &headers, &f) {
        Ok(x) => x,
        Err(m) => return result(&st, &s, &me, Some(m), None, None).await,
    };
    if st.db.list_agents().await.map_or(0, |l| l.len()) >= MAX_AGENTS {
        return result(
            &st,
            &s,
            &me,
            Some(format!(
                "At most {MAX_AGENTS} agents. Remove one you no longer use first."
            )),
            None,
            None,
        )
        .await;
    }
    match st.db.create_agent(&name, &me.username).await {
        Ok((a, secret)) => {
            audit(&st, &me, &info, "AGENT_CREATE", a.name.clone()).await;
            tracing::info!(event = "agent.created", agent = %a.name, by = %me.username, "agent added");
            let e = enroll(&st, a.name.clone(), secret, &choices, false);
            result(
                &st,
                &s,
                &me,
                None,
                Some(format!("Added {}. Set it up on its host now.", a.name)),
                Some((e, &headers)),
            )
            .await
        }
        Err(_) => result(
            &st,
            &s,
            &me,
            Some(
                "That name is already taken. Pick another, or use New token on the existing agent."
                    .into(),
            ),
            None,
            None,
        )
        .await,
    }
}

#[derive(Deserialize)]
struct ActionForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    enabled: Option<String>,
}

async fn toggle(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<ActionForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Ok(Some(a)) = (match id.parse::<i64>() {
        Ok(id) => st.db.agent(id).await,
        Err(_) => Ok(None),
    }) else {
        return result(&st, &s, &me, Some("Unknown agent.".into()), None, None).await;
    };
    let on = f.enabled.is_some();
    if st.db.set_agent_enabled(a.id, on).await.is_err() {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    if on {
        st.agents.clear_problem(a.id);
    }
    let what = if on { "enabled" } else { "disabled" };
    audit(
        &st,
        &me,
        &info,
        "AGENT_UPDATE",
        format!("{} {what}", a.name),
    )
    .await;
    result(
        &st,
        &s,
        &me,
        None,
        Some(format!("{} {what}.", a.name)),
        None,
    )
    .await
}

async fn rotate(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<ActionForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Ok(Some(a)) = (match id.parse::<i64>() {
        Ok(id) => st.db.agent(id).await,
        Err(_) => Ok(None),
    }) else {
        return result(&st, &s, &me, Some("Unknown agent.".into()), None, None).await;
    };
    match st.db.rotate_agent_secret(a.id).await {
        Ok(Some(secret)) => {
            audit(&st, &me, &info, "AGENT_ROTATE", a.name.clone()).await;
            st.agents.clear_problem(a.id);
            // What the agent reported keeps the compose close to what it runs now.
            let mut c = Choices::defaults(server_url(&st, &headers));
            if let Some(r) = a.roots.first().and_then(|r| clean_folder(r)) {
                c.folder = r;
            }
            let e = enroll(&st, a.name.clone(), secret, &c, true);
            result(
                &st,
                &s,
                &me,
                None,
                Some(format!(
                    "New token for {}; the old one no longer works.",
                    a.name
                )),
                Some((e, &headers)),
            )
            .await
        }
        _ => error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    }
}

async fn delete(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<ActionForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Ok(Some(a)) = (match id.parse::<i64>() {
        Ok(id) => st.db.agent(id).await,
        Err(_) => Ok(None),
    }) else {
        return result(&st, &s, &me, Some("Unknown agent.".into()), None, None).await;
    };
    match st.db.delete_agent(a.id).await {
        Ok(true) => {
            audit(&st, &me, &info, "AGENT_DELETE", a.name.clone()).await;
            st.agents.clear_problem(a.id);
            result(
                &st,
                &s,
                &me,
                None,
                Some(format!("Removed {}.", a.name)),
                None,
            )
            .await
        }
        _ => error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    }
}

/// Agent names: letters, digits, dots, dashes and underscores, as in compose.
fn valid_agent_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

async fn rename(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<i64>,
    Form(f): Form<CreateForm>,
) -> Response {
    let (s, me) = match admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let name = f.name.trim();
    if !valid_agent_name(name) {
        return super::ux::back(
            &s,
            "/admin/agents",
            Some("Names are 1 to 64 letters, digits, dots, dashes or underscores.".into()),
            None,
        );
    }
    let Ok(Some(old)) = st.db.agent(id).await else {
        return super::ux::back(&s, "/admin/agents", Some("No such agent.".into()), None);
    };
    match st.db.rename_agent(id, name).await {
        Ok(true) => {
            audit(
                &st,
                &me,
                &info,
                "AGENT_RENAME",
                format!("{} -> {name}", old.name),
            )
            .await;
            super::ux::back(
                &s,
                "/admin/agents",
                None,
                Some(format!("Renamed {} to {name}.", old.name)),
            )
        }
        Ok(false) => super::ux::back(&s, "/admin/agents", Some("No such agent.".into()), None),
        Err(_) => super::ux::back(
            &s,
            "/admin/agents",
            Some("That name is already taken.".into()),
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_choices_match_the_agent_policy() {
        let names: Vec<&str> = ALLOW_CHOICES.iter().map(|c| c.0).collect();
        let policy: Vec<&str> = crate::agent::policy::ALL.iter().map(|p| p.name()).collect();
        assert_eq!(names, policy);
        let defaults: Vec<String> = ALLOW_CHOICES
            .iter()
            .filter(|c| c.2)
            .map(|c| c.0.to_owned())
            .collect();
        let agent_default =
            crate::agent::policy::parse(&["scan,canaries,checks".into()]).expect("p");
        assert_eq!(defaults.len(), agent_default.len());
    }

    #[test]
    fn server_urls_are_plain() {
        assert_eq!(
            clean_server_url("https://nas.lan:8080/").as_deref(),
            Some("https://nas.lan:8080")
        );
        assert_eq!(
            clean_server_url(" http://[fd00::1]:8080 ").as_deref(),
            Some("http://[fd00::1]:8080")
        );
        for bad in [
            "ftp://x",
            "https://u:p@x",
            "https://x/?a=b",
            "https://x/#f",
            "x:8080",
            "https://x/a b",
            "https://x/\"",
            "https://x/$(id)",
        ] {
            assert!(clean_server_url(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn folders_are_plain() {
        assert_eq!(clean_folder("/srv/media/").as_deref(), Some("/srv/media"));
        for bad in ["", "/", "data", "/a/../etc", "/a b", "/a:b", "/a#b"] {
            assert!(clean_folder(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn compose_follows_the_choices() {
        let mut c = Choices::defaults("https://nas:8080".into());
        let y = compose(&c, Some("AB:CD"), false);
        assert!(y.contains("AGENT_SERVER_URL: https://nas:8080"));
        assert!(y.contains("AGENT_SERVER_FINGERPRINT: AB:CD"));
        assert!(y.contains("AGENT_ALLOW: scan,canaries,checks "));
        assert!(y.contains("- /data:/data:ro"));
        assert!(!y.contains("AGENT_ALLOW_PLAINTEXT") && !y.contains("QUARANTINE_DIR"));
        assert!(
            !y.contains("pal_agent_"),
            "the token never goes in the compose"
        );
        c.folder = "/srv/media".into();
        c.allow = vec!["scan", "firewall", "quarantine"];
        let y = compose(&c, None, true);
        assert!(y.contains("AGENT_ALLOW: scan,firewall,quarantine "));
        assert!(y.contains("AGENT_ALLOW_PLAINTEXT: \"true\""));
        assert!(y.contains("QUARANTINE_DIR: /quarantine"));
        assert!(y.contains("- /srv/media:/srv/media  # read-write"));
        assert!(y.contains("system_bus_socket") && y.contains("/var/lib/palisade/firewall"));
        assert!(!y.contains("/var/lib/palisade/timers"));
        assert!(!y.contains("AGENT_SERVER_FINGERPRINT"));
    }
}
