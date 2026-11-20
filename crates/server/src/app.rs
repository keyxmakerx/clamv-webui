//! HTTP router, shared state and security middleware.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::auth::lockout::{Lockout, LockoutPolicy};
use crate::config::Config;
use crate::db::{Db, redact_url};

pub struct AppState {
    pub cfg: Config,
    pub db: Db,
    pub lockout: Lockout,
    /// Password checks running at once (sa3: each holds 19 MiB).
    pub hash_slots: Arc<tokio::sync::Semaphore>,
    /// SSO sign-in starts per address per minute; each one holds a pending entry.
    pub sso_starts: crate::auth::ratelimit::RateLimit,
    /// Sessions that recently confirmed it is really their user: session id hash to expiry (ms).
    pub confirmed: std::sync::Mutex<std::collections::HashMap<String, i64>>,
    /// SSO confirmations in flight: OIDC state to (session id hash, user id, return path, expiry).
    pub sso_confirms: std::sync::Mutex<std::collections::HashMap<String, SsoConfirm>>,
    /// Wrong second-factor codes per account, across sign-in attempts.
    pub mfa_lockout: Lockout,
    pub runner: crate::scan::Runner,
    /// Scan submissions per credential (Java `api.v1.scan-rate-limit-per-minute`).
    pub scan_rate: crate::auth::ratelimit::RateLimit,
    /// Events per agent per minute (real-time scans and canary hits).
    pub agent_events: crate::auth::ratelimit::RateLimit,
    /// Passkey sign-in challenges per address per minute; each one is a database row and needs no login.
    pub passkey_challenges: crate::auth::ratelimit::RateLimit,
    pub watcher: crate::watch::Watcher,
    pub sealer: crate::auth::sealed::Sealer,
    pub trusted_proxies: Vec<crate::webhook::Cidr>,
    pub notifier: crate::webhook::Notifier,
    pub metrics: crate::metrics::Metrics,
    pub oidc: Option<crate::auth::oidc::Oidc>,
    pub ldap: Option<crate::auth::ldap::Ldap>,
    pub agents: crate::agent::Hub,
    pub clamd_conf: crate::clamdconf::Cache,
    pub freshclam_conf: crate::clamdconf::Cache,
    pub updates: crate::update::Updates,
    pub canaries: crate::canary::Central,
    pub falco_throttle: crate::falco::Throttle,
    pub crowdsec: crate::crowdsec::Console,
    pub host_units: crate::hostchecks::States,
    pub firewalls: crate::firewall::Snapshots,
    /// Passkey confirmations in flight: challenge handle to (user, host, action, expiry).
    pub stepups: std::sync::Mutex<std::collections::HashMap<String, Stepup>>,
}

#[derive(Debug, Clone)]
pub struct SsoConfirm {
    pub session_hash: String,
    pub user_id: String,
    pub next: &'static str,
    pub expires: i64,
}

#[derive(Debug, Clone)]
pub struct Stepup {
    pub user_id: String,
    pub host: Option<i64>,
    pub action: &'static str,
    /// The thing acted on when it is not a host, e.g. a quarantine entry id.
    pub item: String,
    pub expires: i64,
}

impl AppState {
    pub fn new(cfg: Config, db: Db) -> Self {
        Self {
            runner: crate::scan::Runner::new(cfg.scan_concurrency),
            scan_rate: crate::auth::ratelimit::RateLimit::new(
                30,
                std::time::Duration::from_secs(60),
            ),
            agent_events: crate::auth::ratelimit::RateLimit::new(
                1200,
                std::time::Duration::from_secs(60),
            ),
            passkey_challenges: crate::auth::ratelimit::RateLimit::new(
                30,
                std::time::Duration::from_secs(60),
            ),
            notifier: crate::webhook::Notifier::new(&cfg),
            metrics: crate::metrics::Metrics::default(),
            ldap: crate::auth::ldap::Ldap::from_config(&cfg).unwrap_or_else(|e| {
                tracing::error!(event = "ldap.config_invalid", error = %e, "directory sign-in disabled");
                None
            }),
            oidc: crate::auth::oidc::Oidc::from_config(&cfg).unwrap_or_else(|e| {
                tracing::error!(event = "oidc.config_invalid", error = %e, "SSO disabled");
                None
            }),
            crowdsec: crate::crowdsec::Console::from_config(&cfg).unwrap_or_else(|e| {
                tracing::error!(event = "crowdsec.config_invalid", error = %e, "CrowdSec pages disabled");
                crate::crowdsec::Console::default()
            }),
            trusted_proxies: cfg
                .trusted_proxies
                .iter()
                .filter_map(|c| crate::webhook::Cidr::parse(c).ok())
                .collect(),
            sealer: crate::auth::sealed::Sealer::new(
                cfg.secret_key_file
                    .clone()
                    .unwrap_or_else(|| cfg.data_dir.join("secret.key")),
            ),
            cfg,
            db,
            lockout: Lockout::new(LockoutPolicy::default()),
            hash_slots: Arc::new(tokio::sync::Semaphore::new(
                crate::auth::login::HASH_SLOTS,
            )),
            sso_starts: crate::auth::ratelimit::RateLimit::new(
                10,
                std::time::Duration::from_secs(60),
            ),
            confirmed: std::sync::Mutex::default(),
            sso_confirms: std::sync::Mutex::default(),
            mfa_lockout: Lockout::new(LockoutPolicy {
                per_pair: 10,
                per_account: 10,
                ..LockoutPolicy::default()
            }),
            watcher: crate::watch::Watcher::default(),
            agents: crate::agent::Hub::default(),
            clamd_conf: crate::clamdconf::Cache::default(),
            freshclam_conf: crate::clamdconf::Cache::default(),
            updates: crate::update::Updates::default(),
            canaries: crate::canary::Central::default(),
            falco_throttle: crate::falco::Throttle::default(),
            host_units: crate::hostchecks::States::default(),
            firewalls: crate::firewall::Snapshots::default(),
            stepups: std::sync::Mutex::default(),
        }
    }

    /// True if the mounted clamd.conf excludes `path` (ExcludePath).
    pub fn excluded(&self, path: &str) -> bool {
        self.clamd_conf
            .load(self.cfg.clamd_conf_file.as_deref())
            .ok()
            .flatten()
            .is_some_and(|c| c.excluded(path))
    }

    pub fn clamd(&self, ep: clamd::Endpoint) -> clamd::Client {
        let limits = clamd::Limits {
            max_stream_bytes: self.cfg.clamd_max_stream_mb.saturating_mul(1024 * 1024),
            ..clamd::Limits::default()
        };
        clamd::Client::new(ep, limits)
    }

    /// Admin-supplied endpoints must be on the allowlist (S10). With none set, only
    /// the host of CLAMD_ENDPOINT, the endpoint configured at install, is allowed.
    pub fn endpoint_allowed(&self, ep: &clamd::Endpoint) -> bool {
        let key = |ep: &clamd::Endpoint| match ep {
            clamd::Endpoint::Tcp { host, .. } => host.to_ascii_lowercase(),
            clamd::Endpoint::Unix(p) => p.display().to_string(),
        };
        let list = &self.cfg.clamd_host_allowlist;
        if list.iter().all(|h| h.trim().is_empty()) {
            return key(ep) == key(&self.cfg.clamd_endpoint);
        }
        list.iter().any(|h| h.trim().eq_ignore_ascii_case(&key(ep)))
    }
}

/// First start: make CLAMD_ENDPOINT the default endpoint.
pub async fn seed_endpoint(db: &Db, cfg: &Config) -> anyhow::Result<()> {
    if db.list_endpoints().await?.is_empty() {
        db.create_endpoint("default", &cfg.clamd_endpoint.to_string(), true)
            .await?;
        tracing::info!(endpoint = %cfg.clamd_endpoint, "created default clamd endpoint");
    }
    Ok(())
}

/// Headers sent on every response (S7). Inline scripts and styles are not allowed.
const SECURITY_HEADERS: &[(&str, &str)] = &[
    (
        "content-security-policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
         font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; \
         form-action 'self'; frame-ancestors 'none'",
    ),
    // same-origin, not no-referrer: Chrome sends `Origin: null` on form posts under no-referrer.
    ("referrer-policy", "same-origin"),
    (
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    ),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("cross-origin-opener-policy", "same-origin"),
];

pub fn router(state: Arc<AppState>, cfg: &Config) -> Router {
    let pages = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .merge(crate::metrics::routes())
        .merge(crate::api::routes())
        .merge(crate::web::routes())
        .layer(tower_http::limit::RequestBodyLimitLayer::new(64 * 1024))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            cfg.request_timeout(),
        ));
    // Uploads stream for as long as the client sends; each file is capped while streaming.
    let per_file = cfg
        .clamd_max_stream_mb
        .saturating_add(1)
        .saturating_mul(1024 * 1024);
    let upload_limit = usize::try_from(per_file.saturating_mul(cfg.upload_max_files.max(1) as u64))
        .unwrap_or(usize::MAX);
    let uploads = crate::web::scan::upload_routes()
        .merge(crate::api::upload_routes())
        .layer(axum::extract::DefaultBodyLimit::disable())
        .layer(tower_http::limit::RequestBodyLimitLayer::new(upload_limit));
    // Agents long-poll and send whole reports: own timeout and body limit.
    let agents = crate::agent::routes()
        .layer(axum::extract::DefaultBodyLimit::disable())
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            32 * 1024 * 1024,
        ))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            crate::agent::POLL_HOLD + std::time::Duration::from_secs(30),
        ));
    let mut app = pages
        .merge(uploads)
        .merge(agents)
        .with_state(state.clone())
        .layer(axum::middleware::from_fn(crate::web::csrf::same_origin))
        .layer(axum::middleware::from_fn(crate::i18n::layer))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::web::session::check_host,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::web::session::resolve_client,
        ));
    for (name, value) in SECURITY_HEADERS {
        app = app.layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        ));
    }
    app.layer(TraceLayer::new_for_http())
}

/// `reset-admin` subcommand: open the database and reset the admin account.
pub async fn reset_admin(cfg: &Config) -> anyhow::Result<std::path::PathBuf> {
    prepare_data_dir(&cfg.data_dir)?;
    let url = cfg.database_url()?;
    let db = Db::open(&url, 1)
        .await
        .map_err(|e| anyhow::anyhow!("database {}: {e}", redact_url(&url)))?;
    crate::auth::bootstrap::reset_admin(&db, &cfg.data_dir).await
}

/// Check the settings that are fatal when wrong, before anything starts. Each error names
/// the setting and how to fix it.
pub fn preflight(cfg: &Config) -> anyhow::Result<()> {
    let files = [
        ("WEBHOOK_URL_FILE", &cfg.webhook_url_file),
        ("METRICS_TOKEN_FILE", &cfg.metrics_token_file),
        ("OIDC_CLIENT_SECRET_FILE", &cfg.oidc_client_secret_file),
        ("LDAP_BIND_PASSWORD_FILE", &cfg.ldap_bind_password_file),
    ];
    for (var, path) in files {
        if let Some(p) = path {
            crate::config::read_setting_file(var, p)?;
        }
    }
    crate::webhook::Target::from_config(cfg)?;
    if cfg.metrics_token().is_some_and(|t| t.len() < 16) {
        anyhow::bail!(
            "METRICS_TOKEN must be at least 16 characters; make one with: openssl rand -hex 32 > metrics_token"
        );
    }
    if let Some(z) = &cfg.schedule_tz {
        crate::cron::zone(z).map_err(|e| {
            anyhow::anyhow!("SCHEDULE_TZ: {e}; use an IANA name such as Europe/Berlin")
        })?;
    }
    cfg.bootstrap_admin_password()?;
    Ok(())
}

/// Problems that do not stop the server; logged once at start with how to fix each.
pub fn startup_warnings(cfg: &Config) -> Vec<String> {
    let mut w = cfg.scan_root_problems();
    if cfg.scan_roots.iter().all(|r| r.as_os_str().is_empty()) {
        w.push(
            "SCAN_ROOTS is empty, so path scans, schedules and watched folders are off (uploads still work); set SCAN_ROOTS=/scan and mount a folder there".to_owned(),
        );
    }
    if let (Some(_), Some(p)) = (&cfg.crowdsec_lapi_url, &cfg.crowdsec_password_file)
        && let Err(e) = crate::config::read_setting_file("CROWDSEC_PASSWORD_FILE", p)
    {
        w.push(format!("{e}; the CrowdSec pages stay off until then"));
    }
    w
}

pub async fn serve(cfg: Config) -> anyhow::Result<()> {
    prepare_data_dir(&cfg.data_dir)?;
    preflight(&cfg)?;
    for w in startup_warnings(&cfg) {
        tracing::warn!(event = "config.warning", "{w}");
    }
    let url = cfg.database_url()?;
    let db = Db::open(&url, cfg.database_max_connections)
        .await
        .map_err(|e| {
            let fix = if url.starts_with("sqlite:") {
                "DATA_DIR must be writable (a named volume, or chown the host folder to the app's uid)"
            } else {
                "check DATABASE_URL and that the database server is up and reachable from this container"
            };
            anyhow::anyhow!("database {}: {e}; {fix}", redact_url(&url))
        })?;
    tracing::info!(database = %redact_url(&url), "database ready");
    let mut cfg = crate::settings::overlay(cfg, &db.list_settings().await.unwrap_or_default());
    crate::auth::oidc::Oidc::from_config(&cfg)?;
    crate::auth::ldap::Ldap::from_config(&cfg)?;
    for c in &cfg.trusted_proxies {
        crate::webhook::Cidr::parse(c).map_err(|e| {
            anyhow::anyhow!(
                "TRUSTED_PROXIES: {e}; list proxy networks as CIDRs, e.g. 172.16.0.0/12"
            )
        })?;
    }
    if cfg.tls_enabled() {
        cfg.cookie_secure = true;
    }
    let supplied = cfg.bootstrap_admin_password()?;
    crate::auth::bootstrap::ensure_admin(&db, &cfg.data_dir, supplied.as_deref())
        .await
        .map_err(|e| match &cfg.bootstrap_admin_password_file {
            Some(_) => anyhow::anyhow!("{e} (read from BOOTSTRAP_ADMIN_PASSWORD_FILE)"),
            None => e,
        })?;
    bootstrap_file_cleanup(&db, &cfg.data_dir, true).await;
    seed_endpoint(&db, &cfg).await?;
    let state = Arc::new(AppState::new(cfg.clone(), db.clone()));
    spawn_housekeeping(state.clone());
    crate::scan::start(state.clone()).await;
    crate::schedule::spawn(state.clone());
    crate::watch::spawn(state.clone());
    crate::watch::spawn_realtime(state.clone());
    crate::canary::spawn(state.clone());
    crate::webhook::spawn(state.clone());
    crate::metrics::spawn(state.clone());
    crate::agent::spawn_monitor(state.clone());
    crate::update::spawn(state.clone());
    crate::integrity::spawn(state.clone());
    crate::falco::spawn(state.clone());
    crate::timeline::spawn(state.clone());
    crate::crowdsec::spawn(state.clone());
    crate::hostchecks::spawn(state.clone());
    crate::firewall::spawn(state.clone());
    spawn_clamd_wait(state.clone());
    let app = router(state, &cfg).into_make_service_with_connect_info::<std::net::SocketAddr>();
    let scheme = if cfg.tls_enabled() { "https" } else { "http" };
    tracing::info!(listen = %cfg.listen, scheme, clamd = %cfg.clamd_endpoint, data_dir = %cfg.data_dir.display(), version = env!("CARGO_PKG_VERSION"), "started");
    if cfg.tls_enabled() {
        let (tls, cert) = crate::tls::config(&cfg).await?;
        tracing::info!(event = "tls.ready", cert = %cert.display(), sha256 = crate::tls::fingerprint(&cert).as_deref().unwrap_or("?"), "serving HTTPS");
        // The container HEALTHCHECK speaks plain HTTP to loopback only.
        let health = Router::new().route("/healthz", get(healthz));
        let hl = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, cfg.health_port))
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "cannot open the health port 127.0.0.1:{} ({e}); set HEALTH_PORT to a free port",
                    cfg.health_port
                )
            })?;
        tokio::spawn(async move {
            let _ = axum::serve(hl, health).await;
        });
        let handle = axum_server::Handle::new();
        let h = handle.clone();
        tokio::spawn(async move {
            shutdown().await;
            h.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
        });
        axum_server::bind_rustls(cfg.listen, tls)
            .handle(handle)
            .serve(app)
            .await
            .map_err(|e| listen_error(cfg.listen, &e))?;
    } else {
        let listener = tokio::net::TcpListener::bind(cfg.listen)
            .await
            .map_err(|e| listen_error(cfg.listen, &e))?;
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown())
            .await?;
    }
    db.close().await;
    tracing::info!("stopped");
    Ok(())
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = term => {} }
}

fn listen_error(addr: std::net::SocketAddr, e: &std::io::Error) -> anyhow::Error {
    anyhow::anyhow!(
        "cannot listen on {addr} ({e}); free that port or set LISTEN_ADDR to another address"
    )
}

/// Create DATA_DIR and make it private: it holds the database and secrets.
pub fn prepare_data_dir(dir: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| {
        anyhow::anyhow!(
            "cannot create DATA_DIR {} ({e}); mount a writable volume there (the compose files use a named volume) or set DATA_DIR to a writable folder",
            dir.display()
        )
    })?;
    // A bind mount Docker created is owned by root; say so instead of failing on the database.
    let probe = dir.join(".write-test");
    if let Err(e) = std::fs::write(&probe, b"") {
        anyhow::bail!(
            "DATA_DIR {} is not writable ({e}); use a named volume (see docker-compose.yml), or on the host run: sudo chown -R {} <data folder>",
            dir.display(),
            crate::config::run_as()
        );
    }
    let _ = std::fs::remove_file(&probe);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
            tracing::warn!(error = %e, dir = %dir.display(), "could not restrict DATA_DIR to mode 0700");
        }
    }
    Ok(())
}

/// Where `auth::bootstrap` writes a generated admin password.
pub fn bootstrap_file(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("bootstrap-admin-password")
}

/// A one-time admin password file is useless once `admin` has chosen its own password (or is
/// gone); remove it so it does not linger in a volume the operator cannot easily reach.
/// While it is still needed and `announce` is set, say how to copy it out without printing it.
pub async fn bootstrap_file_cleanup(db: &Db, data_dir: &std::path::Path, announce: bool) {
    let file = bootstrap_file(data_dir);
    if !file.exists() {
        return;
    }
    let still_needed = match db.user_by_username("admin").await {
        Ok(Some(u)) => u.must_change_password,
        Ok(None) => false,
        Err(_) => return,
    };
    if still_needed {
        if announce {
            tracing::warn!(
                event = "auth.bootstrap_pending",
                file = %file.display(),
                "admin's one-time password is in this file; with Docker, copy it to the host without printing it: docker compose cp palisade:{} ./admin-password",
                file.display()
            );
        }
        return;
    }
    match std::fs::remove_file(&file) {
        Ok(()) => tracing::info!(
            event = "auth.bootstrap_removed",
            file = %file.display(),
            "removed the one-time admin password file: admin has set its own password"
        ),
        Err(e) => tracing::warn!(
            event = "auth.bootstrap_remove_failed",
            file = %file.display(),
            error = %e,
            "could not remove the old one-time admin password file"
        ),
    }
}

/// On first start clamd may still be loading signatures. Log once that it is not reachable yet
/// and again when it answers, so the logs show progress instead of silence.
fn spawn_clamd_wait(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut warned = false;
        // About 20 minutes: enough for a first signature download on a slow line.
        for _ in 0..80 {
            let Ok(Some(ep)) = state.db.default_endpoint().await else {
                return;
            };
            let Ok(addr) = ep.parsed() else { return };
            match state.clamd(addr).ping().await {
                Ok(()) => {
                    if warned {
                        tracing::info!(event = "clamd.ready", endpoint = %ep.address, "clamd answers now; scans can run");
                    }
                    return;
                }
                Err(e) if !warned => {
                    warned = true;
                    tracing::warn!(event = "clamd.waiting", endpoint = %ep.address, error = %e, "clamd is not reachable yet; on first start it loads its signatures, which can take a few minutes");
                }
                Err(_) => {}
            }
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        }
    });
}

/// Periodic cleanup of expired sessions and old jobs (N5).
fn spawn_housekeeping(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(600));
        loop {
            tick.tick().await;
            bootstrap_file_cleanup(&state.db, &state.cfg.data_dir, false).await;
            match state
                .db
                .purge_expired_sessions(state.cfg.session_idle_ms())
                .await
            {
                Ok(n) if n > 0 => tracing::debug!(removed = n, "expired sessions purged"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "session purge failed"),
            }
            let days = state.cfg.job_retention_days;
            if days > 0 {
                let ms = i64::try_from(days.saturating_mul(86_400_000)).unwrap_or(i64::MAX);
                let det = match state.cfg.detection_retention_days {
                    0 => i64::MIN,
                    d => crate::db::now_ms().saturating_sub(
                        i64::try_from(d.saturating_mul(86_400_000)).unwrap_or(i64::MAX),
                    ),
                };
                match state
                    .db
                    .prune_jobs(crate::db::now_ms().saturating_sub(ms), det)
                    .await
                {
                    Ok(n) if n > 0 => {
                        tracing::info!(event = "jobs.pruned", removed = n, "old jobs deleted")
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "job prune failed"),
                }
            }
            let days = state.cfg.audit_retention_days;
            if days > 0 {
                let ms = i64::try_from(days.saturating_mul(86_400_000)).unwrap_or(i64::MAX);
                match state
                    .db
                    .prune_audit(crate::db::now_ms().saturating_sub(ms))
                    .await
                {
                    Ok(n) if n > 0 => {
                        tracing::info!(
                            event = "audit.pruned",
                            removed = n,
                            "old audit events deleted"
                        )
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "audit prune failed"),
                }
                // Integrity runs and Falco alerts follow the audit retention.
                let _ = state
                    .db
                    .prune_integrity(crate::db::now_ms().saturating_sub(ms))
                    .await;
                let _ = state
                    .db
                    .prune_falco(crate::db::now_ms().saturating_sub(ms))
                    .await;
            }
        }
    });
}

/// Liveness: unauthenticated, touches nothing external.
async fn healthz() -> impl IntoResponse {
    ([(header::CACHE_CONTROL, "no-store")], "ok")
}

/// Readiness: database and default clamd reachable? Reveals nothing beyond up/down.
async fn readyz(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if let Err(e) = state.db.ping().await {
        tracing::warn!(error = %e, "database not reachable");
        return (StatusCode::SERVICE_UNAVAILABLE, "database unavailable");
    }
    let ep = match state.db.default_endpoint().await {
        Ok(Some(ep)) => ep,
        Ok(None) => return (StatusCode::SERVICE_UNAVAILABLE, "no clamd endpoint"),
        Err(e) => {
            tracing::warn!(error = %e, "endpoint lookup failed");
            return (StatusCode::SERVICE_UNAVAILABLE, "database unavailable");
        }
    };
    let Ok(addr) = ep.parsed() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "clamd unavailable");
    };
    match state.clamd(addr).ping().await {
        Ok(()) => (StatusCode::OK, "ready"),
        Err(e) => {
            tracing::warn!(error = %e, endpoint = %ep.address, "clamd not reachable");
            (StatusCode::SERVICE_UNAVAILABLE, "clamd unavailable")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use clap::Parser;
    use tower::ServiceExt;

    async fn test_app() -> Router {
        let cli =
            crate::config::Cli::parse_from(["palisade", "--clamd-endpoint", "tcp://127.0.0.1:1"]);
        let db = Db::open("sqlite::memory:", 1).await.expect("db");
        seed_endpoint(&db, &cli.config).await.expect("seed");
        router(Arc::new(AppState::new(cli.config.clone(), db)), &cli.config)
    }

    #[tokio::test]
    async fn healthz_is_open_and_hardened() {
        let res = test_app()
            .await
            .oneshot(Request::get("/healthz").body(Body::empty()).expect("req"))
            .await
            .expect("res");
        assert_eq!(res.status(), StatusCode::OK);
        for (name, _) in SECURITY_HEADERS {
            assert!(res.headers().contains_key(*name), "missing {name}");
        }
    }

    #[tokio::test]
    async fn readyz_fails_without_clamd() {
        let res = test_app()
            .await
            .oneshot(Request::get("/readyz").body(Body::empty()).expect("req"))
            .await
            .expect("res");
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    fn cfg(args: &[&str]) -> Config {
        let mut all = vec!["palisade"];
        all.extend_from_slice(args);
        crate::config::Cli::try_parse_from(all)
            .expect("parse")
            .config
    }

    fn temp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("palisade-app-{name}-{}", crate::db::new_id()))
    }

    #[test]
    fn data_dir_errors_say_how_to_fix() {
        // A file where DATA_DIR should be: cannot be created, even as root.
        let file = temp("file");
        std::fs::write(&file, b"").expect("write");
        let e = prepare_data_dir(&file.join("data"))
            .expect_err("not a folder")
            .to_string();
        assert!(e.contains("cannot create DATA_DIR"), "{e}");
        assert!(e.contains("named volume"), "{e}");
        let _ = std::fs::remove_file(&file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = temp("ro");
            std::fs::create_dir_all(&dir).expect("mkdir");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).expect("chmod");
            // Root writes anyway; the check only means something for other users.
            if std::fs::write(dir.join("probe"), b"").is_err() {
                let e = prepare_data_dir(&dir).expect_err("read-only").to_string();
                assert!(e.contains("is not writable"), "{e}");
                assert!(e.contains("sudo chown -R"), "{e}");
                assert!(e.contains("named volume"), "{e}");
            }
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn preflight_names_the_setting_and_the_fix() {
        assert!(preflight(&cfg(&[])).is_ok(), "defaults start");
        let e = preflight(&cfg(&["--metrics-token-file", "/nonexistent/metrics"]))
            .expect_err("missing")
            .to_string();
        assert!(
            e.contains("METRICS_TOKEN_FILE") && e.contains("mount the file"),
            "{e}"
        );
        let e = preflight(&cfg(&["--metrics-token", "short"]))
            .expect_err("short")
            .to_string();
        assert!(e.contains("openssl rand -hex 32 > metrics_token"), "{e}");
        let e = preflight(&cfg(&["--schedule-tz", "Mars/Olympus"]))
            .expect_err("zone")
            .to_string();
        assert!(
            e.contains("SCHEDULE_TZ") && e.contains("Europe/Berlin"),
            "{e}"
        );
        let e = preflight(&cfg(&[
            "--bootstrap-admin-password-file",
            "/nonexistent/pw",
        ]))
        .expect_err("missing")
        .to_string();
        assert!(e.contains("BOOTSTRAP_ADMIN_PASSWORD_FILE"), "{e}");
    }

    #[test]
    fn missing_scan_roots_warn_instead_of_failing() {
        let c = cfg(&["--scan-roots", "/nonexistent/palisade-scan"]);
        assert!(preflight(&c).is_ok());
        let w = startup_warnings(&c);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("/nonexistent/palisade-scan"), "{w:?}");
        let w = startup_warnings(&cfg(&[]));
        assert!(w.iter().any(|l| l.contains("SCAN_ROOTS is empty")), "{w:?}");
        let w = startup_warnings(&cfg(&[
            "--crowdsec-lapi-url",
            "http://crowdsec:8080",
            "--crowdsec-password-file",
            "/nonexistent/cs",
        ]));
        assert!(
            w.iter().any(|l| l.contains("CROWDSEC_PASSWORD_FILE")),
            "{w:?}"
        );
    }

    #[tokio::test]
    async fn one_time_password_file_goes_once_admin_chose_a_password() {
        let dir = temp("boot");
        let db = Db::open("sqlite::memory:", 1).await.expect("db");
        crate::auth::bootstrap::ensure_admin(&db, &dir, None)
            .await
            .expect("bootstrap");
        let file = bootstrap_file(&dir);
        assert!(file.exists(), "generated password written");
        bootstrap_file_cleanup(&db, &dir, true).await;
        assert!(file.exists(), "kept while admin must change it");
        let admin = db
            .user_by_username("admin")
            .await
            .expect("q")
            .expect("admin");
        db.set_password(&admin.id, &admin.password_hash, false, false)
            .await
            .expect("changed");
        bootstrap_file_cleanup(&db, &dir, false).await;
        assert!(!file.exists(), "removed after the change");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unknown_paths_404_with_headers() {
        let res = test_app()
            .await
            .oneshot(Request::get("/h2").body(Body::empty()).expect("req"))
            .await
            .expect("res");
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert!(res.headers().contains_key("content-security-policy"));
    }
}
