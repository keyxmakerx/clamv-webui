//! Runtime configuration from flags and environment variables.

use std::net::SocketAddr;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    #[command(flatten)]
    pub config: Config,
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub enum Command {
    /// Run the web server (default).
    Serve,
    /// Probe /healthz on the local listener; for container HEALTHCHECK.
    Healthcheck,
    /// Give `admin` a new one-time password in DATA_DIR/bootstrap-admin-password.
    ResetAdmin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Plain,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum WebhookEvents {
    /// Detections, failed scans, unscannable files and failed EICAR checks.
    Alerts,
    /// Every finished scan.
    All,
}

#[derive(Debug, Clone, Args)]
pub struct Config {
    /// Listen address.
    #[arg(
        long,
        env = "LISTEN_ADDR",
        default_value = "0.0.0.0:8080",
        global = true
    )]
    pub listen: SocketAddr,

    /// Log filter, e.g. `info` or `info,clamv_webui=debug`.
    #[arg(long, env = "LOG_LEVEL", default_value = "info", global = true)]
    pub log_level: String,

    /// Log line format.
    #[arg(
        long,
        env = "LOG_FORMAT",
        value_enum,
        default_value = "plain",
        global = true
    )]
    pub log_format: LogFormat,

    /// Writable state directory (database, keys).
    #[arg(long, env = "DATA_DIR", default_value = "./data", global = true)]
    pub data_dir: std::path::PathBuf,

    /// Database URL: sqlite://, postgres://, mysql:// or mariadb://. Defaults to SQLite in DATA_DIR.
    #[arg(long, env = "DATABASE_URL", hide_env_values = true, global = true)]
    pub database_url: Option<String>,

    /// File holding the database URL (Docker secret). Wins over DATABASE_URL.
    #[arg(long, env = "DATABASE_URL_FILE", global = true)]
    pub database_url_file: Option<std::path::PathBuf>,

    /// Maximum database connections.
    #[arg(
        long,
        env = "DATABASE_MAX_CONNECTIONS",
        default_value_t = 10,
        global = true
    )]
    pub database_max_connections: u32,

    /// clamd endpoint created as the default on first start: tcp://host:port or unix:///path.
    #[arg(
        long,
        env = "CLAMD_ENDPOINT",
        default_value = "tcp://clamav:3310",
        global = true
    )]
    pub clamd_endpoint: clamd::Endpoint,

    /// Optional comma-separated hosts (or unix socket paths) admins may add as endpoints (S10). Empty allows any.
    #[arg(
        long,
        env = "CLAMD_HOST_ALLOWLIST",
        value_delimiter = ',',
        global = true
    )]
    pub clamd_host_allowlist: Vec<String>,

    /// Largest stream sent to clamd, in MiB; keep at or below clamd's StreamMaxLength.
    #[arg(
        long,
        env = "CLAMD_MAX_STREAM_MB",
        default_value_t = 256,
        global = true
    )]
    pub clamd_max_stream_mb: u64,

    /// Comma-separated directories path scans may target. Empty disables path scans.
    #[arg(long, env = "SCAN_ROOTS", value_delimiter = ',', global = true)]
    pub scan_roots: Vec<std::path::PathBuf>,

    /// Path scans that run at once.
    #[arg(long, env = "SCAN_CONCURRENCY", default_value_t = 2, global = true)]
    pub scan_concurrency: usize,

    /// Seconds between looks at watched folders.
    #[arg(long, env = "WATCH_POLL_SECS", default_value_t = 60, global = true)]
    pub watch_poll_secs: u64,

    /// Webhook called when a scan finishes (Discord URLs get a chat message).
    #[arg(long, env = "WEBHOOK_URL", hide_env_values = true, global = true)]
    pub webhook_url: Option<String>,

    /// File holding the webhook URL (Docker secret). Wins over WEBHOOK_URL.
    #[arg(long, env = "WEBHOOK_URL_FILE", global = true)]
    pub webhook_url_file: Option<std::path::PathBuf>,

    /// Which finished scans call the webhook.
    #[arg(long, env = "WEBHOOK_EVENTS", value_enum, default_value_t = WebhookEvents::Alerts, global = true)]
    pub webhook_events: WebhookEvents,

    /// Comma-separated CIDRs the webhook may reach even though they are private.
    #[arg(
        long,
        env = "WEBHOOK_ALLOWED_CIDRS",
        value_delimiter = ',',
        global = true
    )]
    pub webhook_allowed_cidrs: Vec<String>,

    /// Let the webhook reach any private, loopback or CGNAT address.
    #[arg(
        long,
        env = "WEBHOOK_ALLOW_PRIVATE",
        default_value_t = false,
        global = true
    )]
    pub webhook_allow_private: bool,

    /// Bearer token Prometheus sends to /metrics. Without it /metrics is off.
    #[arg(long, env = "METRICS_TOKEN", hide_env_values = true, global = true)]
    pub metrics_token: Option<String>,

    /// File holding the metrics token (Docker secret). Wins over METRICS_TOKEN.
    #[arg(long, env = "METRICS_TOKEN_FILE", global = true)]
    pub metrics_token_file: Option<std::path::PathBuf>,

    /// OpenID Connect issuer URL (https). With a client id and secret, enables SSO.
    #[arg(long, env = "OIDC_ISSUER", global = true)]
    pub oidc_issuer: Option<String>,

    /// OIDC client id.
    #[arg(long, env = "OIDC_CLIENT_ID", global = true)]
    pub oidc_client_id: Option<String>,

    /// OIDC client secret.
    #[arg(
        long,
        env = "OIDC_CLIENT_SECRET",
        hide_env_values = true,
        global = true
    )]
    pub oidc_client_secret: Option<String>,

    /// File holding the OIDC client secret (Docker secret). Wins over OIDC_CLIENT_SECRET.
    #[arg(long, env = "OIDC_CLIENT_SECRET_FILE", global = true)]
    pub oidc_client_secret_file: Option<std::path::PathBuf>,

    /// Callback URL registered at the provider, ending in /login/oauth2/code/clamav.
    #[arg(long, env = "OIDC_REDIRECT_URI", global = true)]
    pub oidc_redirect_uri: Option<String>,

    /// Scopes to request.
    #[arg(
        long,
        env = "OIDC_SCOPES",
        default_value = "openid profile email",
        global = true
    )]
    pub oidc_scopes: String,

    /// Claim holding group names; dots walk into objects (e.g. realm_access.roles).
    #[arg(
        long,
        env = "OIDC_GROUPS_CLAIM",
        default_value = "groups",
        global = true
    )]
    pub oidc_groups_claim: String,

    /// Comma-separated groups that get the admin role.
    #[arg(long, env = "OIDC_ADMIN_GROUPS", value_delimiter = ',', global = true)]
    pub oidc_admin_groups: Vec<String>,

    /// Comma-separated groups that get the operator role.
    #[arg(
        long,
        env = "OIDC_OPERATOR_GROUPS",
        value_delimiter = ',',
        global = true
    )]
    pub oidc_operator_groups: Vec<String>,

    /// Comma-separated groups that get the viewer role.
    #[arg(long, env = "OIDC_VIEWER_GROUPS", value_delimiter = ',', global = true)]
    pub oidc_viewer_groups: Vec<String>,

    /// Text on the SSO button.
    #[arg(
        long,
        env = "OIDC_BUTTON_LABEL",
        default_value = "Sign in with SSO",
        global = true
    )]
    pub oidc_button_label: String,

    /// Extra PEM CA bundle for a provider with a private certificate.
    #[arg(long, env = "OIDC_CA_FILE", global = true)]
    pub oidc_ca_file: Option<std::path::PathBuf>,

    /// Also sign out at the provider when an SSO user signs out.
    #[arg(
        long,
        env = "OIDC_PROVIDER_LOGOUT",
        default_value_t = false,
        global = true
    )]
    pub oidc_provider_logout: bool,

    /// Directory URL, ldaps://host:636 (or ldap:// with LDAP_STARTTLS). Enables directory sign-in.
    #[arg(long, env = "LDAP_URL", global = true)]
    pub ldap_url: Option<String>,

    /// Upgrade an ldap:// connection with StartTLS. Plain LDAP is never used.
    #[arg(long, env = "LDAP_STARTTLS", default_value_t = false, global = true)]
    pub ldap_starttls: bool,

    /// Service account DN used to find users.
    #[arg(long, env = "LDAP_BIND_DN", global = true)]
    pub ldap_bind_dn: Option<String>,

    /// Service account password.
    #[arg(
        long,
        env = "LDAP_BIND_PASSWORD",
        hide_env_values = true,
        global = true
    )]
    pub ldap_bind_password: Option<String>,

    /// File holding the service account password (Docker secret). Wins over LDAP_BIND_PASSWORD.
    #[arg(long, env = "LDAP_BIND_PASSWORD_FILE", global = true)]
    pub ldap_bind_password_file: Option<std::path::PathBuf>,

    /// Search base for users.
    #[arg(long, env = "LDAP_USER_BASE", global = true)]
    pub ldap_user_base: Option<String>,

    /// User filter; {username} is replaced with the escaped login name.
    #[arg(
        long,
        env = "LDAP_USER_FILTER",
        default_value = "(&(objectClass=person)(uid={username}))",
        global = true
    )]
    pub ldap_user_filter: String,

    /// Attribute on the user entry that lists groups.
    #[arg(
        long,
        env = "LDAP_GROUP_ATTRIBUTE",
        default_value = "memberOf",
        global = true
    )]
    pub ldap_group_attribute: String,

    /// Comma-separated group names or DNs that get the admin role.
    #[arg(long, env = "LDAP_ADMIN_GROUPS", value_delimiter = ',', global = true)]
    pub ldap_admin_groups: Vec<String>,

    /// Comma-separated group names or DNs that get the operator role.
    #[arg(
        long,
        env = "LDAP_OPERATOR_GROUPS",
        value_delimiter = ',',
        global = true
    )]
    pub ldap_operator_groups: Vec<String>,

    /// Comma-separated group names or DNs that get the viewer role.
    #[arg(long, env = "LDAP_VIEWER_GROUPS", value_delimiter = ',', global = true)]
    pub ldap_viewer_groups: Vec<String>,

    /// Extra PEM CA bundle for the directory's certificate.
    #[arg(long, env = "LDAP_CA_FILE", global = true)]
    pub ldap_ca_file: Option<std::path::PathBuf>,

    /// Files accepted in one upload request.
    #[arg(long, env = "UPLOAD_MAX_FILES", default_value_t = 10, global = true)]
    pub upload_max_files: usize,

    /// Finished jobs older than this are deleted. 0 keeps them forever.
    #[arg(long, env = "JOB_RETENTION_DAYS", default_value_t = 90, global = true)]
    pub job_retention_days: u64,

    /// Audit events older than this are deleted. 0 keeps them forever.
    #[arg(
        long,
        env = "AUDIT_RETENTION_DAYS",
        default_value_t = 365,
        global = true
    )]
    pub audit_retention_days: u64,

    /// PEM certificate chain for HTTPS. With TLS_KEY_FILE, serves HTTPS instead of HTTP.
    #[arg(long, env = "TLS_CERT_FILE", global = true, requires = "tls_key_file")]
    pub tls_cert_file: Option<std::path::PathBuf>,

    /// PEM private key for TLS_CERT_FILE.
    #[arg(long, env = "TLS_KEY_FILE", global = true, requires = "tls_cert_file")]
    pub tls_key_file: Option<std::path::PathBuf>,

    /// Serve HTTPS with a self-signed certificate kept in DATA_DIR/tls (for clamctl over a private network).
    #[arg(
        long,
        env = "TLS_SELF_SIGNED",
        default_value_t = false,
        global = true,
        conflicts_with = "tls_cert_file"
    )]
    pub tls_self_signed: bool,

    /// Comma-separated host names and IPs the self-signed certificate is valid for.
    #[arg(
        long,
        env = "TLS_SELF_SIGNED_NAMES",
        value_delimiter = ',',
        default_value = "localhost",
        global = true
    )]
    pub tls_self_signed_names: Vec<String>,

    /// Loopback port for the plain-HTTP health probe when TLS is on.
    #[arg(long, env = "HEALTH_PORT", default_value_t = 8081, global = true)]
    pub health_port: u16,

    /// Mark the session cookie Secure (always on with TLS). Leave false only when served over plain HTTP on a private network.
    #[arg(long, env = "COOKIE_SECURE", default_value_t = false, global = true)]
    pub cookie_secure: bool,

    /// Sign out after this many idle minutes.
    #[arg(
        long,
        env = "SESSION_IDLE_MINUTES",
        default_value_t = 30,
        global = true
    )]
    pub session_idle_minutes: u32,

    /// Absolute session lifetime in hours.
    #[arg(long, env = "SESSION_MAX_HOURS", default_value_t = 12, global = true)]
    pub session_max_hours: u32,

    /// First admin password (min 12 chars). Without it a random one is written to DATA_DIR/bootstrap-admin-password.
    #[arg(
        long,
        env = "BOOTSTRAP_ADMIN_PASSWORD",
        hide_env_values = true,
        global = true
    )]
    pub bootstrap_admin_password: Option<String>,

    /// Per-request timeout for UI and API calls, in seconds.
    #[arg(
        long,
        env = "REQUEST_TIMEOUT_SECS",
        default_value_t = 60,
        global = true
    )]
    pub request_timeout_secs: u64,
}

impl Config {
    /// Resolve the database URL without ever logging it.
    pub fn database_url(&self) -> anyhow::Result<String> {
        if let Some(path) = &self.database_url_file {
            let raw = std::fs::read_to_string(path).map_err(|e| {
                anyhow::anyhow!("cannot read DATABASE_URL_FILE {}: {e}", path.display())
            })?;
            return Ok(raw.trim().to_owned());
        }
        if let Some(url) = &self.database_url {
            return Ok(url.clone());
        }
        Ok(format!(
            "sqlite://{}",
            self.data_dir.join("clamv-webui.db").display()
        ))
    }

    /// The scrape token, if one is configured and non-empty.
    pub fn metrics_token(&self) -> Option<String> {
        let raw = match &self.metrics_token_file {
            Some(p) => std::fs::read_to_string(p).ok()?,
            None => self.metrics_token.clone()?,
        };
        let t = raw.trim();
        (!t.is_empty()).then(|| t.to_owned())
    }

    pub fn session_idle_ms(&self) -> i64 {
        i64::from(self.session_idle_minutes.max(1)) * 60_000
    }

    pub fn session_max_ms(&self) -> i64 {
        i64::from(self.session_max_hours.max(1)) * 3_600_000
    }

    pub fn tls_enabled(&self) -> bool {
        self.tls_self_signed || self.tls_cert_file.is_some()
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }
}
