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
}

impl AppState {
    pub fn new(cfg: Config, db: Db) -> Self {
        Self {
            cfg,
            db,
            lockout: Lockout::new(LockoutPolicy::default()),
        }
    }

    pub fn clamd(&self, ep: clamd::Endpoint) -> clamd::Client {
        let limits = clamd::Limits {
            max_stream_bytes: self.cfg.clamd_max_stream_mb.saturating_mul(1024 * 1024),
            ..clamd::Limits::default()
        };
        clamd::Client::new(ep, limits)
    }

    /// Admin-supplied endpoints must be on the allowlist when one is set (S10).
    pub fn endpoint_allowed(&self, ep: &clamd::Endpoint) -> bool {
        let list = &self.cfg.clamd_host_allowlist;
        if list.iter().all(|h| h.trim().is_empty()) {
            return true;
        }
        let key = match ep {
            clamd::Endpoint::Tcp { host, .. } => host.to_ascii_lowercase(),
            clamd::Endpoint::Unix(p) => p.display().to_string(),
        };
        list.iter().any(|h| h.trim().eq_ignore_ascii_case(&key))
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
    let mut app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .merge(crate::web::routes())
        .with_state(state)
        .layer(axum::middleware::from_fn(crate::web::csrf::same_origin))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(64 * 1024));
    for (name, value) in SECURITY_HEADERS {
        app = app.layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        ));
    }
    app.layer(TimeoutLayer::with_status_code(
        StatusCode::REQUEST_TIMEOUT,
        cfg.request_timeout(),
    ))
    .layer(TraceLayer::new_for_http())
}

pub async fn serve(cfg: Config) -> anyhow::Result<()> {
    prepare_data_dir(&cfg.data_dir)?;
    let url = cfg.database_url()?;
    let db = Db::open(&url, cfg.database_max_connections)
        .await
        .map_err(|e| anyhow::anyhow!("database {}: {e}", redact_url(&url)))?;
    tracing::info!(database = %redact_url(&url), "database ready");
    crate::auth::bootstrap::ensure_admin(
        &db,
        &cfg.data_dir,
        cfg.bootstrap_admin_password.as_deref(),
    )
    .await?;
    seed_endpoint(&db, &cfg).await?;
    let state = Arc::new(AppState::new(cfg.clone(), db.clone()));
    spawn_housekeeping(state.clone());
    let app = router(state, &cfg).into_make_service_with_connect_info::<std::net::SocketAddr>();
    let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
    tracing::info!(listen = %cfg.listen, clamd = %cfg.clamd_endpoint, data_dir = %cfg.data_dir.display(), version = env!("CARGO_PKG_VERSION"), "started");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
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

/// Create DATA_DIR and make it private: it holds the database and secrets.
fn prepare_data_dir(dir: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)
        .map_err(|e| anyhow::anyhow!("cannot create DATA_DIR {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
            tracing::warn!(error = %e, dir = %dir.display(), "could not restrict DATA_DIR to mode 0700");
        }
    }
    Ok(())
}

/// Periodic cleanup of expired sessions.
fn spawn_housekeeping(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(600));
        loop {
            tick.tick().await;
            match state
                .db
                .purge_expired_sessions(state.cfg.session_idle_ms())
                .await
            {
                Ok(n) if n > 0 => tracing::debug!(removed = n, "expired sessions purged"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "session purge failed"),
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
        let cli = crate::config::Cli::parse_from([
            "clamv-webui",
            "--clamd-endpoint",
            "tcp://127.0.0.1:1",
        ]);
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
