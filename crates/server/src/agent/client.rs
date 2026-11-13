//! `clamv-webui agent`: take jobs from a server and scan with the local clamd.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use reqwest::Url;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore};

use super::proto::{
    Assignment, Failure, PROTOCOL, PollRequest, PollResponse, Report, ResultRequest,
};
use crate::config::Config;
use crate::db::now_ms;
use crate::scan;

/// Unhealthy after this long without a successful poll.
const HEALTHY_WITHIN_MS: i64 = 120_000;

struct Agent {
    cfg: Config,
    http: reqwest::Client,
    base: Url,
    token: String,
    clamd: clamd::Client,
    slots: Arc<Semaphore>,
    freed: Notify,
    running: Mutex<HashSet<String>>,
    last_ok: AtomicI64,
    clamd_version: Mutex<(i64, Option<String>)>,
}

/// Check the agent settings and build the HTTP client, without connecting.
fn build(cfg: Config) -> anyhow::Result<Agent> {
    let Some(base) = cfg.agent_server_url.clone() else {
        anyhow::bail!("set AGENT_SERVER_URL to the server's address");
    };
    if !matches!(base.scheme(), "http" | "https") || base.host().is_none() {
        anyhow::bail!("AGENT_SERVER_URL must be an http(s) URL");
    }
    if !base.username().is_empty() || base.password().is_some() {
        anyhow::bail!("AGENT_SERVER_URL must not contain credentials");
    }
    let Some(token) = cfg.agent_token() else {
        anyhow::bail!(
            "set AGENT_TOKEN or AGENT_TOKEN_FILE to the token shown when the agent was added"
        );
    };
    if !token.starts_with(crate::db::agents::SECRET_PREFIX) {
        anyhow::bail!("AGENT_TOKEN is not an agent token");
    }
    if cfg.scan_roots.is_empty() {
        anyhow::bail!("set SCAN_ROOTS to the folders this agent may scan");
    }
    if base.scheme() == "http" {
        tracing::warn!(
            event = "agent.plaintext",
            "AGENT_SERVER_URL is plain HTTP: the token and results are unencrypted; use only over a VPN or mesh"
        );
    }
    let tls = match &cfg.agent_server_fingerprint {
        Some(fp) => pinned_tls(fp)?,
        None => crate::webhook::client_tls(cfg.agent_ca_file.as_deref())?,
    };
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(super::POLL_HOLD + Duration::from_secs(35))
        .user_agent(concat!("clamv-webui-agent/", env!("CARGO_PKG_VERSION")))
        .tls_backend_preconfigured(tls)
        .build()?;
    let limits = clamd::Limits {
        max_stream_bytes: cfg.clamd_max_stream_mb.saturating_mul(1024 * 1024),
        ..clamd::Limits::default()
    };
    Ok(Agent {
        http,
        base,
        token,
        clamd: clamd::Client::new(cfg.clamd_endpoint.clone(), limits),
        slots: Arc::new(Semaphore::new(cfg.scan_concurrency.max(1))),
        freed: Notify::new(),
        running: Mutex::new(HashSet::new()),
        last_ok: AtomicI64::new(0),
        clamd_version: Mutex::new((0, None)),
        cfg,
    })
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let a = Arc::new(build(cfg)?);
    spawn_health(a.clone()).await?;
    tracing::info!(event = "agent.started", server = %a.base, clamd = %a.cfg.clamd_endpoint, roots = ?a.cfg.scan_roots, slots = a.cfg.scan_concurrency.max(1), version = env!("CARGO_PKG_VERSION"), "agent started");
    tokio::select! {
        () = poll_loop(a) => {}
        () = shutdown() => tracing::info!("agent stopping"),
    }
    Ok(())
}

async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = s.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// `/healthz` on loopback at the LISTEN_ADDR port, so the image HEALTHCHECK works unchanged.
async fn spawn_health(a: Arc<Agent>) -> anyhow::Result<()> {
    let port = a.cfg.listen.port();
    let app = Router::new().route(
        "/healthz",
        get(move || {
            let a = a.clone();
            async move {
                if now_ms() - a.last_ok.load(Ordering::Relaxed) < HEALTHY_WITHIN_MS {
                    (StatusCode::OK, "ok")
                } else {
                    (StatusCode::SERVICE_UNAVAILABLE, "not connected")
                }
            }
        }),
    );
    let l = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    Ok(())
}

async fn poll_loop(a: Arc<Agent>) {
    let mut backoff = Duration::from_secs(1);
    let mut connected = false;
    loop {
        let free = u32::try_from(a.slots.available_permits()).unwrap_or(u32::MAX);
        let req = PollRequest {
            protocol: PROTOCOL,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            clamd_version: clamd_version(&a).await,
            roots: a
                .cfg
                .scan_roots
                .iter()
                .map(|r| r.display().to_string())
                .collect(),
            slots: u32::try_from(a.cfg.scan_concurrency.max(1)).unwrap_or(u32::MAX),
            free,
            running: a.running.lock().await.iter().cloned().collect(),
            wait: free > 0,
        };
        match poll_once(&a, &req).await {
            Ok(jobs) => {
                if !connected {
                    tracing::info!(event = "agent.connected", server = %a.base, "connected to server");
                    connected = true;
                }
                backoff = Duration::from_secs(1);
                a.last_ok.store(now_ms(), Ordering::Relaxed);
                for j in jobs {
                    start_job(&a, j).await;
                }
                if free == 0 {
                    // Busy: heartbeat every 20 s, or sooner when a slot frees.
                    let _ = tokio::time::timeout(Duration::from_secs(20), a.freed.notified()).await;
                }
            }
            Err(PollError::Refused(status)) => {
                connected = false;
                tracing::error!(
                    event = "agent.rejected",
                    status = status.as_u16(),
                    "server refused this agent (token revoked, agent disabled or version mismatch); retrying in 60 s"
                );
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            Err(PollError::Other(e)) => {
                if connected {
                    tracing::warn!(event = "agent.disconnected", error = %e, "lost the server; retrying");
                    connected = false;
                } else {
                    tracing::debug!(error = %e, "server still unreachable");
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        }
    }
}

enum PollError {
    Refused(reqwest::StatusCode),
    Other(String),
}

async fn poll_once(a: &Agent, req: &PollRequest) -> Result<Vec<Assignment>, PollError> {
    let url = a
        .base
        .join("agent/v1/poll")
        .map_err(|e| PollError::Other(e.to_string()))?;
    let r = a
        .http
        .post(url)
        .bearer_auth(&a.token)
        .json(req)
        .send()
        .await
        .map_err(|e| PollError::Other(without_url(&e)))?;
    let s = r.status();
    if matches!(s.as_u16(), 401 | 403 | 426) {
        return Err(PollError::Refused(s));
    }
    if !s.is_success() {
        return Err(PollError::Other(format!("HTTP {s}")));
    }
    r.json::<PollResponse>()
        .await
        .map(|p| p.jobs)
        .map_err(|e| PollError::Other(without_url(&e)))
}

fn without_url(e: &reqwest::Error) -> String {
    let mut s = e.to_string();
    if let Some(u) = e.url() {
        s = s.replace(u.as_str(), "<server>");
    }
    s
}

/// clamd's version string, refreshed at most once a minute.
async fn clamd_version(a: &Agent) -> Option<String> {
    let mut g = a.clamd_version.lock().await;
    if now_ms() - g.0 > 60_000 {
        g.1 = a.clamd.version().await.ok();
        g.0 = now_ms();
        if g.1.is_none() {
            tracing::warn!(event = "clamd.unreachable", endpoint = %a.cfg.clamd_endpoint, "agent cannot reach its clamd");
        }
    }
    g.1.clone()
}

async fn start_job(a: &Arc<Agent>, j: Assignment) {
    let Ok(permit) = a.slots.clone().try_acquire_owned() else {
        // The server sent more than we asked for; it will be reconciled as lost.
        tracing::warn!(job_id = %j.id, "no free slot for assigned job");
        return;
    };
    a.running.lock().await.insert(j.id.clone());
    let a = a.clone();
    tokio::spawn(async move { execute(a, j, permit).await });
}

async fn execute(a: Arc<Agent>, j: Assignment, _permit: OwnedSemaphorePermit) {
    let body = match j.kind.as_str() {
        scan::KIND_PATH => scan_path(&a, &j).await,
        crate::schedule::KIND_CONTROL => {
            let r = tokio::time::timeout(
                Duration::from_secs(30),
                a.clamd.instream(&crate::schedule::eicar()[..]),
            )
            .await;
            match r {
                Ok(Ok(rep)) => ok(Report::from_clamd(rep)),
                _ => fail(scan::SCAN_FAILED),
            }
        }
        other => {
            tracing::error!(job_id = %j.id, kind = other, "job type not supported by this agent");
            fail(scan::SCAN_FAILED)
        }
    };
    deliver(&a, &j.id, &body).await;
    a.running.lock().await.remove(&j.id);
    a.freed.notify_one();
}

fn ok(r: Report) -> ResultRequest {
    ResultRequest {
        report: Some(r),
        failure: None,
    }
}

fn fail(code: &str) -> ResultRequest {
    ResultRequest {
        report: None,
        failure: Some(Failure {
            code: code.to_owned(),
        }),
    }
}

async fn scan_path(a: &Agent, j: &Assignment) -> ResultRequest {
    // The agent is the authority on its own roots.
    let path = match scan::resolve_path(&a.cfg.scan_roots, &j.target).await {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!(event = "scan.rejected", job_id = %j.id, scan_target = %j.target, "path outside this agent's SCAN_ROOTS or missing");
            return fail(scan::POLICY_REJECTED);
        }
    };
    tracing::info!(event = "agent.scan_started", job_id = %j.id, scan_target = %j.target, "scan started");
    match a.clamd.multiscan(&path).await {
        Ok(rep) => {
            for d in &rep.detections {
                if !d.is_limit_exceeded() {
                    tracing::warn!(event = "scan.detected", job_id = %j.id, path = %d.path, signature = %d.signature, "malware detected");
                }
            }
            tracing::info!(event = "agent.scan_finished", job_id = %j.id, scan_target = %j.target, files = rep.ok, detections = rep.detections.len(), errors = rep.errors.len(), "scan finished");
            ok(Report::from_clamd(rep))
        }
        Err(e) => {
            tracing::warn!(event = "scan.failed", job_id = %j.id, error = %e, "clamd path scan failed");
            fail(scan::SCAN_FAILED)
        }
    }
}

/// Post a result, retrying for about ten minutes; the server drops it after that.
async fn deliver(a: &Agent, id: &str, body: &ResultRequest) {
    let Ok(url) = a.base.join(&format!("agent/v1/jobs/{id}/result")) else {
        return;
    };
    let mut wait = Duration::from_secs(2);
    for attempt in 1..=12 {
        match a
            .http
            .post(url.clone())
            .bearer_auth(&a.token)
            .json(body)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => return,
            Ok(r) if r.status() == reqwest::StatusCode::CONFLICT => {
                tracing::warn!(event = "agent.result_dropped", job_id = %id, "server no longer expects this result");
                return;
            }
            Ok(r) => {
                tracing::warn!(job_id = %id, attempt, status = r.status().as_u16(), "result not accepted; retrying")
            }
            Err(e) => {
                tracing::warn!(job_id = %id, attempt, error = %without_url(&e), "could not send result; retrying")
            }
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(Duration::from_secs(120));
    }
    tracing::error!(event = "agent.result_lost", job_id = %id, "gave up sending a scan result");
}

/// Trust exactly the server certificate with this SHA-256, as the server logs at start.
fn pinned_tls(fp: &str) -> anyhow::Result<rustls::ClientConfig> {
    let hex: String = fp.chars().filter(|c| *c != ':').collect();
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| {
            hex.get(i..i + 2)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
        })
        .collect::<Option<Vec<u8>>>();
    let Some(sha) = bytes.and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
        anyhow::bail!("AGENT_SERVER_FINGERPRINT must be a SHA-256 in hex");
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(
        rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned { sha, provider }))
            .with_no_client_auth(),
    )
}

#[derive(Debug)]
struct Pinned {
    sha: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if Sha256::digest(end_entity.as_ref())[..] == self.sha[..] {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate does not match AGENT_SERVER_FINGERPRINT".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn cfg(extra: &[&str]) -> Config {
        let mut a = vec!["x", "agent"];
        a.extend_from_slice(extra);
        crate::config::Cli::parse_from(a).config
    }

    #[test]
    fn settings_are_checked() {
        let tok = format!("{}abc", crate::db::agents::SECRET_PREFIX);
        let good = [
            "--agent-server-url",
            "https://s.example:8080",
            "--agent-token",
            tok.as_str(),
            "--scan-roots",
            "/data",
        ];
        assert!(build(cfg(&good)).is_ok());
        assert!(build(cfg(&good[2..])).is_err(), "server URL required");
        assert!(build(cfg(&good[..4])).is_err(), "roots required");
        let mut bad = good;
        bad[3] = "not-an-agent-token";
        assert!(build(cfg(&bad)).is_err());
        let mut creds = good;
        creds[1] = "https://u:p@s.example";
        assert!(build(cfg(&creds)).is_err());
        let mut pin = good.to_vec();
        pin.extend(["--agent-server-fingerprint", "zz"]);
        assert!(build(cfg(&pin)).is_err());
        let fp = ["AB"; 32].join(":");
        let mut pin = good.to_vec();
        pin.extend(["--agent-server-fingerprint", fp.as_str()]);
        assert!(build(cfg(&pin)).is_ok());
    }
}
