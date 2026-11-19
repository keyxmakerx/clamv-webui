//! `clamv-webui agent`: take jobs from a server and scan with the local clamd.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use reqwest::Url;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore};

use super::outbox::{Item, Outbox};
use super::proto::{
    AgentEvent, Assignment, Failure, PROTOCOL, PollRequest, PollResponse, Report, ResultRequest,
};
use crate::config::Config;
use crate::db::now_ms;
use crate::scan;

/// Unhealthy after this long without a successful poll.
const HEALTHY_WITHIN_MS: i64 = 120_000;

struct Agent {
    cfg: Config,
    http: reqwest::Client,
    /// Never reuses a connection, so a firewall confirmation proves a new one gets through.
    fresh: reqwest::Client,
    /// What this host lets the server have it do; set here, never by the server.
    policy: super::policy::Policy,
    base: Url,
    token: String,
    clamd: clamd::Client,
    slots: Arc<Semaphore>,
    freed: Notify,
    running: Mutex<HashSet<String>>,
    /// Stops a running scan when the server cancels it.
    stops: std::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<()>>>,
    /// Results and events not delivered yet, sent in order.
    outbox: Outbox,
    last_ok: AtomicI64,
    clamd_version: Mutex<(i64, Option<String>)>,
    conf: crate::clamdconf::Cache,
    canaries: tokio::sync::watch::Sender<Vec<crate::canary::Spec>>,
    canary_states: std::sync::Mutex<Option<crate::canary::States>>,
    /// clamv host-check units on this host, read every 5 minutes and after each action.
    host_units: std::sync::Mutex<Option<crate::hostchecks::UnitStates>>,
    /// A firewall plan the host is waiting to hear we still reach the server for.
    firewall_pending: std::sync::Mutex<Option<(String, std::time::Instant)>>,
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
    for p in &cfg.realtime_paths {
        if !super::path_in_roots(&roots_text(&cfg), &p.to_string_lossy()) {
            anyhow::bail!(
                "REALTIME_PATHS entry {} is not inside SCAN_ROOTS",
                p.display()
            );
        }
    }
    let allow =
        match &cfg.agent_allow_file {
            Some(f) => vec![std::fs::read_to_string(f).map_err(|e| {
                anyhow::anyhow!("cannot read AGENT_ALLOW_FILE {}: {e}", f.display())
            })?],
            None => cfg.agent_allow.clone(),
        };
    let policy =
        super::policy::Policy::new(super::policy::parse(&allow).map_err(|e| anyhow::anyhow!(e))?);
    tracing::info!(event = "agent.allow", allow = %policy.names(), "actions this host allows; set AGENT_ALLOW to change");
    if base.scheme() == "http" {
        if !cfg.agent_allow_plaintext {
            anyhow::bail!(
                "AGENT_SERVER_URL is plain http://: use https:// with AGENT_SERVER_FINGERPRINT (shown in Admin > Agents), \
                 or set AGENT_ALLOW_PLAINTEXT=true on this host if the link is a private VPN or mesh"
            );
        }
        tracing::warn!(
            event = "agent.plaintext",
            "AGENT_SERVER_URL is plain HTTP (AGENT_ALLOW_PLAINTEXT=true): the token and results are unencrypted"
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
        .tls_backend_preconfigured(tls.clone())
        .build()?;
    let fresh = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(15))
        .pool_max_idle_per_host(0)
        .user_agent(concat!("clamv-webui-agent/", env!("CARGO_PKG_VERSION")))
        .tls_backend_preconfigured(tls)
        .build()?;
    let limits = clamd::Limits {
        max_stream_bytes: cfg.clamd_max_stream_mb.saturating_mul(1024 * 1024),
        ..clamd::Limits::default()
    };
    Ok(Agent {
        http,
        fresh,
        policy,
        base,
        token,
        clamd: clamd::Client::new(cfg.clamd_endpoint.clone(), limits),
        slots: Arc::new(Semaphore::new(cfg.scan_concurrency.max(1))),
        freed: Notify::new(),
        running: Mutex::new(HashSet::new()),
        stops: std::sync::Mutex::new(HashMap::new()),
        outbox: Outbox::open(cfg.agent_queue_dir.clone())?,
        last_ok: AtomicI64::new(0),
        clamd_version: Mutex::new((0, None)),
        conf: crate::clamdconf::Cache::default(),
        canaries: tokio::sync::watch::channel(Vec::new()).0,
        canary_states: std::sync::Mutex::new(None),
        host_units: std::sync::Mutex::new(None),
        firewall_pending: std::sync::Mutex::new(None),
        cfg,
    })
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let a = Arc::new(build(cfg)?);
    spawn_health(a.clone()).await?;
    tracing::info!(event = "agent.started", server = %a.base, clamd = %a.cfg.clamd_endpoint, roots = ?a.cfg.scan_roots, slots = a.cfg.scan_concurrency.max(1), version = env!("CARGO_PKG_VERSION"), "agent started");
    spawn_realtime(a.clone()).await;
    spawn_canaries(a.clone());
    spawn_integrity(a.clone());
    spawn_falco(a.clone());
    spawn_host_units(a.clone());
    spawn_firewall(a.clone());
    spawn_sender(a.clone());
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
    let mut warned = false;
    loop {
        let free = u32::try_from(a.slots.available_permits()).unwrap_or(u32::MAX);
        let req = PollRequest {
            protocol: PROTOCOL,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            clamd_version: clamd_version(&a).await,
            roots: roots_text(&a.cfg),
            slots: u32::try_from(a.cfg.scan_concurrency.max(1)).unwrap_or(u32::MAX),
            free,
            running: a.running.lock().await.iter().cloned().collect(),
            wait: free > 0,
            canaries: canary_states(&a),
            host_checks: a.host_units.lock().ok().and_then(|g| g.clone()),
            kinds: super::proto::KINDS
                .iter()
                .map(|k| (*k).to_owned())
                .collect(),
        };
        match poll_once(&a, &req).await {
            Ok(resp) => {
                for id in &resp.cancel {
                    stop_job(&a, id);
                }
                let jobs = resp.jobs;
                if let Some(mut list) = resp
                    .canaries
                    .filter(|_| a.policy.allows(super::policy::Perm::Canaries))
                {
                    // The server checks these too; a decoy is never written to a path this host would not accept.
                    list.retain(|s| crate::canary::valid_path(&s.path).is_ok());
                    // Decoys are written only inside this host's CANARY_DIRS; elsewhere the file is just watched.
                    for sp in list.iter_mut().filter(|sp| sp.create) {
                        if !super::path_in_roots(&dirs_text(&a.cfg.canary_dirs), &sp.path) {
                            tracing::warn!(event = "canary.create_refused", path = %sp.path, "decoy not written: outside CANARY_DIRS on this host; watching it only if it exists");
                            sp.create = false;
                        }
                    }
                    a.canaries.send_if_modified(|cur| {
                        let changed = *cur != list;
                        if changed {
                            *cur = list
                                .into_iter()
                                .take(crate::db::canaries::MAX_PER_HOST)
                                .collect();
                        }
                        changed
                    });
                }
                if !connected {
                    tracing::info!(event = "agent.connected", server = %a.base, queued = a.outbox.len(), "connected to server");
                    connected = true;
                    warned = false;
                    a.outbox.ready.notify_one();
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
                    "server refused this agent (token revoked, agent disabled, or version mismatch: update the older of agent and server); retrying in 60 s"
                );
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            Err(PollError::Other(e)) => {
                if connected {
                    tracing::warn!(event = "agent.disconnected", error = %e, "lost the server; retrying");
                    connected = false;
                } else if !warned {
                    // Say it once: a wrong AGENT_SERVER_URL must not fail in silence.
                    tracing::warn!(event = "agent.unreachable", server = %a.base, error = %e, "cannot reach the server; check AGENT_SERVER_URL from this host; retrying");
                    warned = true;
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

async fn poll_once(a: &Agent, req: &PollRequest) -> Result<PollResponse, PollError> {
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
    let (tx, rx) = tokio::sync::oneshot::channel();
    if j.kind == scan::KIND_PATH
        && let Ok(mut g) = a.stops.lock()
    {
        g.insert(j.id.clone(), tx);
    }
    let a = a.clone();
    tokio::spawn(async move {
        let id = j.id.clone();
        tokio::select! {
            () = execute(a.clone(), j, permit) => {}
            Ok(()) = rx => {
                tracing::warn!(event = "agent.job_cancelled", job_id = %id, "job cancelled on the server; scan stopped");
                a.running.lock().await.remove(&id);
                a.freed.notify_one();
            }
        }
        if let Ok(mut g) = a.stops.lock() {
            g.remove(&id);
        }
    });
}

/// Stop a running scan the server cancelled; other kinds run to the end.
fn stop_job(a: &Agent, id: &str) {
    if let Some(tx) = a.stops.lock().ok().and_then(|mut g| g.remove(id)) {
        let _ = tx.send(());
    }
}

async fn execute(a: Arc<Agent>, j: Assignment, _permit: OwnedSemaphorePermit) {
    let action = crate::agent::proto::clean(&j.target, 200);
    let perm = super::policy::classify(&j.kind, &j.target);
    let admitted = match perm {
        Some(p) => a.policy.admit(p),
        None => Ok(()),
    };
    let body = match admitted {
        Err(code) => {
            // Logged here, on this host, so it reaches the log shipper even if the server is not to be trusted.
            tracing::warn!(event = "agent.action_refused", job_id = %j.id, kind = %j.kind, action = %action, perm = perm.map_or("-", |p| p.name()), code, "action refused by this host's AGENT_ALLOW or rate limit");
            fail(code)
        }
        Ok(()) => run_job(&a, &j).await,
    };
    if admitted.is_ok() {
        let code = body.failure.as_ref().map_or("", |f| f.code.as_str());
        tracing::info!(event = "agent.action", job_id = %j.id, kind = %j.kind, action = %action, perm = perm.map_or("-", |p| p.name()), ok = body.failure.is_none(), code, "action run for the server");
    }
    deliver(&a, &j.id, body);
    a.running.lock().await.remove(&j.id);
    a.freed.notify_one();
}

async fn run_job(a: &Arc<Agent>, j: &Assignment) -> ResultRequest {
    match j.kind.as_str() {
        scan::KIND_PATH => scan_path(a, j).await,
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
        crate::hostchecks::KIND => host_check(a, j).await,
        crate::firewall::KIND => firewall_job(a, j).await,
        crate::quarantine::KIND => quarantine_job(a, j).await,
        other => {
            tracing::error!(job_id = %j.id, kind = other, "job type not supported by this agent; update it");
            fail(super::proto::UNSUPPORTED)
        }
    }
}

/// Start one allow-listed unit; anything else the server sends is refused here too.
async fn host_check(a: &Agent, j: &Assignment) -> ResultRequest {
    if let Some((tool, time)) = crate::hostchecks::parse_timer_target(&j.target) {
        let r = crate::hostchecks::set_time(tool, &time).await;
        let states = crate::hostchecks::probe().await;
        if let Ok(mut g) = a.host_units.lock() {
            *g = Some(states);
        }
        return match r {
            Ok(()) => {
                tracing::info!(event = "hostcheck.timer_set", tool, time = %time, "daily timer time set");
                ok(Report::default())
            }
            Err(e) => {
                tracing::warn!(event = "hostcheck.failed", action = "timers.set", code = e.code, error = %e.message, "timer time could not be set");
                fail(e.code)
            }
        };
    }
    let Some(act) = crate::hostchecks::check_action(&j.target) else {
        tracing::error!(event = "hostcheck.refused", job_id = %j.id, action = %crate::agent::proto::clean(&j.target, 64), "unknown host check");
        return fail(crate::hostchecks::FAILED);
    };
    let r = crate::hostchecks::run(act).await;
    if let Ok(mut g) = a.host_units.lock() {
        *g = None;
    }
    let states = crate::hostchecks::probe().await;
    if let Ok(mut g) = a.host_units.lock() {
        *g = Some(states);
    }
    match r {
        Ok(()) => {
            tracing::info!(
                event = "hostcheck.started",
                action = act.name,
                unit = act.unit,
                "host check started"
            );
            ok(Report::default())
        }
        Err(e) => {
            tracing::warn!(event = "hostcheck.failed", action = act.name, unit = act.unit, code = e.code, error = %e.message, "host check could not start");
            fail(e.code)
        }
    }
}

/// Confirm a plan the host has loaded and waits on, once a new connection reaches the server.
async fn confirm_firewall(a: &Agent) {
    let Some((h, since)) = a.firewall_pending.lock().ok().and_then(|g| g.clone()) else {
        return;
    };
    if since.elapsed() > Duration::from_secs(120) {
        if let Ok(mut g) = a.firewall_pending.lock() {
            *g = None;
        }
        return;
    }
    if !crate::firewall::waiting(crate::firewall::dir(), &h) {
        return;
    }
    let Ok(url) = a.base.join("healthz") else {
        return;
    };
    // A pooled connection predates the new rules and would pass anyway.
    let reached = a
        .fresh
        .get(url)
        .send()
        .await
        .is_ok_and(|r| r.status().is_success());
    if reached {
        crate::firewall::confirm(crate::firewall::dir(), &h);
        tracing::info!(event = "firewall.confirmed", hash = %h, "firewall plan confirmed: a new connection still reaches the server");
        if let Ok(mut g) = a.firewall_pending.lock() {
            *g = None;
        }
    }
}

/// Snapshot, apply or remove, through the host's fixed firewall units only.
async fn firewall_job(a: &Arc<Agent>, j: &Assignment) -> ResultRequest {
    let Ok(op) = serde_json::from_str::<crate::firewall::Op>(&j.target) else {
        return fail(crate::hostchecks::FAILED);
    };
    let dir = crate::firewall::dir().to_path_buf();
    let r = match op {
        crate::firewall::Op::Snapshot => match crate::firewall::snapshot(&dir).await {
            Ok(snapshot) => {
                send_event(a, AgentEvent::Firewall { snapshot });
                return ok(Report::default());
            }
            Err(e) => Err(e),
        },
        crate::firewall::Op::Apply { rules } => match crate::firewall::apply(&dir, rules).await {
            Ok(h) => {
                tracing::warn!(event = "firewall.applying", hash = %h, "firewall plan loading; confirming once a new connection reaches the server");
                if let Ok(mut g) = a.firewall_pending.lock() {
                    *g = Some((h, std::time::Instant::now()));
                }
                let a2 = a.clone();
                tokio::spawn(async move {
                    for _ in 0..28 {
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        confirm_firewall(&a2).await;
                        if a2.firewall_pending.lock().map_or(true, |g| g.is_none()) {
                            break;
                        }
                    }
                });
                Ok(())
            }
            Err(e) => Err(e),
        },
        crate::firewall::Op::Remove => crate::firewall::remove().await,
    };
    if let Err(e) = r {
        tracing::warn!(event = "firewall.failed", code = e.code, error = %e.message, "firewall action failed");
        return fail(e.code);
    }
    let a2 = a.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(8)).await;
        firewall_snapshot(&a2).await;
    });
    ok(Report::default())
}

async fn firewall_snapshot(a: &Agent) {
    match crate::firewall::snapshot(crate::firewall::dir()).await {
        Ok(snapshot) => send_event(a, AgentEvent::Firewall { snapshot }),
        Err(e) => tracing::debug!(error = %e.message, "firewall snapshot failed"),
    }
}

fn spawn_firewall(a: Arc<Agent>) {
    if !crate::firewall::dir().is_dir() {
        return;
    }
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(900));
        loop {
            t.tick().await;
            firewall_snapshot(&a).await;
        }
    });
}

fn spawn_host_units(a: Arc<Agent>) {
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(300));
        loop {
            t.tick().await;
            let s = crate::hostchecks::probe().await;
            if let Ok(mut g) = a.host_units.lock() {
                *g = Some(s);
            }
        }
    });
}

fn ok(r: Report) -> ResultRequest {
    ResultRequest {
        report: Some(r),
        failure: None,
        quarantine: None,
    }
}

fn fail(code: &str) -> ResultRequest {
    ResultRequest {
        report: None,
        failure: Some(Failure {
            code: code.to_owned(),
        }),
        quarantine: None,
    }
}

/// Move, restore or delete one file in this host's quarantine folder.
async fn quarantine_job(a: &Agent, j: &Assignment) -> ResultRequest {
    use crate::quarantine as q;
    let Ok(op) = serde_json::from_str::<q::Op>(&j.target) else {
        return fail(q::REJECTED);
    };
    let dir = a.cfg.quarantine_dir.as_deref();
    let r = match op {
        q::Op::Move { id, path } => {
            match q::move_in(&a.clamd, &a.cfg.scan_roots, dir, &id, &path).await {
                Ok(held) => {
                    tracing::warn!(event = "quarantine.moved", path = %path, sha256 = %held.sha256, size = held.size, "infected file moved into quarantine");
                    return ResultRequest {
                        quarantine: Some(held),
                        ..ok(Report::default())
                    };
                }
                Err(c) => Err(c),
            }
        }
        q::Op::Restore { id, path } => {
            let r = q::restore(&a.cfg.scan_roots, dir, &id, &path).await;
            if r.is_ok() {
                tracing::warn!(event = "quarantine.restored", path = %path, "quarantined file restored");
            }
            r
        }
        q::Op::Delete { id } => {
            let r = q::delete(dir, &id).await;
            if r.is_ok() {
                tracing::warn!(event = "quarantine.deleted", id = %id, "quarantined copy deleted");
            }
            r
        }
    };
    match r {
        Ok(()) => ok(Report::default()),
        Err(c) => {
            tracing::warn!(
                event = "quarantine.failed",
                code = c,
                "quarantine step failed"
            );
            fail(c)
        }
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

/// Queue a result; the sender delivers it whenever the server is reachable.
fn deliver(a: &Agent, id: &str, mut body: ResultRequest) {
    if let Some(r) = body.report.as_mut() {
        r.fit(super::proto::MAX_BODY);
    }
    a.outbox.push(&Item::Result {
        job: id.to_owned(),
        body,
    });
}

/// Send queued items in order, waiting out server outages; nothing is dropped
/// unless the server refuses it for good or the queue overflows.
fn spawn_sender(a: Arc<Agent>) {
    tokio::spawn(async move {
        let mut wait = Duration::from_secs(2);
        loop {
            let Some((seq, item)) = a.outbox.peek() else {
                let _ =
                    tokio::time::timeout(Duration::from_secs(5), a.outbox.ready.notified()).await;
                continue;
            };
            match send_item(&a, &item).await {
                Sent::Done => {
                    a.outbox.done(seq);
                    wait = Duration::from_secs(2);
                }
                Sent::Refused(status) => {
                    match &item {
                        Item::Result { job, .. } if status == 409 => {
                            tracing::warn!(event = "agent.result_dropped", job_id = %job, "server no longer expects this result (cancelled or finished)")
                        }
                        Item::Result { job, .. } => {
                            tracing::error!(event = "agent.result_lost", job_id = %job, status, "server refused a result")
                        }
                        Item::Event { .. } => {
                            tracing::warn!(
                                event = "agent.event_refused",
                                status,
                                "server refused an event"
                            )
                        }
                    }
                    a.outbox.done(seq);
                }
                Sent::Retry(why) => {
                    tracing::debug!(item = item.label(), queued = a.outbox.len(), error = %why, "could not send; will retry");
                    let _ = tokio::time::timeout(wait, a.outbox.ready.notified()).await;
                    wait = (wait * 2).min(Duration::from_secs(60));
                }
            }
        }
    });
}

enum Sent {
    Done,
    Refused(u16),
    Retry(String),
}

async fn send_item(a: &Agent, item: &Item) -> Sent {
    let (path, req) = match item {
        Item::Result { job, body } => (
            format!("agent/v1/jobs/{job}/result"),
            serde_json::to_vec(body),
        ),
        Item::Event { body } => ("agent/v1/events".to_owned(), serde_json::to_vec(body)),
    };
    let (Ok(url), Ok(req)) = (a.base.join(&path), req) else {
        return Sent::Refused(0);
    };
    match a
        .http
        .post(url)
        .bearer_auth(&a.token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(req)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => Sent::Done,
        // 408 and 429 pass; 401/403 mean this agent is refused right now, so keep the item.
        Ok(r)
            if r.status().is_client_error()
                && !matches!(r.status().as_u16(), 401 | 403 | 408 | 426 | 429) =>
        {
            Sent::Refused(r.status().as_u16())
        }
        Ok(r) => Sent::Retry(format!("HTTP {}", r.status())),
        Err(e) => Sent::Retry(without_url(&e)),
    }
}

fn roots_text(cfg: &Config) -> Vec<String> {
    dirs_text(&cfg.scan_roots)
}

fn dirs_text(dirs: &[std::path::PathBuf]) -> Vec<String> {
    dirs.iter().map(|r| r.display().to_string()).collect()
}

/// Scan files under REALTIME_PATHS as soon as they are written, one at a time.
async fn spawn_realtime(a: Arc<Agent>) {
    if !a.cfg.watch_realtime || a.cfg.realtime_paths.is_empty() {
        return;
    }
    let mut dirs = Vec::new();
    for p in &a.cfg.realtime_paths {
        match scan::resolve_path(&a.cfg.scan_roots, &p.to_string_lossy()).await {
            Ok(d) => dirs.push(d),
            Err(_) => {
                tracing::warn!(event = "realtime.path_rejected", path = %p.display(), "real-time folder is missing or outside SCAN_ROOTS")
            }
        }
    }
    if dirs.is_empty() {
        return;
    }
    let mut rx = match crate::fsevents::files(dirs.clone()) {
        Ok(rx) => rx,
        Err(e) => {
            tracing::warn!(event = "realtime.unavailable", error = %e, "real-time scanning off");
            return;
        }
    };
    tracing::info!(
        event = "realtime.started",
        folders = dirs.len(),
        "real-time scanning on"
    );
    tokio::spawn(async move {
        let mut seen: std::collections::HashMap<std::path::PathBuf, (i64, i64)> =
            std::collections::HashMap::new();
        while let Some(p) = rx.recv().await {
            let Ok(m) = tokio::fs::symlink_metadata(&p).await else {
                continue;
            };
            if !m.is_file() || !dirs.iter().any(|d| p.starts_with(d)) {
                continue;
            }
            let stamp = crate::watch::stamp(&m);
            if seen.get(&p) == Some(&stamp) {
                continue;
            }
            let conf = a.conf.load(a.cfg.clamd_conf_file.as_deref()).ok().flatten();
            if conf.is_some_and(|c| c.excluded(&p.to_string_lossy())) {
                continue;
            }
            if seen.len() > 100_000 {
                seen.clear();
            }
            seen.insert(p.clone(), stamp);
            let body = realtime_scan(&a, &p).await;
            send_event(&a, body);
        }
    });
}

async fn realtime_scan(a: &Agent, p: &std::path::Path) -> AgentEvent {
    let (key, result) = match p.to_str() {
        Some(s) => (s.to_owned(), a.clamd.multiscan(p).await),
        None => {
            // clamd names files as text; stream it so the name never matters.
            let key = crate::watch::raw_key(p);
            let r = match tokio::fs::File::open(p).await {
                Ok(f) => a
                    .clamd
                    .instream(tokio::io::BufReader::new(f))
                    .await
                    .map(|mut r| {
                        for d in &mut r.detections {
                            d.path.clone_from(&key);
                        }
                        for e in &mut r.errors {
                            e.path.clone_from(&key);
                        }
                        r
                    }),
                Err(e) => Err(clamd::Error::Io(e)),
            };
            (key, r)
        }
    };
    let (report, failure) = match result {
        Ok(rep) => {
            for d in &rep.detections {
                if !d.is_limit_exceeded() {
                    tracing::warn!(event = "scan.detected", kind = scan::KIND_WATCH, path = %d.path, signature = %d.signature, "malware detected");
                }
            }
            (Some(Report::from_clamd(rep)), None)
        }
        Err(clamd::Error::StreamTooLarge(_)) => (
            None,
            Some(Failure {
                code: scan::LIMIT_EXCEEDED.to_owned(),
            }),
        ),
        Err(e) => {
            tracing::warn!(event = "scan.failed", path = %key, error = %e, "clamd real-time scan failed");
            (
                None,
                Some(Failure {
                    code: scan::SCAN_FAILED.to_owned(),
                }),
            )
        }
    };
    AgentEvent::Scan {
        path: key,
        report,
        failure,
    }
}

/// Forward Falco alerts from this host to the server.
fn spawn_falco(a: Arc<Agent>) {
    let path = a.cfg.falco_events.clone();
    let min = crate::falco::rank(&a.cfg.falco_min_priority);
    crate::falco::follow(path, min, move |alerts| {
        let a = a.clone();
        async move { send_event(&a, AgentEvent::Falco { alerts }) }
    });
}

/// Send each new AIDE or rkhunter run to the server.
fn spawn_integrity(a: Arc<Agent>) {
    let sources = crate::integrity::sources(&a.cfg);
    // The server ignores runs it already has, so a restart may resend the latest.
    crate::integrity::watch(sources, Vec::new(), move |report| {
        let a = a.clone();
        async move {
            if !report.ok {
                tracing::warn!(event = "integrity.findings", tool = %report.tool, summary = %report.summary, "integrity check found changes");
            }
            send_event(&a, AgentEvent::Integrity { report });
        }
    });
}

/// What the agent reports about its managed canaries on each poll.
fn canary_states(a: &Agent) -> Vec<crate::agent::proto::CanaryState> {
    let Ok(g) = a.canary_states.lock() else {
        return Vec::new();
    };
    let Some(s) = g.as_ref().and_then(|s| s.lock().ok().map(|m| m.clone())) else {
        return Vec::new();
    };
    s.into_iter()
        .map(|(path, armed)| crate::agent::proto::CanaryState { path, armed })
        .collect()
}

/// Watch CANARY_FILES and the canaries the server sends, and report any access.
fn spawn_canaries(a: Arc<Agent>) {
    let files = a.cfg.canary_files.clone();
    let conf = a.conf.load(a.cfg.clamd_conf_file.as_deref()).ok().flatten();
    crate::canary::check_placement(&files, &a.cfg.scan_roots, conf.as_deref());
    let mut r = crate::canary::run(files, a.canaries.subscribe());
    if let Ok(mut g) = a.canary_states.lock() {
        *g = Some(r.states.clone());
    }
    tokio::spawn(async move {
        while let Some((p, what)) = r.hits.recv().await {
            // Logged here too, so the alert survives a server outage.
            tracing::error!(event = "canary.tripped", path = %p, what = %what, "canary file touched");
            let ev = AgentEvent::Canary { path: p, what };
            send_event(&a, ev);
        }
    });
}

/// Queue an event; the sender delivers it whenever the server is reachable.
fn send_event(a: &Agent, mut ev: AgentEvent) {
    if let AgentEvent::Scan {
        report: Some(r), ..
    } = &mut ev
    {
        r.fit(super::proto::MAX_BODY);
    }
    a.outbox.push(&Item::Event { body: ev });
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
        let mut plain = good.to_vec();
        plain[1] = "http://s.example:8080";
        assert!(build(cfg(&plain)).is_err(), "plain HTTP refused by default");
        plain.extend(["--agent-allow-plaintext", "true"]);
        assert!(build(cfg(&plain)).is_ok(), "allowed on this host");
    }
}
