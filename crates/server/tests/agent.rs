//! Remote agents end to end: a real server socket, a real agent loop, a fake clamd.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use clamv_webui::app::{AppState, router};
use clamv_webui::config::Cli;
use clamv_webui::db::Db;
use clamv_webui::db::jobs::{self, Job, NewJob};
use clap::Parser;
use tower::ServiceExt;

mod common;
use common::fake_clamd;

struct Server {
    st: Arc<AppState>,
    app: axum::Router,
    url: String,
}

async fn server() -> Server {
    let cli = Cli::parse_from(["clamv-webui", "--clamd-endpoint", "tcp://127.0.0.1:1"]);
    let db = Db::open("sqlite::memory:", 1).await.expect("db");
    clamv_webui::app::seed_endpoint(&db, &cli.config)
        .await
        .expect("seed");
    let st = Arc::new(AppState::new(cli.config.clone(), db));
    let app = router(st.clone(), &cli.config);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", l.local_addr().expect("addr"));
    let svc = app
        .clone()
        .into_make_service_with_connect_info::<std::net::SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(l, svc).await;
    });
    Server { st, app, url }
}

fn agent_cli(url: &str, token: &str, clamd: u16, root: &str) -> Cli {
    Cli::parse_from([
        "clamv-webui",
        "agent",
        "--listen",
        "127.0.0.1:0",
        "--agent-server-url",
        url,
        "--agent-token",
        token,
        "--clamd-endpoint",
        &format!("tcp://127.0.0.1:{clamd}"),
        "--scan-roots",
        root,
    ])
}

async fn queue(st: &AppState, kind: &str, target: &str, agent: i64) -> Job {
    let j = st
        .db
        .create_job(NewJob {
            kind,
            target,
            endpoint_id: None,
            schedule_id: None,
            agent_id: Some(agent),
            submitted_by: Some("test"),
            transport: "UI",
            running: false,
        })
        .await
        .expect("job");
    st.agents.poke();
    j
}

async fn wait_done(st: &AppState, id: &str) -> Job {
    for _ in 0..200 {
        let j = st.db.job(id).await.expect("q").expect("job");
        if j.status == jobs::FINISHED {
            return j;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("job {id} did not finish");
}

#[tokio::test]
async fn agent_runs_jobs_and_reports_back() {
    let srv = server().await;
    let clamd = fake_clamd().await;
    let root = std::env::temp_dir().join(format!("clamv-agent-{}", clamv_webui::db::new_id()));
    std::fs::create_dir_all(root.join("media")).expect("mkdir");
    let root_s = root.to_str().expect("utf8").to_owned();
    let (agent, token) = srv
        .st
        .db
        .create_agent("nas-2", "admin")
        .await
        .expect("agent");

    // Queued before the agent connects: it waits.
    let early = queue(&srv.st, "PATH", &format!("{root_s}/media"), agent.id).await;
    // The server's own dispatcher must never take an agent job.
    clamv_webui::scan::start(srv.st.clone()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        srv.st
            .db
            .job(&early.id)
            .await
            .expect("q")
            .expect("j")
            .status,
        jobs::QUEUED
    );

    let cli = agent_cli(&srv.url, &token, clamd, &root_s);
    let handle = tokio::spawn(clamv_webui::agent::client::run(cli.config));

    let j = wait_done(&srv.st, &early.id).await;
    assert_eq!(j.verdict.as_deref(), Some(jobs::VIRUS_FOUND));
    assert!(j.detections.keys().any(|p| p.ends_with("/eicar.com")));
    assert_eq!(j.errors.len(), 2, "locked file and limit hit");

    let a = srv.st.db.agent(agent.id).await.expect("q").expect("a");
    assert!(a.online && a.last_seen_at.is_some());
    assert_eq!(a.roots, vec![root_s.clone()]);
    assert!(
        a.clamd_version
            .as_deref()
            .is_some_and(|v| v.starts_with("ClamAV"))
    );

    // Long-poll: a job queued while the agent waits is picked up at once.
    let ctl = queue(&srv.st, "CONTROL", "EICAR test file", agent.id).await;
    let j = wait_done(&srv.st, &ctl.id).await;
    assert_eq!(j.verdict.as_deref(), Some(jobs::OK), "EICAR control passed");

    // The agent enforces its own roots even if the server was fooled.
    let out = queue(&srv.st, "PATH", "/etc", agent.id).await;
    let j = wait_done(&srv.st, &out.id).await;
    assert_eq!(j.error_code.as_deref(), Some("POLICY_REJECTED"));

    // Removing the agent fails its queued work; nothing else runs it.
    handle.abort();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let orphan = queue(&srv.st, "PATH", &format!("{root_s}/media"), agent.id).await;
    assert!(srv.st.db.delete_agent(agent.id).await.expect("delete"));
    let j = srv.st.db.job(&orphan.id).await.expect("q").expect("j");
    assert_eq!(j.status, jobs::FINISHED);
    assert_eq!(j.error_code.as_deref(), Some("CONFIGURATION_UNAVAILABLE"));
    let _ = std::fs::remove_dir_all(&root);
}

fn poll(token: &str, body: &str) -> Request<Body> {
    Request::post("/agent/v1/poll")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .expect("req")
}

const HELLO: &str = r#"{"protocol":1,"version":"t","roots":["/data"],"slots":1,"free":0}"#;

#[tokio::test]
async fn agent_endpoints_check_who_is_calling() {
    let srv = server().await;
    let (agent, token) = srv.st.db.create_agent("a1", "admin").await.expect("agent");
    let (other, other_token) = srv.st.db.create_agent("a2", "admin").await.expect("agent");

    let status = |r: Request<Body>| {
        let app = srv.app.clone();
        async move { app.oneshot(r).await.expect("res").status() }
    };
    assert_eq!(
        status(poll("clamv_agent_nope", HELLO)).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(poll("not-an-agent-token", HELLO)).await,
        StatusCode::UNAUTHORIZED
    );
    let wrong = HELLO.replace("\"protocol\":1", "\"protocol\":99");
    assert_eq!(
        status(poll(&token, &wrong)).await,
        StatusCode::UPGRADE_REQUIRED
    );
    assert_eq!(status(poll(&token, HELLO)).await, StatusCode::OK);

    // Another agent cannot post results for this agent's job.
    let j = queue(&srv.st, "PATH", "/data/x", agent.id).await;
    let claimed = srv
        .st
        .db
        .claim_agent_jobs(agent.id, 1)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    let post = |tok: &str| {
        Request::post(format!("/agent/v1/jobs/{}/result", j.id))
            .header(header::AUTHORIZATION, format!("Bearer {tok}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"report":{"ok":3}}"#))
            .expect("req")
    };
    assert_eq!(status(post(&other_token)).await, StatusCode::CONFLICT);
    assert_eq!(status(post(&token)).await, StatusCode::NO_CONTENT);
    let done = srv.st.db.job(&j.id).await.expect("q").expect("j");
    assert_eq!(
        (done.verdict.as_deref(), done.files_scanned),
        (Some(jobs::OK), 3)
    );
    assert_eq!(
        status(post(&token)).await,
        StatusCode::CONFLICT,
        "only once"
    );

    // Disabled agents are refused; a new token replaces the old one.
    srv.st
        .db
        .set_agent_enabled(other.id, false)
        .await
        .expect("disable");
    assert_eq!(
        status(poll(&other_token, HELLO)).await,
        StatusCode::FORBIDDEN
    );
    let fresh = srv
        .st
        .db
        .rotate_agent_secret(agent.id)
        .await
        .expect("rotate")
        .expect("some");
    assert_eq!(status(poll(&token, HELLO)).await, StatusCode::UNAUTHORIZED);
    assert_eq!(status(poll(&fresh, HELLO)).await, StatusCode::OK);
}

#[tokio::test]
async fn jobs_lost_by_an_agent_are_failed() {
    let srv = server().await;
    let (agent, token) = srv.st.db.create_agent("a1", "admin").await.expect("agent");
    let j = queue(&srv.st, "PATH", "/data/x", agent.id).await;
    srv.st
        .db
        .claim_agent_jobs(agent.id, 1)
        .await
        .expect("claim");
    // Still within the grace period: kept.
    let r = srv
        .app
        .clone()
        .oneshot(poll(&token, HELLO))
        .await
        .expect("res");
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        srv.st.db.job(&j.id).await.expect("q").expect("j").status,
        jobs::RUNNING
    );
    // The agent says it runs it: kept, whatever its age.
    let running = HELLO.replace(
        "\"free\":0",
        &format!("\"free\":0,\"running\":[\"{}\"]", j.id),
    );
    let r = srv
        .app
        .clone()
        .oneshot(poll(&token, &running))
        .await
        .expect("res");
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        srv.st.db.job(&j.id).await.expect("q").expect("j").status,
        jobs::RUNNING
    );
}

/// Over HTTPS with a self-signed certificate, the agent trusts exactly the pinned one.
#[tokio::test]
async fn agent_pins_the_server_certificate() {
    let dir = std::env::temp_dir().join(format!("clamv-agent-tls-{}", clamv_webui::db::new_id()));
    let data = dir.to_str().expect("utf8").to_owned();
    let cli = Cli::parse_from([
        "clamv-webui",
        "--clamd-endpoint",
        "tcp://127.0.0.1:1",
        "--data-dir",
        &data,
        "--tls-self-signed",
        "--tls-self-signed-names",
        "localhost",
    ]);
    let db = Db::open("sqlite::memory:", 1).await.expect("db");
    let st = Arc::new(AppState::new(cli.config.clone(), db));
    let (tls, cert) = clamv_webui::tls::config(&cli.config).await.expect("tls");
    let fp = clamv_webui::tls::fingerprint(&cert).expect("fp");
    let std_l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!(
        "https://127.0.0.1:{}",
        std_l.local_addr().expect("addr").port()
    );
    let svc = router(st.clone(), &cli.config)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();
    tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(std_l, tls)
            .expect("listener")
            .serve(svc)
            .await;
    });
    let (agent, token) = st.db.create_agent("tls", "admin").await.expect("agent");
    let clamd = fake_clamd().await;

    let wrong = ["00"; 32].join(":");
    let mut c = agent_cli(&url, &token, clamd, &data);
    c.config.agent_server_fingerprint = Some(wrong);
    let h = tokio::spawn(clamv_webui::agent::client::run(c.config));
    tokio::time::sleep(Duration::from_millis(800)).await;
    h.abort();
    assert!(
        st.db
            .agent(agent.id)
            .await
            .expect("q")
            .expect("a")
            .last_seen_at
            .is_none(),
        "wrong pin never connects"
    );

    // No pin and no CA: the self-signed certificate is refused too.
    let c = agent_cli(&url, &token, clamd, &data);
    let h = tokio::spawn(clamv_webui::agent::client::run(c.config));
    tokio::time::sleep(Duration::from_millis(800)).await;
    h.abort();
    assert!(
        st.db
            .agent(agent.id)
            .await
            .expect("q")
            .expect("a")
            .last_seen_at
            .is_none()
    );

    let mut c = agent_cli(&url, &token, clamd, &data);
    c.config.agent_server_fingerprint = Some(fp.to_lowercase());
    let h = tokio::spawn(clamv_webui::agent::client::run(c.config));
    let mut seen = false;
    for _ in 0..100 {
        if st
            .db
            .agent(agent.id)
            .await
            .expect("q")
            .expect("a")
            .last_seen_at
            .is_some()
        {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    h.abort();
    assert!(seen, "right pin connects");
    let _ = std::fs::remove_dir_all(&dir);
}
