//! Agent link round 5: protocol versions, late results, cancel, and agents in the API.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use clamv_webui::app::{AppState, router};
use clamv_webui::config::Cli;
use clamv_webui::db::Db;
use clamv_webui::db::jobs::{self, Job, NewJob};
use clamv_webui::db::tokens::NewToken;
use clap::Parser;
use serde_json::{Value, json};
use tower::ServiceExt;

struct T {
    app: Router,
    st: Arc<AppState>,
}

async fn setup() -> T {
    let cli = Cli::parse_from([
        "clamv-webui",
        "--clamd-endpoint",
        "tcp://127.0.0.1:1",
        "--scan-roots",
        "/tmp",
    ]);
    let db = Db::open("sqlite::memory:", 1).await.expect("db");
    clamv_webui::app::seed_endpoint(&db, &cli.config)
        .await
        .expect("seed");
    // review-only: API tokens need their creator to exist as an enabled admin (#7).
    db.create_user("admin", "x", clamv_webui::auth::Role::Admin, false)
        .await
        .expect("admin");
    let st = Arc::new(AppState::new(cli.config.clone(), db));
    T {
        app: router(st.clone(), &cli.config),
        st,
    }
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = app.clone().oneshot(req).await.expect("res");
    let status = res.status();
    let b = http_body_util::BodyExt::collect(res.into_body())
        .await
        .expect("body")
        .to_bytes();
    (status, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

fn post(uri: &str, auth: &str, body: &Value) -> Request<Body> {
    Request::post(uri)
        .header(header::AUTHORIZATION, auth)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("req")
}

fn get(uri: &str, auth: &str) -> Request<Body> {
    Request::get(uri)
        .header(header::AUTHORIZATION, auth)
        .body(Body::empty())
        .expect("req")
}

fn hello(protocol: u32, running: &[&str], kinds: &[&str]) -> Value {
    json!({"protocol": protocol, "version": "9.9", "roots": ["/data"], "slots": 2,
           "free": 0, "running": running, "kinds": kinds})
}

async fn queue(st: &AppState, kind: &str, target: &str, agent: i64) -> Job {
    st.db
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
        .expect("job")
}

async fn token(st: &AppState, scopes: &[&str], eps: Option<&[i64]>) -> String {
    let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
    let (secret, _) = st
        .db
        .create_token(NewToken {
            label: "t",
            scopes: &scopes,
            endpoint_ids: eps,
            path_roots: None,
            created_by: "admin",
            expires_at: None,
        })
        .await
        .expect("token");
    format!("Bearer {secret}")
}

#[tokio::test]
async fn protocol_versions_and_job_kinds() {
    let t = setup().await;
    let (agent, tok) = t.st.db.create_agent("a1", "admin").await.expect("agent");
    let bearer = format!("Bearer {tok}");
    // Too new: refused, and the page can say which side to update.
    let (s, _) = call(
        &t.app,
        post("/agent/v1/poll", &bearer, &hello(99, &[], &[])),
    )
    .await;
    assert_eq!(s, StatusCode::UPGRADE_REQUIRED);
    let hint = t.st.agents.version_hint(agent.id).expect("hint");
    assert!(hint.contains("update the server"), "{hint}");
    // Protocol 1 is still accepted and clears the hint.
    let (s, _) = call(&t.app, post("/agent/v1/poll", &bearer, &hello(1, &[], &[]))).await;
    assert_eq!(s, StatusCode::OK);
    assert!(t.st.agents.version_hint(agent.id).is_none());
    // A protocol 2 agent that runs only path scans: a firewall job fails with a clear reason.
    let fw = queue(&t.st, "FIREWALL", r#"{"op":"snapshot"}"#, agent.id).await;
    let mut h = hello(2, &[], &["PATH"]);
    h["free"] = json!(2);
    let (s, b) = call(&t.app, post("/agent/v1/poll", &bearer, &h)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["jobs"].as_array().map(Vec::len), Some(0));
    let j = t.st.db.job(&fw.id).await.expect("q").expect("j");
    assert_eq!(j.status, jobs::FINISHED);
    assert_eq!(j.error_code.as_deref(), Some("AGENT_UNSUPPORTED"));
}

#[tokio::test]
async fn late_results_finish_jobs_given_up_on_and_cancel_stops_agents() {
    let t = setup().await;
    let (agent, tok) = t.st.db.create_agent("a1", "admin").await.expect("agent");
    let bearer = format!("Bearer {tok}");
    let (s, _) = call(
        &t.app,
        post("/agent/v1/poll", &bearer, &hello(2, &[], &["PATH"])),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // A job the server gave up on (agent away) still takes the result.
    let j = queue(&t.st, "PATH", "/data/a", agent.id).await;
    t.st.db.claim_agent_jobs(agent.id, 1).await.expect("claim");
    let lost = clamv_webui::scan::failure(clamv_webui::agent::AGENT_LOST, "gone");
    assert!(
        t.st.db
            .finish_job_if(&j.id, jobs::RUNNING, &lost)
            .await
            .expect("lose")
    );
    let uri = format!("/agent/v1/jobs/{}/result", j.id);
    let report = json!({"report": {"ok": 4, "detections": [{"path": "/data/a/x", "text": "Eicar-Test-Signature"}]}});
    let (s, _) = call(&t.app, post(&uri, &bearer, &report)).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "late result accepted");
    let done = t.st.db.job(&j.id).await.expect("q").expect("j");
    assert_eq!(done.verdict.as_deref(), Some(jobs::VIRUS_FOUND));
    let (s, _) = call(&t.app, post(&uri, &bearer, &report)).await;
    assert_eq!(s, StatusCode::CONFLICT, "only once");

    // Cancelling a running agent job: the next poll tells the agent, and its result is refused.
    let r = queue(&t.st, "PATH", "/data/b", agent.id).await;
    t.st.db.claim_agent_jobs(agent.id, 1).await.expect("claim");
    let r = t.st.db.job(&r.id).await.expect("q").expect("j");
    clamv_webui::cancel::cancel(&t.st, &r, "op")
        .await
        .expect("cancel");
    let (s, b) = call(
        &t.app,
        post("/agent/v1/poll", &bearer, &hello(2, &[&r.id], &["PATH"])),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["cancel"], json!([r.id]));
    let (s, _) = call(
        &t.app,
        post(&format!("/agent/v1/jobs/{}/result", r.id), &bearer, &report),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "cancelled jobs take no result");
    let c = t.st.db.job(&r.id).await.expect("q").expect("j");
    assert_eq!(c.error_code.as_deref(), Some("CANCELLED"));
    assert!(
        clamv_webui::cancel::cancel(&t.st, &c, "op").await.is_err(),
        "once"
    );
}

#[tokio::test]
async fn api_targets_agents_and_schedules() {
    let t = setup().await;
    let (agent, tok) = t.st.db.create_agent("nas", "admin").await.expect("agent");
    let (s, _) = call(
        &t.app,
        post(
            "/agent/v1/poll",
            &format!("Bearer {tok}"),
            &hello(2, &[], &["PATH"]),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let full = token(
        &t.st,
        &[
            "scan:path",
            "jobs:read",
            "endpoints:read",
            "schedules:read",
            "schedules:write",
        ],
        None,
    )
    .await;

    let (s, b) = call(&t.app, get("/api/v1/agents", &full)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b[0]["name"], "nas");
    assert_eq!(b[0]["online"], true);

    // Path scan on the agent, by name; outside its roots is refused.
    let (s, b) = call(
        &t.app,
        post(
            "/api/v1/scans/paths",
            &full,
            &json!({"path": "/data/x", "agent": "NAS"}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    let id = b["jobId"].as_str().expect("id").to_owned();
    let j = t.st.db.job(&id).await.expect("q").expect("j");
    assert_eq!(j.agent_id, Some(agent.id));
    let (s, _) = call(
        &t.app,
        post(
            "/api/v1/scans/paths",
            &full,
            &json!({"path": "/etc/passwd", "agentId": agent.id}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = call(
        &t.app,
        post(
            "/api/v1/scans/paths",
            &full,
            &json!({"path": "/data/x", "agent": "nope"}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Cancel it through the API.
    let (s, b) = call(
        &t.app,
        post(&format!("/api/v1/jobs/{id}/cancel"), &full, &json!({})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["error"]["code"], "CANCELLED");
    assert_eq!(b["agentId"], agent.id);
    let (s, _) = call(
        &t.app,
        post(&format!("/api/v1/jobs/{id}/cancel"), &full, &json!({})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);

    // A token tied to an endpoint never reaches agents.
    let narrow = token(&t.st, &["scan:path", "endpoints:read"], Some(&[1])).await;
    let (_, b) = call(&t.app, get("/api/v1/agents", &narrow)).await;
    assert_eq!(b, json!([]));
    let (s, _) = call(
        &t.app,
        post(
            "/api/v1/scans/paths",
            &narrow,
            &json!({"path": "/data/x", "agent": "nas"}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Schedules: create on the agent, list, run, pause, delete.
    let (s, b) = call(
        &t.app,
        post(
            "/api/v1/schedules",
            &full,
            &json!({"name": "nightly", "cron": "0 3 * * *", "paths": ["/data"], "agent": "nas"}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let sid = b["id"].as_str().expect("id").to_owned();
    assert_eq!(b["agent"], "nas");
    let (_, b) = call(&t.app, get("/api/v1/schedules", &full)).await;
    assert_eq!(b.as_array().map(Vec::len), Some(1));
    let (s, b) = call(
        &t.app,
        post(&format!("/api/v1/schedules/{sid}/run"), &full, &json!({})),
    )
    .await;
    assert_eq!((s, b["created"].as_u64()), (StatusCode::ACCEPTED, Some(1)));
    let patch = Request::patch(format!("/api/v1/schedules/{sid}"))
        .header(header::AUTHORIZATION, &full)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"enabled":false}"#))
        .expect("req");
    let (s, b) = call(&t.app, patch).await;
    assert_eq!((s, b["enabled"].as_bool()), (StatusCode::OK, Some(false)));
    let (s, _) = call(&t.app, get("/api/v1/schedules", &narrow)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "scope needed");
    let del = Request::delete(format!("/api/v1/schedules/{sid}"))
        .header(header::AUTHORIZATION, &full)
        .body(Body::empty())
        .expect("req");
    let (s, _) = call(&t.app, del).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // Zone, window and whole-path exclusions; nextRunAt honours them.
    let (s, b) = call(
        &t.app,
        post(
            "/api/v1/schedules",
            &full,
            &json!({"name": "night", "cron": "*/30 * * * *", "paths": ["/data/a", "/data/b"], "agent": "nas",
                "timeZone": "Europe/Berlin", "window": {"start": "22:00", "end": "06:00"}, "exclusions": ["/data/b/"]}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    assert_eq!(b["timeZone"], "Europe/Berlin");
    assert_eq!(b["window"], json!({"start": "22:00", "end": "06:00"}));
    assert_eq!(b["exclusions"], json!(["/data/b"]));
    let next = b["nextRunAt"].as_str().expect("next run");
    let at = next
        .parse::<jiff::Timestamp>()
        .expect("time")
        .in_tz("Europe/Berlin")
        .expect("zone");
    let hm = i32::from(at.hour()) * 60 + i32::from(at.minute());
    assert!(
        !(6 * 60..22 * 60).contains(&hm),
        "inside the window: {next}"
    );
    for (body, why) in [
        (
            json!({"name": "a", "cron": "0 3 * * *", "paths": ["/data"], "agent": "nas", "timeZone": "Mars/Base"}),
            "zone",
        ),
        (
            json!({"name": "b", "cron": "0 12 * * *", "paths": ["/data"], "agent": "nas", "window": {"start": "22:00", "end": "06:00"}}),
            "never runs",
        ),
        (
            json!({"name": "c", "cron": "0 3 * * *", "paths": ["/data"], "agent": "nas", "exclusions": ["/data/x"]}),
            "inner exclusion",
        ),
        (
            json!({"name": "d", "cron": "0 3 * * *", "paths": ["/data"], "agent": "nas", "window": {"start": "25:00", "end": "06:00"}}),
            "bad time",
        ),
    ] {
        let (s, _) = call(&t.app, post("/api/v1/schedules", &full, &body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{why}");
    }

    // Prometheus has a series per agent.
    let text = clamv_webui::metrics::render(&t.st).await;
    assert!(
        text.contains("clamav_agent_up{agent=\"nas\"} 1"),
        "agent metric"
    );
}

#[tokio::test]
async fn job_page_cancels_a_queued_job() {
    let t = setup().await;
    let h = clamv_webui::auth::password::hash("x-long-password-1").expect("hash");
    let u =
        t.st.db
            .create_user("op", &h, clamv_webui::auth::Role::Operator, false)
            .await
            .expect("user");
    let (raw, s) =
        t.st.db
            .create_session(&u.id, 3_600_000, None, None)
            .await
            .expect("session");
    let cookie = format!("clamv_session={raw}");
    let (agent, _) = t.st.db.create_agent("nas", "admin").await.expect("agent");
    let j = queue(&t.st, "PATH", "/data/x", agent.id).await;
    let page = Request::get(format!("/jobs/{}", j.id))
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .expect("req");
    let res = t.app.clone().oneshot(page).await.expect("res");
    let html = http_body_util::BodyExt::collect(res.into_body())
        .await
        .expect("body")
        .to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(
        html.contains(&format!("/jobs/{}/cancel", j.id)),
        "button shown"
    );
    let form = |csrf: &str| {
        Request::post(format!("/jobs/{}/cancel", j.id))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::HOST, "nas:8080")
            .header(header::COOKIE, &cookie)
            .body(Body::from(format!("_csrf={csrf}")))
            .expect("req")
    };
    let res = t.app.clone().oneshot(form("wrong")).await.expect("res");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = t
        .app
        .clone()
        .oneshot(form(&s.csrf_token))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let done = t.st.db.job(&j.id).await.expect("q").expect("j");
    assert_eq!(done.error_code.as_deref(), Some("CANCELLED"));
    assert_eq!(done.error_message.as_deref(), Some("Cancelled by op."));
    let audit = t.st.db.audit_page(0, 10).await.expect("audit");
    assert!(audit.0.iter().any(|a| a.action == "CANCEL_JOB"));
}
