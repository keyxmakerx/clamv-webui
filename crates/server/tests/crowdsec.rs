//! CrowdSec console against a fake Local API.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::routing::{delete, get, post};
use clamv_webui::app::{AppState, router};
use clamv_webui::config::Cli;
use clamv_webui::db::Db;
use clap::Parser;
use serde_json::{Value, json};
use tower::ServiceExt;

#[derive(Default)]
struct Fake {
    password: String,
    token: String,
    alerts: Vec<Value>,
    deleted: Vec<i64>,
    posted: Vec<Value>,
    logins: usize,
}

type Shared = Arc<Mutex<Fake>>;

fn authed(f: &Fake, h: &HeaderMap) -> bool {
    h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {}", f.token))
}

async fn login(
    State(f): State<Shared>,
    axum::Json(b): axum::Json<Value>,
) -> (StatusCode, axum::Json<Value>) {
    let mut f = f.lock().expect("lock");
    f.logins += 1;
    if b["machine_id"] != "clamv-webui" || b["password"] != f.password.as_str() {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"code": 401, "message": "incorrect Username or Password"})),
        );
    }
    (
        StatusCode::OK,
        axum::Json(json!({"code": 200, "expire": "2099-01-01T00:00:00Z", "token": f.token})),
    )
}

async fn list(
    State(f): State<Shared>,
    h: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> (StatusCode, axum::Json<Value>) {
    let f = f.lock().expect("lock");
    if !authed(&f, &h) {
        return (StatusCode::UNAUTHORIZED, axum::Json(json!({})));
    }
    assert_eq!(q.get("simulated").map(String::as_str), Some("true"));
    let active = q.contains_key("has_active_decision");
    let out: Vec<Value> = f
        .alerts
        .iter()
        .filter_map(|a| {
            let mut a = a.clone();
            let ds: Vec<Value> = a["decisions"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|d| {
                    let id = d["id"].as_i64().unwrap_or(0);
                    !f.deleted.contains(&id)
                        && !(active && d["duration"].as_str().unwrap_or("").starts_with('-'))
                })
                .collect();
            if active && ds.is_empty() {
                return None;
            }
            a["decisions"] = Value::Array(ds);
            Some(a)
        })
        .collect();
    (StatusCode::OK, axum::Json(Value::Array(out)))
}

async fn add(
    State(f): State<Shared>,
    h: HeaderMap,
    axum::Json(b): axum::Json<Value>,
) -> (StatusCode, axum::Json<Value>) {
    let mut f = f.lock().expect("lock");
    if !authed(&f, &h) {
        return (StatusCode::UNAUTHORIZED, axum::Json(json!({})));
    }
    let mut a = b[0].clone();
    let id = 100 + i64::try_from(f.posted.len()).expect("n");
    a["id"] = json!(id);
    a["machine_id"] = json!("clamv-webui");
    a["created_at"] = json!(clamv_webui::timefmt::rfc3339(clamv_webui::db::now_ms()));
    a["decisions"][0]["id"] = json!(id + 1000);
    f.posted.push(b[0].clone());
    f.alerts.push(a);
    (StatusCode::CREATED, axum::Json(json!([id.to_string()])))
}

async fn del_one(
    State(f): State<Shared>,
    h: HeaderMap,
    Path(id): Path<i64>,
) -> (StatusCode, axum::Json<Value>) {
    let mut f = f.lock().expect("lock");
    if !authed(&f, &h) {
        return (StatusCode::UNAUTHORIZED, axum::Json(json!({})));
    }
    f.deleted.push(id);
    (StatusCode::OK, axum::Json(json!({"nbDeleted": "1"})))
}

async fn del_ip(
    State(f): State<Shared>,
    h: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> (StatusCode, axum::Json<Value>) {
    let mut f = f.lock().expect("lock");
    if !authed(&f, &h) {
        return (StatusCode::UNAUTHORIZED, axum::Json(json!({})));
    }
    let ip = q.get("ip").cloned().unwrap_or_default();
    let ids: Vec<i64> = f
        .alerts
        .iter()
        .flat_map(|a| a["decisions"].as_array().cloned().unwrap_or_default())
        .filter(|d| d["value"] == ip.as_str())
        .filter_map(|d| d["id"].as_i64())
        .collect();
    let n = ids.len();
    f.deleted.extend(ids);
    (
        StatusCode::OK,
        axum::Json(json!({"nbDeleted": n.to_string()})),
    )
}

fn alert(id: i64, ip: &str, cn: &str, scenario: &str, machine: &str, decisions: Value) -> Value {
    json!({
        "id": id, "scenario": scenario, "machine_id": machine, "events_count": 5, "simulated": false,
        "message": format!("Ip {ip} performed '{scenario}'"),
        "created_at": clamv_webui::timefmt::rfc3339(clamv_webui::db::now_ms() - 600_000),
        "source": {"scope": "Ip", "value": ip, "ip": ip, "cn": cn, "as_name": "EXAMPLE-AS", "as_number": "64500", "latitude": 52.3, "longitude": 4.9},
        "decisions": decisions,
        "events": [{"meta": [{"key": "service", "value": "ssh"}, {"key": "target_user", "value": "root"}]}],
    })
}

async fn fake_lapi() -> (String, Shared) {
    let shared: Shared = Arc::new(Mutex::new(Fake {
        password: clamv_webui::auth::token::random_secret(),
        token: clamv_webui::auth::token::random_secret(),
        alerts: vec![
            alert(
                1,
                "198.51.100.4",
                "NL",
                "crowdsecurity/ssh-bf",
                "nas",
                json!([
                    {"id": 11, "origin": "crowdsec", "type": "ban", "scope": "Ip", "value": "198.51.100.4", "duration": "3h50m", "scenario": "crowdsecurity/ssh-bf", "simulated": false},
                ]),
            ),
            alert(
                2,
                "192.0.2.9",
                "US",
                "crowdsecurity/http-probing",
                "edge",
                json!([
                    {"id": 12, "origin": "crowdsec", "type": "ban", "scope": "Ip", "value": "192.0.2.9", "duration": "-10m", "scenario": "crowdsecurity/http-probing", "simulated": false},
                ]),
            ),
        ],
        ..Fake::default()
    }));
    let app = Router::new()
        .route("/v1/watchers/login", post(login))
        .route("/v1/alerts", get(list).post(add))
        .route("/v1/decisions/{id}", delete(del_one))
        .route("/v1/decisions", delete(del_ip))
        .with_state(shared.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", l.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(l, app).await });
    (url, shared)
}

async fn app_with(extra: &[&str]) -> (Router, Arc<AppState>, String) {
    let mut args = vec!["clamv-webui", "--clamd-endpoint", "tcp://127.0.0.1:1"];
    args.extend_from_slice(extra);
    let cli = Cli::parse_from(args);
    let db = Db::open("sqlite::memory:", 1).await.expect("db");
    let dir = std::env::temp_dir();
    let pw = clamv_webui::auth::token::random_secret();
    clamv_webui::auth::bootstrap::ensure_admin(&db, &dir, Some(&pw))
        .await
        .expect("bootstrap");
    let admin = db
        .user_by_username("admin")
        .await
        .expect("q")
        .expect("admin");
    let (raw, s) = db
        .create_session(&admin.id, 3_600_000, None, None)
        .await
        .expect("session");
    let st = Arc::new(AppState::new(cli.config.clone(), db));
    (
        router(st.clone(), &cli.config),
        st,
        format!("clamv_session={raw}|{}", s.csrf_token),
    )
}

fn get_req(uri: &str, cookie: &str) -> Request<Body> {
    Request::get(uri)
        .header(header::COOKIE, cookie.split('|').next().expect("c"))
        .body(Body::empty())
        .expect("req")
}

fn post_req(uri: &str, body: &str, cookie: &str) -> Request<Body> {
    let (c, t) = cookie.split_once('|').expect("c|t");
    Request::post(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::HOST, "nas:8080")
        .header(header::COOKIE, c)
        .body(Body::from(format!("_csrf={t}&{body}")))
        .expect("req")
}

async fn body(res: axum::response::Response) -> String {
    let b = http_body_util::BodyExt::collect(res.into_body())
        .await
        .expect("body")
        .to_bytes();
    String::from_utf8_lossy(&b).into_owned()
}

#[tokio::test]
async fn console_reads_alerts_and_manages_decisions() {
    let (url, fake) = fake_lapi().await;
    let pw = fake.lock().expect("lock").password.clone();
    let (app, st, c) = app_with(&["--crowdsec-lapi-url", &url, "--crowdsec-password", &pw]).await;
    clamv_webui::crowdsec::tick(&st, true).await;
    let s = st.crowdsec.status();
    assert!(s.up, "{:?}", s.error);

    let page = body(
        app.clone()
            .oneshot(get_req("/crowdsec", &c))
            .await
            .expect("res"),
    )
    .await;
    assert!(page.contains("attack-map") && page.contains("/images/world.svg"));
    assert!(page.contains("crowdsecurity/ssh-bf") && page.contains("EXAMPLE-AS"));
    assert!(page.contains("LAPI up"));

    let res = app
        .clone()
        .oneshot(get_req("/crowdsec/alerts?q=country%3DNL", &c))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    let page = body(res).await;
    assert!(page.contains("198.51.100.4") && !page.contains("192.0.2.9"));
    assert!(page.contains("target_user"));

    let page = body(
        app.clone()
            .oneshot(get_req("/crowdsec/decisions", &c))
            .await
            .expect("res"),
    )
    .await;
    assert!(page.contains("198.51.100.4") && !page.contains("<code>192.0.2.9</code>"));
    assert!(page.contains("Add a decision"));
    let page = body(
        app.clone()
            .oneshot(get_req("/crowdsec/decisions?expired=1", &c))
            .await
            .expect("res"),
    )
    .await;
    assert!(page.contains("<code>192.0.2.9</code>") && page.contains("ended"));

    // A ban goes to the LAPI as a manual alert, then shows up.
    let res = app
        .clone()
        .oneshot(post_req(
            "/crowdsec/decisions",
            "value=203.0.113.7&kind=ban&duration=4h&custom=&reason=probing+wp-login",
            &c,
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    let page = body(res).await;
    assert!(page.contains("ban on 203.0.113.7 for 4h"), "{page}");
    assert!(page.contains("<code>203.0.113.7</code>"));
    {
        let f = fake.lock().expect("lock");
        let d = &f.posted[0]["decisions"][0];
        assert_eq!(
            (
                d["value"].as_str(),
                d["duration"].as_str(),
                d["origin"].as_str()
            ),
            (Some("203.0.113.7"), Some("4h"), Some("cscli"))
        );
        assert!(
            f.posted[0]["scenario"]
                .as_str()
                .unwrap_or("")
                .contains("admin")
        );
    }
    let res = app
        .clone()
        .oneshot(post_req(
            "/crowdsec/decisions",
            "value=127.0.0.1&kind=ban&duration=4h&reason=x",
            &c,
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Removing one decision, then all on an IP.
    let res = app
        .clone()
        .oneshot(post_req("/crowdsec/decisions/11/delete", "", &c))
        .await
        .expect("res");
    assert!(body(res).await.contains("Removed ban 198.51.100.4"));
    assert!(fake.lock().expect("lock").deleted.contains(&11));
    let res = app
        .clone()
        .oneshot(post_req(
            "/crowdsec/decisions/remove",
            "value=203.0.113.7",
            &c,
        ))
        .await
        .expect("res");
    assert!(
        body(res)
            .await
            .contains("Removed 1 decision(s) on 203.0.113.7")
    );
    assert!(st.crowdsec.active().is_empty());

    let audit = st
        .db
        .audit_by_action("CROWDSEC_BAN", 0)
        .await
        .expect("audit");
    assert_eq!(audit.len(), 1);
    assert_eq!(
        st.db
            .audit_by_action("CROWDSEC_UNBAN", 0)
            .await
            .expect("audit")
            .len(),
        2
    );
}

#[tokio::test]
async fn read_only_wrong_password_and_unset() {
    let (url, _fake) = fake_lapi().await;
    let (app, st, c) = app_with(&[
        "--crowdsec-lapi-url",
        &url,
        "--crowdsec-password",
        "wrong",
        "--crowdsec-read-only",
        "true",
    ])
    .await;
    clamv_webui::crowdsec::tick(&st, true).await;
    let s = st.crowdsec.status();
    assert!(!s.up);
    assert!(s.error.as_deref().unwrap_or("").contains("refused machine"));
    let page = body(
        app.clone()
            .oneshot(get_req("/crowdsec/decisions", &c))
            .await
            .expect("res"),
    )
    .await;
    assert!(page.contains("LAPI down") && !page.contains("Add a decision"));
    let res = app
        .clone()
        .oneshot(post_req(
            "/crowdsec/decisions",
            "value=203.0.113.7&kind=ban&duration=4h&reason=x",
            &c,
        ))
        .await
        .expect("res");
    assert!(body(res).await.contains("CROWDSEC_READ_ONLY"));

    let (app, _st, c) = app_with(&[]).await;
    let page = body(app.oneshot(get_req("/crowdsec", &c)).await.expect("res")).await;
    assert!(page.contains("Connect CrowdSec"));
}

#[tokio::test]
async fn bad_lapi_urls_are_refused() {
    for u in ["ftp://x", "http://user:pw@crowdsec:8080", "not a url"] {
        let cli = Cli::parse_from([
            "clamv-webui",
            "--crowdsec-lapi-url",
            u,
            "--crowdsec-password",
            "x",
        ]);
        assert!(
            clamv_webui::crowdsec::Console::from_config(&cli.config).is_err(),
            "{u}"
        );
    }
    let cli = Cli::parse_from(["clamv-webui", "--crowdsec-lapi-url", "http://crowdsec:8080"]);
    assert!(clamv_webui::crowdsec::Console::from_config(&cli.config).is_err());
}
