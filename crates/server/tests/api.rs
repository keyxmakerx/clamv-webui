//! `/api/v1`: authentication, scopes, CSRF for Basic writes, token restrictions.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use clamv_webui::app::{AppState, router};
use clamv_webui::auth::Role;
use clamv_webui::config::Cli;
use clamv_webui::db::Db;
use clamv_webui::db::tokens::NewToken;
use clap::Parser;
use serde_json::Value;
use tower::ServiceExt;

struct T {
    app: Router,
    st: Arc<AppState>,
    pw: String,
}

async fn setup(extra: &[&str]) -> T {
    let mut args = vec!["clamv-webui", "--clamd-endpoint", "tcp://127.0.0.1:1"];
    args.extend_from_slice(extra);
    let cli = Cli::parse_from(args);
    let db = Db::open("sqlite::memory:", 1).await.expect("db");
    clamv_webui::app::seed_endpoint(&db, &cli.config)
        .await
        .expect("seed");
    let st = Arc::new(AppState::new(cli.config.clone(), db));
    let pw = clamv_webui::auth::token::random_secret();
    let h = clamv_webui::auth::password::hash(&pw).expect("hash");
    for (name, role) in [
        ("viewer", Role::Viewer),
        ("op", Role::Operator),
        ("admin", Role::Admin),
    ] {
        st.db
            .create_user(name, &h, role, false)
            .await
            .expect("user");
    }
    T {
        app: router(st.clone(), &cli.config),
        st,
        pw,
    }
}

fn basic(user: &str, pw: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pw}"))
    )
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Option<String>, Value) {
    let res = app.clone().oneshot(req).await.expect("res");
    let status = res.status();
    let cookie = res
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::to_owned);
    let b = http_body_util::BodyExt::collect(res.into_body())
        .await
        .expect("body")
        .to_bytes();
    (
        status,
        cookie,
        serde_json::from_slice(&b).unwrap_or(Value::Null),
    )
}

fn get(uri: &str, auth: &str) -> Request<Body> {
    Request::get(uri)
        .header(header::AUTHORIZATION, auth)
        .body(Body::empty())
        .expect("req")
}

#[tokio::test]
async fn auth_and_role_scopes() {
    let t = setup(&[]).await;
    let (s, _, b) = call(
        &t.app,
        Request::get("/api/v1/auth")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(b["error"], "unauthorized");
    let (s, _, _) = call(
        &t.app,
        get("/api/v1/auth", &basic("viewer", "wrong-password")),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, b) = call(&t.app, get("/api/v1/auth", &basic("viewer", &t.pw))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        (b["principal"].as_str(), b["authentication"].as_str()),
        (Some("viewer"), Some("user"))
    );
    // Route x role table (lesson 8).
    let table: &[(&str, Role)] = &[
        ("/api/v1/endpoints", Role::Viewer),
        ("/api/v1/health/live", Role::Viewer),
        ("/api/v1/jobs", Role::Operator),
        ("/api/v1/audit", Role::Admin),
    ];
    for (user, role) in [
        ("viewer", Role::Viewer),
        ("op", Role::Operator),
        ("admin", Role::Admin),
    ] {
        for (path, need) in table {
            let (s, _, _) = call(&t.app, get(path, &basic(user, &t.pw))).await;
            let want = if role.allows(*need) {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            };
            assert_eq!(s, want, "GET {path} as {user}");
        }
    }
    let (s, _, b) = call(&t.app, get("/api/v1/nope", &basic("viewer", &t.pw))).await;
    assert_eq!(
        (s, b["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
    let (_, _, b) = call(&t.app, get("/api/v1/endpoints", &basic("viewer", &t.pw))).await;
    assert_eq!(b[0]["name"], "default");
    assert!(b[0].get("address").is_none(), "no hostnames");
}

#[tokio::test]
async fn basic_writes_need_session_csrf() {
    let t = setup(&["--scan-roots", "/nonexistent-root"]).await;
    let auth = basic("op", &t.pw);
    let post = |cookie: Option<&str>, csrf: Option<&str>| {
        let mut b = Request::post("/api/v1/scans/paths")
            .header(header::AUTHORIZATION, &auth)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, c);
        }
        if let Some(c) = csrf {
            b = b.header("X-CSRF-TOKEN", c);
        }
        b.body(Body::from(r#"{"path":"/etc"}"#)).expect("req")
    };
    let (s, _, _) = call(&t.app, post(None, None)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, cookie, b) = call(&t.app, get("/api/v1/csrf", &auth)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["headerName"], "X-CSRF-TOKEN");
    let token = b["token"].as_str().expect("token").to_owned();
    let cookie = cookie.expect("session cookie");
    let (s, _, _) = call(&t.app, post(Some(&cookie), Some("wrong"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // CSRF passes; the path is then refused by policy.
    let (s, _, b) = call(&t.app, post(Some(&cookie), Some(&token))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    // Another user's session cannot back this user's CSRF token.
    let (_, viewer_cookie, vb) = call(&t.app, get("/api/v1/csrf", &basic("admin", &t.pw))).await;
    let vt = vb["token"].as_str().expect("token").to_owned();
    let (s, _, _) = call(&t.app, post(viewer_cookie.as_deref(), Some(&vt))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn tokens_are_scoped_and_restricted() {
    let t = setup(&[]).await;
    let ep2 =
        t.st.db
            .create_endpoint("second", "tcp://127.0.0.1:2", false)
            .await
            .expect("ep");
    let (secret, tok) =
        t.st.db
            .create_token(NewToken {
                label: "ci",
                scopes: &["jobs:read".to_owned(), "endpoints:read".to_owned()],
                endpoint_ids: Some(&[ep2.id]),
                path_roots: None,
                created_by: "admin",
                expires_at: None,
            })
            .await
            .expect("token");
    let bearer = format!("Bearer {secret}");
    let (s, _, b) = call(&t.app, get("/api/v1/auth", &bearer)).await;
    assert_eq!(
        (s, b["authentication"].as_str()),
        (StatusCode::OK, Some("token"))
    );
    let (_, _, b) = call(&t.app, get("/api/v1/endpoints", &bearer)).await;
    assert_eq!(b.as_array().map(Vec::len), Some(1), "only its endpoint");
    assert_eq!(b[0]["id"], ep2.id);
    let (s, _, _) = call(&t.app, get("/api/v1/audit", &bearer)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "scope not granted");
    let (s, _, _) = call(&t.app, get("/api/v1/jobs?endpointId=1", &bearer)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "endpoint not granted");
    let (s, _, _) = call(&t.app, get("/api/v1/jobs", &bearer)).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = call(&t.app, get("/api/v1/jobs?size=1000", &bearer)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // Tokens cannot mint tokens; Basic cannot either.
    let (s, _, _) = call(&t.app, get("/api/v1/tokens", &bearer)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = call(&t.app, get("/api/v1/tokens", &basic("admin", &t.pw))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(t.st.db.revoke_token(tok.id).await.expect("revoke"));
    let (s, _, b) = call(&t.app, get("/api/v1/auth", &bearer)).await;
    assert_eq!(
        (s, b["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_token"))
    );
    let (s, _, _) = call(&t.app, get("/api/v1/auth", "Bearer cvw_not-a-real-token")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn basic_auth_is_throttled_like_the_form() {
    let t = setup(&[]).await;
    let mut last = StatusCode::OK;
    for _ in 0..6 {
        let (s, _, _) = call(
            &t.app,
            get("/api/v1/auth", &basic("op", "definitely-wrong")),
        )
        .await;
        last = s;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    let (s, _, _) = call(&t.app, get("/api/v1/auth", &basic("op", &t.pw))).await;
    assert_eq!(
        s,
        StatusCode::TOO_MANY_REQUESTS,
        "locked even with the right password"
    );
}

#[tokio::test]
async fn admin_session_issues_tokens() {
    let t = setup(&[]).await;
    let admin =
        t.st.db
            .user_by_username("admin")
            .await
            .expect("q")
            .expect("u");
    let (raw, s) =
        t.st.db
            .create_session(&admin.id, 3_600_000, None, None)
            .await
            .expect("session");
    let req = |body: &str, csrf: &str| {
        Request::post("/api/v1/tokens")
            .header(header::COOKIE, format!("clamv_session={raw}"))
            .header("sec-fetch-site", "same-origin")
            .header("X-CSRF-TOKEN", csrf)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .expect("req")
    };
    let (st, _, _) = call(
        &t.app,
        req(r#"{"label":"x","scopes":["jobs:read"]}"#, "bad"),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _, b) = call(
        &t.app,
        req(r#"{"label":"x","scopes":["root"]}"#, &s.csrf_token),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{b}");
    let (st, _, b) = call(
        &t.app,
        req(r#"{"label":"cli","scopes":["jobs:read","health:read"],"expiresAt":"2099-01-01T00:00:00Z"}"#, &s.csrf_token),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{b}");
    let secret = b["token"].as_str().expect("secret").to_owned();
    assert!(secret.starts_with("cvw_"));
    let (st, _, _) = call(&t.app, get("/api/v1/jobs", &format!("Bearer {secret}"))).await;
    assert_eq!(st, StatusCode::OK);
    let (_, _, list) = call(
        &t.app,
        Request::get("/api/v1/tokens")
            .header(header::COOKIE, format!("clamv_session={raw}"))
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert!(list[0].get("token").is_none(), "secret is shown only once");
    assert_eq!(list[0]["expiresAt"], "2099-01-01T00:00:00.000Z");
}
