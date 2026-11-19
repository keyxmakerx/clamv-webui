//! Audit of 18 Nov (sa2-sa4): step-up before admin changes, sign-in floods, host names.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use clamv_webui::app::{AppState, router};
use clamv_webui::config::Cli;
use clamv_webui::db::Db;
use clap::Parser;
use http_body_util::BodyExt;
use tower::ServiceExt;

fn pw() -> &'static str {
    static PW: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PW.get_or_init(clamv_webui::auth::token::random_secret)
}

async fn app(extra: &[&str]) -> (Router, Arc<AppState>) {
    let mut args = vec!["clamv-webui", "--clamd-endpoint", "tcp://127.0.0.1:1"];
    args.extend_from_slice(extra);
    let cli = Cli::parse_from(args);
    let db = Db::open("sqlite::memory:", 1).await.expect("db");
    clamv_webui::auth::bootstrap::ensure_admin(&db, &std::env::temp_dir(), Some(pw()))
        .await
        .expect("bootstrap");
    let admin = db
        .user_by_username("admin")
        .await
        .expect("q")
        .expect("admin");
    db.set_password(&admin.id, &admin.password_hash, false, false)
        .await
        .expect("clear");
    let st = Arc::new(AppState::new(cli.config.clone(), db));
    (router(st.clone(), &cli.config), st)
}

fn req(method: &str, uri: &str, host: &str, body: String, cookie: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, host)
        .header("sec-fetch-site", "same-origin")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if !cookie.is_empty() {
        b = b.header(header::COOKIE, cookie);
    }
    b.body(Body::from(body)).expect("req")
}

fn form(uri: &str, body: &str, cookie: &str) -> Request<Body> {
    req("POST", uri, "clamav.example.com", body.to_owned(), cookie)
}

async fn text(res: axum::response::Response) -> String {
    String::from_utf8(
        res.into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes()
            .to_vec(),
    )
    .expect("utf8")
}

fn urlenc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

async fn signed_in(app: &Router) -> (String, String) {
    let res = app
        .clone()
        .oneshot(form(
            "/login",
            &format!("username=admin&password={}", urlenc(pw())),
            "",
        ))
        .await
        .expect("res");
    let session = res.headers()[header::SET_COOKIE]
        .to_str()
        .expect("str")
        .split(';')
        .next()
        .expect("pair")
        .to_owned();
    let page = text(
        app.clone()
            .oneshot(req(
                "GET",
                "/admin/users",
                "clamav.example.com",
                String::new(),
                &session,
            ))
            .await
            .expect("res"),
    )
    .await;
    let i = page.find("name=\"_csrf\" value=\"").expect("csrf") + 20;
    let csrf = page[i..i + page[i..].find('"').expect("end")].to_owned();
    (session, csrf)
}

#[tokio::test]
async fn making_an_admin_needs_a_fresh_confirmation() {
    let (app, st) = app(&[]).await;
    let (session, csrf) = signed_in(&app).await;
    let new_pw = clamv_webui::auth::token::random_secret();
    let body = format!("_csrf={csrf}&username=second&role=ADMIN&password={new_pw}");
    let res = app
        .clone()
        .oneshot(form("/admin/users", &body, &session))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(st.db.user_by_username("second").await.expect("q").is_none());
    // A viewer needs no confirmation.
    let res = app
        .clone()
        .oneshot(form(
            "/admin/users",
            &format!("_csrf={csrf}&username=viewer1&role=VIEWER&password={new_pw}"),
            &session,
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let viewer = st
        .db
        .user_by_username("viewer1")
        .await
        .expect("q")
        .expect("viewer");
    // Raising the viewer to admin is refused without confirmation, too.
    let res = app
        .clone()
        .oneshot(form(
            &format!("/admin/users/{}/role", viewer.id),
            &format!("_csrf={csrf}&role=ADMIN&enabled=1"),
            &session,
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    // Confirm with the password, then it works.
    let res = app
        .clone()
        .oneshot(form(
            "/account/confirm",
            &format!("_csrf={csrf}&next=/admin/users&proof={}", urlenc(pw())),
            &session,
        ))
        .await
        .expect("res");
    assert_eq!(res.headers()[header::LOCATION], "/admin/users");
    let res = app
        .clone()
        .oneshot(form("/admin/users", &body, &session))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(st.db.user_by_username("second").await.expect("q").is_some());
}

#[tokio::test]
async fn a_burst_of_wrong_passwords_gets_only_the_lockout_allowance() {
    let (app, st) = app(&[]).await;
    let mut tasks = Vec::new();
    for _ in 0..40 {
        let app = app.clone();
        tasks.push(tokio::spawn(async move {
            app.oneshot(form(
                "/login",
                "username=admin&password=wrong-password-123",
                "",
            ))
            .await
            .expect("res")
            .status()
        }));
    }
    let mut unauthorized = 0;
    for t in tasks {
        match t.await.expect("join") {
            StatusCode::UNAUTHORIZED => unauthorized += 1,
            StatusCode::TOO_MANY_REQUESTS => {}
            other => panic!("unexpected {other}"),
        }
    }
    assert_eq!(unauthorized, 5, "only five guesses were checked");
    // The right password from another address still works.
    assert!(
        st.lockout
            .check("admin", "10.9.9.9".parse().expect("ip"))
            .is_ok()
    );
}

#[tokio::test]
async fn unknown_host_names_are_refused_with_public_url() {
    let (app, _) = app(&[
        "--public-url",
        "https://clamav.example.com",
        "--allowed-hosts",
        "100.82.0.5",
    ])
    .await;
    for (host, ok) in [
        ("clamav.example.com", true),
        ("100.82.0.5:8080", true),
        ("localhost:8080", true),
        ("rebind.attacker.example", false),
    ] {
        let res = app
            .clone()
            .oneshot(req("GET", "/login", host, String::new(), ""))
            .await
            .expect("res");
        assert_eq!(res.status() == StatusCode::OK, ok, "{host}");
    }
    let res = app
        .clone()
        .oneshot(req("GET", "/healthz", "anything", String::new(), ""))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK, "health checks are exempt");
}

#[tokio::test]
async fn tokens_stop_with_their_creator() {
    let (_, st) = app(&[]).await;
    let pw2 = clamv_webui::auth::password::hash(&clamv_webui::auth::token::random_secret())
        .expect("hash");
    let u = st
        .db
        .create_user("ops", &pw2, clamv_webui::auth::Role::Admin, false)
        .await
        .expect("user");
    let (secret, _) = st
        .db
        .create_token(clamv_webui::db::tokens::NewToken {
            label: "ci",
            scopes: &["scan".to_owned()],
            endpoint_ids: None,
            path_roots: None,
            created_by: "ops",
            expires_at: None,
        })
        .await
        .expect("token");
    assert!(st.db.token_by_secret(&secret).await.expect("q").is_some());
    st.db
        .set_role_enabled(&u.id, clamv_webui::auth::Role::Admin, false)
        .await
        .expect("disable");
    assert!(st.db.token_by_secret(&secret).await.expect("q").is_none());
}
