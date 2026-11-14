//! End-to-end checks of login, sessions, CSRF and role gates through the router.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use clamv_webui::app::{AppState, router};
use clamv_webui::config::Cli;
use clamv_webui::db::Db;
use clap::Parser;
use tower::ServiceExt;

/// Generated per run so no credential literal lives in the source.
fn pw() -> &'static str {
    static PW: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PW.get_or_init(clamv_webui::auth::token::random_secret)
}

fn new_pw() -> &'static str {
    static PW: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PW.get_or_init(clamv_webui::auth::token::random_secret)
}

async fn app() -> (Router, Arc<AppState>) {
    app_with(&[]).await
}

async fn app_with(extra: &[&str]) -> (Router, Arc<AppState>) {
    let mut args = vec!["clamv-webui", "--clamd-endpoint", "tcp://127.0.0.1:1"];
    args.extend_from_slice(extra);
    let cli = Cli::parse_from(args);
    let db = Db::open("sqlite::memory:", 1).await.expect("db");
    let dir = std::env::temp_dir();
    clamv_webui::auth::bootstrap::ensure_admin(&db, &dir, Some(pw()))
        .await
        .expect("bootstrap");
    // Behave like a first start with a generated password: change it on first sign-in.
    let admin = db
        .user_by_username("admin")
        .await
        .expect("q")
        .expect("admin");
    db.set_password(&admin.id, &admin.password_hash, true, false)
        .await
        .expect("flag");
    clamv_webui::app::seed_endpoint(&db, &cli.config)
        .await
        .expect("seed");
    let st = Arc::new(AppState::new(cli.config.clone(), db));
    (router(st.clone(), &cli.config), st)
}

fn form(uri: &str, body: &str, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::post(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::HOST, "nas:8080");
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    b.body(Body::from(body.to_owned())).expect("req")
}

fn get(uri: &str, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::get(uri);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    b.body(Body::empty()).expect("req")
}

fn session_cookie(res: &axum::response::Response) -> String {
    let v = res
        .headers()
        .get(header::SET_COOKIE)
        .expect("set-cookie")
        .to_str()
        .expect("str");
    assert!(v.contains("HttpOnly") && v.contains("SameSite=Strict"));
    v.split(';').next().expect("pair").to_owned()
}

async fn body(res: axum::response::Response) -> String {
    let b = http_body_util::BodyExt::collect(res.into_body())
        .await
        .expect("body")
        .to_bytes();
    String::from_utf8_lossy(&b).into_owned()
}

fn csrf_from(html: &str) -> String {
    let i = html.find("name=\"_csrf\" value=\"").expect("csrf field") + 20;
    html[i..i + 43].to_owned()
}

#[tokio::test]
async fn anonymous_is_sent_to_login() {
    let (app, _) = app().await;
    let res = app.oneshot(get("/dashboard", None)).await.expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers()[header::LOCATION], "/login");
}

#[tokio::test]
async fn wrong_password_then_lockout() {
    let (app, _) = app().await;
    for _ in 0..5 {
        let res = app
            .clone()
            .oneshot(form(
                "/login",
                &format!(
                    "username=admin&password={}",
                    clamv_webui::auth::token::random_secret()
                ),
                None,
            ))
            .await
            .expect("res");
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
    // Even the right password is refused while locked.
    let res = app
        .oneshot(form(
            "/login",
            &format!("username=admin&password={}", pw()),
            None,
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn unknown_user_looks_like_wrong_password() {
    let (app, _) = app().await;
    let res = app
        .oneshot(form(
            "/login",
            &format!(
                "username=nobody&password={}",
                clamv_webui::auth::token::random_secret()
            ),
            None,
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(body(res).await.contains("Invalid username or password."));
}

#[tokio::test]
async fn first_login_forces_password_change_then_works() {
    let (app, _) = app().await;
    let res = app
        .clone()
        .oneshot(form(
            "/login",
            &format!("username=admin&password={}", pw()),
            None,
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers()[header::LOCATION], "/account/password");
    let c = session_cookie(&res);

    // Every page redirects to the password form until it is changed.
    let res = app
        .clone()
        .oneshot(get("/dashboard", Some(&c)))
        .await
        .expect("res");
    assert_eq!(res.headers()[header::LOCATION], "/account/password");

    let page = body(
        app.clone()
            .oneshot(get("/account/password", Some(&c)))
            .await
            .expect("res"),
    )
    .await;
    let csrf = csrf_from(&page);

    // Missing CSRF token is refused.
    let bad = format!("current={}&new={n}&confirm={n}", pw(), n = new_pw());
    let res = app
        .clone()
        .oneshot(form("/account/password", &bad, Some(&c)))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let ok = format!(
        "_csrf={csrf}&current={}&new={n}&confirm={n}",
        pw(),
        n = new_pw()
    );
    let res = app
        .clone()
        .oneshot(form("/account/password", &ok, Some(&c)))
        .await
        .expect("res");
    assert_eq!(res.headers()[header::LOCATION], "/login?changed");

    // Old session is gone (N7).
    let res = app
        .clone()
        .oneshot(get("/dashboard", Some(&c)))
        .await
        .expect("res");
    assert_eq!(res.headers()[header::LOCATION], "/login");

    let res = app
        .clone()
        .oneshot(form(
            "/login",
            &format!("username=admin&password={}", new_pw()),
            None,
        ))
        .await
        .expect("res");
    assert_eq!(res.headers()[header::LOCATION], "/dashboard");
    let c = session_cookie(&res);
    let res = app
        .clone()
        .oneshot(get("/dashboard", Some(&c)))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    let html = body(res).await;
    assert!(html.contains("Dashboard") && html.contains("unreachable"));

    // Logout needs the token too, then ends the session.
    let csrf = csrf_from(&html);
    let res = app
        .clone()
        .oneshot(form("/logout", "", Some(&c)))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = app
        .clone()
        .oneshot(form("/logout", &format!("_csrf={csrf}"), Some(&c)))
        .await
        .expect("res");
    assert_eq!(res.headers()[header::LOCATION], "/login?logout");
    let res = app.oneshot(get("/dashboard", Some(&c))).await.expect("res");
    assert_eq!(res.headers()[header::LOCATION], "/login");
}

#[tokio::test]
async fn cross_origin_posts_are_rejected() {
    let (app, _) = app().await;
    let mut req = form("/login", &format!("username=admin&password={}", pw()), None);
    req.headers_mut()
        .insert(header::ORIGIN, "http://evil.example".parse().expect("hv"));
    let res = app.clone().oneshot(req).await.expect("res");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let mut req = form("/login", &format!("username=admin&password={}", pw()), None);
    req.headers_mut()
        .insert("sec-fetch-site", "cross-site".parse().expect("hv"));
    let res = app.clone().oneshot(req).await.expect("res");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let mut req = form("/login", &format!("username=admin&password={}", pw()), None);
    req.headers_mut()
        .insert(header::ORIGIN, "http://nas:8080".parse().expect("hv"));
    let res = app.oneshot(req).await.expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn assets_and_404() {
    let (app, _) = app().await;
    let res = app
        .clone()
        .oneshot(get("/css/bootstrap.min.css", None))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CONTENT_TYPE], "text/css");
    let res = app.clone().oneshot(get("/h2", None)).await.expect("res");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let res = app.oneshot(get("/../Cargo.toml", None)).await.expect("res");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// Every page, every role: the route table is explicit and tested (audit lesson 8).
#[tokio::test]
async fn route_table_by_role() {
    use clamv_webui::auth::{Role, password};
    let (app, st) = app().await;
    let pages: &[(&str, Role)] = &[
        ("/dashboard", Role::Viewer),
        ("/clamd", Role::Viewer),
        ("/admin/users", Role::Admin),
        ("/admin/audit", Role::Admin),
        ("/admin/endpoints", Role::Admin),
        ("/scan", Role::Operator),
        ("/jobs", Role::Operator),
        ("/admin/api-tokens", Role::Admin),
        ("/admin/schedules", Role::Admin),
        ("/admin/watch", Role::Admin),
        ("/admin/integrations", Role::Admin),
        ("/admin/settings", Role::Admin),
        ("/admin/agents", Role::Admin),
        ("/admin/clamd-config", Role::Admin),
    ];
    let posts: &[(&str, Role)] = &[
        ("/admin/users", Role::Admin),
        ("/admin/users/x/role", Role::Admin),
        ("/admin/users/x/password", Role::Admin),
        ("/admin/users/x/delete", Role::Admin),
        ("/admin/endpoints", Role::Admin),
        ("/admin/endpoints/x/default", Role::Admin),
        ("/admin/endpoints/x/enabled", Role::Admin),
        ("/admin/endpoints/x/delete", Role::Admin),
        ("/admin/endpoints/x/test", Role::Admin),
        ("/scan/path", Role::Operator),
        ("/scan/upload", Role::Operator),
        ("/admin/api-tokens", Role::Admin),
        ("/admin/api-tokens/x/revoke", Role::Admin),
        ("/admin/schedules", Role::Admin),
        ("/admin/schedules/x/run", Role::Admin),
        ("/admin/schedules/x/enabled", Role::Admin),
        ("/admin/schedules/x/delete", Role::Admin),
        ("/admin/watch", Role::Admin),
        ("/admin/watch/x/enabled", Role::Admin),
        ("/admin/watch/x/delete", Role::Admin),
        ("/admin/integrations/webhook/test", Role::Admin),
        ("/admin/settings/review", Role::Admin),
        ("/admin/settings/apply", Role::Admin),
        ("/admin/agents", Role::Admin),
        ("/admin/agents/x/enabled", Role::Admin),
        ("/admin/agents/x/rotate", Role::Admin),
        ("/admin/agents/x/delete", Role::Admin),
    ];
    for role in [Role::Viewer, Role::Operator, Role::Admin] {
        let h = password::hash(&clamv_webui::auth::token::random_secret()).expect("hash");
        let u = st
            .db
            .create_user(&format!("t-{role}"), &h, role, false)
            .await
            .expect("user");
        let (raw, s) = st
            .db
            .create_session(&u.id, 3_600_000, None, None)
            .await
            .expect("session");
        let c = format!("clamv_session={raw}");
        for (path, need) in pages {
            let res = app.clone().oneshot(get(path, Some(&c))).await.expect("res");
            let want = if role.allows(*need) {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            };
            assert_eq!(res.status(), want, "GET {path} as {role}");
        }
        for (path, need) in posts {
            let res = app
                .clone()
                .oneshot(form(
                    path,
                    &format!("_csrf={}&role=VIEWER&username=zz&password=x", s.csrf_token),
                    Some(&c),
                ))
                .await
                .expect("res");
            if role.allows(*need) {
                assert_ne!(res.status(), StatusCode::FORBIDDEN, "POST {path} as {role}");
            } else {
                assert_eq!(res.status(), StatusCode::FORBIDDEN, "POST {path} as {role}");
            }
        }
        // Anonymous never gets in.
        for (path, _) in pages {
            let res = app.clone().oneshot(get(path, None)).await.expect("res");
            assert_eq!(res.status(), StatusCode::SEE_OTHER, "GET {path} anonymous");
        }
    }
}

#[tokio::test]
async fn last_admin_cannot_be_removed() {
    use clamv_webui::auth::Role;
    let (app, st) = app().await;
    let admin = st
        .db
        .user_by_username("admin")
        .await
        .expect("q")
        .expect("admin");
    st.db
        .set_password(&admin.id, &admin.password_hash, false, false)
        .await
        .expect("clear flag");
    let (raw, s) = st
        .db
        .create_session(&admin.id, 3_600_000, None, None)
        .await
        .expect("session");
    let c = format!("clamv_session={raw}");
    let res = app
        .clone()
        .oneshot(form(
            &format!("/admin/users/{}/role", admin.id),
            &format!("_csrf={}&role=VIEWER&enabled=1", s.csrf_token),
            Some(&c),
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(
        body(res)
            .await
            .contains("At least one enabled admin must remain.")
    );
    let still = st.db.user_by_id(&admin.id).await.expect("q").expect("u");
    assert_eq!(still.role, Role::Admin);
}

/// Signed-in admin with the forced password change cleared.
async fn admin_cookie(st: &AppState) -> (String, String) {
    let admin = st
        .db
        .user_by_username("admin")
        .await
        .expect("q")
        .expect("admin");
    st.db
        .set_password(&admin.id, &admin.password_hash, false, false)
        .await
        .expect("clear flag");
    let (raw, s) = st
        .db
        .create_session(&admin.id, 3_600_000, None, None)
        .await
        .expect("session");
    (format!("clamv_session={raw}"), s.csrf_token)
}

#[tokio::test]
async fn endpoints_are_validated_and_allowlisted() {
    let (app, st) = app_with(&["--clamd-host-allowlist", "clamav,127.0.0.1"]).await;
    let (c, t) = admin_cookie(&st).await;
    let post = |body: String| {
        let app = app.clone();
        let c = c.clone();
        async move {
            app.oneshot(form("/admin/endpoints", &body, Some(&c)))
                .await
                .expect("res")
        }
    };
    let res = post(format!("_csrf={t}&name=evil&address=tcp://10.0.0.9:3310")).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(body(res).await.contains("CLAMD_HOST_ALLOWLIST"));
    let res = post(format!("_csrf={t}&name=bad&address=tcp://a/b:3310")).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = post(format!("_csrf={t}&name=nas&address=CLAMAV:3310")).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body(res).await.contains("tcp://CLAMAV:3310"));
    let res = post(format!("_csrf={t}&name=nas&address=clamav:3310")).await;
    assert!(body(res).await.contains("already taken"));

    // The default cannot be deleted; a non-default can.
    let list = st.db.list_endpoints().await.expect("list");
    let def = list.iter().find(|e| e.is_default).expect("default");
    let other = list.iter().find(|e| !e.is_default).expect("other");
    let res = app
        .clone()
        .oneshot(form(
            &format!("/admin/endpoints/{}/delete", def.id),
            &format!("_csrf={t}"),
            Some(&c),
        ))
        .await
        .expect("res");
    assert!(body(res).await.contains("Pick another default"));
    let res = app
        .clone()
        .oneshot(form(
            &format!("/admin/endpoints/{}/delete", other.id),
            &format!("_csrf={t}"),
            Some(&c),
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(st.db.list_endpoints().await.expect("list").len(), 1);

    // Dashboard lists the unreachable default without leaking the raw error.
    let res = app
        .clone()
        .oneshot(get("/dashboard", Some(&c)))
        .await
        .expect("res");
    let html = body(res).await;
    assert!(html.contains("unreachable") && html.contains("no response"));
}

#[tokio::test]
async fn admin_issues_and_revokes_tokens() {
    let (app, st) = app().await;
    let (c, t) = admin_cookie(&st).await;
    let res = app
        .clone()
        .oneshot(form(
            "/admin/api-tokens",
            &format!("_csrf={t}&label=ci&scope=jobs%3Aread&scope=health%3Aread&days=30"),
            Some(&c),
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    let html = body(res).await;
    assert!(html.contains("New token secret") && html.contains("cvw_"));
    let list = st.db.list_tokens().await.expect("list");
    assert_eq!(
        list[0].scopes,
        vec!["jobs:read".to_owned(), "health:read".to_owned()]
    );
    assert!(list[0].expires_at.is_some());
    let res = app
        .clone()
        .oneshot(get("/admin/api-tokens", Some(&c)))
        .await
        .expect("res");
    assert!(!body(res).await.contains("New token secret"), "shown once");
    let res = app
        .clone()
        .oneshot(form(
            "/admin/api-tokens",
            &format!("_csrf={t}&label=bad&scope=root"),
            Some(&c),
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = app
        .clone()
        .oneshot(form(
            &format!("/admin/api-tokens/{}/revoke", list[0].id),
            &format!("_csrf={t}"),
            Some(&c),
        ))
        .await
        .expect("res");
    assert!(body(res).await.contains("Token revoked."));
}

#[tokio::test]
async fn admin_adds_an_agent_and_targets_it() {
    let (app, st) = app().await;
    let (c, t) = admin_cookie(&st).await;
    let post = |uri: String, b: String| {
        let app = app.clone();
        let c = c.clone();
        async move { app.oneshot(form(&uri, &b, Some(&c))).await.expect("res") }
    };
    let res = post("/admin/agents".into(), format!("_csrf={t}&name=bad%20name")).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = post("/admin/agents".into(), format!("_csrf={t}&name=nas-2")).await;
    let html = body(res).await;
    assert!(html.contains("Token for nas-2") && html.contains("clamv_agent_"));
    assert!(html.contains("AGENT_TOKEN_FILE") && html.contains("command: agent"));
    let a = st.db.list_agents().await.expect("list").remove(0);
    let res = app
        .clone()
        .oneshot(get("/admin/agents", Some(&c)))
        .await
        .expect("res");
    let html = body(res).await;
    assert!(!html.contains("Token for"), "token shown once");
    assert!(html.contains("never connected"));

    // Not offered as a target until it has connected and reported its roots.
    let res = post(
        "/scan/path".into(),
        format!("_csrf={t}&path=%2Fdata%2Fx&endpoint=a%3A{}", a.id),
    )
    .await;
    assert!(body(res).await.contains("has not connected yet"));
    st.db
        .heartbeat_agent(
            a.id,
            &clamv_webui::db::agents::Heartbeat {
                ip: "100.82.0.9",
                version: "t",
                clamd_version: None,
                roots: &["/data".to_owned()],
                slots: 1,
            },
        )
        .await
        .expect("hb");
    let res = post(
        "/scan/path".into(),
        format!("_csrf={t}&path=%2Fetc&endpoint=a%3A{}", a.id),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = post(
        "/scan/path".into(),
        format!("_csrf={t}&path=%2Fdata%2Fx&endpoint=a%3A{}", a.id),
    )
    .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let jobs = st.db.agent_jobs(a.id, "QUEUED").await.expect("jobs");
    assert_eq!(jobs[0].target, "/data/x");
    let res = post(
        "/admin/schedules".into(),
        format!(
            "_csrf={t}&name=remote&cron=%40daily&paths=%2Fdata&endpoint=a%3A{}&eicar=1",
            a.id
        ),
    )
    .await;
    assert!(body(res).await.contains("Added remote."));
    let s = st.db.list_schedules().await.expect("list").remove(0);
    assert_eq!((s.agent_id, s.endpoint_id), (Some(a.id), None));
    let n = clamv_webui::schedule::run(&st, &s, "manual")
        .await
        .expect("run");
    assert_eq!(n, 1);
    let queued = st.db.agent_jobs(a.id, "QUEUED").await.expect("jobs");
    assert!(
        queued.iter().any(|j| j.kind == "CONTROL"),
        "EICAR control goes to the agent"
    );

    let res = post(
        format!("/admin/agents/{}/rotate", a.id),
        format!("_csrf={t}"),
    )
    .await;
    assert!(body(res).await.contains("the old one no longer works"));
    let res = post(
        format!("/admin/agents/{}/delete", a.id),
        format!("_csrf={t}"),
    )
    .await;
    assert!(body(res).await.contains("Removed nas-2."));
    assert!(
        st.db
            .agent_jobs(a.id, "QUEUED")
            .await
            .expect("jobs")
            .is_empty()
    );
}

#[tokio::test]
async fn settings_are_reviewed_then_saved() {
    let (app, st) = app().await;
    let (c, t) = admin_cookie(&st).await;
    let post = |uri: &'static str, body: String| {
        let app = app.clone();
        let c = c.clone();
        async move { app.oneshot(form(uri, &body, Some(&c))).await.expect("res") }
    };
    let res = app
        .clone()
        .oneshot(get("/admin/settings", Some(&c)))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    let html = body(res).await;
    assert!(html.contains("SCAN_CONCURRENCY") && html.contains("Deployment"));
    let res = post(
        "/admin/settings/review",
        format!("_csrf={t}&SCAN_CONCURRENCY=0"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = post(
        "/admin/settings/review",
        format!("_csrf={t}&SCAN_CONCURRENCY=5&WEBHOOK_EVENTS=all&JOB_RETENTION_DAYS="),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body(res).await;
    assert!(html.contains("Review changes"), "{html}");
    assert!(
        !html.contains("JOB_RETENTION_DAYS"),
        "unchanged fields are left out"
    );
    let rev = html
        .split("name=\"_revision\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("revision")
        .to_owned();
    let apply = format!("_csrf={t}&_revision={rev}&SCAN_CONCURRENCY=5&WEBHOOK_EVENTS=all");
    let res = post("/admin/settings/apply", apply.clone()).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body(res).await.contains("applies after restart"));
    let saved: Vec<(String, String)> = st
        .db
        .list_settings()
        .await
        .expect("list")
        .into_iter()
        .map(|s| (s.name, s.value))
        .collect();
    assert_eq!(
        saved,
        vec![
            ("SCAN_CONCURRENCY".into(), "5".into()),
            ("WEBHOOK_EVENTS".into(), "all".into())
        ]
    );
    // A stale review is refused.
    let res = post(
        "/admin/settings/apply",
        format!("_csrf={t}&_revision={rev}&SCAN_CONCURRENCY=6"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // Stored values reach the config on the next start.
    let rows = st.db.list_settings().await.expect("list");
    let cfg = clamv_webui::settings::overlay(st.cfg.clone(), &rows);
    assert_eq!(cfg.scan_concurrency, 5);
    // Clearing a field goes back to the default.
    let rev = clamv_webui::db::settings::revision(&rows);
    let res = post(
        "/admin/settings/apply",
        format!("_csrf={t}&_revision={rev}&SCAN_CONCURRENCY="),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(st.db.list_settings().await.expect("list").len(), 1);
}

#[tokio::test]
async fn reset_admin_recovers_a_locked_out_admin() {
    use clamv_webui::auth::Role;
    let (app, st) = app().await;
    let admin = st
        .db
        .user_by_username("admin")
        .await
        .expect("q")
        .expect("admin");
    st.db
        .set_role_enabled(&admin.id, Role::Viewer, false)
        .await
        .expect("break it");
    let dir = std::env::temp_dir().join(format!("cvw-reset-{}", clamv_webui::db::new_id()));
    let file = clamv_webui::auth::bootstrap::reset_admin(&st.db, &dir)
        .await
        .expect("reset");
    let pw = std::fs::read_to_string(&file)
        .expect("file")
        .trim()
        .to_owned();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let u = st
        .db
        .user_by_username("admin")
        .await
        .expect("q")
        .expect("admin");
    assert!(u.enabled && u.role == Role::Admin && u.must_change_password);
    let res = app
        .oneshot(form(
            "/login",
            &format!("username=admin&password={}", urlencode(&pw)),
            None,
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers()[header::LOCATION], "/account/password");
    let _ = std::fs::remove_dir_all(dir);
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[tokio::test]
async fn static_assets_are_versioned_compressed_and_revalidated() {
    let (app, _st) = app().await;
    let v = clamv_webui::web::asset_v();
    let res = app
        .clone()
        .oneshot(
            Request::get(format!("/css/bootstrap.min.css?v={v}"))
                .header(header::ACCEPT_ENCODING, "gzip")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CONTENT_ENCODING], "gzip");
    assert!(
        res.headers()[header::CACHE_CONTROL]
            .to_str()
            .is_ok_and(|c| c.contains("immutable"))
    );
    let etag = res.headers()[header::ETAG].clone();
    let res = app
        .clone()
        .oneshot(
            Request::get("/css/bootstrap.min.css")
                .header(header::IF_NONE_MATCH, etag)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(res.headers()[header::CACHE_CONTROL], "public, max-age=3600");
    let page = app
        .oneshot(Request::get("/login").body(Body::empty()).expect("req"))
        .await
        .expect("res");
    let html = String::from_utf8(
        axum::body::to_bytes(page.into_body(), 1 << 20)
            .await
            .expect("body")
            .to_vec(),
    )
    .expect("utf8");
    assert!(html.contains(&format!("/css/ui.css?v={v}")));
}
