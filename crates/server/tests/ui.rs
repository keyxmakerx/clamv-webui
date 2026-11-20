//! End-to-end checks of login, sessions, CSRF and role gates through the router.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use clap::Parser;
use palisade::app::{AppState, router};
use palisade::config::Cli;
use palisade::db::Db;
use tower::ServiceExt;

/// Generated per run so no credential literal lives in the source.
fn pw() -> &'static str {
    static PW: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PW.get_or_init(palisade::auth::token::random_secret)
}

fn new_pw() -> &'static str {
    static PW: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PW.get_or_init(palisade::auth::token::random_secret)
}

async fn app() -> (Router, Arc<AppState>) {
    app_with(&[]).await
}

async fn app_with(extra: &[&str]) -> (Router, Arc<AppState>) {
    let mut args = vec!["palisade", "--clamd-endpoint", "tcp://127.0.0.1:1"];
    args.extend_from_slice(extra);
    let cli = Cli::parse_from(args);
    let db = Db::open("sqlite::memory:", 1).await.expect("db");
    let dir = std::env::temp_dir();
    palisade::auth::bootstrap::ensure_admin(&db, &dir, Some(pw()))
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
    palisade::app::seed_endpoint(&db, &cli.config)
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

/// Send a form and, like a browser, load the page a 303 points to (u03: forms
/// answer with a redirect back to their list). The flash message and its
/// status (400 for an error) come from that page.
async fn send(
    app: Router,
    req: Request<Body>,
) -> Result<axum::response::Response, std::convert::Infallible> {
    let cookie = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let res = app.clone().oneshot(req).await?;
    if res.status() != StatusCode::SEE_OTHER {
        return Ok(res);
    }
    let to = res.headers()[header::LOCATION]
        .to_str()
        .expect("location")
        .to_owned();
    if to.starts_with("/login") || to.starts_with("/jobs/") {
        return Ok(res);
    }
    app.oneshot(get(&to, cookie.as_deref())).await
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
                    palisade::auth::token::random_secret()
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
                palisade::auth::token::random_secret()
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
    use palisade::auth::{Role, password};
    let (app, st) = app().await;
    let pages: &[(&str, Role)] = &[
        ("/dashboard", Role::Viewer),
        ("/clamd", Role::Viewer),
        ("/coverage", Role::Viewer),
        ("/integrity", Role::Operator),
        ("/timeline", Role::Operator),
        ("/crowdsec", Role::Operator),
        ("/crowdsec/alerts", Role::Operator),
        ("/crowdsec/decisions", Role::Operator),
        ("/admin/users", Role::Admin),
        ("/admin/audit", Role::Admin),
        ("/admin/endpoints", Role::Admin),
        ("/scan", Role::Operator),
        ("/jobs", Role::Operator),
        ("/admin/api-tokens", Role::Admin),
        ("/admin/schedules", Role::Admin),
        ("/admin/watch", Role::Admin),
        ("/admin/canaries", Role::Admin),
        ("/admin/integrations", Role::Admin),
        ("/admin/settings", Role::Admin),
        ("/admin/agents", Role::Admin),
        ("/admin/clamd-config", Role::Admin),
        ("/admin/firewall", Role::Admin),
        ("/admin/quarantine", Role::Admin),
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
        ("/crowdsec/decisions", Role::Admin),
        ("/crowdsec/decisions/1/delete", Role::Admin),
        ("/crowdsec/decisions/remove", Role::Admin),
        ("/crowdsec/refresh", Role::Admin),
        ("/integrity/run", Role::Admin),
        ("/admin/firewall/rules", Role::Admin),
        ("/admin/quarantine", Role::Admin),
        ("/admin/firewall/rules/delete", Role::Admin),
        ("/admin/firewall/refresh", Role::Admin),
        ("/admin/api-tokens", Role::Admin),
        ("/admin/api-tokens/x/revoke", Role::Admin),
        ("/admin/schedules", Role::Admin),
        ("/admin/schedules/x/run", Role::Admin),
        ("/admin/schedules/x/enabled", Role::Admin),
        ("/admin/schedules/x/delete", Role::Admin),
        ("/admin/watch", Role::Admin),
        ("/admin/canaries", Role::Admin),
        ("/admin/canaries/x/delete", Role::Admin),
        ("/admin/watch/x/enabled", Role::Admin),
        ("/admin/watch/x/delete", Role::Admin),
        ("/admin/watch/x/scan", Role::Admin),
        ("/admin/integrations/webhook/test", Role::Admin),
        ("/admin/settings/review", Role::Admin),
        ("/admin/settings/apply", Role::Admin),
        ("/admin/agents", Role::Admin),
        ("/admin/agents/x/enabled", Role::Admin),
        ("/admin/agents/x/rotate", Role::Admin),
        ("/admin/agents/x/delete", Role::Admin),
    ];
    for role in [Role::Viewer, Role::Operator, Role::Admin] {
        let h = password::hash(&palisade::auth::token::random_secret()).expect("hash");
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
        let c = format!("palisade_session={raw}");
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
    use palisade::auth::Role;
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
    let c = format!("palisade_session={raw}");
    let res = send(
        app.clone(),
        form(
            &format!("/admin/users/{}/role", admin.id),
            &format!("_csrf={}&role=VIEWER&enabled=1", s.csrf_token),
            Some(&c),
        ),
    )
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
    (format!("palisade_session={raw}"), s.csrf_token)
}

#[tokio::test]
async fn endpoints_are_validated_and_allowlisted() {
    let (app, st) = app_with(&["--clamd-host-allowlist", "clamav,127.0.0.1"]).await;
    let (c, t) = admin_cookie(&st).await;
    let post = |body: String| {
        let app = app.clone();
        let c = c.clone();
        async move {
            send(app, form("/admin/endpoints", &body, Some(&c)))
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
    let res = send(
        app.clone(),
        form(
            &format!("/admin/endpoints/{}/delete", def.id),
            &format!("_csrf={t}"),
            Some(&c),
        ),
    )
    .await
    .expect("res");
    assert!(body(res).await.contains("Pick another default"));
    let res = send(
        app.clone(),
        form(
            &format!("/admin/endpoints/{}/delete", other.id),
            &format!("_csrf={t}"),
            Some(&c),
        ),
    )
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
    let res = send(
        app.clone(),
        form(
            "/admin/api-tokens",
            &format!("_csrf={t}&label=ci&scope=jobs%3Aread&scope=health%3Aread&days=30"),
            Some(&c),
        ),
    )
    .await
    .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    let html = body(res).await;
    assert!(html.contains("New token secret") && html.contains("pal_"));
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
    let res = send(
        app.clone(),
        form(
            "/admin/api-tokens",
            &format!("_csrf={t}&label=bad&scope=root"),
            Some(&c),
        ),
    )
    .await
    .expect("res");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = send(
        app.clone(),
        form(
            &format!("/admin/api-tokens/{}/revoke", list[0].id),
            &format!("_csrf={t}"),
            Some(&c),
        ),
    )
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
        async move { send(app, form(&uri, &b, Some(&c))).await.expect("res") }
    };
    let res = post("/admin/agents".into(), format!("_csrf={t}&name=bad%20name")).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = post("/admin/agents".into(), format!("_csrf={t}&name=nas-2")).await;
    let html = body(res).await;
    assert!(html.contains("Set up nas-2 on its host") && html.contains("pal_agent_"));
    assert!(html.contains("AGENT_TOKEN_FILE") && html.contains("command: agent"));
    // Plain HTTP: say agents need HTTPS; the http:// compose is only the opt-in VPN variant.
    assert!(html.contains("Agents need HTTPS.") && html.contains("TLS_SELF_SIGNED"));
    assert!(html.contains("AGENT_SERVER_URL: http://nas:8080"));
    assert!(html.contains("AGENT_ALLOW_PLAINTEXT: "));
    assert!(html.contains("AGENT_ALLOW: scan,canaries,checks "));
    // The token goes into a file by pasting, never into a command line.
    assert!(html.contains("cat &gt; agent_token") && !html.contains("echo pal_agent_"));
    let a = st.db.list_agents().await.expect("list").remove(0);
    let res = app
        .clone()
        .oneshot(get("/admin/agents", Some(&c)))
        .await
        .expect("res");
    let html = body(res).await;
    assert!(
        !html.contains("Set up nas-2") && !html.contains("enroll-token"),
        "token shown once"
    );
    assert!(
        html.contains("never connected") && html.contains("docker compose logs palisade-agent")
    );
    // A refusal by the agent's own AGENT_ALLOW shows on the page with what to add.
    st.agents.note_problem(
        a.id,
        "Refused a FIREWALL job: add firewall to AGENT_ALLOW on that host if you want to allow it.",
    );
    let res = app
        .clone()
        .oneshot(get("/admin/agents", Some(&c)))
        .await
        .expect("res");
    assert!(body(res).await.contains("Last problem"));

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
            &palisade::db::agents::Heartbeat {
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
    let n = palisade::schedule::run(&st, &s, "manual")
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
async fn agent_setup_uses_public_url_https_and_the_ticked_permissions() {
    let dir = std::env::temp_dir().join(format!("palisade-ui-tls-{}", palisade::db::new_id()));
    let data = dir.to_str().expect("utf8").to_owned();
    let (app, st) = app_with(&[
        "--public-url",
        "https://palisade.example.com",
        "--allowed-hosts",
        "nas",
        "--tls-self-signed",
        "--data-dir",
        &data,
    ])
    .await;
    let (c, t) = admin_cookie(&st).await;
    let page = || {
        Request::get("/admin/agents")
            .header(header::HOST, "nas:8080")
            .header(header::COOKIE, &c)
            .body(Body::empty())
            .expect("req")
    };
    let html = body(app.clone().oneshot(page()).await.expect("res")).await;
    assert!(
        html.contains("value=\"https://palisade.example.com\""),
        "PUBLIC_URL prefilled"
    );
    assert!(!html.contains("Agents need HTTPS."));
    assert!(html.contains("name=\"allow\" value=\"firewall\""));

    let res = app
        .clone()
        .oneshot(form(
            "/admin/agents",
            &format!("_csrf={t}&choices=1&name=edge&server=&folder=%2Fsrv%2Fmedia&allow=scan&allow=quarantine"),
            Some(&c),
        ))
        .await
        .expect("res");
    let html = body(res).await;
    assert!(
        html.contains("AGENT_SERVER_URL: https://palisade.example.com "),
        "{html}"
    );
    assert!(html.contains("AGENT_SERVER_FINGERPRINT: "));
    assert!(html.contains("AGENT_ALLOW: scan,quarantine "));
    assert!(html.contains("SCAN_ROOTS: /srv/media "));
    assert!(html.contains("QUARANTINE_DIR: /quarantine"));
    assert!(!html.contains("AGENT_ALLOW_PLAINTEXT"));
    assert!(html.contains("data-copy=\"enroll-compose\""));

    // Bad input is refused with what to do, and nothing is created.
    for (body_s, says) in [
        ("name=x1&choices=1&allow=root", "Unknown permission."),
        ("name=x2&choices=1", "Tick at least one"),
        (
            "name=x3&allow=scan&server=https%3A%2F%2Fu%3Ap%40h",
            "Server address",
        ),
        ("name=x4&allow=scan&folder=%2Fa%20b", "Folder to scan"),
    ] {
        let res = app
            .clone()
            .oneshot(form(
                "/admin/agents",
                &format!("_csrf={t}&{body_s}"),
                Some(&c),
            ))
            .await
            .expect("res");
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let html = body(app.clone().oneshot(page()).await.expect("res")).await;
        assert!(html.contains(says), "{says}");
        assert_eq!(st.db.list_agents().await.expect("list").len(), 1, "{says}");
    }
    let _ = std::fs::remove_dir_all(&dir);
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
    let cfg = palisade::settings::overlay(st.cfg.clone(), &rows);
    assert_eq!(cfg.scan_concurrency, 5);
    // Clearing a field goes back to the default.
    let rev = palisade::db::settings::revision(&rows);
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
    use palisade::auth::Role;
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
    let dir = std::env::temp_dir().join(format!("cvw-reset-{}", palisade::db::new_id()));
    let file = palisade::auth::bootstrap::reset_admin(&st.db, &dir)
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
    let v = palisade::web::asset_v();
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

#[tokio::test]
async fn admin_manages_canaries_per_host() {
    let base = std::env::temp_dir().join(format!("palisade-ui-can-{}", palisade::db::new_id()));
    std::fs::create_dir_all(base.join("media")).expect("mkdir");
    std::fs::create_dir_all(base.join("share")).expect("mkdir");
    let roots = base.join("media").to_str().expect("utf8").to_owned();
    let (app, st) = app_with(&["--scan-roots", &roots]).await;
    let (c, t) = admin_cookie(&st).await;
    let (agent, _) = st.db.create_agent("edge-1", "admin").await.expect("agent");
    let post = |body: String| {
        let app = app.clone();
        let c = c.clone();
        async move {
            send(app, form("/admin/canaries", &body, Some(&c)))
                .await
                .expect("res")
        }
    };
    // Inside a scanned folder: refused, since scans would trip it.
    let res = post(format!(
        "_csrf={t}&host=&path={}/bait.txt&create=1",
        urlencode(&roots)
    ))
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(body(res).await.contains("inside the scanned folder"));
    let res = post(format!("_csrf={t}&host=&path=relative.txt")).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let decoy = base.join("share").join("passwords.csv");
    let decoy_s = decoy.to_str().expect("utf8").to_owned();
    let res = post(format!(
        "_csrf={t}&host=&path={}&create=1",
        urlencode(&decoy_s)
    ))
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let res = post(format!(
        "_csrf={t}&host={}&path=/home/ops/vpn.conf",
        agent.id
    ))
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body(res).await;
    assert!(html.contains("edge-1") && html.contains("/home/ops/vpn.conf"));
    assert!(html.contains("-k palisade_canary"), "auditd rule offered");
    let dup = post(format!(
        "_csrf={t}&host={}&path=/home/ops/vpn.conf",
        agent.id
    ))
    .await;
    assert_eq!(dup.status(), StatusCode::BAD_REQUEST);
    let list = st.db.list_canaries().await.expect("q");
    assert_eq!(list.len(), 2);
    let central = list.iter().find(|c| c.agent_id.is_none()).expect("central");
    let res = send(
        app.clone(),
        form(
            &format!("/admin/canaries/{}/delete", central.id),
            &format!("_csrf={t}"),
            Some(&c),
        ),
    )
    .await
    .expect("res");
    assert!(body(res).await.contains("left in place"));
    assert_eq!(st.db.list_canaries().await.expect("q").len(), 1);
    // Coverage lists this server and the agent, with the agent's canary waiting for it.
    let res = app
        .clone()
        .oneshot(get("/coverage", Some(&c)))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    let html = body(res).await;
    assert!(html.contains("edge-1") && html.contains("this server"));
    assert!(html.contains("Ransomware and snooping") && html.contains("1 missing"));
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test]
async fn this_servers_aide_report_is_read_and_shown() {
    let dir = std::env::temp_dir().join(format!("palisade-aide-{}", palisade::db::new_id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let log = dir.join("aide.log");
    std::fs::write(
        &log,
        "Start timestamp: 2026-11-11 03:00:01 +0000 (AIDE 0.17.4)\nAIDE found differences between database and filesystem!!\n\nSummary:\n  Added entries:\t1\n  Removed entries:\t0\n  Changed entries:\t0\n\nAdded entries:\n\nf++++++++++++++++: /etc/cron.d/backdoor\n",
    )
    .expect("write");
    let log_s = log.to_str().expect("utf8").to_owned();
    let none_s = dir.join("rkhunter.log").to_str().expect("utf8").to_owned();
    let (app, st) = app_with(&["--aide-log", &log_s, "--rkhunter-log", &none_s]).await;
    let (c, _) = admin_cookie(&st).await;
    palisade::integrity::spawn(st.clone());
    let mut found = false;
    for _ in 0..50 {
        if !st.db.recent_integrity(5).await.expect("q").is_empty() {
            found = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(found, "report read");
    let html = body(
        app.clone()
            .oneshot(get("/integrity", Some(&c)))
            .await
            .expect("res"),
    )
    .await;
    assert!(
        html.contains("/etc/cron.d/backdoor") && html.contains("1 added, 0 removed, 0 changed")
    );
    let cov = body(app.oneshot(get("/coverage", Some(&c))).await.expect("res")).await;
    assert!(cov.contains("aide: 1 added"));
    assert!(cov.contains("no Falco alerts in 30 days"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn firewall_plan_is_checked_and_previewed() {
    let (app, st) = app().await;
    let (c, t) = admin_cookie(&st).await;
    let post = |uri: &'static str, body: String| {
        let app = app.clone();
        let c = c.clone();
        async move { send(app, form(uri, &body, Some(&c))).await.expect("res") }
    };
    let res = post(
        "/admin/firewall/rules",
        format!("_csrf={t}&host=&port=2049&proto=tcp&allow=100.82.0.0%2F16%2C+10.0.0.0%2F8"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let page = body(res).await;
    assert!(page.contains("Added 2049/tcp"));
    assert!(page.contains("tcp dport 2049 ip saddr { 10.0.0.0/8, 100.82.0.0/16 } accept"));
    assert!(page.contains("tcp dport 2049 drop"));
    for bad in [
        "port=0&proto=tcp&allow=",
        "port=70000&proto=tcp&allow=",
        "port=80&proto=tcp&allow=not-a-cidr",
        "port=80&proto=tcp&allow=1.2.3.4%2F8%3B+flush+ruleset",
    ] {
        let res = post("/admin/firewall/rules", format!("_csrf={t}&host=&{bad}")).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{bad}");
    }
    let plan = st.db.firewall_plan(None).await.expect("plan");
    assert_eq!(plan.rules.len(), 1);
    assert_eq!(plan.rules[0].allow, ["10.0.0.0/8", "100.82.0.0/16"]);
    // An agent has its own plan.
    let (a, _) = st.db.create_agent("vps-fw", "admin").await.expect("agent");
    let res = post(
        "/admin/firewall/rules",
        format!(
            "_csrf={t}&host={}&port=22&proto=tcp&allow=100.82.0.0%2F16",
            a.id
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        st.db
            .firewall_plan(Some(a.id))
            .await
            .expect("p")
            .rules
            .len(),
        1
    );
    assert_eq!(st.db.firewall_plan(None).await.expect("p").rules.len(), 1);
    let res = post(
        "/admin/firewall/rules",
        format!("_csrf={t}&host=999999&port=22&proto=tcp&allow="),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // No systemd here: reading the firewall says so instead of failing silently.
    let res = post("/admin/firewall/refresh", format!("_csrf={t}&host=")).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = post(
        "/admin/firewall/rules/delete",
        format!("_csrf={t}&host=&port=2049&proto=tcp"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(st.db.firewall_plan(None).await.expect("p").rules.is_empty());
    assert_eq!(
        st.db
            .audit_by_action("FIREWALL_PLAN", 0)
            .await
            .expect("a")
            .len(),
        3
    );
}

#[tokio::test]
async fn quarantine_is_off_until_configured_and_needs_a_real_detection() {
    let (app, st) = app().await;
    let (c, t) = admin_cookie(&st).await;
    let res = app
        .clone()
        .oneshot(get("/admin/quarantine", Some(&c)))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body(res).await.contains("QUARANTINE_DIR"));
    for d in ["999999", "x", ""] {
        let res = send(
            app.clone(),
            form(
                "/admin/quarantine",
                &format!("_csrf={t}&detection={d}"),
                Some(&c),
            ),
        )
        .await
        .expect("res");
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{d}");
    }
    // Held files are counted with their total size.
    for (p, size) in [("/scan/a.exe", 2048), ("/scan/b.exe", 1024)] {
        let i = st
            .db
            .create_quarantine(None, p, "Eicar", "admin")
            .await
            .expect("create")
            .expect("new");
        st.db
            .set_quarantine_state(
                &i.id,
                palisade::db::quarantine::HELD,
                None,
                Some(("ab", size)),
                "admin",
            )
            .await
            .expect("held");
    }
    let res = app
        .clone()
        .oneshot(get("/admin/quarantine", Some(&c)))
        .await
        .expect("res");
    let html = body(res).await;
    assert!(
        html.contains("<strong>2</strong> file(s) in quarantine, <strong>3.0 KiB</strong>"),
        "{html}"
    );
}

#[tokio::test]
async fn empty_clamd_allowlist_allows_only_the_install_endpoint() {
    let (app, st) = app().await;
    let (c, t) = admin_cookie(&st).await;
    let post = |addr: &str| {
        let app = app.clone();
        let c = c.clone();
        let body = format!("_csrf={t}&name=x{}&address={addr}", addr.len());
        async move {
            send(app, form("/admin/endpoints", &body, Some(&c)))
                .await
                .expect("res")
        }
    };
    let res = post("tcp://evil.example:3310").await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(body(res).await.contains("CLAMD_HOST_ALLOWLIST"));
    let res = post("tcp://127.0.0.1:3311").await;
    assert_ne!(res.status(), StatusCode::BAD_REQUEST);
}

// ---- UI audit round (u02, u03, u06) ----

async fn last_seen(st: &AppState) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT last_seen_at FROM sessions")
        .fetch_one(st.db.pool())
        .await
        .expect("last seen")
}

#[tokio::test]
async fn background_refresh_does_not_extend_the_session() {
    let (app, st) = app().await;
    let (c, _) = admin_cookie(&st).await;
    let old = palisade::db::now_ms() - 5 * 60_000;
    sqlx::query("UPDATE sessions SET last_seen_at = ?")
        .bind(old)
        .execute(st.db.pool())
        .await
        .expect("age the session");
    let req = Request::get("/dashboard")
        .header(header::COOKIE, &c)
        .header("x-palisade-refresh", "1")
        .body(Body::empty())
        .expect("req");
    let res = app.clone().oneshot(req).await.expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    let html = body(res).await;
    assert!(html.contains("data-refresh-region") && !html.contains("http-equiv=\"refresh\""));
    assert_eq!(last_seen(&st).await, old, "a refresh is not activity");
    let res = app.oneshot(get("/dashboard", Some(&c))).await.expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    assert!(last_seen(&st).await > old, "a real page load is");
}

#[tokio::test]
async fn forms_go_back_to_their_list_and_risky_actions_ask_first() {
    let (app, st) = app().await;
    let (c, t) = admin_cookie(&st).await;
    let res = app
        .clone()
        .oneshot(form(
            "/admin/users",
            &format!("_csrf={t}&username=jane&role=VIEWER&password={}", pw()),
            Some(&c),
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers()[header::LOCATION], "/admin/users");
    let page = body(
        app.clone()
            .oneshot(get("/admin/users", Some(&c)))
            .await
            .expect("res"),
    )
    .await;
    assert!(
        page.contains("Created jane."),
        "message shown once after the redirect"
    );
    assert!(
        page.contains("<details class=\"confirm\">"),
        "delete asks first"
    );
    assert!(
        page.contains("can&#39;t be undone")
            || page.contains("can&#x27;t be undone")
            || page.contains("can't be undone")
    );
    let again = body(
        app.oneshot(get("/admin/users", Some(&c)))
            .await
            .expect("res"),
    )
    .await;
    assert!(!again.contains("Created jane."), "and not again");
}

#[tokio::test]
async fn admin_edits_agents_and_endpoints_in_place() {
    let (app, st) = app().await;
    let (c, t) = admin_cookie(&st).await;
    let (a, _) = st.db.create_agent("nas-2", "admin").await.expect("agent");
    st.db.create_agent("nas-3", "admin").await.expect("agent");
    let post = |uri: String, b: String| {
        let app = app.clone();
        let c = c.clone();
        async move { send(app, form(&uri, &b, Some(&c))).await.expect("res") }
    };
    let res = post(
        format!("/admin/agents/{}/rename", a.id),
        format!("_csrf={t}&name=nas-3"),
    )
    .await;
    assert!(body(res).await.contains("That name is already taken."));
    let res = post(
        format!("/admin/agents/{}/rename", a.id),
        format!("_csrf={t}&name=bad%20name"),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "the list shows the error"
    );
    assert!(body(res).await.contains("Names are 1 to 64"));
    let res = post(
        format!("/admin/agents/{}/rename", a.id),
        format!("_csrf={t}&name=backup-nas"),
    )
    .await;
    assert!(body(res).await.contains("Renamed nas-2 to backup-nas."));
    assert_eq!(
        st.db.agent(a.id).await.expect("q").expect("a").name,
        "backup-nas"
    );

    let ep = st.db.list_endpoints().await.expect("list").remove(0);
    let res = post(
        format!("/admin/endpoints/{}/edit", ep.id),
        format!("_csrf={t}&name=main&address=tcp://evil.example:3310"),
    )
    .await;
    assert!(body(res).await.contains("CLAMD_HOST_ALLOWLIST"));
    let res = post(
        format!("/admin/endpoints/{}/edit", ep.id),
        format!("_csrf={t}&name=main&address={}", ep.address),
    )
    .await;
    assert!(body(res).await.contains("Saved main."));
    assert_eq!(
        st.db.endpoint(ep.id).await.expect("q").expect("e").name,
        "main"
    );
}

#[tokio::test]
async fn audit_log_filters_pages_and_exports() {
    let (app, st) = app().await;
    let (c, _) = admin_cookie(&st).await;
    for i in 0..60 {
        st.db
            .audit(palisade::db::audit::AuditEntry {
                username: Some("ops".into()),
                action: if i % 2 == 0 { "TEST_EVEN" } else { "TEST_ODD" },
                outcome: "OK",
                details: Some(format!("=item {i}")),
                ..Default::default()
            })
            .await;
    }
    let page = body(
        app.clone()
            .oneshot(get("/admin/audit?action=TEST_ODD&q=item+59", Some(&c)))
            .await
            .expect("res"),
    )
    .await;
    assert!(
        page.contains("=item 59")
            && !page.contains("=item 57")
            && !page.contains("TEST_EVEN</code>")
    );
    let page = body(
        app.clone()
            .oneshot(get("/admin/audit?user=ops", Some(&c)))
            .await
            .expect("res"),
    )
    .await;
    assert!(
        page.contains("60 event(s)") && page.contains("Page 1 of 2") && page.contains("page=1")
    );
    let res = app
        .oneshot(get("/admin/audit.csv?action=TEST_EVEN", Some(&c)))
        .await
        .expect("res");
    assert_eq!(
        res.headers()[header::CONTENT_TYPE],
        "text/csv; charset=utf-8"
    );
    let csv = body(res).await;
    assert!(csv.starts_with("at,user,action,outcome,details,job_id,ip\n"));
    assert_eq!(csv.matches("TEST_EVEN").count(), 30);
    assert!(csv.contains("\"'=item 0\""), "cells cannot become formulas");
}
