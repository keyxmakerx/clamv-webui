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

const PW: &str = "initial-admin-password";

async fn app() -> (Router, Arc<AppState>) {
    let cli = Cli::parse_from(["clamv-webui", "--clamd-endpoint", "tcp://127.0.0.1:1"]);
    let db = Db::open("sqlite::memory:", 1).await.expect("db");
    let dir = std::env::temp_dir();
    clamv_webui::auth::bootstrap::ensure_admin(&db, &dir, Some(PW))
        .await
        .expect("bootstrap");
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
                "username=admin&password=wrong-password!",
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
            &format!("username=admin&password={PW}"),
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
            "username=nobody&password=whatever-password",
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
            &format!("username=admin&password={PW}"),
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
    let bad = format!("current={PW}&new=brand-new-password-1&confirm=brand-new-password-1");
    let res = app
        .clone()
        .oneshot(form("/account/password", &bad, Some(&c)))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let ok =
        format!("_csrf={csrf}&current={PW}&new=brand-new-password-1&confirm=brand-new-password-1");
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
            "username=admin&password=brand-new-password-1",
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
    let mut req = form("/login", &format!("username=admin&password={PW}"), None);
    req.headers_mut()
        .insert(header::ORIGIN, "http://evil.example".parse().expect("hv"));
    let res = app.clone().oneshot(req).await.expect("res");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let mut req = form("/login", &format!("username=admin&password={PW}"), None);
    req.headers_mut()
        .insert("sec-fetch-site", "cross-site".parse().expect("hv"));
    let res = app.clone().oneshot(req).await.expect("res");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let mut req = form("/login", &format!("username=admin&password={PW}"), None);
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
        ("/admin/users", Role::Admin),
        ("/admin/audit", Role::Admin),
    ];
    let posts: &[(&str, Role)] = &[
        ("/admin/users", Role::Admin),
        ("/admin/users/x/role", Role::Admin),
        ("/admin/users/x/password", Role::Admin),
        ("/admin/users/x/delete", Role::Admin),
    ];
    for role in [Role::Viewer, Role::Operator, Role::Admin] {
        let h = password::hash("role-test-password").expect("hash");
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
