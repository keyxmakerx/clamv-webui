//! Directory sign-in against a real server. Runs only with TEST_LDAP_CA set
//! (an osixia/openldap container on localhost:13636 and :13389 seeded with
//! alice in cn=clamav-admins and bob in no group).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use clamv_webui::app::{AppState, router};
use clamv_webui::auth::Role;
use clamv_webui::auth::ldap::{Ldap, LdapError};
use clamv_webui::config::Cli;
use clamv_webui::db::Db;
use clap::Parser;
use tower::ServiceExt;

fn cli(url: &str, ca: &str, extra: &[&str]) -> Cli {
    let mut a = vec![
        "clamv-webui",
        "--clamd-endpoint",
        "tcp://127.0.0.1:1",
        "--ldap-url",
        url,
        "--ldap-ca-file",
        ca,
        "--ldap-bind-dn",
        "cn=admin,dc=lan,dc=test",
        "--ldap-bind-password",
        "adminpw",
        "--ldap-user-base",
        "ou=people,dc=lan,dc=test",
        "--ldap-admin-groups",
        "clamav-admins",
    ];
    a.extend_from_slice(extra);
    Cli::parse_from(a)
}

#[tokio::test]
async fn empty_password_never_binds() {
    let cfg = Cli::parse_from([
        "x",
        "--ldap-url",
        "ldaps://127.0.0.1:1",
        "--ldap-bind-dn",
        "cn=svc",
        "--ldap-bind-password",
        "p",
        "--ldap-user-base",
        "dc=lan",
        "--ldap-admin-groups",
        "a",
    ])
    .config;
    let l = Ldap::from_config(&cfg).expect("cfg").expect("on");
    assert_eq!(l.authenticate("alice", "").await, Err(LdapError::Bad));
    assert_eq!(l.authenticate("", "pw").await, Err(LdapError::Bad));
    assert!(matches!(
        l.authenticate("alice", "pw").await,
        Err(LdapError::Unavailable(_))
    ));
}

#[tokio::test]
async fn directory_sign_in() {
    let Ok(ca) = std::env::var("TEST_LDAP_CA") else {
        eprintln!("skipped: TEST_LDAP_CA not set");
        return;
    };
    for (url, extra) in [
        ("ldaps://localhost:13636", &[][..]),
        ("ldap://localhost:13389", &["--ldap-starttls"][..]),
    ] {
        let c = cli(url, &ca, extra);
        let l = Ldap::from_config(&c.config).expect("cfg").expect("on");
        let id = l.authenticate("alice", "alicepw-long").await.expect(url);
        assert_eq!(l.role_for(&id.groups), Some(Role::Admin), "{url}");
        assert_eq!(id.name, "alice");
        assert!(!id.subject.contains('='), "entryUUID, not the DN");
        let bob = l
            .authenticate("bob", "bobpw-long")
            .await
            .expect("bob binds");
        assert_eq!(l.role_for(&bob.groups), None);
        assert_eq!(l.authenticate("alice", "wrong").await, Err(LdapError::Bad));
        assert_eq!(l.authenticate("nobody", "x").await, Err(LdapError::Bad));
        assert_eq!(
            l.authenticate("*", "alicepw-long").await,
            Err(LdapError::Bad),
            "filter is escaped"
        );
    }
    // Without the CA the certificate is refused.
    let mut a = cli("ldaps://localhost:13636", &ca, &[]).config;
    a.ldap_ca_file = None;
    let l = Ldap::from_config(&a).expect("cfg").expect("on");
    assert!(matches!(
        l.authenticate("alice", "alicepw-long").await,
        Err(LdapError::Unavailable(_))
    ));

    // Through the login form.
    let c = cli("ldaps://localhost:13636", &ca, &[]);
    let db = Db::open("sqlite::memory:", 1).await.expect("db");
    let st = Arc::new(AppState::new(c.config.clone(), db));
    let app = router(st.clone(), &c.config);
    let post = |body: &'static str| {
        Request::post("/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .expect("req")
    };
    let res = app
        .clone()
        .oneshot(post("source=ldap&username=alice&password=alicepw-long"))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let u = st
        .db
        .user_by_username("ldap:alice")
        .await
        .expect("q")
        .expect("user");
    assert_eq!(u.role, Role::Admin);
    let res = app
        .clone()
        .oneshot(post("source=ldap&username=bob&password=bobpw-long"))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    // Never falls back to local accounts, and local never reaches the directory.
    let res = app
        .clone()
        .oneshot(post("username=alice&password=alicepw-long"))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
