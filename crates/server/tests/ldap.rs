//! Directory sign-in against a real server. Runs only with TEST_LDAP_CA set
//! (an osixia/openldap container on localhost:13636 and :13389 seeded with
//! alice in cn=clamav-admins and bob in no group).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use clap::Parser;
use palisade::app::{AppState, router};
use palisade::auth::Role;
use palisade::auth::ldap::{Ldap, LdapError};
use palisade::config::Cli;
use palisade::db::Db;
use tower::ServiceExt;

fn cli(url: &str, ca: &str, extra: &[&str]) -> Cli {
    let mut a = vec![
        "palisade",
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
        // A passkey sign-in looks the user up again without a password.
        let again = l
            .lookup(&id.issuer, &id.subject)
            .await
            .expect(url)
            .expect("alice still there");
        assert_eq!(
            (again.subject.as_str(), again.name.as_str()),
            (id.subject.as_str(), "alice")
        );
        assert_eq!(l.role_for(&again.groups), Some(Role::Admin));
        let b = l
            .lookup(&bob.issuer, &bob.subject)
            .await
            .expect(url)
            .expect("bob");
        assert_eq!(l.role_for(&b.groups), None, "bob still has no group");
        assert_eq!(
            l.lookup(&id.issuer, "00000000-0000-0000-0000-000000000000")
                .await,
            Ok(None)
        );
        assert_eq!(
            l.lookup(&id.issuer, "uid=gone,ou=people,dc=lan,dc=test")
                .await,
            Ok(None)
        );
        assert_eq!(
            l.lookup("ldaps://elsewhere", &id.subject).await,
            Ok(None),
            "other directory"
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

/// A passkey sign-in by a directory user asks the directory again: still in
/// the admin group signs in; a role changed there follows; a user the
/// directory no longer gives a role is refused.
#[tokio::test]
async fn directory_passkey_sign_in_rechecks_the_directory() {
    use palisade::auth::webauthn::{self, b64u, testkit::SoftKey};
    let Ok(ca) = std::env::var("TEST_LDAP_CA") else {
        eprintln!("skipped: TEST_LDAP_CA not set");
        return;
    };
    let origin = "https://clamav.example.com";
    let rp = "clamav.example.com";
    let c = cli("ldaps://localhost:13636", &ca, &["--public-url", origin]);
    let db = Db::open("sqlite::memory:", 1).await.expect("db");
    let st = Arc::new(AppState::new(c.config.clone(), db));
    let app = router(st.clone(), &c.config);
    let json = |uri: &str, body: serde_json::Value| {
        Request::post(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, origin)
            .header(header::HOST, rp)
            .body(Body::from(body.to_string()))
            .expect("req")
    };
    let sign_in = |k: &mut SoftKey| {
        let app = app.clone();
        let mut k2 = std::mem::replace(k, SoftKey::new());
        async move {
            let res = app
                .clone()
                .oneshot(json(
                    "/login/passkey/options",
                    serde_json::json!({"mode": "login"}),
                ))
                .await
                .expect("res");
            let b = axum::body::to_bytes(res.into_body(), 1 << 20)
                .await
                .expect("body");
            let opt: serde_json::Value = serde_json::from_slice(&b).expect("json");
            let (cd, ad, sig) = k2.sign(
                opt["publicKey"]["challenge"].as_str().expect("c"),
                origin,
                rp,
            );
            let res = app
                .oneshot(json(
                    "/login/passkey",
                    serde_json::json!({
                        "handle": opt["handle"], "id": b64u(&k2.cred_id),
                        "clientDataJson": b64u(&cd), "authenticatorData": b64u(&ad), "signature": b64u(&sig)
                    }),
                ))
                .await
                .expect("res");
            (res.status(), k2)
        }
    };
    // Alice signs in once with her password, then has a passkey.
    let res = app
        .clone()
        .oneshot(
            Request::post("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::HOST, rp)
                .header(header::ORIGIN, origin)
                .body(Body::from(
                    "source=ldap&username=alice&password=alicepw-long",
                ))
                .expect("req"),
        )
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let alice = st
        .db
        .user_by_username("ldap:alice")
        .await
        .expect("q")
        .expect("alice");
    let mut k = SoftKey::new();
    let (cd, att) = k.register("Y2hhbGxlbmdl", origin, rp);
    let reg = webauthn::verify_registration(&cd, &att, "Y2hhbGxlbmdl", origin, rp).expect("reg");
    st.db
        .add_passkey(
            &alice.id,
            &reg.cred_id,
            "Key",
            &reg.public_key,
            reg.sign_count,
        )
        .await
        .expect("add");

    // Still an admin in the directory: signs in.
    let (status, k1) = sign_in(&mut k).await;
    assert_eq!(status, StatusCode::OK);
    k = k1;

    // Demoted here by hand: the directory's admin role comes back on sign-in.
    st.db
        .set_role_enabled(&alice.id, Role::Viewer, true)
        .await
        .expect("demote");
    let (status, _) = sign_in(&mut k).await;
    assert_eq!(status, StatusCode::OK);
    let u = st
        .db
        .user_by_id(&alice.id)
        .await
        .expect("q")
        .expect("alice");
    assert_eq!(u.role, Role::Admin, "role follows the directory");

    // Linked to a directory entry that is gone: refused, no session.
    let ids = st.db.identities_of(&alice.id).await.expect("ids");
    assert_eq!(ids.len(), 1);
    let gone = Ldap::from_config(&c.config).expect("cfg").expect("on");
    assert_eq!(
        gone.lookup(&ids[0].1, "uid=gone,ou=people,dc=lan,dc=test")
            .await,
        Ok(None)
    );
    let db2 = Db::open("sqlite::memory:", 1).await.expect("db");
    let bob = db2
        .create_user("ldap:bob", "!", Role::Admin, false)
        .await
        .expect("bob");
    db2.link_identity(
        "ldap:x",
        &bob.id,
        "LDAP",
        &ids[0].1,
        "uid=gone,ou=people,dc=lan,dc=test",
    )
    .await
    .expect("link");
    let mut kb = SoftKey::new();
    let (cd, att) = kb.register("Y2hhbGxlbmdl", origin, rp);
    let reg = webauthn::verify_registration(&cd, &att, "Y2hhbGxlbmdl", origin, rp).expect("reg");
    db2.add_passkey(
        &bob.id,
        &reg.cred_id,
        "Key",
        &reg.public_key,
        reg.sign_count,
    )
    .await
    .expect("add");
    let st2 = Arc::new(AppState::new(c.config.clone(), db2));
    let app2 = router(st2.clone(), &c.config);
    let res = app2
        .clone()
        .oneshot(json(
            "/login/passkey/options",
            serde_json::json!({"mode": "login"}),
        ))
        .await
        .expect("res");
    let b = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .expect("body");
    let opt: serde_json::Value = serde_json::from_slice(&b).expect("json");
    let (cd, ad, sig) = kb.sign(
        opt["publicKey"]["challenge"].as_str().expect("c"),
        origin,
        rp,
    );
    let res = app2
        .oneshot(json(
            "/login/passkey",
            serde_json::json!({
                "handle": opt["handle"], "id": b64u(&kb.cred_id),
                "clientDataJson": b64u(&cd), "authenticatorData": b64u(&ad), "signature": b64u(&sig)
            }),
        ))
        .await
        .expect("res");
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "gone from the directory"
    );
}
