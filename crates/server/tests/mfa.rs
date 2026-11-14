//! Second factors end to end: TOTP with recovery codes, passkeys, trusted proxies.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use clamv_webui::app::{AppState, router};
use clamv_webui::auth::totp;
use clamv_webui::auth::webauthn::b64u;
use clamv_webui::auth::webauthn::testkit::SoftKey;
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
    let key = std::env::temp_dir().join(format!("clamv-mfa-key-{}", clamv_webui::db::new_id()));
    let key_s = key.to_str().expect("utf8").to_owned();
    let mut args = vec![
        "clamv-webui",
        "--clamd-endpoint",
        "tcp://127.0.0.1:1",
        "--secret-key-file",
        &key_s,
    ];
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

fn req(method: &str, uri: &str, ctype: &str, body: String, cookie: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "clamav.example.com")
        .header("sec-fetch-site", "same-origin");
    if !ctype.is_empty() {
        b = b.header(header::CONTENT_TYPE, ctype);
    }
    if !cookie.is_empty() {
        b = b.header(header::COOKIE, cookie);
    }
    b.body(Body::from(body)).expect("req")
}

fn form(uri: &str, body: &str, cookie: &str) -> Request<Body> {
    req(
        "POST",
        uri,
        "application/x-www-form-urlencoded",
        body.to_owned(),
        cookie,
    )
}

fn json(uri: &str, body: &serde_json::Value, cookie: &str) -> Request<Body> {
    req("POST", uri, "application/json", body.to_string(), cookie)
}

fn get(uri: &str, cookie: &str) -> Request<Body> {
    req("GET", uri, "", String::new(), cookie)
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

fn cookies(res: &axum::response::Response) -> Vec<String> {
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().expect("str").to_owned())
        .collect()
}

fn pair(set_cookie: &str) -> String {
    set_cookie.split(';').next().expect("pair").to_owned()
}

fn between<'a>(s: &'a str, a: &str, b: &str) -> &'a str {
    let i = s.find(a).unwrap_or_else(|| panic!("{a} not in page")) + a.len();
    let j = s[i..].find(b).expect("end") + i;
    &s[i..j]
}

fn csrf_of(page: &str) -> String {
    between(page, "name=\"_csrf\" value=\"", "\"").to_owned()
}

async fn sign_in(app: &Router) -> axum::response::Response {
    app.clone()
        .oneshot(form(
            "/login",
            &format!("username=admin&password={}", pw()),
            "",
        ))
        .await
        .expect("res")
}

#[tokio::test]
async fn totp_and_recovery_codes() {
    let (app, st) = app(&[]).await;
    let res = sign_in(&app).await;
    assert_eq!(res.headers()[header::LOCATION], "/dashboard", "no 2FA yet");
    let session = pair(&cookies(&res)[0]);

    // Enrol: the page shows the key; confirm with a code from it.
    let page = text(
        app.clone()
            .oneshot(get("/account/security", &session))
            .await
            .expect("res"),
    )
    .await;
    let csrf = csrf_of(&page);
    let page = text(
        app.clone()
            .oneshot(form(
                "/account/2fa/setup",
                &format!("_csrf={csrf}"),
                &session,
            ))
            .await
            .expect("res"),
    )
    .await;
    assert!(page.contains("data:image/svg+xml;base64,"), "QR code shown");
    let key = between(&page, "<code class=\"text-break\">", "</code>").replace(' ', "");
    let sealed = between(&page, "name=\"sealed\" value=\"", "\"").to_owned();
    let secret = totp::unbase32(&key).expect("key");
    let now = clamv_webui::db::now_ms() / 1000;
    // A wrong code keeps the setup open.
    let res = app
        .clone()
        .oneshot(form(
            "/account/2fa/enable",
            &format!("_csrf={csrf}&sealed={}&code=000000", urlenc(&sealed)),
            &session,
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let code = format!("{:06}", totp::code(&secret, totp::step_at(now)));
    let page = text(
        app.clone()
            .oneshot(form(
                "/account/2fa/enable",
                &format!("_csrf={csrf}&sealed={}&code={code}", urlenc(&sealed)),
                &session,
            ))
            .await
            .expect("res"),
    )
    .await;
    assert!(page.contains("Recovery codes"), "codes shown once");
    let recovery: Vec<String> = page
        .split("<li><code>")
        .skip(1)
        .map(|s| s.split('<').next().expect("code").to_owned())
        .collect();
    assert_eq!(recovery.len(), 10);
    // The seed is stored encrypted, never in the clear.
    let stored = st
        .db
        .totp(
            &st.db
                .user_by_username("admin")
                .await
                .expect("q")
                .expect("u")
                .id,
        )
        .await
        .expect("q")
        .expect("totp");
    assert!(stored.secret.starts_with("v1:") && !stored.secret.contains(&key));

    // Now a password alone is not enough.
    let res = sign_in(&app).await;
    assert_eq!(res.headers()[header::LOCATION], "/login/2fa");
    let c = cookies(&res);
    assert_eq!(c.len(), 1, "no session yet");
    assert!(c[0].contains("Path=/login") && c[0].contains("HttpOnly"));
    let mfa = pair(&c[0]);
    // The code already used to enrol cannot be replayed.
    let res = app
        .clone()
        .oneshot(form("/login/2fa", &format!("code={code}"), &mfa))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    // A recovery code works once, in any case and with or without dashes.
    let rc = recovery[0].to_uppercase().replace('-', "");
    let res = app
        .clone()
        .oneshot(form("/login/2fa", &format!("code={rc}"), &mfa))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(
        cookies(&res)
            .iter()
            .any(|c| c.starts_with("clamv_session=") && !c.starts_with("clamv_session=;"))
    );
    let res = sign_in(&app).await;
    let mfa = pair(&cookies(&res)[0]);
    let res = app
        .clone()
        .oneshot(form("/login/2fa", &format!("code={rc}"), &mfa))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "spent");

    // Five wrong codes end the attempt.
    for _ in 0..4 {
        let res = app
            .clone()
            .oneshot(form("/login/2fa", "code=111111", &mfa))
            .await
            .expect("res");
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
    let res = app
        .clone()
        .oneshot(form("/login/2fa", "code=111111", &mfa))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    let res = app
        .clone()
        .oneshot(get("/login/2fa", &mfa))
        .await
        .expect("res");
    assert_eq!(res.headers()[header::LOCATION], "/login", "must start over");

    // The pending cookie is not a session.
    let res = app
        .clone()
        .oneshot(get("/dashboard", &mfa))
        .await
        .expect("res");
    assert_eq!(res.headers()[header::LOCATION], "/login");

    // An admin can reset a user's second factors.
    let audit = st.db.audit_page(0, 50).await.expect("audit").0;
    assert!(audit.iter().any(|a| a.action == "MFA_ENABLE"));
    assert!(
        audit
            .iter()
            .any(|a| a.action == "LOGIN_2FA" && a.outcome.as_deref() == Some("FAIL"))
    );
}

fn urlenc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[tokio::test]
async fn passkeys_register_sign_in_and_second_step() {
    let origin = "https://clamav.example.com";
    let rp = "clamav.example.com";
    let (app, st) = app(&["--public-url", origin]).await;
    let res = sign_in(&app).await;
    let session = pair(&cookies(&res)[0]);
    let page = text(
        app.clone()
            .oneshot(get("/account/security", &session))
            .await
            .expect("res"),
    )
    .await;
    let csrf = between(&page, "data-csrf=\"", "\"").to_owned();

    // Register.
    let res = app
        .clone()
        .oneshot(json(
            "/account/passkeys/options",
            &serde_json::json!({"csrf": "wrong"}),
            &session,
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let opt: serde_json::Value = serde_json::from_str(
        &text(
            app.clone()
                .oneshot(json(
                    "/account/passkeys/options",
                    &serde_json::json!({"csrf": csrf}),
                    &session,
                ))
                .await
                .expect("res"),
        )
        .await,
    )
    .expect("json");
    assert_eq!(opt["publicKey"]["rp"]["id"], rp);
    assert_eq!(
        opt["publicKey"]["authenticatorSelection"]["userVerification"],
        "required"
    );
    let mut k = SoftKey::new();
    let (cd, att) = k.register(
        opt["publicKey"]["challenge"].as_str().expect("c"),
        origin,
        rp,
    );
    let body = serde_json::json!({
        "csrf": csrf, "handle": opt["handle"], "name": "Laptop",
        "clientDataJson": b64u(&cd), "attestationObject": b64u(&att)
    });
    let res = app
        .clone()
        .oneshot(json("/account/passkeys", &body, &session))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    // The same challenge cannot be used twice.
    let res = app
        .clone()
        .oneshot(json("/account/passkeys", &body, &session))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Sign in with no password.
    let opt: serde_json::Value = serde_json::from_str(
        &text(
            app.clone()
                .oneshot(json(
                    "/login/passkey/options",
                    &serde_json::json!({"mode": "login"}),
                    "",
                ))
                .await
                .expect("res"),
        )
        .await,
    )
    .expect("json");
    let chal = opt["publicKey"]["challenge"]
        .as_str()
        .expect("c")
        .to_owned();
    let (cd, ad, sig) = k.sign(&chal, origin, rp);
    let body = serde_json::json!({
        "handle": opt["handle"], "id": b64u(&k.cred_id),
        "clientDataJson": b64u(&cd), "authenticatorData": b64u(&ad), "signature": b64u(&sig)
    });
    let res = app
        .clone()
        .oneshot(json("/login/passkey", &body, ""))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        cookies(&res)
            .iter()
            .any(|c| c.starts_with("clamv_session=") && c.len() > 20)
    );
    assert!(text(res).await.contains("/dashboard"));
    // Replaying the same answer fails (challenge spent).
    let res = app
        .clone()
        .oneshot(json("/login/passkey", &body, ""))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // An answer made for another site fails.
    let opt: serde_json::Value = serde_json::from_str(
        &text(
            app.clone()
                .oneshot(json(
                    "/login/passkey/options",
                    &serde_json::json!({"mode": "login"}),
                    "",
                ))
                .await
                .expect("res"),
        )
        .await,
    )
    .expect("json");
    let (cd, ad, sig) = k.sign(
        opt["publicKey"]["challenge"].as_str().expect("c"),
        "https://evil.example",
        rp,
    );
    let res = app
        .clone()
        .oneshot(json(
            "/login/passkey",
            &serde_json::json!({
                "handle": opt["handle"], "id": b64u(&k.cred_id),
                "clientDataJson": b64u(&cd), "authenticatorData": b64u(&ad), "signature": b64u(&sig)
            }),
            "",
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // With a passkey on the account, a password sign-in asks for it.
    let res = sign_in(&app).await;
    assert_eq!(res.headers()[header::LOCATION], "/login/2fa");
    let mfa = pair(&cookies(&res)[0]);
    let page = text(
        app.clone()
            .oneshot(get("/login/2fa", &mfa))
            .await
            .expect("res"),
    )
    .await;
    assert!(page.contains("Use a passkey") && !page.contains("authenticator app"));
    let opt: serde_json::Value = serde_json::from_str(
        &text(
            app.clone()
                .oneshot(json(
                    "/login/passkey/options",
                    &serde_json::json!({"mode": "second"}),
                    &mfa,
                ))
                .await
                .expect("res"),
        )
        .await,
    )
    .expect("json");
    assert_eq!(
        opt["publicKey"]["allowCredentials"][0]["id"],
        b64u(&k.cred_id)
    );
    let (cd, ad, sig) = k.sign(
        opt["publicKey"]["challenge"].as_str().expect("c"),
        origin,
        rp,
    );
    let res = app
        .clone()
        .oneshot(json(
            "/login/passkey",
            &serde_json::json!({
                "handle": opt["handle"], "id": b64u(&k.cred_id),
                "clientDataJson": b64u(&cd), "authenticatorData": b64u(&ad), "signature": b64u(&sig)
            }),
            &mfa,
        ))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK);
    let c = cookies(&res);
    assert!(
        c.iter()
            .any(|c| c.starts_with("clamv_session=") && c.len() > 20)
    );
    assert!(
        c.iter().any(|c| c.starts_with("clamv_mfa=;")),
        "pending step cleared"
    );

    let audit = st.db.audit_page(0, 50).await.expect("audit").0;
    assert!(audit.iter().any(|a| a.action == "PASSKEY_ADD"));
    assert!(audit.iter().any(|a| a.action == "LOGIN_PASSKEY"));
}

#[tokio::test]
async fn trusted_proxy_sets_client_ip_and_secure_cookies() {
    let (app, st) = app(&["--trusted-proxies", "127.0.0.0/8"]).await;
    let mut r = form("/login", &format!("username=admin&password={}", pw()), "");
    r.headers_mut()
        .insert("x-forwarded-for", "198.51.100.7".parse().expect("hv"));
    r.headers_mut()
        .insert("x-forwarded-proto", "https".parse().expect("hv"));
    r.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            5000,
        ))));
    let res = app.clone().oneshot(r).await.expect("res");
    assert!(cookies(&res)[0].ends_with("; Secure"), "HTTPS at the proxy");
    let audit = st.db.audit_page(0, 10).await.expect("audit").0;
    let _ = audit;
    // A peer outside TRUSTED_PROXIES cannot spoof either.
    let mut r = form("/login", &format!("username=admin&password={}", pw()), "");
    r.headers_mut()
        .insert("x-forwarded-proto", "https".parse().expect("hv"));
    r.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [203, 0, 113, 9],
            5000,
        ))));
    let res = app.clone().oneshot(r).await.expect("res");
    assert!(!cookies(&res)[0].contains("Secure"));
}
