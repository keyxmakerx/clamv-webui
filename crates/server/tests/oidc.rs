//! OIDC sign-in against a fake provider that signs ID tokens with Ed25519.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use clamv_webui::app::{AppState, router};
use clamv_webui::auth::Role;
use clamv_webui::config::Cli;
use clamv_webui::db::Db;
use clap::Parser;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use tower::ServiceExt;

struct Idp {
    base: String,
    key: Ed25519KeyPair,
    other: Ed25519KeyPair,
}

fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn keypair() -> Ed25519KeyPair {
    let rng = ring::rand::SystemRandom::new();
    let doc = Ed25519KeyPair::generate_pkcs8(&rng).expect("gen");
    Ed25519KeyPair::from_pkcs8(doc.as_ref()).expect("key")
}

fn sign(key: &Ed25519KeyPair, claims: &Value) -> String {
    let h = b64(json!({"alg": "EdDSA", "kid": "k1", "typ": "JWT"})
        .to_string()
        .as_bytes());
    let p = b64(claims.to_string().as_bytes());
    let sig = key.sign(format!("{h}.{p}").as_bytes());
    format!("{h}.{p}.{}", b64(sig.as_ref()))
}

/// The code carries the test's wishes: nonce|groups|subject|flag.
async fn token(
    State(idp): State<Arc<Idp>>,
    headers: HeaderMap,
    body: String,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let want = format!("Basic {}", STANDARD.encode("cid:s3cret"));
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        != Some(want.as_str())
    {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "invalid_client"})),
        )
            .into_response();
    }
    let form: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    let get = |k: &str| {
        form.iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    if get("code_verifier").len() < 43 || get("grant_type") != "authorization_code" {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    }
    let code = get("code");
    let parts: Vec<&str> = code.split('|').collect();
    let now = clamv_webui::db::now_ms() / 1000;
    let groups: Vec<&str> = parts[1].split(',').filter(|g| !g.is_empty()).collect();
    let claims = json!({
        "iss": idp.base, "aud": "cid", "sub": parts[2], "exp": now + 300, "iat": now,
        "nonce": parts[0], "preferred_username": "alice", "groups": groups,
    });
    let key = if parts.get(3) == Some(&"badsig") {
        &idp.other
    } else {
        &idp.key
    };
    axum::Json(
        json!({"access_token": "at", "token_type": "Bearer", "id_token": sign(key, &claims)}),
    )
    .into_response()
}

async fn idp() -> Arc<Idp> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("addr").port()
    );
    let idp = Arc::new(Idp {
        base: base.clone(),
        key: keypair(),
        other: keypair(),
    });
    let pubkey = b64(idp.key.public_key().as_ref());
    let meta = json!({
        "issuer": base, "authorization_endpoint": format!("{base}/auth"),
        "token_endpoint": format!("{base}/token"), "jwks_uri": format!("{base}/jwks"),
        "end_session_endpoint": format!("{base}/logout"),
    });
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(move || async move { axum::Json(meta) }))
        .route(
            "/jwks",
            get(move || async move {
                axum::Json(json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "use": "sig", "x": pubkey}]}))
            }),
        )
        .route("/token", post(token))
        .with_state(idp.clone());
    tokio::spawn(async move { axum::serve(listener, app).await });
    idp
}

async fn app(idp: &Idp) -> (Router, Arc<AppState>) {
    let cli = Cli::parse_from([
        "clamv-webui",
        "--clamd-endpoint",
        "tcp://127.0.0.1:1",
        "--oidc-issuer",
        &idp.base,
        "--oidc-client-id",
        "cid",
        "--oidc-client-secret",
        "s3cret",
        "--oidc-redirect-uri",
        "http://nas:8080/login/oauth2/code/clamav",
        "--oidc-admin-groups",
        "Admins",
        "--oidc-viewer-groups",
        "viewers",
    ]);
    let db = Db::open("sqlite::memory:", 1).await.expect("db");
    let st = Arc::new(AppState::new(cli.config.clone(), db));
    assert!(st.oidc.is_some(), "OIDC configured");
    (router(st.clone(), &cli.config), st)
}

fn req(uri: &str, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::get(uri);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    b.body(Body::empty()).expect("req")
}

/// Start a sign-in: returns (state, nonce, state cookie).
async fn begin(app: &Router) -> (String, String, String) {
    let res = app
        .clone()
        .oneshot(req("/login/oidc", None))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let loc = res.headers()[header::LOCATION]
        .to_str()
        .expect("loc")
        .to_owned();
    let u = url::Url::parse(&loc).expect("url");
    let q = |k: &str| {
        u.query_pairs()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.into_owned())
            .expect(k)
    };
    assert_eq!(q("code_challenge_method"), "S256");
    assert_eq!(
        q("redirect_uri"),
        "http://nas:8080/login/oauth2/code/clamav"
    );
    let cookie = res.headers()[header::SET_COOKIE]
        .to_str()
        .expect("cookie")
        .to_owned();
    assert!(cookie.contains("SameSite=Lax") && cookie.contains("HttpOnly"));
    let cookie = cookie.split(';').next().expect("pair").to_owned();
    (q("state"), q("nonce"), cookie)
}

async fn finish(
    app: &Router,
    state: &str,
    code: &str,
    cookie: Option<&str>,
) -> axum::response::Response {
    let code = url::form_urlencoded::byte_serialize(code.as_bytes()).collect::<String>();
    app.clone()
        .oneshot(req(
            &format!("/login/oauth2/code/clamav?code={code}&state={state}"),
            cookie,
        ))
        .await
        .expect("res")
}

#[tokio::test]
async fn sso_maps_groups_to_roles_and_denies_by_default() {
    let idp = idp().await;
    let (app, st) = app(&idp).await;
    let res = app.clone().oneshot(req("/login", None)).await.expect("res");
    let b = http_body_util::BodyExt::collect(res.into_body())
        .await
        .expect("b")
        .to_bytes();
    assert!(String::from_utf8_lossy(&b).contains("Sign in with SSO"));

    // Admin by group (case-insensitive), session cookie set on a refresh page.
    let (state, nonce, cookie) = begin(&app).await;
    let res = finish(
        &app,
        &state,
        &format!("{nonce}|admins|sub-1"),
        Some(&cookie),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let cookies: Vec<String> = res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().expect("c").to_owned())
        .collect();
    let session = cookies
        .iter()
        .find(|c| c.starts_with("clamv_session=") && !c.starts_with("clamv_session=;"))
        .expect("session cookie")
        .split(';')
        .next()
        .expect("pair")
        .to_owned();
    let u = st
        .db
        .user_by_username("sso:alice")
        .await
        .expect("q")
        .expect("user");
    assert_eq!(u.role, Role::Admin);
    assert!(u.is_external());
    let res = app
        .clone()
        .oneshot(req("/admin/users", Some(&session)))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::OK, "admin pages open");

    // The same state cannot be used twice.
    let res = finish(
        &app,
        &state,
        &format!("{nonce}|admins|sub-1"),
        Some(&cookie),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // The state must be bound to this browser.
    let (state, nonce, _) = begin(&app).await;
    let res = finish(&app, &state, &format!("{nonce}|admins|sub-1"), None).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Wrong nonce and forged signatures are refused.
    let (state, _, cookie) = begin(&app).await;
    let res = finish(&app, &state, "other-nonce|admins|sub-1", Some(&cookie)).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let (state, nonce, cookie) = begin(&app).await;
    let res = finish(
        &app,
        &state,
        &format!("{nonce}|admins|sub-1|badsig"),
        Some(&cookie),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // No matching group: no access, no account.
    let (state, nonce, cookie) = begin(&app).await;
    let res = finish(&app, &state, &format!("{nonce}|staff|sub-2"), Some(&cookie)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(st.db.list_users().await.expect("users").len(), 1);

    // Groups decide the role at each sign-in; the old admin session ends.
    let (state, nonce, cookie) = begin(&app).await;
    let res = finish(
        &app,
        &state,
        &format!("{nonce}|viewers|sub-1"),
        Some(&cookie),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let u = st
        .db
        .user_by_username("sso:alice")
        .await
        .expect("q")
        .expect("user");
    assert_eq!(u.role, Role::Viewer);
    let res = app
        .clone()
        .oneshot(req("/admin/users", Some(&session)))
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "old session is gone");

    // A different subject with the same display name gets its own account.
    let (state, nonce, cookie) = begin(&app).await;
    let res = finish(
        &app,
        &state,
        &format!("{nonce}|viewers|sub-3"),
        Some(&cookie),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        st.db
            .user_by_username("sso:alice-2")
            .await
            .expect("q")
            .is_some()
    );

    // SSO accounts never sign in with a password.
    let res = app
        .clone()
        .oneshot(
            Request::post("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("username=sso%3Aalice&password=%21"))
                .expect("req"),
        )
        .await
        .expect("res");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn bad_oidc_config_is_rejected() {
    let parse = |extra: &[&str]| {
        let mut a = vec!["clamv-webui"];
        a.extend_from_slice(extra);
        clamv_webui::auth::oidc::Oidc::from_config(&Cli::parse_from(a).config)
    };
    assert!(parse(&[]).expect("off").is_none());
    let base = [
        "--oidc-client-id",
        "c",
        "--oidc-client-secret",
        "s",
        "--oidc-redirect-uri",
        "https://nas/login/oauth2/code/clamav",
        "--oidc-admin-groups",
        "a",
    ];
    let mut plain = vec!["--oidc-issuer", "http://idp.example"];
    plain.extend_from_slice(&base);
    assert!(parse(&plain).is_err(), "http only for loopback");
    let mut nogroups = vec!["--oidc-issuer", "https://idp.example"];
    nogroups.extend_from_slice(&base[..6]);
    assert!(
        parse(&nogroups).is_err(),
        "no group means nobody can sign in"
    );
    let mut ok = vec!["--oidc-issuer", "https://idp.example"];
    ok.extend_from_slice(&base);
    assert!(parse(&ok).expect("valid").is_some());
}
