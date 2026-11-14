//! Passkey ceremonies: add one on the account page, sign in with one
//! (no password), or use one as the second step after a password.

use std::sync::Arc;

use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use super::session::{Auth, cookie};
use super::{RequestInfo, csrf};
use crate::app::AppState;
use crate::auth::Role;
use crate::auth::webauthn::{self, b64u, unb64u};
use crate::db::audit::AuditEntry;
use crate::db::passkeys::MAX_PASSKEYS;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/account/passkeys/options", post(register_options))
        .route("/account/passkeys", post(register))
        .route("/account/passkeys/{id}/delete", post(remove))
        .route("/login/passkey/options", post(login_options))
        .route("/login/passkey", post(login))
}

/// (origin, relying-party id): PUBLIC_URL when set, otherwise the Host the browser used.
pub fn relying_party(st: &AppState, h: &HeaderMap) -> Option<(String, String)> {
    if let Some(u) = &st.cfg.public_url {
        let host = u.host_str()?.to_owned();
        return Some((u.origin().ascii_serialization(), host));
    }
    let host = h.get(header::HOST)?.to_str().ok()?;
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c))
    {
        return None;
    }
    let scheme = if st.cfg.tls_enabled() || super::session::forwarded_https(st, h) {
        "https"
    } else {
        "http"
    };
    let name = if host.starts_with('[') {
        host.split(']').next().map(|s| format!("{s}]"))?
    } else {
        host.rsplit_once(':').map_or(host, |(n, _)| n).to_owned()
    };
    Some((format!("{scheme}://{host}"), name))
}

fn jerr(status: StatusCode, msg: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "error": msg })),
    )
        .into_response()
}

fn jok(v: serde_json::Value) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Json(v)).into_response()
}

#[derive(Deserialize)]
struct CsrfJson {
    #[serde(default)]
    csrf: String,
}

async fn register_options(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    headers: HeaderMap,
    Json(b): Json<CsrfJson>,
) -> Response {
    let Ok((s, u)) = auth.require(Role::Viewer) else {
        return jerr(StatusCode::UNAUTHORIZED, "Sign in again.");
    };
    if !csrf::token_ok(&s.csrf_token, Some(&b.csrf)) {
        return jerr(StatusCode::FORBIDDEN, "Reload the page and try again.");
    }
    let Some((_, rp_id)) = relying_party(&st, &headers) else {
        return jerr(StatusCode::BAD_REQUEST, "Set PUBLIC_URL to use passkeys.");
    };
    let existing = st.db.list_passkeys(&u.id).await.unwrap_or_default();
    if i64::try_from(existing.len()).unwrap_or(i64::MAX) >= MAX_PASSKEYS {
        return jerr(StatusCode::BAD_REQUEST, "At most 10 passkeys per account.");
    }
    let Ok((handle, challenge)) = st.db.create_challenge("register", Some(&u.id)).await else {
        return jerr(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    jok(json!({
        "handle": handle,
        "publicKey": {
            "challenge": challenge,
            "rp": { "id": rp_id, "name": "ClamAV Web UI" },
            "user": { "id": b64u(u.id.as_bytes()), "name": u.username, "displayName": u.username },
            "pubKeyCredParams": [
                { "type": "public-key", "alg": webauthn::ALG_ES256 },
                { "type": "public-key", "alg": webauthn::ALG_EDDSA },
                { "type": "public-key", "alg": webauthn::ALG_RS256 }
            ],
            "authenticatorSelection": { "residentKey": "required", "userVerification": "required" },
            "excludeCredentials": existing.iter().map(|k| json!({ "type": "public-key", "id": k.cred_id })).collect::<Vec<_>>(),
            "attestation": "none",
            "timeout": 120000
        }
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterBody {
    #[serde(default)]
    csrf: String,
    handle: String,
    #[serde(default)]
    name: String,
    client_data_json: String,
    attestation_object: String,
}

async fn register(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    headers: HeaderMap,
    Json(b): Json<RegisterBody>,
) -> Response {
    let Ok((s, u)) = auth.require(Role::Viewer) else {
        return jerr(StatusCode::UNAUTHORIZED, "Sign in again.");
    };
    if !csrf::token_ok(&s.csrf_token, Some(&b.csrf)) {
        return jerr(StatusCode::FORBIDDEN, "Reload the page and try again.");
    }
    let Ok(Some(ch)) = st.db.take_challenge(&b.handle).await else {
        return jerr(StatusCode::BAD_REQUEST, "This request expired. Try again.");
    };
    if ch.purpose != "register" || ch.user_id.as_deref() != Some(u.id.as_str()) {
        return jerr(StatusCode::BAD_REQUEST, "This request expired. Try again.");
    }
    let Some((origin, rp_id)) = relying_party(&st, &headers) else {
        return jerr(StatusCode::BAD_REQUEST, "Set PUBLIC_URL to use passkeys.");
    };
    let (Ok(cd), Ok(att)) = (unb64u(&b.client_data_json), unb64u(&b.attestation_object)) else {
        return jerr(
            StatusCode::BAD_REQUEST,
            "The browser sent an unreadable answer.",
        );
    };
    let reg = match webauthn::verify_registration(&cd, &att, &ch.challenge, &origin, &rp_id) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(event = "auth.passkey_rejected", user = %u.username, reason = %e, "passkey registration rejected");
            return jerr(
                StatusCode::BAD_REQUEST,
                "The passkey could not be verified.",
            );
        }
    };
    let name: String = b
        .name
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();
    let name = if name.is_empty() {
        "Passkey".to_owned()
    } else {
        name
    };
    if st
        .db
        .add_passkey(&u.id, &reg.cred_id, &name, &reg.public_key, reg.sign_count)
        .await
        .is_err()
    {
        return jerr(StatusCode::CONFLICT, "That passkey is already registered.");
    }
    tracing::info!(event = "auth.passkey_added", user = %u.username, name = %name, "passkey added");
    st.db
        .audit(AuditEntry {
            username: Some(u.username.clone()),
            action: "PASSKEY_ADD",
            outcome: "OK",
            details: Some(name),
            transport: Some("UI"),
            ip: Some(info.ip.to_string()),
            user_agent: info.user_agent.clone(),
            ..Default::default()
        })
        .await;
    jok(json!({ "redirect": "/account/security" }))
}

#[derive(Deserialize)]
struct RemoveForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
}

async fn remove(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<RemoveForm>,
) -> Response {
    let (s, u) = match auth.require(Role::Viewer) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !csrf::token_ok(&s.csrf_token, f.csrf.as_deref()) {
        return super::error_page(
            StatusCode::FORBIDDEN,
            "Your session form expired. Reload and try again.",
        );
    }
    let removed = st.db.delete_passkey(&u.id, &id).await.unwrap_or(false);
    if removed {
        tracing::warn!(event = "auth.passkey_removed", user = %u.username, "passkey removed");
        st.db
            .audit(AuditEntry {
                username: Some(u.username.clone()),
                action: "PASSKEY_DELETE",
                outcome: "OK",
                transport: Some("UI"),
                ip: Some(info.ip.to_string()),
                user_agent: info.user_agent.clone(),
                ..Default::default()
            })
            .await;
    }
    let msg = if removed {
        "Passkey removed."
    } else {
        "Unknown passkey."
    };
    super::mfa::security(
        &st,
        &s,
        &u,
        (!removed).then(|| msg.to_owned()),
        removed.then(|| msg.to_owned()),
        None,
        Vec::new(),
    )
    .await
}

#[derive(Deserialize)]
struct LoginOptionsBody {
    /// "login" (no password) or "second" (after a password).
    #[serde(default)]
    mode: String,
}

async fn login_options(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(b): Json<LoginOptionsBody>,
) -> Response {
    let Some((_, rp_id)) = relying_party(&st, &headers) else {
        return jerr(StatusCode::BAD_REQUEST, "Set PUBLIC_URL to use passkeys.");
    };
    let (purpose, user_id, allow) = if b.mode == "second" {
        let Some(p) = pending(&st, &headers).await else {
            return jerr(StatusCode::UNAUTHORIZED, "Sign in again.");
        };
        let keys = st.db.list_passkeys(&p.user_id).await.unwrap_or_default();
        let allow: Vec<_> = keys
            .iter()
            .map(|k| json!({ "type": "public-key", "id": k.cred_id }))
            .collect();
        ("second", Some(p.user_id), allow)
    } else {
        ("login", None, Vec::new())
    };
    let Ok((handle, challenge)) = st.db.create_challenge(purpose, user_id.as_deref()).await else {
        return jerr(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    jok(json!({
        "handle": handle,
        "publicKey": {
            "challenge": challenge,
            "rpId": rp_id,
            "allowCredentials": allow,
            "userVerification": "required",
            "timeout": 120000
        }
    }))
}

async fn pending(st: &AppState, h: &HeaderMap) -> Option<crate::db::mfa::Pending> {
    let raw = cookie(h, super::mfa::MFA_COOKIE)?;
    st.db.mfa_pending(&raw).await.ok()?
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginBody {
    handle: String,
    id: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    #[serde(default)]
    user_handle: Option<String>,
}

async fn login(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    headers: HeaderMap,
    Json(b): Json<LoginBody>,
) -> Response {
    let fail = |why: &'static str| {
        let ip = info.ip;
        async move {
            tracing::warn!(event = "auth.passkey_failed", ip = %ip, reason = why, "passkey sign-in rejected");
            jerr(StatusCode::UNAUTHORIZED, "That passkey was not accepted.")
        }
    };
    if st.lockout.check("passkey", info.ip).is_err() {
        return jerr(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Try again later.",
        );
    }
    let Ok(Some(ch)) = st.db.take_challenge(&b.handle).await else {
        return jerr(StatusCode::BAD_REQUEST, "This request expired. Try again.");
    };
    let Some((origin, rp_id)) = relying_party(&st, &headers) else {
        return jerr(StatusCode::BAD_REQUEST, "Set PUBLIC_URL to use passkeys.");
    };
    let Ok(Some(key)) = st.db.passkey_by_cred(&b.id).await else {
        let _ = st.lockout.fail("passkey", info.ip);
        return fail("unknown credential").await;
    };
    if let Some(h) = &b.user_handle
        && unb64u(h).ok().as_deref() != Some(key.user_id.as_bytes())
    {
        let _ = st.lockout.fail("passkey", info.ip);
        return fail("user handle mismatch").await;
    }
    let second = ch.purpose == "second";
    if second && ch.user_id.as_deref() != Some(key.user_id.as_str()) {
        return fail("passkey of another user").await;
    }
    if !second && ch.purpose != "login" {
        return fail("wrong challenge").await;
    }
    let (Ok(cd), Ok(ad), Ok(sig)) = (
        unb64u(&b.client_data_json),
        unb64u(&b.authenticator_data),
        unb64u(&b.signature),
    ) else {
        return jerr(
            StatusCode::BAD_REQUEST,
            "The browser sent an unreadable answer.",
        );
    };
    let count = match webauthn::verify_assertion(
        &cd,
        &ad,
        &sig,
        &ch.challenge,
        &origin,
        &rp_id,
        &key.public_key,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(event = "auth.passkey_failed", ip = %info.ip, reason = %e, "passkey signature rejected");
            let _ = st.lockout.fail("passkey", info.ip);
            return jerr(StatusCode::UNAUTHORIZED, "That passkey was not accepted.");
        }
    };
    if !st
        .db
        .use_passkey(&key.id, key.sign_count, count)
        .await
        .unwrap_or(false)
    {
        tracing::error!(event = "auth.passkey_cloned", user_id = %key.user_id, "passkey counter went backwards: it may have been copied");
        return jerr(StatusCode::UNAUTHORIZED, "That passkey was not accepted.");
    }
    let Ok(Some(u)) = st.db.user_by_id(&key.user_id).await else {
        return fail("user gone").await;
    };
    if !u.enabled {
        return jerr(StatusCode::FORBIDDEN, "Your account is disabled.");
    }
    let resp = if second {
        let Some(p) = pending(&st, &headers).await else {
            return jerr(StatusCode::UNAUTHORIZED, "Sign in again.");
        };
        if p.user_id != u.id {
            return fail("pending sign-in of another user").await;
        }
        super::mfa::finish(&st, auth, &u, &info, &p, "passkey").await
    } else {
        st.db
            .audit(AuditEntry {
                username: Some(u.username.clone()),
                action: "LOGIN_PASSKEY",
                outcome: "OK",
                transport: Some("UI"),
                ip: Some(info.ip.to_string()),
                user_agent: info.user_agent.clone(),
                ..Default::default()
            })
            .await;
        match super::begin_session(&st, auth, &u, &info, "PASSKEY").await {
            Ok((c, to)) => ([(header::SET_COOKIE, c)], Redirect303(to)).into_response(),
            Err(r) => r,
        }
    };
    // Hand the redirect to the script as JSON, keeping the cookies.
    let (mut parts, _) = resp.into_parts();
    let to = parts
        .headers
        .remove(header::LOCATION)
        .and_then(|v| v.to_str().ok().map(str::to_owned))
        .unwrap_or_else(|| "/dashboard".into());
    parts.status = StatusCode::OK;
    parts.headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    Response::from_parts(
        parts,
        axum::body::Body::from(json!({ "redirect": to }).to_string()),
    )
}

struct Redirect303(&'static str);

impl IntoResponse for Redirect303 {
    fn into_response(self) -> Response {
        axum::response::Redirect::to(self.0).into_response()
    }
}
