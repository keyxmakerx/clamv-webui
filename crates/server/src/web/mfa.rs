//! Second sign-in step (TOTP or recovery code; passkeys in `passkeys`) and the
//! account page where users manage their second factors.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use super::session::{Auth, cookie};
use super::{Nav, RequestInfo, csrf, error_page, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::auth::token::hash_secret;
use crate::auth::totp;
use crate::db::audit::AuditEntry;
use crate::db::sessions::Session;
use crate::db::users::User;

pub const MFA_COOKIE: &str = "clamv_mfa";
const ISSUER: &str = "ClamAV Web UI";

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/login/2fa", get(second_page).post(second_submit))
        .route("/account/security", get(security_page))
        .route("/account/2fa/setup", post(setup))
        .route("/account/2fa/enable", post(enable))
        .route("/account/2fa/disable", post(disable))
        .route("/account/2fa/recovery", post(new_recovery))
        .route("/admin/users/{id}/mfa-reset", post(admin_reset))
}

fn mfa_cookie(value: &str, max_age: i64, secure: bool) -> String {
    format!(
        "{MFA_COOKIE}={value}; Path=/login; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

fn transport_name(t: &str) -> &'static str {
    match t {
        "LDAP" => "LDAP",
        _ => "UI",
    }
}

/// After a correct password: a session, or the second step when the user has one.
pub(crate) async fn after_password(
    st: &AppState,
    auth: Auth,
    user: &User,
    info: &RequestInfo,
    transport: &'static str,
) -> Response {
    match st.db.mfa_methods(&user.id).await {
        Ok((false, 0)) => match super::begin_session(st, auth, user, info, transport).await {
            Ok((c, to)) => ([(header::SET_COOKIE, c)], Redirect::to(to)).into_response(),
            Err(r) => r,
        },
        Ok(_) => match st.db.create_mfa_pending(&user.id, transport).await {
            Ok(raw) => {
                tracing::info!(event = "auth.second_factor_required", user = %user.username, ip = %info.ip, "password accepted; second factor next");
                let ttl = crate::db::mfa::PENDING_TTL_MS / 1000;
                (
                    [(
                        header::SET_COOKIE,
                        mfa_cookie(&raw, ttl, st.cfg.cookie_secure),
                    )],
                    Redirect::to("/login/2fa"),
                )
                    .into_response()
            }
            Err(_) => error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
        },
        Err(_) => error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    }
}

#[derive(Template)]
#[template(path = "login_2fa.html")]
struct SecondPage {
    error: Option<String>,
    totp: bool,
    passkeys: bool,
}

async fn pending(st: &AppState, h: &HeaderMap) -> Option<(crate::db::mfa::Pending, User)> {
    let raw = cookie(h, MFA_COOKIE)?;
    let p = st.db.mfa_pending(&raw).await.ok()??;
    let u = st.db.user_by_id(&p.user_id).await.ok()??;
    u.enabled.then_some((p, u))
}

async fn second_page(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some((_, u)) = pending(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let (totp, keys) = st.db.mfa_methods(&u.id).await.unwrap_or_default();
    render(
        StatusCode::OK,
        &SecondPage {
            error: None,
            totp,
            passkeys: keys > 0,
        },
    )
}

/// Check a TOTP or recovery code. Returns which one matched.
async fn check_code(st: &AppState, user_id: &str, input: &str) -> Option<&'static str> {
    let input = input.trim();
    if input.is_empty() || input.len() > 64 {
        return None;
    }
    if let Ok(Some(t)) = st.db.totp(user_id).await {
        match st.sealer.open(&t.secret, &format!("totp:{user_id}")) {
            Ok(secret) => {
                let now = crate::db::now_ms() / 1000;
                if let Some(step) = totp::verify(&secret, input, t.last_step, now)
                    && st.db.use_totp_step(user_id, step).await.unwrap_or(false)
                {
                    return Some("totp");
                }
            }
            Err(e) => {
                tracing::error!(event = "auth.totp_unreadable", error = %e, "stored 2FA seed cannot be decrypted (SECRET_KEY_FILE changed?)");
            }
        }
    }
    let norm = totp::normalize_recovery(input);
    if norm.len() == 12
        && st
            .db
            .use_recovery_code(user_id, &hash_secret(&norm))
            .await
            .unwrap_or(false)
    {
        return Some("recovery code");
    }
    None
}

#[derive(Deserialize)]
struct CodeForm {
    #[serde(default)]
    code: String,
}

async fn second_submit(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    headers: HeaderMap,
    Form(f): Form<CodeForm>,
) -> Response {
    let Some((p, u)) = pending(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let (has_totp, keys) = st.db.mfa_methods(&u.id).await.unwrap_or_default();
    // Signing in again starts a fresh pending step, so wrong codes are also
    // counted per account; a correct password does not reset this counter.
    let lock_key = format!("2fa:{}", u.id);
    if st.mfa_lockout.check(&lock_key, info.ip).is_err() {
        let _ = st.db.delete_mfa_pending(&p.id_hash).await;
        tracing::warn!(event = "auth.locked", user = %u.username, ip = %info.ip, transport = "2FA", "second factor refused while locked");
        return (
            [(header::SET_COOKIE, mfa_cookie("", 0, st.cfg.cookie_secure))],
            render(
                StatusCode::TOO_MANY_REQUESTS,
                &SecondPage {
                    error: Some("Too many wrong codes. Try again later.".into()),
                    totp: false,
                    passkeys: false,
                },
            ),
        )
            .into_response();
    }
    if !st.db.count_mfa_attempt(&p.id_hash).await.unwrap_or(false) {
        let _ = st.db.delete_mfa_pending(&p.id_hash).await;
        fail_audit(&st, &u, &info, "too many codes").await;
        return (
            [(header::SET_COOKIE, mfa_cookie("", 0, st.cfg.cookie_secure))],
            render(
                StatusCode::TOO_MANY_REQUESTS,
                &SecondPage {
                    error: Some("Too many wrong codes. Sign in again.".into()),
                    totp: false,
                    passkeys: false,
                },
            ),
        )
            .into_response();
    }
    match check_code(&st, &u.id, &f.code).await {
        Some(how) => finish(&st, auth, &u, &info, &p, how).await,
        None => {
            if let Some(scope) = st.mfa_lockout.fail(&lock_key, info.ip) {
                tracing::warn!(event = "auth.locked", user = %u.username, ip = %info.ip, scope = ?scope, transport = "2FA", "second factor locked");
            }
            fail_audit(&st, &u, &info, "wrong code").await;
            let left = crate::db::mfa::PENDING_MAX_ATTEMPTS - p.attempts - 1;
            render(
                StatusCode::UNAUTHORIZED,
                &SecondPage {
                    error: Some(format!("That code is not valid. {left} attempt(s) left.")),
                    totp: has_totp,
                    passkeys: keys > 0,
                },
            )
        }
    }
}

/// Second factor passed: end the pending step and start the session.
pub(crate) async fn finish(
    st: &AppState,
    auth: Auth,
    u: &User,
    info: &RequestInfo,
    p: &crate::db::mfa::Pending,
    how: &'static str,
) -> Response {
    let _ = st.db.delete_mfa_pending(&p.id_hash).await;
    if how == "recovery code" {
        let left = st.db.recovery_codes_left(&u.id).await.unwrap_or(0);
        tracing::warn!(event = "auth.recovery_code_used", user = %u.username, ip = %info.ip, left, "signed in with a recovery code");
    }
    st.db
        .audit(AuditEntry {
            username: Some(u.username.clone()),
            action: "LOGIN_2FA",
            outcome: "OK",
            details: Some(how.into()),
            transport: Some(transport_name(&p.transport)),
            ip: Some(info.ip.to_string()),
            user_agent: info.user_agent.clone(),
            ..Default::default()
        })
        .await;
    match super::begin_session(st, auth, u, info, transport_name(&p.transport)).await {
        Ok((c, to)) => (
            axum::response::AppendHeaders([
                (header::SET_COOKIE, c),
                (header::SET_COOKIE, mfa_cookie("", 0, st.cfg.cookie_secure)),
            ]),
            Redirect::to(to),
        )
            .into_response(),
        Err(r) => r,
    }
}

async fn fail_audit(st: &AppState, u: &User, info: &RequestInfo, why: &str) {
    tracing::warn!(event = "auth.second_factor_failed", user = %u.username, ip = %info.ip, reason = why, "second factor rejected");
    st.db
        .audit(AuditEntry {
            username: Some(u.username.clone()),
            action: "LOGIN_2FA",
            outcome: "FAIL",
            details: Some(why.into()),
            transport: Some("UI"),
            ip: Some(info.ip.to_string()),
            user_agent: info.user_agent.clone(),
            ..Default::default()
        })
        .await;
}

// ---- account page ----

pub struct PasskeyRow {
    pub id: String,
    pub name: String,
    pub created: String,
    pub last_used: String,
}

pub struct Enrolment {
    sealed: String,
    qr: String,
    key: String,
}

#[derive(Template)]
#[template(path = "account_security.html")]
struct SecurityPage {
    nav: Nav,
    totp_since: Option<String>,
    recovery_left: i64,
    passkeys: Vec<PasskeyRow>,
    enrol: Option<Enrolment>,
    codes: Vec<String>,
    sso: bool,
}

pub(crate) async fn security(
    st: &AppState,
    s: &Session,
    u: &User,
    error: Option<String>,
    success: Option<String>,
    enrol: Option<Enrolment>,
    codes: Vec<String>,
) -> Response {
    let mut nav = Nav::new("security", s, u);
    nav.error = error;
    nav.success = success;
    let totp = st.db.totp(&u.id).await.ok().flatten();
    let recovery_left = st.db.recovery_codes_left(&u.id).await.unwrap_or(0);
    let passkeys = st
        .db
        .list_passkeys(&u.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|k| PasskeyRow {
            id: k.id,
            name: k.name,
            created: super::admin::fmt_ts(k.created_at),
            last_used: k
                .last_used_at
                .map_or_else(|| "never".into(), super::admin::fmt_ts),
        })
        .collect();
    let status = if nav.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    render(
        status,
        &SecurityPage {
            nav,
            totp_since: totp.map(|t| super::admin::fmt_ts(t.created_at)),
            recovery_left,
            passkeys,
            enrol,
            codes,
            sso: u.is_external() && st.ldap.is_none(),
        },
    )
}

async fn security_page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Viewer) {
        Ok(x) => x,
        Err(r) => return r,
    };
    security(&st, &s, &u, None, None, None, Vec::new()).await
}

#[derive(Deserialize)]
struct CsrfForm {
    #[serde(rename = "_csrf")]
    csrf: Option<String>,
    #[serde(default)]
    code: String,
    #[serde(default)]
    sealed: String,
}

fn signed_in(auth: Auth, csrf_value: Option<&str>) -> Result<(Session, User), Response> {
    let (s, u) = auth.require(Role::Viewer)?;
    if !csrf::token_ok(&s.csrf_token, csrf_value) {
        return Err(error_page(
            StatusCode::FORBIDDEN,
            "Your session form expired. Reload and try again.",
        ));
    }
    Ok((s, u))
}

async fn setup(State(st): State<Arc<AppState>>, auth: Auth, Form(f): Form<CsrfForm>) -> Response {
    let (s, u) = match signed_in(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let secret = totp::new_secret();
    // The candidate seed rides in the form, sealed to this user, until confirmed.
    let sealed = match st.sealer.seal(&secret, &format!("enrol:{}", u.id)) {
        Ok(x) => x,
        Err(e) => {
            tracing::error!(event = "secret_key.unavailable", error = %e, "cannot use the secret key");
            return security(&st, &s, &u, Some("The server cannot store secrets: check SECRET_KEY_FILE or that DATA_DIR is writable.".into()), None, None, Vec::new()).await;
        }
    };
    let uri = totp::otpauth_uri(ISSUER, &u.username, &secret);
    let enrol = Enrolment {
        sealed,
        qr: totp::qr_data_uri(&uri).unwrap_or_default(),
        key: totp::base32(&secret)
            .as_bytes()
            .chunks(4)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join(" "),
    };
    security(&st, &s, &u, None, None, Some(enrol), Vec::new()).await
}

async fn audit_user(
    st: &AppState,
    u: &User,
    info: &RequestInfo,
    action: &'static str,
    details: Option<String>,
) {
    st.db
        .audit(AuditEntry {
            username: Some(u.username.clone()),
            action,
            outcome: "OK",
            details,
            transport: Some("UI"),
            ip: Some(info.ip.to_string()),
            user_agent: info.user_agent.clone(),
            ..Default::default()
        })
        .await;
}

fn recovery_set() -> (Vec<String>, Vec<String>) {
    let codes = totp::new_recovery_codes();
    let hashes = codes
        .iter()
        .map(|c| hash_secret(&totp::normalize_recovery(c)))
        .collect();
    (codes, hashes)
}

async fn enable(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Form(f): Form<CsrfForm>,
) -> Response {
    let (s, u) = match signed_in(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Ok(secret) = st.sealer.open(&f.sealed, &format!("enrol:{}", u.id)) else {
        return security(
            &st,
            &s,
            &u,
            Some("Setup expired. Start again.".into()),
            None,
            None,
            Vec::new(),
        )
        .await;
    };
    let now = crate::db::now_ms() / 1000;
    let Some(step) = totp::verify(&secret, &f.code, 0, now) else {
        // Show the same QR again so the user can retry.
        let uri = totp::otpauth_uri(ISSUER, &u.username, &secret);
        let enrol = Enrolment {
            sealed: f.sealed.clone(),
            qr: totp::qr_data_uri(&uri).unwrap_or_default(),
            key: totp::base32(&secret),
        };
        return security(
            &st,
            &s,
            &u,
            Some("That code did not match. Check the time on your phone and try again.".into()),
            None,
            Some(enrol),
            Vec::new(),
        )
        .await;
    };
    let Ok(stored) = st.sealer.seal(&secret, &format!("totp:{}", u.id)) else {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    let (codes, hashes) = recovery_set();
    if st
        .db
        .enable_totp(&u.id, &stored, step, &hashes)
        .await
        .is_err()
    {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    tracing::info!(event = "auth.totp_enabled", user = %u.username, "two-factor sign-in turned on");
    audit_user(&st, &u, &info, "MFA_ENABLE", Some("totp".into())).await;
    security(
        &st,
        &s,
        &u,
        None,
        Some(
            "Two-factor sign-in is on. Save these recovery codes now; they are shown once.".into(),
        ),
        None,
        codes,
    )
    .await
}

async fn disable(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Form(f): Form<CsrfForm>,
) -> Response {
    let (s, u) = match signed_in(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if check_code(&st, &u.id, &f.code).await.is_none() {
        return security(
            &st,
            &s,
            &u,
            Some(
                "Enter a current code from your app, or a recovery code, to turn this off.".into(),
            ),
            None,
            None,
            Vec::new(),
        )
        .await;
    }
    if st.db.disable_totp(&u.id).await.is_err() {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    tracing::warn!(event = "auth.totp_disabled", user = %u.username, "two-factor sign-in turned off");
    audit_user(&st, &u, &info, "MFA_DISABLE", Some("totp".into())).await;
    security(
        &st,
        &s,
        &u,
        None,
        Some("Authenticator app removed.".into()),
        None,
        Vec::new(),
    )
    .await
}

async fn new_recovery(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Form(f): Form<CsrfForm>,
) -> Response {
    let (s, u) = match signed_in(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if st.db.totp(&u.id).await.ok().flatten().is_none()
        || check_code(&st, &u.id, &f.code).await != Some("totp")
    {
        return security(
            &st,
            &s,
            &u,
            Some("Enter a current code from your authenticator app.".into()),
            None,
            None,
            Vec::new(),
        )
        .await;
    }
    let (codes, hashes) = recovery_set();
    if st.db.replace_recovery_codes(&u.id, &hashes).await.is_err() {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    audit_user(&st, &u, &info, "MFA_RECOVERY_CODES", None).await;
    security(
        &st,
        &s,
        &u,
        None,
        Some("New recovery codes; the old ones no longer work.".into()),
        None,
        codes,
    )
    .await
}

async fn admin_reset(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let (_s, me) = match super::admin::admin_post(auth, f.csrf.as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Ok(Some(target)) = st.db.user_by_id(&id).await else {
        return Redirect::to("/admin/users").into_response();
    };
    if st.db.clear_mfa(&target.id).await.is_err() {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    let _ = st.db.delete_user_sessions(&target.id).await;
    tracing::warn!(event = "auth.mfa_reset", user = %target.username, by = %me.username, "second factors removed by an admin");
    super::admin::audit(&st, &me, &info, "MFA_RESET", target.username.clone()).await;
    Redirect::to("/admin/users").into_response()
}
