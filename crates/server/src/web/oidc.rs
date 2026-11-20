//! Browser side of OIDC sign-in.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use super::session::Auth;
use super::{LoginPage, RequestInfo, render};
use crate::app::AppState;
use crate::auth::external::ProvisionError;
use crate::auth::oidc::CALLBACK_PATH;
use crate::db::audit::AuditEntry;

const STATE_COOKIE: &str = "palisade_oidc";

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/login/oidc", get(start))
        .route("/account/confirm/sso", get(start_confirm))
        .route(CALLBACK_PATH, get(callback))
}

#[derive(Deserialize)]
struct ConfirmQuery {
    #[serde(default)]
    next: String,
}

/// A signed-in SSO user confirms who they are with a fresh sign-in at the provider (sa2).
async fn start_confirm(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Query(q): Query<ConfirmQuery>,
) -> Response {
    let Some(o) = &st.oidc else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (s, u) = match auth.require(crate::auth::Role::Viewer) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !st
        .sso_starts
        .allow(&crate::auth::lockout::ip_key(info.ip).to_string())
    {
        return super::error_page(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many sign-in attempts. Try again in a minute.",
        );
    }
    let next = super::mfa::confirm_next(&q.next);
    match o.start(true).await {
        Ok((url, state)) => {
            if let Ok(mut g) = st.sso_confirms.lock() {
                let now = crate::db::now_ms();
                g.retain(|_, v| v.expires > now);
                if g.len() >= 1000 {
                    return super::error_page(
                        StatusCode::TOO_MANY_REQUESTS,
                        "Try again in a minute.",
                    );
                }
                g.insert(
                    state.clone(),
                    crate::app::SsoConfirm {
                        session_hash: s.id_hash.clone(),
                        user_id: u.id.clone(),
                        next,
                        expires: now + 600_000,
                    },
                );
            }
            (
                [(
                    header::SET_COOKIE,
                    state_cookie(&state, 600, st.cfg.cookie_secure),
                )],
                Redirect::to(&url),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(event = "oidc.failed", error = %e, "could not start SSO confirmation");
            super::error_page(
                StatusCode::BAD_GATEWAY,
                "Single sign-on is unavailable right now.",
            )
        }
    }
}

/// An HTML hop instead of a redirect: Strict cookies are only sent on a
/// same-site navigation, so the next request must start from this site.
fn hop(to: &str, cookies: Vec<axum::http::HeaderValue>, secure: bool) -> Response {
    let mut r = (
        [(header::CACHE_CONTROL, "no-store")],
        Html(format!(
            "<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=\"0;url={to}\"><title>Signing in</title><p><a href=\"{to}\">Continue</a></p>"
        )),
    )
        .into_response();
    for c in cookies {
        r.headers_mut().append(header::SET_COOKIE, c);
    }
    if let Ok(v) = state_cookie("", 0, secure).parse() {
        r.headers_mut().append(header::SET_COOKIE, v);
    }
    r
}

fn state_cookie(value: &str, max_age: i64, secure: bool) -> String {
    // Lax so it survives the top-level redirect back from the provider.
    format!(
        "{STATE_COOKIE}={value}; Path=/login; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

fn login_error(st: &AppState, status: StatusCode, msg: &'static str) -> Response {
    let mut r = render(
        status,
        &LoginPage {
            error: Some(msg),
            info: None,
            username: String::new(),
            sso: st.oidc.as_ref().map(|o| o.label().to_owned()),
            ldap: st.ldap.is_some(),
            source: String::new(),
            first_run: None,
        },
    );
    if let Ok(v) = state_cookie("", 0, st.cfg.cookie_secure).parse() {
        r.headers_mut().append(header::SET_COOKIE, v);
    }
    r
}

async fn start(State(st): State<Arc<AppState>>, info: RequestInfo) -> Response {
    let Some(o) = &st.oidc else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Each start holds a pending entry; one address must not fill the table (sa3).
    if !st
        .sso_starts
        .allow(&crate::auth::lockout::ip_key(info.ip).to_string())
    {
        tracing::warn!(event = "auth.oidc_throttled", ip = %info.ip, "too many SSO starts from one address");
        return login_error(
            &st,
            StatusCode::TOO_MANY_REQUESTS,
            "Too many sign-in attempts. Try again in a minute.",
        );
    }
    match o.start(false).await {
        Ok((url, state)) => (
            [(
                header::SET_COOKIE,
                state_cookie(&state, 600, st.cfg.cookie_secure),
            )],
            Redirect::to(&url),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(event = "oidc.failed", error = %e, "could not start SSO sign-in");
            login_error(
                &st,
                StatusCode::BAD_GATEWAY,
                "Single sign-on is unavailable right now.",
            )
        }
    }
}

#[derive(Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

fn cookie_state(h: &HeaderMap) -> Option<String> {
    h.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| {
            c.trim()
                .strip_prefix(&format!("{STATE_COOKIE}="))
                .map(str::to_owned)
        })
}

async fn deny(st: &AppState, info: &RequestInfo, who: &str, reason: &str) {
    tracing::warn!(event = "auth.oidc_denied", user = %who, ip = %info.ip, reason, "SSO sign-in refused");
    st.db
        .audit(AuditEntry {
            username: Some(who.to_owned()),
            action: "LOGIN",
            outcome: "DENIED",
            transport: Some("OIDC"),
            ip: Some(info.ip.to_string()),
            user_agent: info.user_agent.clone(),
            details: Some(reason.to_owned()),
            ..Default::default()
        })
        .await;
}

async fn callback(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    headers: HeaderMap,
    Query(q): Query<Callback>,
) -> Response {
    let Some(o) = &st.oidc else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if q.error.is_some() {
        return login_error(
            &st,
            StatusCode::UNAUTHORIZED,
            "Sign-in was cancelled or refused by the provider.",
        );
    }
    let (Some(code), Some(state)) = (q.code.as_deref(), q.state.as_deref()) else {
        return login_error(
            &st,
            StatusCode::BAD_REQUEST,
            "Sign-in response was incomplete.",
        );
    };
    // The state must come back to the same browser that started the sign-in.
    let bound =
        cookie_state(&headers).is_some_and(|c| bool::from(c.as_bytes().ct_eq(state.as_bytes())));
    if !bound {
        return login_error(&st, StatusCode::BAD_REQUEST, "Sign-in expired. Try again.");
    }
    let finished = match o.finish(state, code).await {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(event = "oidc.failed", error = %e, ip = %info.ip, "SSO sign-in failed");
            return login_error(
                &st,
                StatusCode::UNAUTHORIZED,
                "Single sign-on failed. Try again.",
            );
        }
    };
    let id = finished.id;
    if finished.reauth {
        return confirmed(&st, &info, state, &id).await;
    }
    let Some(role) = o.role_for(&id.groups) else {
        deny(&st, &info, &id.name, "no matching group").await;
        return login_error(
            &st,
            StatusCode::FORBIDDEN,
            "Your account is not in a group that may use this app.",
        );
    };
    let user = match crate::auth::external::provision(&st, &id, role).await {
        Ok(u) => u,
        Err(ProvisionError::Disabled) => {
            deny(&st, &info, &id.name, "account disabled").await;
            return login_error(&st, StatusCode::FORBIDDEN, "Your account is disabled here.");
        }
        Err(ProvisionError::Unavailable) => {
            tracing::error!(event = "oidc.failed", "could not record SSO user");
            return login_error(&st, StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
        }
    };
    // A passkey or authenticator app added here is asked for after SSO too (sa4).
    let resp = super::mfa::after_password(&st, auth, &user, &info, "OIDC").await;
    let to = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let Some(to) = to.filter(|t| t.starts_with('/') && !t.starts_with("//")) else {
        return resp;
    };
    let cookies = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .cloned()
        .collect();
    hop(&to, cookies, st.cfg.cookie_secure)
}

/// The provider showed a fresh sign-in for a confirmation: if it is the same
/// person as the session that asked, mark that session confirmed.
async fn confirmed(
    st: &AppState,
    info: &RequestInfo,
    state: &str,
    id: &crate::auth::external::Identity,
) -> Response {
    let pending = st
        .sso_confirms
        .lock()
        .ok()
        .and_then(|mut g| g.remove(state));
    let Some(p) = pending.filter(|p| p.expires > crate::db::now_ms()) else {
        return login_error(
            st,
            StatusCode::BAD_REQUEST,
            "Confirmation expired. Try again.",
        );
    };
    let same = matches!(
        st.db.identity_user(&id.principal()).await,
        Ok(Some(uid)) if uid == p.user_id
    );
    if !same {
        tracing::warn!(event = "auth.confirm_failed", ip = %info.ip, provider_user = %id.name, "SSO confirmation came back as a different person");
        return super::error_page(
            StatusCode::FORBIDDEN,
            "That sign-in was a different account. Sign in at the provider as yourself.",
        );
    }
    super::mfa::mark_confirmed(st, &p.session_hash);
    tracing::info!(event = "auth.confirmed", provider_user = %id.name, ip = %info.ip, "user confirmed their identity at the provider");
    st.db
        .audit(AuditEntry {
            username: Some(id.name.clone()),
            action: "REAUTH",
            outcome: "OK",
            transport: Some("OIDC"),
            ip: Some(info.ip.to_string()),
            user_agent: info.user_agent.clone(),
            ..Default::default()
        })
        .await;
    hop(p.next, Vec::new(), st.cfg.cookie_secure)
}
