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
use crate::auth::oidc::{CALLBACK_PATH, Identity};
use crate::db::audit::AuditEntry;
use crate::db::users::User;

const STATE_COOKIE: &str = "clamv_oidc";

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/login/oidc", get(start))
        .route(CALLBACK_PATH, get(callback))
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
        },
    );
    if let Ok(v) = state_cookie("", 0, st.cfg.cookie_secure).parse() {
        r.headers_mut().append(header::SET_COOKIE, v);
    }
    r
}

async fn start(State(st): State<Arc<AppState>>) -> Response {
    let Some(o) = &st.oidc else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match o.start().await {
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

/// A local name for display and audit: `sso:` plus the provider's name, made unique.
async fn free_username(st: &AppState, name: &str) -> Option<String> {
    let base: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
        .take(48)
        .collect();
    let base = if base.is_empty() {
        "user".to_owned()
    } else {
        base
    };
    for i in 1..100 {
        let candidate = if i == 1 {
            format!("sso:{base}")
        } else {
            format!("sso:{base}-{i}")
        };
        if matches!(st.db.user_by_username(&candidate).await, Ok(None)) {
            return Some(candidate);
        }
    }
    None
}

async fn local_user(
    st: &AppState,
    id: &Identity,
    role: crate::auth::Role,
) -> Result<User, &'static str> {
    let principal = id.principal();
    let existing = st
        .db
        .identity_user(&principal)
        .await
        .map_err(|_| "database")?;
    if let Some(uid) = existing {
        let u = st
            .db
            .user_by_id(&uid)
            .await
            .map_err(|_| "database")?
            .ok_or("database")?;
        if !u.enabled {
            return Err("account disabled");
        }
        // Groups decide the role on every sign-in; a change also ends old sessions.
        if u.role != role {
            st.db
                .set_role_enabled(&u.id, role, true)
                .await
                .map_err(|_| "database")?;
            tracing::info!(event = "auth.role_changed", user = %u.username, role = %role, "role updated from SSO groups");
            return st
                .db
                .user_by_id(&uid)
                .await
                .map_err(|_| "database")?
                .ok_or("database");
        }
        return Ok(u);
    }
    let name = free_username(st, &id.name)
        .await
        .ok_or("no free username")?;
    // "!" is not a valid hash, so the account can never sign in with a password.
    let u = st
        .db
        .create_user(&name, crate::db::users::NO_PASSWORD, role, false)
        .await
        .map_err(|_| "database")?;
    st.db
        .link_identity(&principal, &u.id, "OIDC", &id.issuer, &id.subject)
        .await
        .map_err(|_| "database")?;
    tracing::info!(event = "auth.user_provisioned", user = %u.username, role = %role, "SSO user created");
    Ok(u)
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
    let id = match o.finish(state, code).await {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(event = "oidc.failed", error = %e, ip = %info.ip, "SSO sign-in failed");
            return login_error(
                &st,
                StatusCode::UNAUTHORIZED,
                "Single sign-on failed. Try again.",
            );
        }
    };
    let Some(role) = o.role_for(&id.groups) else {
        deny(&st, &info, &id.name, "no matching group").await;
        return login_error(
            &st,
            StatusCode::FORBIDDEN,
            "Your account is not in a group that may use this app.",
        );
    };
    let user = match local_user(&st, &id, role).await {
        Ok(u) => u,
        Err("account disabled") => {
            deny(&st, &info, &id.name, "account disabled").await;
            return login_error(&st, StatusCode::FORBIDDEN, "Your account is disabled here.");
        }
        Err(e) => {
            tracing::error!(
                event = "oidc.failed",
                error = e,
                "could not record SSO user"
            );
            return login_error(&st, StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
        }
    };
    let (cookie, to) = match super::begin_session(&st, auth, &user, &info, "OIDC").await {
        Ok(x) => x,
        Err(r) => return r,
    };
    // A page, not a redirect: the Strict session cookie is only sent on a same-site navigation.
    let mut r = (
        [(header::CACHE_CONTROL, "no-store")],
        Html(format!(
            "<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=\"0;url={to}\"><title>Signing in</title><p><a href=\"{to}\">Continue</a></p>"
        )),
    )
        .into_response();
    for c in [cookie, state_cookie("", 0, st.cfg.cookie_secure)] {
        if let Ok(v) = c.parse() {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    r
}
