//! Admin page for API tokens. The secret is shown once, right after creation.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};

use super::admin::{admin_post, audit, fmt_ts};
use super::session::Auth;
use super::{Nav, RequestInfo, error_page, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::db::endpoints::Endpoint;
use crate::db::now_ms;
use crate::db::sessions::Session;
use crate::db::tokens::{NewToken, SCOPES};
use crate::db::users::User;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin/api-tokens", get(page).post(create))
        .route("/admin/api-tokens/{id}/revoke", post(revoke))
}

pub struct TokenRow {
    id: i64,
    label: String,
    prefix: String,
    scopes: String,
    limits: String,
    created: String,
    expires: String,
    last_used: String,
    state: &'static str,
}

#[derive(Template)]
#[template(path = "admin_tokens.html")]
struct TokensPage {
    nav: Nav,
    tokens: Vec<TokenRow>,
    endpoints: Vec<Endpoint>,
    scopes: [&'static str; 6],
    roots: String,
    secret: Option<String>,
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Admin) {
        Ok(x) => x,
        Err(r) => return r,
    };
    show(&st, Nav::new("tokens", &s, &u), None).await
}

async fn show(st: &AppState, nav: Nav, secret: Option<String>) -> Response {
    let (Ok(list), Ok(endpoints)) = (st.db.list_tokens().await, st.db.list_endpoints().await)
    else {
        return error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    let now = now_ms();
    let names = |ids: &[i64]| {
        ids.iter()
            .map(|id| {
                endpoints
                    .iter()
                    .find(|e| e.id == *id)
                    .map_or_else(|| format!("#{id}"), |e| e.name.clone())
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let tokens = list
        .iter()
        .map(|t| {
            let mut limits = Vec::new();
            if let Some(ids) = &t.endpoint_ids {
                limits.push(format!("endpoints: {}", names(ids)));
            }
            if let Some(r) = &t.path_roots {
                limits.push(format!("paths: {}", r.join(", ")));
            }
            TokenRow {
                id: t.id,
                label: t.label.clone(),
                prefix: t.prefix.clone(),
                scopes: t.scopes.join(" "),
                limits: limits.join("; "),
                created: format!(
                    "{} by {}",
                    fmt_ts(t.created_at),
                    t.created_by.as_deref().unwrap_or("?")
                ),
                expires: t.expires_at.map_or_else(|| "never".into(), fmt_ts),
                last_used: t.last_used_at.map_or_else(|| "never".into(), fmt_ts),
                state: if t.revoked_at.is_some() {
                    "revoked"
                } else if t.active(now) {
                    "active"
                } else {
                    "expired"
                },
            }
        })
        .collect();
    let status = if nav.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    render(
        status,
        &TokensPage {
            nav,
            tokens,
            endpoints,
            scopes: SCOPES,
            roots: st
                .cfg
                .scan_roots
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            secret,
        },
    )
}

async fn result(
    st: &AppState,
    s: &Session,
    me: &User,
    error: Option<String>,
    success: Option<String>,
    secret: Option<String>,
) -> Response {
    let mut nav = Nav::new("tokens", s, me);
    nav.error = error;
    nav.success = success;
    show(st, nav, secret).await
}

async fn create(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    // A list of pairs keeps repeated keys (`scope=a&scope=b`).
    Form(f): Form<Vec<(String, String)>>,
) -> Response {
    let get1 = |k: &str| f.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let (s, me) = match admin_post(auth, get1("_csrf").as_deref()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let label = get1("label").unwrap_or_default();
    let scopes: Vec<String> = f
        .iter()
        .filter(|(k, _)| k == "scope")
        .map(|(_, v)| v.clone())
        .collect();
    let mut endpoint_ids = Vec::new();
    for (_, v) in f.iter().filter(|(k, _)| k == "endpoint") {
        match v.parse::<i64>() {
            Ok(id) => endpoint_ids.push(id),
            Err(_) => {
                return result(&st, &s, &me, Some("Unknown endpoint.".into()), None, None).await;
            }
        }
    }
    let roots: Vec<String> = get1("roots")
        .unwrap_or_default()
        .split([',', '\n'])
        .map(|r| r.trim().to_owned())
        .filter(|r| !r.is_empty())
        .collect();
    let expires_at = match get1("days").as_deref().map(str::trim) {
        None | Some("") | Some("0") => None,
        Some(d) => match d.parse::<i64>() {
            Ok(n) if (1..=3650).contains(&n) => Some(now_ms() + n * 86_400_000),
            _ => {
                return result(
                    &st,
                    &s,
                    &me,
                    Some("Expiry is 1 to 3650 days, or empty for never.".into()),
                    None,
                    None,
                )
                .await;
            }
        },
    };
    let eps = (!endpoint_ids.is_empty()).then_some(endpoint_ids.as_slice());
    let rts = (!roots.is_empty()).then_some(roots.as_slice());
    if let Err(m) = crate::api::validate_token(&st, &label, &scopes, eps, rts).await {
        return result(&st, &s, &me, Some(m), None, None).await;
    }
    match st
        .db
        .create_token(NewToken {
            label: label.trim(),
            scopes: &scopes,
            endpoint_ids: eps,
            path_roots: rts,
            created_by: &me.username,
            expires_at,
        })
        .await
    {
        Ok((secret, t)) => {
            audit(
                &st,
                &me,
                &info,
                "TOKEN_CREATE",
                format!("{} ({})", t.label, t.prefix),
            )
            .await;
            result(
                &st,
                &s,
                &me,
                None,
                Some(format!(
                    "Created {}. Copy the secret now; it is not shown again.",
                    t.label
                )),
                Some(secret),
            )
            .await
        }
        Err(e) => {
            tracing::error!(error = %e, "token create failed");
            error_page(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.")
        }
    }
}

async fn revoke(
    State(st): State<Arc<AppState>>,
    auth: Auth,
    info: RequestInfo,
    Path(id): Path<String>,
    // A list of pairs keeps repeated keys (`scope=a&scope=b`).
    Form(f): Form<Vec<(String, String)>>,
) -> Response {
    let csrf = f
        .iter()
        .find(|(k, _)| k == "_csrf")
        .map(|(_, v)| v.as_str());
    let (s, me) = match admin_post(auth, csrf) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let revoked = match id.parse::<i64>() {
        Ok(n) => st.db.revoke_token(n).await.unwrap_or(false),
        Err(_) => false,
    };
    if !revoked {
        return result(
            &st,
            &s,
            &me,
            Some("No such active token.".into()),
            None,
            None,
        )
        .await;
    }
    audit(&st, &me, &info, "TOKEN_REVOKE", id.clone()).await;
    result(&st, &s, &me, None, Some("Token revoked.".into()), None).await
}
