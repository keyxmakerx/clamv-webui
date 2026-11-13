//! Cookie session lookup and role checks for UI routes.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};

use crate::app::AppState;
use crate::auth::Role;
use crate::db::sessions::Session;
use crate::db::users::User;

pub const COOKIE: &str = "clamv_session";

/// The signed-in user for this request, if any.
pub struct Auth(pub Option<(Session, User)>);

impl FromRequestParts<Arc<AppState>> for Auth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Response> {
        let Some(raw) = cookie(&parts.headers, COOKIE) else {
            return Ok(Auth(None));
        };
        match state
            .db
            .session_user(&raw, state.cfg.session_idle_ms())
            .await
        {
            Ok(found) => Ok(Auth(found)),
            Err(e) => {
                tracing::error!(error = %e, "session lookup failed");
                Err(StatusCode::SERVICE_UNAVAILABLE.into_response())
            }
        }
    }
}

impl Auth {
    /// The user if they hold at least `role`. Anonymous users go to the login
    /// page; signed-in users without the role get 403. A user who must change
    /// their password can only reach the password page.
    pub fn require(self, role: Role) -> Result<(Session, User), Response> {
        match self.0 {
            None => Err(Redirect::to("/login").into_response()),
            Some((_, u)) if u.must_change_password => {
                Err(Redirect::to("/account/password").into_response())
            }
            Some((s, u)) if u.role.allows(role) => Ok((s, u)),
            Some(_) => Err(super::error_page(
                StatusCode::FORBIDDEN,
                "You do not have access to this page.",
            )),
        }
    }
}

/// Socket peer address. Forwarded headers are ignored (audit S1).
pub fn client_ip(parts_ext: &axum::http::Extensions) -> IpAddr {
    parts_ext
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0.ip())
}

pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned())
        .filter(|v| !v.is_empty() && v.len() <= 128)
}

pub fn set_cookie(value: &str, max_age_secs: i64, secure: bool) -> String {
    format!(
        "{COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_secs}{}",
        if secure { "; Secure" } else { "" }
    )
}

pub fn clear_cookie(secure: bool) -> String {
    set_cookie("", 0, secure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cookie_header() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            "a=1; clamv_session=abc; b=2".parse().expect("hv"),
        );
        assert_eq!(cookie(&h, COOKIE).as_deref(), Some("abc"));
        assert_eq!(cookie(&h, "zzz"), None);
        assert!(set_cookie("x", 60, false).contains("SameSite=Strict"));
        assert!(set_cookie("x", 60, true).ends_with("; Secure"));
    }
}
