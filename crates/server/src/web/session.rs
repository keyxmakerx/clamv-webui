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

/// The client as resolved by `resolve_client`: forwarded headers count only
/// when the socket peer is in TRUSTED_PROXIES (audit S1).
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub IpAddr);

/// Set when a trusted proxy says the browser used HTTPS.
#[derive(Clone, Copy, Debug)]
pub struct ForwardedHttps;

pub fn client_ip(parts_ext: &axum::http::Extensions) -> IpAddr {
    if let Some(c) = parts_ext.get::<ClientIp>() {
        return c.0;
    }
    peer_ip(parts_ext)
}

fn peer_ip(parts_ext: &axum::http::Extensions) -> IpAddr {
    parts_ext
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0.ip())
}

/// Whether a trusted proxy reported HTTPS for this request (headers only; see `resolve_client`).
pub fn forwarded_https(st: &AppState, h: &HeaderMap) -> bool {
    !st.trusted_proxies.is_empty() && h.get("x-clamv-forwarded-https").is_some()
}

fn trusted(list: &[crate::webhook::Cidr], ip: IpAddr) -> bool {
    list.iter().any(|c| c.contains(ip))
}

/// The client address: walk X-Forwarded-For from the right, skipping trusted
/// proxies; the first untrusted hop is the client.
pub fn forwarded_client(list: &[crate::webhook::Cidr], peer: IpAddr, xff: Option<&str>) -> IpAddr {
    if !trusted(list, peer) {
        return peer;
    }
    let Some(xff) = xff else { return peer };
    let mut client = peer;
    for hop in xff.rsplit(',').map(str::trim) {
        let Ok(ip) = hop.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() else {
            // A malformed entry: stop at the last good address.
            break;
        };
        client = ip;
        if !trusted(list, ip) {
            break;
        }
    }
    client
}

/// Resolve the client address and scheme once per request. With HTTPS from a
/// trusted proxy, every cookie set in the response is marked Secure.
pub async fn resolve_client(
    axum::extract::State(st): axum::extract::State<Arc<AppState>>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // Never accept this marker from outside.
    req.headers_mut().remove("x-clamv-forwarded-https");
    let peer = peer_ip(req.extensions());
    let mut https = false;
    if trusted(&st.trusted_proxies, peer) {
        let xff = req
            .headers()
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>()
            .join(",");
        let ip = forwarded_client(
            &st.trusted_proxies,
            peer,
            (!xff.is_empty()).then_some(xff.as_str()),
        );
        req.extensions_mut().insert(ClientIp(ip));
        https = req
            .headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .is_some_and(|p| p.trim().eq_ignore_ascii_case("https"));
        if https {
            req.extensions_mut().insert(ForwardedHttps);
            req.headers_mut().insert(
                "x-clamv-forwarded-https",
                axum::http::HeaderValue::from_static("1"),
            );
        }
    } else {
        req.extensions_mut().insert(ClientIp(peer));
    }
    let mut res = next.run(req).await;
    if https {
        let cookies: Vec<_> = res
            .headers_mut()
            .get_all(header::SET_COOKIE)
            .iter()
            .cloned()
            .collect();
        if !cookies.is_empty() {
            res.headers_mut().remove(header::SET_COOKIE);
            for c in cookies {
                let s = c.to_str().unwrap_or_default();
                let v = if s.contains("; Secure") {
                    s.to_owned()
                } else {
                    format!("{s}; Secure")
                };
                if let Ok(hv) = v.parse() {
                    res.headers_mut().append(header::SET_COOKIE, hv);
                }
            }
        }
    }
    res
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
    fn forwarded_for_is_only_believed_from_trusted_proxies() {
        let list = vec![crate::webhook::Cidr::parse("10.0.0.0/8").expect("cidr")];
        let ip = |s: &str| s.parse::<IpAddr>().expect("ip");
        // Untrusted peer: headers ignored.
        assert_eq!(
            forwarded_client(&list, ip("203.0.113.9"), Some("1.2.3.4")),
            ip("203.0.113.9")
        );
        // Trusted proxy: the client it reports.
        assert_eq!(
            forwarded_client(&list, ip("10.0.0.2"), Some("198.51.100.7")),
            ip("198.51.100.7")
        );
        // A forged left-most entry does not win over the real hop.
        assert_eq!(
            forwarded_client(
                &list,
                ip("10.0.0.2"),
                Some("6.6.6.6, 198.51.100.7, 10.0.0.3")
            ),
            ip("198.51.100.7")
        );
        assert_eq!(
            forwarded_client(&list, ip("10.0.0.2"), Some("junk")),
            ip("10.0.0.2")
        );
        assert_eq!(
            forwarded_client(&list, ip("10.0.0.2"), None),
            ip("10.0.0.2")
        );
    }

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
