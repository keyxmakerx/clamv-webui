//! CSRF defence for state-changing requests.
//!
//! Two layers: every unsafe request must come from our own origin
//! (Sec-Fetch-Site / Origin vs Host), and session-authenticated forms must
//! carry the session's token in `_csrf` (checked by the handler).

use axum::extract::Request;
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth::token::constant_time_eq;

pub async fn same_origin(req: Request, next: Next) -> Response {
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return next.run(req).await;
    }
    let h = req.headers();
    // Bearer-token API calls carry no ambient credentials.
    let bearer = h
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("Bearer "));
    if !bearer {
        // Browsers set Sec-Fetch-Site and pages cannot forge it; trust it when present.
        match h.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
            Some("same-origin" | "none") => {}
            Some(_) => return forbidden(),
            None => {
                if let Some(origin) = h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
                    let host = h
                        .get(header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default();
                    let origin_host = origin.split_once("://").map_or("", |(_, r)| r);
                    if origin == "null" || !origin_host.eq_ignore_ascii_case(host) {
                        return forbidden();
                    }
                }
            }
        }
    }
    next.run(req).await
}

pub fn token_ok(expected: &str, supplied: Option<&str>) -> bool {
    supplied.is_some_and(|s| constant_time_eq(expected, s))
}

fn forbidden() -> Response {
    tracing::warn!(
        event = "auth.csrf_rejected",
        "cross-origin state-changing request rejected"
    );
    (StatusCode::FORBIDDEN, "cross-origin request rejected").into_response()
}
