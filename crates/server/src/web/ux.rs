//! Small UI helpers: flash messages for post/redirect/get, and path wrapping.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::response::{IntoResponse, Redirect, Response};

use crate::db::sessions::Session;

/// A message shown once on the next page this session loads.
struct Flash {
    at: Instant,
    error: Option<String>,
    success: Option<String>,
}

/// Keyed by the session's id hash; never holds secrets, only status text.
static FLASH: LazyLock<Mutex<HashMap<String, Flash>>> = LazyLock::new(Default::default);

const TTL: Duration = Duration::from_secs(120);
const MAX: usize = 4096;

fn store(key: &str, error: Option<String>, success: Option<String>) {
    if error.is_none() && success.is_none() {
        return;
    }
    let Ok(mut m) = FLASH.lock() else { return };
    if m.len() >= MAX {
        m.retain(|_, f| f.at.elapsed() < TTL);
        if m.len() >= MAX {
            return;
        }
    }
    m.insert(
        key.to_owned(),
        Flash {
            at: Instant::now(),
            error,
            success,
        },
    );
}

/// The pending message for this session, if any, removed as it is read.
pub fn take(s: &Session) -> (Option<String>, Option<String>) {
    let Ok(mut m) = FLASH.lock() else {
        return (None, None);
    };
    match m.remove(&s.id_hash) {
        Some(f) if f.at.elapsed() < TTL => (f.error, f.success),
        _ => (None, None),
    }
}

/// Keep the message and send the browser to `to` (303), so reloading the
/// page that follows never re-sends the form.
pub fn back(s: &Session, to: &str, error: Option<String>, success: Option<String>) -> Response {
    store(&s.id_hash, error, success);
    Redirect::to(to).into_response()
}

/// `back` for a `Result` whose two sides are the success and error texts.
pub fn back_with(s: &Session, to: &str, r: Result<String, String>) -> Response {
    match r {
        Ok(m) => back(s, to, None, Some(m)),
        Err(m) => back(s, to, Some(m), None),
    }
}

/// HTML for a path that may wrap after each `/` or `\` rather than mid-name.
/// The text is escaped here, so templates use it with `|safe`.
pub fn wbr(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + path.len() / 8);
    for c in path.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '/' | '\\' => {
                out.push(c);
                out.push_str("<wbr>");
            }
            _ => out.push(c),
        }
    }
    out
}

/// Whether this request is a background refresh from `script.js`. Such
/// requests must not count as activity for the idle sign-out.
pub fn is_refresh(h: &axum::http::HeaderMap) -> bool {
    h.get(REFRESH_HEADER).is_some_and(|v| v.as_bytes() == b"1")
}

pub const REFRESH_HEADER: &str = "x-clamv-refresh";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_wrap_at_slashes_and_stay_escaped() {
        assert_eq!(wbr("/a/b.txt"), "/<wbr>a/<wbr>b.txt");
        assert_eq!(wbr("C:\\x"), "C:\\<wbr>x");
        assert_eq!(
            wbr("/t/<script>&\"'"),
            "/<wbr>t/<wbr>&lt;script&gt;&amp;&quot;&#39;"
        );
    }

    #[test]
    fn flash_is_read_once() {
        let s = Session {
            id_hash: "test-flash".into(),
            user_id: String::new(),
            csrf_token: String::new(),
            created_at: 0,
            last_seen_at: 0,
            expires_at: 0,
            lang: "en",
        };
        let r = back(&s, "/x", None, Some("Saved.".into()));
        assert_eq!(r.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(take(&s), (None, Some("Saved.".into())));
        assert_eq!(take(&s), (None, None));
    }
}
