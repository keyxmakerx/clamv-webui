//! Read-only view of the mounted clamd.conf and freshclam.conf, with checks against this app's limits.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;

use super::admin::fmt_ts;
use super::session::Auth;
use super::{Nav, render};
use crate::app::AppState;
use crate::auth::Role;
use crate::clamdconf::{ConfFile, size_bytes};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/admin/clamd-config", get(page))
}

pub struct FileView {
    title: &'static str,
    env: &'static str,
    path: String,
    error: Option<String>,
    modified: String,
    directives: Vec<(String, String)>,
    text: String,
}

#[derive(Template)]
#[template(path = "admin_clamd_config.html")]
struct Page {
    nav: Nav,
    files: Vec<FileView>,
    /// `(ok, message)`
    checks: Vec<(bool, String)>,
    excludes: Vec<String>,
}

fn view(
    title: &'static str,
    env: &'static str,
    path: Option<&std::path::Path>,
    r: &Result<Option<Arc<ConfFile>>, String>,
) -> FileView {
    let mut v = FileView {
        title,
        env,
        path: path.map(|p| p.display().to_string()).unwrap_or_default(),
        error: None,
        modified: String::new(),
        directives: Vec::new(),
        text: String::new(),
    };
    match r {
        Ok(Some(c)) => {
            v.modified = c
                .modified
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| fmt_ts(i64::try_from(d.as_millis()).unwrap_or(0)))
                .unwrap_or_default();
            v.directives = c.directives.clone();
            v.text = c.text.clone();
        }
        Ok(None) => {}
        Err(e) => v.error = Some(e.clone()),
    }
    v
}

/// Compare clamd's limits with what this app sends it.
pub fn checks(c: &ConfFile, max_stream_mb: u64) -> Vec<(bool, String)> {
    let mut out = Vec::new();
    if c.get("Example").is_some() {
        out.push((
            false,
            "The Example line is still present; clamd refuses to start with it.".into(),
        ));
    }
    let ours = max_stream_mb.saturating_mul(1024 * 1024);
    match c.get("StreamMaxLength").and_then(size_bytes) {
        Some(v) if v < ours => out.push((
            false,
            format!(
                "StreamMaxLength is {} MiB but CLAMD_MAX_STREAM_MB is {max_stream_mb}: larger uploads will fail. Raise StreamMaxLength to {max_stream_mb}M.",
                v / 1024 / 1024
            ),
        )),
        Some(_) => out.push((true, "StreamMaxLength covers the upload limit.".into())),
        None => out.push((
            false,
            "StreamMaxLength is not set; clamd's default (25 MiB in most builds) caps uploads.".into(),
        )),
    }
    for key in ["MaxFileSize", "MaxScanSize"] {
        if let Some(v) = c.get(key).and_then(size_bytes)
            && v != 0
            && v < ours
        {
            out.push((
                false,
                format!(
                    "{key} is {} MiB: larger files are only partly scanned (reported as not fully scanned).",
                    v / 1024 / 1024
                ),
            ));
        }
    }
    match c.get("AlertExceedsMax") {
        Some(v) if v.eq_ignore_ascii_case("yes") || v.eq_ignore_ascii_case("true") => {
            out.push((true, "AlertExceedsMax is on: files over the limits are reported.".into()));
        }
        _ => out.push((
            false,
            "AlertExceedsMax is off: files over MaxFileSize or MaxScanSize pass silently as clean. Turn it on.".into(),
        )),
    }
    for b in &c.bad_excludes {
        out.push((
            false,
            format!("ExcludePath {b} is not a valid regular expression and is ignored."),
        ));
    }
    out
}

async fn page(State(st): State<Arc<AppState>>, auth: Auth) -> Response {
    let (s, u) = match auth.require(Role::Admin) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let cp = st.cfg.clamd_conf_file.as_deref();
    let fp = st.cfg.freshclam_conf_file.as_deref();
    let clamd = st.clamd_conf.load(cp);
    let fresh = st.freshclam_conf.load(fp);
    let (checks, excludes) = match &clamd {
        Ok(Some(c)) => (
            checks(c, st.cfg.clamd_max_stream_mb),
            c.excludes.iter().map(|r| r.as_str().to_owned()).collect(),
        ),
        _ => (Vec::new(), Vec::new()),
    };
    render(
        StatusCode::OK,
        &Page {
            nav: Nav::new("clamdconf", &s, &u),
            files: vec![
                view("clamd.conf", "CLAMD_CONF_FILE", cp, &clamd),
                view("freshclam.conf", "FRESHCLAM_CONF_FILE", fp, &fresh),
            ],
            checks,
            excludes,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_limits_below_the_upload_cap() {
        let c = crate::clamdconf::parse(
            std::path::Path::new("x"),
            "StreamMaxLength 100M\nMaxFileSize 25M\nExcludePath ([\n".into(),
            None,
        );
        let r = checks(&c, 1024);
        let bad: Vec<_> = r
            .iter()
            .filter(|(ok, _)| !ok)
            .map(|(_, m)| m.as_str())
            .collect();
        assert!(
            bad.iter()
                .any(|m| m.contains("Raise StreamMaxLength to 1024M"))
        );
        assert!(bad.iter().any(|m| m.starts_with("MaxFileSize")));
        assert!(bad.iter().any(|m| m.starts_with("AlertExceedsMax is off")));
        assert!(
            bad.iter()
                .any(|m| m.contains("not a valid regular expression"))
        );
        let good = crate::clamdconf::parse(
            std::path::Path::new("x"),
            "StreamMaxLength 1024M\nMaxFileSize 2G\nMaxScanSize 4G\nAlertExceedsMax yes\n".into(),
            None,
        );
        assert!(checks(&good, 1024).iter().all(|(ok, _)| *ok));
    }
}
