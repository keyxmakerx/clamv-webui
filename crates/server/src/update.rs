//! Daily check for a newer release on GitHub. Sends nothing but the version in
//! the User-Agent; turn it off with UPDATE_CHECK=false.

use std::sync::{Arc, Mutex};
use std::time::Duration;

const RELEASES: &str = "https://api.github.com/repos/keyxmakerx/clamv-webui/releases/latest";

/// A release newer than the running build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub url: String,
}

#[derive(Default)]
pub struct Updates {
    latest: Mutex<Option<Release>>,
}

impl Updates {
    pub fn available(&self) -> Option<Release> {
        self.latest.lock().ok().and_then(|g| g.clone())
    }

    fn set(&self, r: Option<Release>) {
        if let Ok(mut g) = self.latest.lock() {
            *g = r;
        }
    }
}

/// `v1.2.3` → (1, 2, 3); a pre-release suffix is ignored.
fn parse(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.trim().trim_start_matches(['v', 'V']);
    let core = core.split(['-', '+']).next()?;
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    let a = it.next()??;
    let b = it.next().unwrap_or(Some(0))?;
    let c = it.next().unwrap_or(Some(0))?;
    Some((a, b, c))
}

/// Whether `tag` is newer than `current`.
pub fn newer(tag: &str, current: &str) -> bool {
    matches!((parse(tag), parse(current)), (Some(t), Some(c)) if t > c)
}

async fn fetch() -> Result<Option<Release>, String> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent(concat!("clamv-webui/", env!("CARGO_PKG_VERSION")))
        .tls_backend_preconfigured(
            crate::webhook::client_tls(None).map_err(|e| format!("tls: {e}"))?,
        )
        .build()
        .map_err(|e| format!("client: {e}"))?;
    let r = client
        .get(RELEASES)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;
    if r.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None); // no release published yet
    }
    if !r.status().is_success() {
        return Err(format!("HTTP {}", r.status().as_u16()));
    }
    let v: serde_json::Value = r.json().await.map_err(|e| format!("body: {e}"))?;
    let tag = v["tag_name"].as_str().unwrap_or_default();
    let url = v["html_url"].as_str().unwrap_or_default();
    if !newer(tag, env!("CARGO_PKG_VERSION"))
        || !url.starts_with("https://github.com/keyxmakerx/clamv-webui/")
    {
        return Ok(None);
    }
    Ok(Some(Release {
        version: tag.chars().take(32).collect(),
        url: url.to_owned(),
    }))
}

pub fn spawn(st: Arc<crate::app::AppState>) {
    if !st.cfg.update_check {
        return;
    }
    tokio::spawn(async move {
        // Let start-up settle first.
        tokio::time::sleep(Duration::from_secs(60)).await;
        let mut told: Option<String> = None;
        loop {
            match fetch().await {
                Ok(r) => {
                    if let Some(rel) = &r
                        && told.as_deref() != Some(rel.version.as_str())
                    {
                        tracing::info!(event = "update.available", version = %rel.version, current = env!("CARGO_PKG_VERSION"), "a newer release is available");
                        told = Some(rel.version.clone());
                    }
                    st.updates.set(r);
                }
                Err(e) => {
                    tracing::debug!(event = "update.check_failed", error = %e, "update check failed")
                }
            }
            tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_versions() {
        assert!(newer("v1.2.0", "1.1.9"));
        assert!(newer("2.0", "1.9.9"));
        assert!(!newer("v1.2.0", "1.2.0"));
        assert!(!newer("v1.2.0-rc1", "1.2.0"));
        assert!(!newer("nightly", "1.0.0"));
        assert!(!newer("v0.9.0", "1.0.0"));
    }
}
