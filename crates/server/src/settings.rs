//! Settings an admin may change from the UI. Precedence: env or flag, then
//! the UI store, then the default. Stored values apply on the next start.
//! Secrets and security boundaries (scan roots, clamd allowlist, TLS,
//! database) stay deployment-only.

use clap::Parser;

use crate::config::{Cli, Config, WebhookEvents};
use crate::db::settings::Setting;

#[derive(Debug, Clone, Copy)]
pub enum Kind {
    Bool,
    Number {
        min: i64,
        max: i64,
    },
    Select(&'static [&'static str]),
    /// Comma-separated CIDRs.
    Cidrs,
}

pub struct Field {
    pub env: &'static str,
    pub section: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    pub kind: Kind,
    pub current: fn(&Config) -> String,
}

pub const FIELDS: &[Field] = &[
    Field {
        env: "SCAN_CONCURRENCY",
        section: "Scanning",
        label: "Path scans at once",
        help: "Path and watched-folder jobs that run in parallel.",
        kind: Kind::Number { min: 1, max: 64 },
        current: |c| c.scan_concurrency.to_string(),
    },
    Field {
        env: "UPLOAD_MAX_FILES",
        section: "Scanning",
        label: "Files per upload",
        help: "Files accepted in one upload request.",
        kind: Kind::Number { min: 1, max: 100 },
        current: |c| c.upload_max_files.to_string(),
    },
    Field {
        env: "CLAMD_MAX_STREAM_MB",
        section: "Scanning",
        label: "Upload size limit (MB)",
        help: "Keep at or below clamd StreamMaxLength.",
        kind: Kind::Number { min: 1, max: 4096 },
        current: |c| c.clamd_max_stream_mb.to_string(),
    },
    Field {
        env: "JOB_RETENTION_DAYS",
        section: "Scanning",
        label: "Keep finished jobs (days)",
        help: "0 keeps them forever.",
        kind: Kind::Number { min: 0, max: 36500 },
        current: |c| c.job_retention_days.to_string(),
    },
    Field {
        env: "WATCH_POLL_SECS",
        section: "Scanning",
        label: "Watched folder interval (s)",
        help: "Seconds between looks at watched folders.",
        kind: Kind::Number {
            min: 10,
            max: 86400,
        },
        current: |c| c.watch_poll_secs.to_string(),
    },
    Field {
        env: "WEBHOOK_EVENTS",
        section: "Notifications",
        label: "Webhook sends",
        help: "alerts: detections, failures, unscannable files, failed EICAR checks. all: every scan.",
        kind: Kind::Select(&["alerts", "all"]),
        current: |c| match c.webhook_events {
            WebhookEvents::Alerts => "alerts".into(),
            WebhookEvents::All => "all".into(),
        },
    },
    Field {
        env: "WEBHOOK_ALLOWED_CIDRS",
        section: "Notifications",
        label: "Webhook private networks",
        help: "Comma-separated CIDRs the webhook may reach, e.g. 100.82.0.0/16.",
        kind: Kind::Cidrs,
        current: |c| c.webhook_allowed_cidrs.join(","),
    },
    Field {
        env: "WEBHOOK_ALLOW_PRIVATE",
        section: "Notifications",
        label: "Webhook may reach any private address",
        help: "Prefer a CIDR list instead. Cloud metadata stays blocked.",
        kind: Kind::Bool,
        current: |c| c.webhook_allow_private.to_string(),
    },
    Field {
        env: "SESSION_IDLE_MINUTES",
        section: "Sessions",
        label: "Idle sign-out (minutes)",
        help: "Sessions end after this long without a request.",
        kind: Kind::Number { min: 5, max: 1440 },
        current: |c| c.session_idle_minutes.to_string(),
    },
    Field {
        env: "SESSION_MAX_HOURS",
        section: "Sessions",
        label: "Longest session (hours)",
        help: "Sessions end after this long regardless of use.",
        kind: Kind::Number { min: 1, max: 720 },
        current: |c| c.session_max_hours.to_string(),
    },
    Field {
        env: "COOKIE_SECURE",
        section: "Sessions",
        label: "Secure cookies",
        help: "Only send cookies over HTTPS. Always on when TLS is on.",
        kind: Kind::Bool,
        current: |c| c.cookie_secure.to_string(),
    },
    Field {
        env: "REQUEST_TIMEOUT_SECS",
        section: "System",
        label: "Request timeout (s)",
        help: "Per-request limit for pages and API calls (not uploads).",
        kind: Kind::Number { min: 5, max: 3600 },
        current: |c| c.request_timeout_secs.to_string(),
    },
];

pub fn field(env: &str) -> Option<&'static Field> {
    FIELDS.iter().find(|f| f.env == env)
}

fn flag(env: &str) -> String {
    format!("--{}", env.to_ascii_lowercase().replace('_', "-"))
}

/// The env value or flag that pins this field, if any.
pub fn locked(f: &Field) -> Option<String> {
    let fl = flag(f.env);
    if std::env::args().any(|a| a == fl || a.starts_with(&format!("{fl}="))) {
        return Some("command line".into());
    }
    std::env::var(f.env).ok().filter(|v| !v.trim().is_empty())
}

/// Trim and check a submitted value; None means "use the default".
pub fn normalize(f: &Field, raw: &str) -> Result<Option<String>, String> {
    let v = raw.trim();
    if v.is_empty() {
        return Ok(None);
    }
    match f.kind {
        Kind::Bool => match v {
            "true" | "false" => Ok(Some(v.into())),
            _ => Err(format!("{}: pick yes or no.", f.label)),
        },
        Kind::Number { min, max } => match v.parse::<i64>() {
            Ok(n) if (min..=max).contains(&n) => Ok(Some(n.to_string())),
            _ => Err(format!(
                "{}: enter a whole number from {min} to {max}.",
                f.label
            )),
        },
        Kind::Select(opts) => opts
            .iter()
            .find(|o| **o == v)
            .map(|o| Some((*o).to_owned()))
            .ok_or_else(|| format!("{}: pick one of {}.", f.label, opts.join(", "))),
        Kind::Cidrs => {
            let parts: Vec<&str> = v
                .split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .collect();
            if parts.len() > 64 {
                return Err(format!("{}: at most 64 entries.", f.label));
            }
            for p in &parts {
                crate::webhook::parse_cidr(p).map_err(|e| format!("{}: {e}", f.label))?;
            }
            Ok((!parts.is_empty()).then(|| parts.join(",")))
        }
    }
}

/// Flags for stored values that env does not pin.
fn args(stored: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (name, value) in stored {
        let Some(f) = field(name) else { continue };
        if locked(f).is_some() {
            continue;
        }
        match f.kind {
            // A bool flag only turns on; off is the default anyway.
            Kind::Bool => {
                if value == "true" {
                    out.push(flag(f.env));
                }
            }
            _ => {
                out.push(flag(f.env));
                out.push(value.clone());
            }
        }
    }
    out
}

/// Check that a set of stored values still yields a valid configuration.
pub fn check(stored: &[(String, String)]) -> Result<Config, String> {
    let mut argv: Vec<String> = std::env::args().take(1).collect();
    if argv.is_empty() {
        argv.push("clamv-webui".into());
    }
    argv.extend(args(stored));
    let cli = Cli::try_parse_from(argv).map_err(|e| e.kind().to_string())?;
    Ok(cli.config)
}

/// Copy one field from a parsed config.
fn copy(env: &str, dst: &mut Config, src: &Config) {
    match env {
        "SCAN_CONCURRENCY" => dst.scan_concurrency = src.scan_concurrency,
        "UPLOAD_MAX_FILES" => dst.upload_max_files = src.upload_max_files,
        "CLAMD_MAX_STREAM_MB" => dst.clamd_max_stream_mb = src.clamd_max_stream_mb,
        "JOB_RETENTION_DAYS" => dst.job_retention_days = src.job_retention_days,
        "WATCH_POLL_SECS" => dst.watch_poll_secs = src.watch_poll_secs,
        "WEBHOOK_EVENTS" => dst.webhook_events = src.webhook_events,
        "WEBHOOK_ALLOWED_CIDRS" => dst
            .webhook_allowed_cidrs
            .clone_from(&src.webhook_allowed_cidrs),
        "WEBHOOK_ALLOW_PRIVATE" => dst.webhook_allow_private = src.webhook_allow_private,
        "SESSION_IDLE_MINUTES" => dst.session_idle_minutes = src.session_idle_minutes,
        "SESSION_MAX_HOURS" => dst.session_max_hours = src.session_max_hours,
        "COOKIE_SECURE" => dst.cookie_secure = src.cookie_secure,
        "REQUEST_TIMEOUT_SECS" => dst.request_timeout_secs = src.request_timeout_secs,
        _ => {}
    }
}

/// Apply stored settings on top of the running configuration at start.
pub fn overlay(mut cfg: Config, stored: &[Setting]) -> Config {
    let pairs: Vec<(String, String)> = stored
        .iter()
        .filter(|s| field(&s.name).is_some_and(|f| locked(f).is_none()))
        .map(|s| (s.name.clone(), s.value.clone()))
        .collect();
    if pairs.is_empty() {
        return cfg;
    }
    match check(&pairs) {
        Ok(src) => {
            for (name, _) in &pairs {
                copy(name, &mut cfg, &src);
            }
            tracing::info!(
                event = "settings.applied",
                count = pairs.len(),
                "saved settings applied"
            );
        }
        // Never refuse to start over a stored value; fall back to env and defaults.
        Err(e) => {
            tracing::error!(event = "settings.invalid", error = %e, "saved settings ignored");
        }
    }
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_checked() {
        let f = field("SCAN_CONCURRENCY").expect("field");
        assert_eq!(normalize(f, " 4 "), Ok(Some("4".into())));
        assert!(normalize(f, "0").is_err());
        assert!(normalize(f, "x").is_err());
        assert_eq!(normalize(f, ""), Ok(None));
        let f = field("WEBHOOK_ALLOWED_CIDRS").expect("field");
        assert_eq!(
            normalize(f, "100.82.0.0/16, ,10.0.0.1"),
            Ok(Some("100.82.0.0/16,10.0.0.1".into()))
        );
        assert!(normalize(f, "100.82.0.0/40").is_err());
        let f = field("WEBHOOK_EVENTS").expect("field");
        assert!(normalize(f, "some").is_err());
    }

    #[test]
    fn every_field_is_copied() {
        let mut stored = Vec::new();
        for f in FIELDS {
            let v = match f.kind {
                Kind::Bool => "true".to_owned(),
                Kind::Number { max, .. } => max.to_string(),
                Kind::Select(o) => o[o.len() - 1].to_owned(),
                Kind::Cidrs => "10.9.0.0/16".to_owned(),
            };
            stored.push(Setting {
                name: f.env.into(),
                value: v,
                updated_at: 0,
                updated_by: None,
            });
        }
        let base = check(&[]).expect("defaults");
        let after = overlay(base.clone(), &stored);
        for f in FIELDS {
            assert_ne!(
                (f.current)(&base),
                (f.current)(&after),
                "{} not applied",
                f.env
            );
        }
    }

    #[test]
    fn stored_values_become_config() {
        let c = check(&[
            ("SCAN_CONCURRENCY".into(), "7".into()),
            ("WEBHOOK_EVENTS".into(), "all".into()),
            ("WEBHOOK_ALLOW_PRIVATE".into(), "true".into()),
            (
                "WEBHOOK_ALLOWED_CIDRS".into(),
                "10.0.0.0/8,100.82.0.0/16".into(),
            ),
        ])
        .expect("valid");
        assert_eq!(c.scan_concurrency, 7);
        assert_eq!(c.webhook_events, WebhookEvents::All);
        assert!(c.webhook_allow_private);
        assert_eq!(c.webhook_allowed_cidrs.len(), 2);
        for f in FIELDS {
            assert!((f.current)(&c).len() < 1000, "{}", f.env);
        }
    }
}
