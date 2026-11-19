//! Optional HTTPS: operator-supplied PEM files or a self-signed certificate.

use std::path::{Path, PathBuf};

use axum_server::tls_rustls::RustlsConfig;
use sha2::{Digest, Sha256};

use crate::config::Config;

/// Paths to the certificate and key the server should use.
pub fn files(cfg: &Config) -> anyhow::Result<(PathBuf, PathBuf)> {
    if let (Some(c), Some(k)) = (&cfg.tls_cert_file, &cfg.tls_key_file) {
        return Ok((c.clone(), k.clone()));
    }
    self_signed(&cfg.data_dir.join("tls"), &cfg.tls_self_signed_names)
}

/// How long a new self-signed certificate is valid.
const VALID_YEARS: i32 = 10;
/// Warn at start when the certificate ends within this many days.
const WARN_DAYS: i64 = 60;
/// The Agents page mentions a replaced certificate for this long.
const REPLACED_NOTICE_MS: i64 = 30 * 24 * 3_600_000;

/// A self-signed certificate replaced recently, for the Agents page.
pub struct Replaced {
    pub when: String,
    pub fingerprint: String,
}

/// The current certificate's fingerprint if the self-signed one was replaced in the last 30 days.
pub fn recently_replaced(cfg: &Config) -> Option<Replaced> {
    if cfg.tls_cert_file.is_some() {
        return None;
    }
    let dir = cfg.data_dir.join("tls");
    let at: i64 = std::fs::read_to_string(dir.join("replaced"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    if crate::db::now_ms() - at > REPLACED_NOTICE_MS {
        return None;
    }
    Some(Replaced {
        when: crate::timefmt::display(at),
        fingerprint: fingerprint(&dir.join("cert.pem"))?,
    })
}

/// The stamp file: the names on line 1, the end date (Unix ms) on line 2.
/// Certificates from before line 2 existed end on 1 Jan 2035.
fn read_stamp(stamp: &Path) -> Option<(String, i64)> {
    let s = std::fs::read_to_string(stamp).ok()?;
    let mut lines = s.lines();
    let names = lines.next()?.to_owned();
    let end = lines
        .next()
        .and_then(|l| l.trim().parse().ok())
        .unwrap_or(2_051_222_400_000);
    Some((names, end))
}

/// Create (or reuse) a self-signed certificate for `names`. Regenerated when the names change or it has expired.
fn self_signed(dir: &Path, names: &[String]) -> anyhow::Result<(PathBuf, PathBuf)> {
    let names: Vec<String> = names
        .iter()
        .map(|n| n.trim().to_owned())
        .filter(|n| !n.is_empty())
        .collect();
    let mut wanted = names.clone();
    wanted.push("localhost".into());
    wanted.sort();
    wanted.dedup();
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let stamp = dir.join("names");
    let listed = wanted.join(",");
    let now = crate::db::now_ms();
    let old = if cert.exists() && key.exists() {
        read_stamp(&stamp)
    } else {
        None
    };
    if let Some((names, end)) = &old
        && *names == listed
        && *end > now
    {
        let days = (end - now) / 86_400_000;
        if days < WARN_DAYS {
            tracing::warn!(
                event = "tls.expiring",
                days,
                "self-signed certificate ends soon; it is replaced when it ends, and agents will then need the new AGENT_SERVER_FINGERPRINT"
            );
        }
        return Ok((cert, key));
    }
    let old_fp = old.as_ref().and_then(|_| fingerprint(&cert));
    std::fs::create_dir_all(dir)?;
    let mut params = rcgen::CertificateParams::new(wanted.clone())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "clamv-webui");
    // Ten years from today: a private-network certificate that clamctl and agents pin.
    let year: i32 = crate::timefmt::rfc3339(now)
        .get(..4)
        .and_then(|y| y.parse().ok())
        .unwrap_or(2026);
    params.not_before = rcgen::date_time_ymd(year - 1, 1, 1);
    params.not_after = rcgen::date_time_ymd(year + VALID_YEARS, 1, 1);
    let end_ms = crate::timefmt::parse_rfc3339(&format!("{}-01-01T00:00:00Z", year + VALID_YEARS))
        .unwrap_or(now + i64::from(VALID_YEARS) * 365 * 86_400_000);
    let kp = rcgen::KeyPair::generate()?;
    let c = params.self_signed(&kp)?;
    write_private(&key, kp.serialize_pem().as_bytes())?;
    std::fs::write(&cert, c.pem())?;
    std::fs::write(&stamp, format!("{listed}\n{end_ms}\n"))?;
    tracing::info!(event = "tls.generated", names = %listed, cert = %cert.display(), "self-signed certificate created");
    if let Some(old_fp) = old_fp {
        let _ = std::fs::write(dir.join("replaced"), now.to_string());
        tracing::warn!(
            event = "tls.cert_replaced",
            old_fingerprint = %old_fp,
            new_fingerprint = %fingerprint(&cert).unwrap_or_default(),
            "self-signed certificate replaced (TLS_SELF_SIGNED_NAMES changed or it ended): every agent needs the new AGENT_SERVER_FINGERPRINT"
        );
    }
    Ok((cert, key))
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)
    }
    #[cfg(not(unix))]
    std::fs::write(path, data)
}

/// SHA-256 of the first certificate in a PEM file, as colon-separated hex.
pub fn fingerprint(cert_pem: &Path) -> Option<String> {
    let pem = std::fs::read_to_string(cert_pem).ok()?;
    let b64: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let d = Sha256::digest(&der);
    Some(
        d.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

pub async fn config(cfg: &Config) -> anyhow::Result<(RustlsConfig, PathBuf)> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (cert, key) = files(cfg)?;
    let rc = RustlsConfig::from_pem_file(&cert, &key)
        .await
        .map_err(|e| anyhow::anyhow!("TLS certificate {}: {e}", cert.display()))?;
    Ok((rc, cert))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_is_reused_until_names_change() {
        let dir = std::env::temp_dir().join(format!("clamv-tls-{}", crate::db::new_id()));
        let (c, k) = self_signed(&dir, &["nas".into()]).expect("gen");
        let fp = fingerprint(&c).expect("fp");
        assert_eq!(fp.len(), 95);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&k).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        self_signed(&dir, &["nas".into()]).expect("again");
        assert_eq!(fingerprint(&c), Some(fp.clone()), "reused");
        self_signed(&dir, &["nas".into(), "100.82.0.5".into()]).expect("new names");
        assert_ne!(fingerprint(&c), Some(fp), "regenerated");
        assert!(
            dir.join("replaced").exists(),
            "replacement noted for the Agents page"
        );
        // A stamp from before end dates were stored keeps its certificate.
        let fp2 = fingerprint(&c);
        std::fs::write(dir.join("names"), "100.82.0.5,localhost,nas").expect("old stamp");
        self_signed(&dir, &["nas".into(), "100.82.0.5".into()]).expect("old format");
        assert_eq!(fingerprint(&c), fp2, "old-format stamp reused");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
