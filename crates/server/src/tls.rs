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

/// Create (or reuse) a self-signed certificate for `names`. Regenerated when the names change.
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
    if cert.exists()
        && key.exists()
        && std::fs::read_to_string(&stamp).ok().as_deref() == Some(listed.as_str())
    {
        return Ok((cert, key));
    }
    std::fs::create_dir_all(dir)?;
    let mut params = rcgen::CertificateParams::new(wanted.clone())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "clamv-webui");
    // Ten years: a private-network certificate that clamctl pins with --ca-file.
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after = rcgen::date_time_ymd(2035, 1, 1);
    let kp = rcgen::KeyPair::generate()?;
    let c = params.self_signed(&kp)?;
    write_private(&key, kp.serialize_pem().as_bytes())?;
    std::fs::write(&cert, c.pem())?;
    std::fs::write(&stamp, &listed)?;
    tracing::info!(event = "tls.generated", names = %listed, cert = %cert.display(), "self-signed certificate created");
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
        let _ = std::fs::remove_dir_all(&dir);
    }
}
