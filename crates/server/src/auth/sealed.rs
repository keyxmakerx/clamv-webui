//! Encrypts small secrets kept in the database (TOTP seeds) with AES-256-GCM.
//! The key lives in a file next to the database, or in `SECRET_KEY_FILE`, so a
//! stolen database alone does not reveal the seeds.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};

const PREFIX: &str = "v1:";

pub struct Sealer {
    path: PathBuf,
    key: OnceLock<Result<[u8; 32], String>>,
}

impl Sealer {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            key: OnceLock::new(),
        }
    }

    fn key(&self) -> Result<LessSafeKey, String> {
        let k = self
            .key
            .get_or_init(|| load_or_create(&self.path))
            .clone()?;
        let unbound = UnboundKey::new(&AES_256_GCM, &k).map_err(|_| "bad key".to_owned())?;
        Ok(LessSafeKey::new(unbound))
    }

    /// Encrypt `plain`; `context` binds the result to its use (e.g. the user id).
    pub fn seal(&self, plain: &[u8], context: &str) -> Result<String, String> {
        let key = self.key()?;
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| "no randomness".to_owned())?;
        let mut buf = plain.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(context.as_bytes()),
            &mut buf,
        )
        .map_err(|_| "seal failed".to_owned())?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        Ok(format!("{PREFIX}{}", B64.encode(out)))
    }

    pub fn open(&self, sealed: &str, context: &str) -> Result<Vec<u8>, String> {
        let key = self.key()?;
        let raw = sealed
            .strip_prefix(PREFIX)
            .and_then(|s| B64.decode(s).ok())
            .filter(|r| r.len() > NONCE_LEN)
            .ok_or_else(|| "not a sealed value".to_owned())?;
        let (n, ct) = raw.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(n).map_err(|_| "bad nonce".to_owned())?;
        let mut buf = ct.to_vec();
        let plain = key
            .open_in_place(nonce, Aad::from(context.as_bytes()), &mut buf)
            .map_err(|_| "cannot decrypt (wrong key or altered)".to_owned())?;
        Ok(plain.to_vec())
    }
}

fn load_or_create(path: &Path) -> Result<[u8; 32], String> {
    match std::fs::read(path) {
        Ok(b) => {
            let s = String::from_utf8_lossy(&b);
            let k = B64
                .decode(s.trim().trim_end_matches('='))
                .map_err(|_| format!("{} is not a valid key file", path.display()))?;
            <[u8; 32]>::try_from(k.as_slice())
                .map_err(|_| format!("{} must hold a 32-byte key", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut k = [0u8; 32];
            SystemRandom::new()
                .fill(&mut k)
                .map_err(|_| "no randomness".to_owned())?;
            write_new(path, &B64.encode(k))
                .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
            tracing::info!(event = "secret_key.created", path = %path.display(), "created the key that encrypts stored secrets; back it up with the database");
            Ok(k)
        }
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

fn write_new(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(path)?;
    f.write_all(content.as_bytes())?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_context_binding() {
        let p = std::env::temp_dir().join(format!("clamv-key-{}", crate::db::new_id()));
        let s = Sealer::new(p.clone());
        let c = s.seal(b"seed", "user-1").expect("seal");
        assert!(c.starts_with("v1:"));
        assert_eq!(s.open(&c, "user-1").expect("open"), b"seed");
        assert!(s.open(&c, "user-2").is_err(), "bound to its user");
        // A new process reads the same key back.
        let again = Sealer::new(p.clone());
        assert_eq!(again.open(&c, "user-1").expect("open"), b"seed");
        let _ = std::fs::remove_file(&p);
    }
}
