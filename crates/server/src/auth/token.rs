//! Random secrets and their stored hashes.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// 256-bit random secret, base64url (43 chars).
pub fn random_secret() -> String {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

/// Stored form of a high-entropy secret (session id, API token). Lowercase hex SHA-256.
pub fn hash_secret(secret: &str) -> String {
    let d = Sha256::digest(secret.as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_random_and_hash_stably() {
        let a = random_secret();
        assert_eq!(a.len(), 43);
        assert_ne!(a, random_secret());
        assert_eq!(hash_secret("x"), hash_secret("x"));
        assert_eq!(hash_secret("x").len(), 64);
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
    }
}
