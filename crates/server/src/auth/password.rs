//! Password hashing: Argon2id for new hashes; bcrypt hashes (from the Java app)
//! still verify and are flagged for rehash on the next successful login.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

pub const MIN_LEN: usize = 12;
pub const MAX_LEN: usize = 128;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PasswordError {
    #[error("password must be {MIN_LEN} to {MAX_LEN} characters")]
    Length,
    #[error("password hashing failed")]
    Hash,
}

fn argon2() -> Argon2<'static> {
    // OWASP 2024 baseline: m=19 MiB, t=2, p=1.
    let params = Params::new(19 * 1024, 2, 1, None).unwrap_or_default();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn validate(password: &str) -> Result<(), PasswordError> {
    let n = password.chars().count();
    if (MIN_LEN..=MAX_LEN).contains(&n) {
        Ok(())
    } else {
        Err(PasswordError::Length)
    }
}

pub fn hash(password: &str) -> Result<String, PasswordError> {
    validate(password)?;
    let salt = SaltString::generate(&mut OsRng);
    argon2()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| PasswordError::Hash)
}

/// Result of a verification attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum Verified {
    No,
    Yes,
    /// Correct, but stored with an old scheme; store a fresh hash.
    YesRehash,
}

pub fn verify(password: &str, stored: &str) -> Verified {
    if password.len() > MAX_LEN * 4 {
        return Verified::No;
    }
    if stored.starts_with("$2a$") || stored.starts_with("$2b$") || stored.starts_with("$2y$") {
        return match bcrypt::verify(password, stored) {
            Ok(true) => Verified::YesRehash,
            _ => Verified::No,
        };
    }
    let Ok(parsed) = PasswordHash::new(stored) else {
        return Verified::No;
    };
    if argon2()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
    {
        Verified::Yes
    } else {
        Verified::No
    }
}

/// Burn the same time as a real check, so unknown usernames are not revealed by timing.
pub fn verify_dummy(password: &str) {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let h = DUMMY.get_or_init(|| hash(&super::token::random_secret()).unwrap_or_default());
    let _ = verify(password, h);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::token::random_secret;

    #[test]
    fn argon2_round_trip() {
        let pw = random_secret();
        let h = hash(&pw).expect("hash");
        assert!(h.starts_with("$argon2id$"));
        assert_eq!(verify(&pw, &h), Verified::Yes);
        assert_eq!(verify(&random_secret(), &h), Verified::No);
    }

    #[test]
    fn length_rules() {
        assert_eq!(hash(&"x".repeat(MIN_LEN - 1)), Err(PasswordError::Length));
        assert!(validate(&"x".repeat(MAX_LEN + 1)).is_err());
        assert!(validate(&"x".repeat(MIN_LEN)).is_ok());
    }

    #[test]
    fn bcrypt_from_java_verifies_and_asks_for_rehash() {
        let pw = random_secret();
        let legacy = bcrypt::hash(&pw, 4).expect("bcrypt");
        assert_eq!(verify(&pw, &legacy), Verified::YesRehash);
        assert_eq!(verify(&random_secret(), &legacy), Verified::No);
    }

    #[test]
    fn garbage_hash_never_verifies() {
        let pw = random_secret();
        assert_eq!(verify(&pw, "not a hash"), Verified::No);
        assert_eq!(verify(&pw, ""), Verified::No);
    }
}
