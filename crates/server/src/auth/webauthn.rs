//! WebAuthn (passkeys): checks a browser's registration and sign-in answers.
//!
//! Attestation is not verified ("none"): any authenticator the user owns is
//! fine for a self-hosted app. What is checked: the challenge (single use), the
//! origin, the relying-party hash, user presence and user verification, the
//! signature over authenticator data and client data, and the sign counter.
//! Algorithms: ES256, EdDSA and RS256.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use ciborium::value::Value;
use ring::signature;
use sha2::{Digest, Sha256};

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;
pub const ALG_ES256: i64 = -7;
pub const ALG_EDDSA: i64 = -8;
pub const ALG_RS256: i64 = -257;

#[derive(Debug)]
pub struct Registered {
    pub cred_id: String,
    pub public_key: String,
    pub sign_count: i64,
}

pub fn b64u(data: &[u8]) -> String {
    B64U.encode(data)
}

pub fn unb64u(s: &str) -> Result<Vec<u8>, String> {
    B64U.decode(s.trim_end_matches('='))
        .map_err(|_| "bad base64url".to_owned())
}

#[derive(serde::Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
}

fn check_client_data(raw: &[u8], kind: &str, challenge: &str, origin: &str) -> Result<(), String> {
    let cd: ClientData =
        serde_json::from_slice(raw).map_err(|_| "client data is not valid".to_owned())?;
    if cd.kind != kind {
        return Err("wrong ceremony type".into());
    }
    if !crate::auth::token::constant_time_eq(&cd.challenge, challenge) {
        return Err("challenge mismatch".into());
    }
    if cd.origin != origin {
        return Err(format!("origin {} does not match {origin}", cd.origin));
    }
    if cd.cross_origin {
        return Err("cross-origin ceremony".into());
    }
    Ok(())
}

/// Checks the fixed 37-byte head of authenticator data; returns (flags, counter).
fn check_auth_data(ad: &[u8], rp_id: &str) -> Result<(u8, i64), String> {
    if ad.len() < 37 {
        return Err("authenticator data too short".into());
    }
    if ad[..32] != Sha256::digest(rp_id.as_bytes())[..] {
        return Err("relying party mismatch".into());
    }
    let flags = ad[32];
    if flags & FLAG_UP == 0 {
        return Err("user not present".into());
    }
    if flags & FLAG_UV == 0 {
        return Err("user not verified (PIN or biometric required)".into());
    }
    let count = u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]]);
    Ok((flags, i64::from(count)))
}

fn map_get<'a>(m: &'a [(Value, Value)], key: &Value) -> Option<&'a Value> {
    m.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn int(v: &Value) -> Option<i64> {
    v.as_integer().and_then(|i| i64::try_from(i).ok())
}

fn int_key(i: i64) -> Value {
    Value::Integer(i.into())
}

/// Validate a COSE key and return its algorithm.
fn cose_alg(key: &[u8]) -> Result<i64, String> {
    let v: Value =
        ciborium::de::from_reader(key).map_err(|_| "public key is not CBOR".to_owned())?;
    let m = v.as_map().ok_or("public key is not a map")?;
    let kty = map_get(m, &int_key(1)).and_then(int).ok_or("no key type")?;
    let alg = map_get(m, &int_key(3))
        .and_then(int)
        .ok_or("no algorithm")?;
    let bytes = |k: i64| map_get(m, &int_key(k)).and_then(Value::as_bytes);
    match (kty, alg) {
        (2, ALG_ES256) => {
            let crv = map_get(m, &int_key(-1)).and_then(int);
            if crv != Some(1)
                || bytes(-2).map(Vec::len) != Some(32)
                || bytes(-3).map(Vec::len) != Some(32)
            {
                return Err("bad P-256 key".into());
            }
        }
        (1, ALG_EDDSA) => {
            let crv = map_get(m, &int_key(-1)).and_then(int);
            if crv != Some(6) || bytes(-2).map(Vec::len) != Some(32) {
                return Err("bad Ed25519 key".into());
            }
        }
        (3, ALG_RS256) => {
            let n = bytes(-1).ok_or("bad RSA key")?;
            if n.len() < 256 || bytes(-2).is_none() {
                return Err("RSA keys must be at least 2048 bits".into());
            }
        }
        _ => return Err(format!("unsupported key (type {kty}, algorithm {alg})")),
    }
    Ok(alg)
}

/// Read the CBOR item at the start of `data` and return how many bytes it used.
fn cbor_len(data: &[u8]) -> Result<usize, String> {
    let mut cur = std::io::Cursor::new(data);
    let _: Value = ciborium::de::from_reader(&mut cur).map_err(|_| "bad CBOR".to_owned())?;
    usize::try_from(cur.position()).map_err(|_| "bad CBOR".to_owned())
}

pub fn verify_registration(
    client_data_json: &[u8],
    attestation_object: &[u8],
    challenge: &str,
    origin: &str,
    rp_id: &str,
) -> Result<Registered, String> {
    check_client_data(client_data_json, "webauthn.create", challenge, origin)?;
    let att: Value = ciborium::de::from_reader(attestation_object)
        .map_err(|_| "attestation is not CBOR".to_owned())?;
    let m = att.as_map().ok_or("attestation is not a map")?;
    let ad = map_get(m, &Value::Text("authData".into()))
        .and_then(Value::as_bytes)
        .ok_or("no authenticator data")?;
    let (flags, count) = check_auth_data(ad, rp_id)?;
    if flags & FLAG_AT == 0 || ad.len() < 55 {
        return Err("no credential in authenticator data".into());
    }
    let id_len = usize::from(u16::from_be_bytes([ad[53], ad[54]]));
    if id_len == 0 || id_len > 1023 || ad.len() < 55 + id_len {
        return Err("bad credential id".into());
    }
    let cred_id = &ad[55..55 + id_len];
    let key_bytes = &ad[55 + id_len..];
    let key_len = cbor_len(key_bytes)?;
    let key = &key_bytes[..key_len];
    cose_alg(key)?;
    Ok(Registered {
        cred_id: b64u(cred_id),
        public_key: b64u(key),
        sign_count: count,
    })
}

/// Check a sign-in answer against the stored key. Returns the new counter.
pub fn verify_assertion(
    client_data_json: &[u8],
    authenticator_data: &[u8],
    sig: &[u8],
    challenge: &str,
    origin: &str,
    rp_id: &str,
    public_key: &str,
) -> Result<i64, String> {
    check_client_data(client_data_json, "webauthn.get", challenge, origin)?;
    let (_, count) = check_auth_data(authenticator_data, rp_id)?;
    let key = unb64u(public_key)?;
    let alg = cose_alg(&key)?;
    let v: Value = ciborium::de::from_reader(key.as_slice()).map_err(|_| "bad key".to_owned())?;
    let m = v.as_map().ok_or("bad key")?;
    let bytes = |k: i64| {
        map_get(m, &int_key(k))
            .and_then(Value::as_bytes)
            .cloned()
            .unwrap_or_default()
    };
    let mut msg = authenticator_data.to_vec();
    msg.extend_from_slice(&Sha256::digest(client_data_json));
    let ok = match alg {
        ALG_ES256 => {
            let mut point = vec![0x04];
            point.extend_from_slice(&bytes(-2));
            point.extend_from_slice(&bytes(-3));
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, point)
                .verify(&msg, sig)
                .is_ok()
        }
        ALG_EDDSA => signature::UnparsedPublicKey::new(&signature::ED25519, bytes(-2))
            .verify(&msg, sig)
            .is_ok(),
        ALG_RS256 => signature::RsaPublicKeyComponents {
            n: bytes(-1),
            e: bytes(-2),
        }
        .verify(&signature::RSA_PKCS1_2048_8192_SHA256, &msg, sig)
        .is_ok(),
        _ => false,
    };
    if !ok {
        return Err("signature does not verify".into());
    }
    Ok(count)
}

#[cfg(any(test, feature = "testkit"))]
pub mod testkit {
    //! A software authenticator for tests.
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

    pub struct SoftKey {
        pair: EcdsaKeyPair,
        pub cred_id: Vec<u8>,
        pub counter: u32,
    }

    impl Default for SoftKey {
        fn default() -> Self {
            Self::new()
        }
    }

    impl SoftKey {
        pub fn new() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).expect("gen");
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                    .expect("pair");
            Self {
                pair,
                cred_id: b"soft-credential-1".to_vec(),
                counter: 0,
            }
        }

        fn cose(&self) -> Vec<u8> {
            let p = self.pair.public_key().as_ref();
            let v = Value::Map(vec![
                (int_key(1), int_key(2)),
                (int_key(3), int_key(ALG_ES256)),
                (int_key(-1), int_key(1)),
                (int_key(-2), Value::Bytes(p[1..33].to_vec())),
                (int_key(-3), Value::Bytes(p[33..65].to_vec())),
            ]);
            let mut out = Vec::new();
            ciborium::ser::into_writer(&v, &mut out).expect("cbor");
            out
        }

        fn head(&self, rp_id: &str, flags: u8) -> Vec<u8> {
            let mut ad = Sha256::digest(rp_id.as_bytes()).to_vec();
            ad.push(flags);
            ad.extend_from_slice(&self.counter.to_be_bytes());
            ad
        }

        pub fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
            serde_json::json!({"type": kind, "challenge": challenge, "origin": origin})
                .to_string()
                .into_bytes()
        }

        /// (clientDataJSON, attestationObject)
        pub fn register(&self, challenge: &str, origin: &str, rp_id: &str) -> (Vec<u8>, Vec<u8>) {
            let mut ad = self.head(rp_id, FLAG_UP | FLAG_UV | FLAG_AT);
            ad.extend_from_slice(&[0u8; 16]);
            ad.extend_from_slice(
                &u16::try_from(self.cred_id.len())
                    .expect("len")
                    .to_be_bytes(),
            );
            ad.extend_from_slice(&self.cred_id);
            ad.extend_from_slice(&self.cose());
            let att = Value::Map(vec![
                (Value::Text("fmt".into()), Value::Text("none".into())),
                (Value::Text("attStmt".into()), Value::Map(vec![])),
                (Value::Text("authData".into()), Value::Bytes(ad)),
            ]);
            let mut out = Vec::new();
            ciborium::ser::into_writer(&att, &mut out).expect("cbor");
            (Self::client_data("webauthn.create", challenge, origin), out)
        }

        /// (clientDataJSON, authenticatorData, signature)
        pub fn sign(
            &mut self,
            challenge: &str,
            origin: &str,
            rp_id: &str,
        ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            self.counter += 1;
            let cd = Self::client_data("webauthn.get", challenge, origin);
            let ad = self.head(rp_id, FLAG_UP | FLAG_UV);
            let mut msg = ad.clone();
            msg.extend_from_slice(&Sha256::digest(&cd));
            let sig = self
                .pair
                .sign(&SystemRandom::new(), &msg)
                .expect("sign")
                .as_ref()
                .to_vec();
            (cd, ad, sig)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::SoftKey;
    use super::*;

    const O: &str = "https://clamav.example.com";
    const RP: &str = "clamav.example.com";

    #[test]
    fn register_then_sign_in() {
        let mut k = SoftKey::new();
        let (cd, att) = k.register("chal1", O, RP);
        let reg = verify_registration(&cd, &att, "chal1", O, RP).expect("registered");
        assert_eq!(unb64u(&reg.cred_id).expect("id"), k.cred_id);
        let (cd, ad, sig) = k.sign("chal2", O, RP);
        assert_eq!(
            verify_assertion(&cd, &ad, &sig, "chal2", O, RP, &reg.public_key),
            Ok(1)
        );
        // Every binding matters.
        assert!(verify_assertion(&cd, &ad, &sig, "other", O, RP, &reg.public_key).is_err());
        assert!(
            verify_assertion(
                &cd,
                &ad,
                &sig,
                "chal2",
                "https://evil.example",
                RP,
                &reg.public_key
            )
            .is_err()
        );
        assert!(
            verify_assertion(&cd, &ad, &sig, "chal2", O, "evil.example", &reg.public_key).is_err()
        );
        let mut bad = sig.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(verify_assertion(&cd, &ad, &bad, "chal2", O, RP, &reg.public_key).is_err());
        // A registration answer cannot be used to sign in.
        let (cd, att) = k.register("chal3", O, RP);
        assert!(verify_registration(&cd, &att, "chal3", O, "other.example").is_err());
        let _ = att;
    }

    #[test]
    fn user_verification_is_required() {
        let mut k = SoftKey::new();
        let (cd, att) = k.register("c", O, RP);
        let reg = verify_registration(&cd, &att, "c", O, RP).expect("reg");
        let (cd, mut ad, _) = k.sign("d", O, RP);
        ad[32] &= !FLAG_UV;
        assert!(
            verify_assertion(&cd, &ad, &[0u8; 64], "d", O, RP, &reg.public_key)
                .is_err_and(|e| e.contains("verified"))
        );
    }
}
