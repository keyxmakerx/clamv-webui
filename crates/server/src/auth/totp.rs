//! Time-based one-time passwords (RFC 6238: SHA-1, 6 digits, 30 s), the kind
//! every authenticator app supports, plus single-use recovery codes.

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

pub const STEP_SECS: i64 = 30;
const DIGITS: u32 = 6;
/// Codes from one step before or after are accepted, for clock drift.
const DRIFT: i64 = 1;
pub const RECOVERY_CODES: usize = 10;

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn unbase32(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let v = B32
            .iter()
            .position(|&x| x == c.to_ascii_uppercase() as u8)?;
        buf = (buf << 5) | u32::try_from(v).ok()?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// A new 160-bit secret.
pub fn new_secret() -> Vec<u8> {
    let mut s = vec![0u8; 20];
    SystemRandom::new().fill(&mut s).expect("system randomness");
    s
}

pub fn step_at(unix_secs: i64) -> i64 {
    unix_secs.div_euclid(STEP_SECS)
}

pub fn code(secret: &[u8], step: i64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &step.to_be_bytes());
    let h = tag.as_ref();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(h[off]) & 0x7f) << 24
        | u32::from(h[off + 1]) << 16
        | u32::from(h[off + 2]) << 8
        | u32::from(h[off + 3]);
    bin % 10u32.pow(DIGITS)
}

/// The step `input` matches near `now_secs`, if any, newer than `last_step`
/// (a code is never accepted twice).
pub fn verify(secret: &[u8], input: &str, last_step: i64, now_secs: i64) -> Option<i64> {
    let digits: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() != DIGITS as usize || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let want: u32 = digits.parse().ok()?;
    let now = step_at(now_secs);
    let mut hit = None;
    // Check every candidate so timing does not reveal which step matched.
    for s in (now - DRIFT)..=(now + DRIFT) {
        let ok = subtle::ConstantTimeEq::ct_eq(
            &code(secret, s).to_be_bytes()[..],
            &want.to_be_bytes()[..],
        );
        if bool::from(ok) && s > last_step {
            hit = Some(s);
        }
    }
    hit
}

/// The link authenticator apps read from the QR code.
pub fn otpauth_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    let enc = |s: &str| {
        url::form_urlencoded::byte_serialize(s.as_bytes())
            .collect::<String>()
            .replace('+', "%20")
    };
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        enc(issuer),
        enc(account),
        base32(secret),
        enc(issuer)
    )
}

/// The URI as an SVG QR code, ready for an `<img src>`.
pub fn qr_data_uri(uri: &str) -> Option<String> {
    use base64::Engine;
    let code = qrcode::QrCode::with_error_correction_level(uri, qrcode::EcLevel::M).ok()?;
    let svg = code
        .render::<qrcode::render::svg::Color<'_>>()
        .min_dimensions(200, 200)
        .quiet_zone(true)
        .build();
    Some(format!(
        "data:image/svg+xml;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(svg)
    ))
}

/// Ten codes like `k3f9-x2mq-7hdp`, shown once.
pub fn new_recovery_codes() -> Vec<String> {
    const ALPHA: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let rng = SystemRandom::new();
    (0..RECOVERY_CODES)
        .map(|_| {
            let mut b = [0u8; 12];
            rng.fill(&mut b).expect("system randomness");
            let s: String = b
                .iter()
                .map(|x| ALPHA[*x as usize % ALPHA.len()] as char)
                .collect();
            format!("{}-{}-{}", &s[0..4], &s[4..8], &s[8..12])
        })
        .collect()
}

/// Recovery codes are compared without case, dashes or spaces.
pub fn normalize_recovery(input: &str) -> String {
    input
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vectors() {
        // RFC 6238 appendix B, SHA-1, last six digits.
        let secret = b"12345678901234567890";
        assert_eq!(code(secret, step_at(59)), 287_082);
        assert_eq!(code(secret, step_at(1_111_111_109)), 81_804);
        assert_eq!(code(secret, step_at(1_234_567_890)), 5_924);
        assert_eq!(code(secret, step_at(2_000_000_000)), 279_037);
    }

    #[test]
    fn verify_drift_and_replay() {
        let s = new_secret();
        let now = 1_700_000_000;
        let c = format!("{:06}", code(&s, step_at(now)));
        let step = verify(&s, &c, 0, now).expect("valid");
        assert_eq!(verify(&s, &c, step, now), None, "not twice");
        let prev = format!("{:06}", code(&s, step_at(now) - 1));
        assert!(verify(&s, &prev, 0, now).is_some(), "one step of drift");
        let old = format!("{:06}", code(&s, step_at(now) - 3));
        assert_eq!(verify(&s, &old, 0, now), None);
        assert_eq!(verify(&s, "12345", 0, now), None);
        assert_eq!(verify(&s, "abcdef", 0, now), None);
    }

    #[test]
    fn base32_round_trip() {
        let s = new_secret();
        assert_eq!(unbase32(&base32(&s)).as_deref(), Some(&s[..]));
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        let codes = new_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODES);
        assert_eq!(normalize_recovery(&codes[0].to_uppercase()).len(), 12);
        assert!(
            otpauth_uri("ClamAV Web UI", "ad min", &s)
                .starts_with("otpauth://totp/ClamAV%20Web%20UI:ad%20min?secret=")
        );
        assert!(
            qr_data_uri("otpauth://totp/x?secret=AA")
                .is_some_and(|u| u.starts_with("data:image/svg+xml;base64,"))
        );
    }
}
