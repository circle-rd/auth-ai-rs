//! The short-lived sealed cookies: an encrypted, authenticated, expiring JSON value.
//!
//! The wire form is a compact JWE (`alg` `dir`, `enc` `A256GCM`) carrying
//! `{ data, iat, exp }`, so a Python or TypeScript backend can read what this
//! one sealed and the other way round.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::error::{AuthAiError, ErrorCode, Result};
use crate::util::{b64url, b64url_decode, fill_random, now_unix, sha256};

/// The shortest secret accepted.
pub const MIN_SECRET_LENGTH: usize = 32;
const KEY_LENGTH: usize = 32;
const TAG_LENGTH: usize = 16;
// A cookie never exceeds a few kilobytes: anything longer is not one of ours.
const MAX_TOKEN_LENGTH: usize = 8192;
const HEADER: &str = r#"{"alg":"dir","enc":"A256GCM"}"#;

/// The AES-256 key sealing the cookies, derived from the application's secret.
///
/// It never prints itself and is wiped on drop.
pub struct SealKey(Zeroizing<[u8; KEY_LENGTH]>);

impl std::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealKey([REDACTED])")
    }
}

impl SealKey {
    fn cipher(&self) -> Result<LessSafeKey> {
        UnboundKey::new(&AES_256_GCM, self.0.as_ref())
            .map(LessSafeKey::new)
            .map_err(|_| {
                AuthAiError::new(ErrorCode::Srv001).with_message("The sealing key is unusable")
            })
    }
}

/// Derives the AES-256 key sealing the short-lived cookies from the
/// application's secret.
///
/// The secret must be long and random (for example 32 bytes of base64): it is
/// never stored or logged.
///
/// # Errors
/// `CFG_001` when the secret is shorter than 32 characters.
pub fn derive_seal_key(secret: &str) -> Result<SealKey> {
    if secret.chars().count() < MIN_SECRET_LENGTH {
        return Err(AuthAiError::new(ErrorCode::Cfg001).with_message(format!(
            "The secret must be at least {MIN_SECRET_LENGTH} characters long"
        )));
    }
    let digest = Zeroizing::new(sha256(format!("auth-ai:seal:{secret}").as_bytes()));
    let key: [u8; KEY_LENGTH] = digest.as_slice().try_into().map_err(|_| {
        AuthAiError::new(ErrorCode::Srv001).with_message("The sealing key has an unexpected length")
    })?;
    Ok(SealKey(Zeroizing::new(key)))
}

/// Encrypts and authenticates a JSON value into a compact token that expires.
///
/// # Errors
/// `SRV_001` when the system random number generator or the cipher fails.
pub fn seal(key: &SealKey, data: &Value, ttl_seconds: i64) -> Result<String> {
    let now = now_unix();
    let payload = json!({ "data": data, "iat": now, "exp": now + ttl_seconds });
    let mut in_out = serde_json::to_vec(&payload).map_err(|err| {
        AuthAiError::new(ErrorCode::Srv001)
            .with_message("The cookie value cannot be serialised")
            .with_source(err)
    })?;
    let encoded_header = b64url(HEADER.as_bytes());
    let mut iv = [0_u8; NONCE_LEN];
    fill_random(&mut iv)?;
    let tag = key
        .cipher()?
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(iv),
            Aad::from(encoded_header.as_bytes()),
            &mut in_out,
        )
        .map_err(|_| {
            AuthAiError::new(ErrorCode::Srv001).with_message("The cookie value cannot be sealed")
        })?;
    Ok(format!(
        "{encoded_header}..{}.{}.{}",
        b64url(&iv),
        b64url(&in_out),
        b64url(tag.as_ref())
    ))
}

fn tampered() -> AuthAiError {
    AuthAiError::new(ErrorCode::Ses002)
}

/// The value of [`seal`], deserialised as `T`.
///
/// # Errors
/// `SES_002` for any tampered, expired or malformed token.
pub fn unseal<T: DeserializeOwned>(key: &SealKey, token: &str) -> Result<T> {
    if token.len() > MAX_TOKEN_LENGTH {
        return Err(tampered());
    }
    let parts: Vec<&str> = token.split('.').collect();
    let [encoded_header, encrypted_key, iv, ciphertext, tag] = parts.as_slice() else {
        return Err(tampered());
    };
    let header: Map<String, Value> =
        serde_json::from_slice(&b64url_decode(encoded_header).ok_or_else(tampered)?)
            .map_err(|_| tampered())?;
    let expected =
        |name: &str, value: &str| header.get(name).and_then(Value::as_str) == Some(value);
    if !encrypted_key.is_empty()
        || !expected("alg", "dir")
        || !expected("enc", "A256GCM")
        || header.contains_key("zip")
        || header.contains_key("crit")
    {
        return Err(tampered());
    }
    let iv: [u8; NONCE_LEN] = b64url_decode(iv)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(tampered)?;
    let tag = b64url_decode(tag)
        .filter(|tag| tag.len() == TAG_LENGTH)
        .ok_or_else(tampered)?;
    let mut in_out = b64url_decode(ciphertext).ok_or_else(tampered)?;
    in_out.extend_from_slice(&tag);
    let plaintext = key
        .cipher()?
        .open_in_place(
            Nonce::assume_unique_for_key(iv),
            Aad::from(encoded_header.as_bytes()),
            &mut in_out,
        )
        .map_err(|_| tampered())?;

    let envelope: Map<String, Value> = serde_json::from_slice(plaintext).map_err(|_| tampered())?;
    let expires_at = envelope
        .get("exp")
        .and_then(Value::as_f64)
        .ok_or_else(tampered)?;
    if expires_at <= crate::util::now_unix_f64() {
        return Err(tampered());
    }
    let data = envelope.get("data").cloned().ok_or_else(tampered)?;
    serde_json::from_value(data).map_err(|_| tampered())
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Payload {
        a: String,
    }

    fn key() -> SealKey {
        derive_seal_key(SECRET).unwrap()
    }

    #[test]
    fn short_secrets_are_refused() {
        assert_eq!(
            derive_seal_key("too short").unwrap_err().code(),
            ErrorCode::Cfg001
        );
        assert!(derive_seal_key(&"x".repeat(MIN_SECRET_LENGTH)).is_ok());
    }

    #[test]
    fn the_key_never_prints() {
        assert!(!format!("{:?}", key()).contains(SECRET));
    }

    #[test]
    fn a_sealed_value_round_trips() {
        let token = seal(&key(), &json!({ "a": "hello" }), 60).unwrap();
        assert_eq!(
            unseal::<Payload>(&key(), &token).unwrap(),
            Payload {
                a: "hello".to_owned()
            }
        );
        assert_eq!(token.split('.').count(), 5);
    }

    #[test]
    fn sealing_is_randomised() {
        let first = seal(&key(), &json!({ "a": "x" }), 60).unwrap();
        let second = seal(&key(), &json!({ "a": "x" }), 60).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn the_wire_form_is_a_compact_jwe_of_the_documented_header() {
        let token = seal(&key(), &json!({ "a": "x" }), 60).unwrap();
        let header = token.split('.').next().unwrap();
        assert_eq!(b64url_decode(header).unwrap(), HEADER.as_bytes());
        assert_eq!(token.split('.').nth(1), Some(""));
    }

    #[test]
    fn another_key_cannot_read_it() {
        let token = seal(&key(), &json!({ "a": "x" }), 60).unwrap();
        let other = derive_seal_key("ffffffffffffffffffffffffffffffff").unwrap();
        assert_eq!(
            unseal::<Payload>(&other, &token).unwrap_err().code(),
            ErrorCode::Ses002
        );
    }

    #[test]
    fn an_expired_value_is_refused() {
        let token = seal(&key(), &json!({ "a": "x" }), -1).unwrap();
        assert_eq!(
            unseal::<Payload>(&key(), &token).unwrap_err().code(),
            ErrorCode::Ses002
        );
    }

    #[test]
    fn a_value_of_the_wrong_shape_is_refused() {
        let token = seal(&key(), &json!({ "b": 1 }), 60).unwrap();
        assert_eq!(
            unseal::<Payload>(&key(), &token).unwrap_err().code(),
            ErrorCode::Ses002
        );
    }

    #[test]
    fn every_tampered_part_is_refused() {
        let token = seal(&key(), &json!({ "a": "x" }), 60).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        for index in [0_usize, 2, 3, 4] {
            let mut altered: Vec<String> = parts.iter().map(|part| (*part).to_owned()).collect();
            let target = altered.get_mut(index).unwrap();
            let flipped = if target.starts_with('A') { 'B' } else { 'A' };
            target.replace_range(0..1, &flipped.to_string());
            assert!(
                unseal::<Payload>(&key(), &altered.join(".")).is_err(),
                "part {index}"
            );
        }
        for garbage in [
            "",
            "a.b.c.d.e",
            "....",
            "a.b.c.d",
            &"x".repeat(MAX_TOKEN_LENGTH + 1),
        ] {
            assert!(unseal::<Payload>(&key(), garbage).is_err(), "{garbage}");
        }
    }

    #[test]
    fn a_foreign_header_is_refused() {
        let token = seal(&key(), &json!({ "a": "x" }), 60).unwrap();
        let rest: Vec<&str> = token.split('.').skip(1).collect();
        for header in [
            r#"{"alg":"A256KW","enc":"A256GCM"}"#,
            r#"{"alg":"dir","enc":"A128GCM"}"#,
            r#"{"alg":"dir","enc":"A256GCM","zip":"DEF"}"#,
            r#"{"alg":"dir","enc":"A256GCM","crit":["x"]}"#,
        ] {
            let forged = format!("{}.{}", b64url(header.as_bytes()), rest.join("."));
            assert!(unseal::<Payload>(&key(), &forged).is_err(), "{header}");
        }
    }
}
