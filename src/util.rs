//! Small helpers shared by the modules: time, randomness, encodings.

use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::fill;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

use crate::error::{AuthAiError, ErrorCode, Result};

/// Everything but the RFC 3986 unreserved characters, as `urllib.parse.quote(safe="")`.
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Seconds since the Unix epoch. A clock set before 1970 is a broken host: it
/// reads as the epoch, which expires every token.
pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Same instant in fractional seconds, to compare with JWT `exp` and `iat` values.
pub(crate) fn now_unix_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

pub(crate) fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}

/// `byte_len` random bytes from the operating system's CSPRNG, base64url encoded.
pub(crate) fn random_token(byte_len: usize) -> Result<String> {
    let mut bytes = vec![0_u8; byte_len];
    fill(&mut bytes).map_err(|_| {
        AuthAiError::new(ErrorCode::Srv001)
            .with_message("The system random number generator failed")
    })?;
    Ok(b64url(&bytes))
}

pub(crate) fn fill_random(bytes: &mut [u8]) -> Result<()> {
    fill(bytes).map_err(|_| {
        AuthAiError::new(ErrorCode::Srv001)
            .with_message("The system random number generator failed")
    })
}

/// SHA-256 of `value`, base64url encoded without padding.
pub(crate) fn sha256_b64url(value: &str) -> String {
    b64url(digest(&SHA256, value.as_bytes()).as_ref())
}

pub(crate) fn sha256(value: &[u8]) -> Vec<u8> {
    digest(&SHA256, value).as_ref().to_vec()
}

/// Constant-time equality of two secrets (state, nonce).
pub(crate) fn secrets_equal(left: &str, right: &str) -> bool {
    verify_slices_are_equal(left.as_bytes(), right.as_bytes()).is_ok()
}

/// A value placed in a URL path segment: every reserved character is escaped.
pub(crate) fn encode_segment(value: &str) -> String {
    utf8_percent_encode(value, SEGMENT).to_string()
}

/// `application/x-www-form-urlencoded` of name/value pairs.
pub(crate) fn form_encode<'a, I>(pairs: I) -> String
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(name, value);
    }
    serializer.finish()
}

/// Appends `pairs` to the query `url` already carries, repeated names kept.
pub(crate) fn with_query<'a, I>(url: &str, pairs: I) -> Result<String>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut parsed = url::Url::parse(url).map_err(|err| {
        AuthAiError::new(ErrorCode::Cfg001)
            .with_message("Not a valid URL")
            .with_source(err)
    })?;
    {
        let mut query = parsed.query_pairs_mut();
        for (name, value) in pairs {
            query.append_pair(name, value);
        }
    }
    Ok(parsed.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_escape_every_reserved_character() {
        assert_eq!(encode_segment("a/b c?d#e%f"), "a%2Fb%20c%3Fd%23e%25f");
        assert_eq!(encode_segment("Az09-._~"), "Az09-._~");
        assert_eq!(encode_segment("é"), "%C3%A9");
    }

    #[test]
    fn random_tokens_are_unique_and_url_safe() {
        let first = random_token(32).unwrap();
        let second = random_token(32).unwrap();
        assert_ne!(first, second);
        assert_eq!(first.len(), 43);
        assert!(
            first
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn sha256_is_base64url_without_padding() {
        assert_eq!(
            sha256_b64url("abc"),
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
        );
    }

    #[test]
    fn query_is_appended_to_the_existing_one() {
        let url = with_query(
            "https://a.example/auth?x=1",
            [("scope", "a b"), ("r", "1"), ("r", "2")],
        )
        .unwrap();
        assert_eq!(url, "https://a.example/auth?x=1&scope=a+b&r=1&r=2");
    }

    #[test]
    fn secrets_compare_by_value() {
        assert!(secrets_equal("abc", "abc"));
        assert!(!secrets_equal("abc", "abd"));
        assert!(!secrets_equal("abc", "abcd"));
    }
}
