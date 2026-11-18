//! Cookie names, parsing and serialization for the SDK's three cookies.

use std::collections::HashMap;

use crate::error::{AuthAiError, ErrorCode, Result};

const HOST_PREFIX: &str = "__Host-";

// Token characters only: the values handled here are base64url ids and compact JWEs.
fn is_value_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-')
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-')
}

/// Name of a cookie of the SDK.
///
/// `__Host-` pins the cookie to this host and needs `Secure`, so it only
/// applies over https.
#[must_use]
pub fn cookie_name(base: &str, secure: bool) -> String {
    if secure {
        format!("{HOST_PREFIX}{base}")
    } else {
        base.to_owned()
    }
}

/// The cookies of a `Cookie` header. The first occurrence of a name wins, as it
/// is the one scoped most specifically.
#[must_use]
pub fn parse_cookies(header: Option<&str>) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    for part in header.unwrap_or_default().split(';') {
        if let Some((name, value)) = part.split_once('=') {
            cookies
                .entry(name.trim().to_owned())
                .or_insert_with(|| value.trim().to_owned());
        }
    }
    cookies
}

/// A `Set-Cookie` value. `max_age_seconds` of 0 expires the cookie at once;
/// `secure` adds `Secure`.
///
/// # Errors
/// `CFG_001` when the name or the value holds a character outside the token set.
pub fn serialize_cookie(
    name: &str,
    value: &str,
    max_age_seconds: i64,
    secure: bool,
) -> Result<String> {
    let bare = name.strip_prefix(HOST_PREFIX).unwrap_or(name);
    if bare.is_empty() || !bare.chars().all(is_name_char) {
        return Err(AuthAiError::new(ErrorCode::Cfg001).with_message("Invalid cookie name"));
    }
    if !value.chars().all(is_value_char) {
        return Err(AuthAiError::new(ErrorCode::Cfg001).with_message("Invalid cookie value"));
    }
    // Lax still sends the cookie on the top-level GET that returns from the provider.
    let mut cookie = format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        max_age_seconds.max(0)
    );
    if secure {
        cookie.push_str("; Secure");
    }
    Ok(cookie)
}

/// A `Set-Cookie` value that removes the cookie.
///
/// # Errors
/// `CFG_001` when the name is invalid.
pub fn clear_cookie(name: &str, secure: bool) -> Result<String> {
    serialize_cookie(name, "", 0, secure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_prefix_follows_the_scheme() {
        assert_eq!(cookie_name("aai_session", true), "__Host-aai_session");
        assert_eq!(cookie_name("aai_session", false), "aai_session");
    }

    #[test]
    fn the_first_cookie_of_a_name_wins() {
        let cookies = parse_cookies(Some("a=1; b=2 ;a=3; junk; c="));
        assert_eq!(cookies.get("a").map(String::as_str), Some("1"));
        assert_eq!(cookies.get("b").map(String::as_str), Some("2"));
        assert_eq!(cookies.get("c").map(String::as_str), Some(""));
        assert!(!cookies.contains_key("junk"));
        assert!(parse_cookies(None).is_empty());
    }

    #[test]
    fn serialized_cookies_are_hardened() {
        let cookie = serialize_cookie("__Host-aai_session", "abc.DEF_1-~", 3600, true).unwrap();
        assert_eq!(
            cookie,
            "__Host-aai_session=abc.DEF_1-~; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600; Secure"
        );
        let insecure = serialize_cookie("aai_login", "x", 600, false).unwrap();
        assert!(!insecure.contains("Secure"));
    }

    #[test]
    fn clearing_expires_at_once_and_a_negative_age_is_zero() {
        assert!(
            clear_cookie("aai_login", false)
                .unwrap()
                .ends_with("Max-Age=0")
        );
        assert!(
            serialize_cookie("a", "b", -5, false)
                .unwrap()
                .contains("Max-Age=0")
        );
    }

    #[test]
    fn values_and_names_cannot_inject_attributes() {
        for value in ["a;b", "a b", "a\r\nSet-Cookie: x=y", "a=b", "é"] {
            assert!(
                serialize_cookie("aai", value, 1, false).is_err(),
                "{value:?}"
            );
        }
        for name in ["", "a;b", "a b", "__Host-", "a=b"] {
            assert!(serialize_cookie(name, "v", 1, false).is_err(), "{name:?}");
        }
    }
}
