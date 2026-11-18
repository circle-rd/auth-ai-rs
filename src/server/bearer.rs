//! Bearer-token verification for your own API.

use serde_json::Value;
use url::Url;

use crate::claims::AccessTokenClaims;
use crate::client::AuthClient;
use crate::error::{AuthAiError, ErrorCode, Result};

fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
}

/// Extracts the token of an `Authorization: Bearer <token>` header.
///
/// # Errors
/// `TOK_003` when the header is absent or is not a well-formed Bearer credential.
pub fn extract_bearer_token(authorization: Option<&str>) -> Result<&str> {
    let malformed = || AuthAiError::new(ErrorCode::Tok003);
    let header = authorization.ok_or_else(malformed)?;
    let (scheme, rest) = header
        .split_at_checked("Bearer".len())
        .ok_or_else(malformed)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(malformed());
    }
    let token = rest.trim_start_matches(' ');
    if token.len() == rest.len() {
        return Err(malformed());
    }
    let body = token.trim_end_matches('=');
    if body.is_empty() || !body.bytes().all(is_token_char) {
        return Err(malformed());
    }
    Ok(token)
}

/// A verified JWT access token.
#[derive(Debug, Clone)]
pub struct VerifiedAccessToken {
    /// The end user, or `None` for a `client_credentials` token (machine call).
    pub user_id: Option<String>,
    /// The OAuth client (application slug) the token was issued to.
    pub client_id: String,
    /// The granted scopes.
    pub scopes: Vec<String>,
    /// The audiences.
    pub audiences: Vec<String>,
    /// The claims.
    pub claims: AccessTokenClaims,
}

/// Verifies JWT access tokens minted for this API (`aud` contains `audience`).
///
/// Opaque tokens are refused: they carry no audience this API could trust.
#[derive(Debug, Clone)]
pub struct BearerVerifier {
    auth: AuthClient,
    audience: String,
}

impl BearerVerifier {
    /// A verifier of the tokens whose audience is `audience`, the URL of this API.
    ///
    /// # Errors
    /// `CFG_001` when `audience` is not an absolute URL.
    pub fn new(auth: AuthClient, audience: impl Into<String>) -> Result<Self> {
        let audience = audience.into();
        if !Url::parse(&audience).is_ok_and(|url| url.has_host()) {
            return Err(AuthAiError::new(ErrorCode::Cfg001)
                .with_message("audience must be the URL of this API"));
        }
        Ok(Self { auth, audience })
    }

    /// Verifies a raw JWT access token.
    ///
    /// # Errors
    /// `TOK_001` when it does not verify or is not bound to a client.
    pub async fn verify(&self, token: &str) -> Result<VerifiedAccessToken> {
        if token.split('.').count() != 3 {
            return Err(AuthAiError::new(ErrorCode::Tok001)
                .with_message("Only JWT access tokens are accepted"));
        }
        let payload = self.auth.verify_jwt(token, &self.audience, None).await?;
        let claims: AccessTokenClaims =
            serde_json::from_value(Value::Object(payload)).map_err(|err| {
                AuthAiError::new(ErrorCode::Tok001)
                    .with_message("The access token is not bound to a client")
                    .with_source(err)
            })?;
        Ok(VerifiedAccessToken {
            // For client_credentials tokens `sub` is the client id itself.
            user_id: (claims.sub != claims.azp).then(|| claims.sub.clone()),
            client_id: claims.azp.clone(),
            scopes: claims
                .scope
                .as_deref()
                .map(|scope| {
                    scope
                        .split(' ')
                        .filter(|item| !item.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            audiences: claims.aud.to_vec(),
            claims,
        })
    }

    /// Verifies the token of an `Authorization` header.
    ///
    /// # Errors
    /// `TOK_003` for a malformed header, otherwise as [`BearerVerifier::verify`].
    pub async fn verify_header(&self, authorization: Option<&str>) -> Result<VerifiedAccessToken> {
        self.verify(extract_bearer_token(authorization)?).await
    }
}

/// Fails with `TOK_004` unless the token carries every listed scope.
///
/// # Errors
/// `TOK_004`, naming the missing scopes.
pub fn require_scopes(token: &VerifiedAccessToken, required: &[&str]) -> Result<()> {
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|scope| !token.scopes.iter().any(|held| held == scope))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let missing = missing.join(" ");
    Err(AuthAiError::new(ErrorCode::Tok004)
        .with_message(format!("Missing required scope: {missing}"))
        .with_detail("missing", missing))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_headers_yield_their_token() {
        for (header, token) in [
            ("Bearer abc.def.ghi", "abc.def.ghi"),
            ("bearer   a-b_c~d+e/f==", "a-b_c~d+e/f=="),
            ("BEARER x", "x"),
        ] {
            assert_eq!(
                extract_bearer_token(Some(header)).unwrap(),
                token,
                "{header}"
            );
        }
    }

    #[test]
    fn malformed_headers_are_refused() {
        for header in [
            None,
            Some(""),
            Some("Bearer"),
            Some("Bearer "),
            Some("Bearerabc"),
            Some("Basic abc"),
            Some("Bearer a b"),
            Some("Bearer a=b"),
            Some("Bearer ===="),
            Some("Bearer a\u{e9}"),
            Some("Béarer x"),
        ] {
            let err = extract_bearer_token(header).unwrap_err();
            assert_eq!(err.code(), ErrorCode::Tok003, "{header:?}");
        }
    }
}
