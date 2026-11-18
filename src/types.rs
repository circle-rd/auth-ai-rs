//! Values exchanged between the steps of a sign-in.

use crate::claims::IdTokenClaims;
use crate::error::{AuthAiError, ErrorCode, Result};
use crate::secret::SecretString;

/// The `prompt` parameter of an authorization request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prompt {
    /// Force a new authentication.
    Login,
    /// Force the consent screen.
    Consent,
    /// Let the user pick an account.
    SelectAccount,
    /// Send the user to registration.
    Create,
    /// Never show a screen.
    None,
}

impl Prompt {
    /// The wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Consent => "consent",
            Self::SelectAccount => "select_account",
            Self::Create => "create",
            Self::None => "none",
        }
    }

    /// Parses the wire form; `None` for anything else.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        [
            Self::Login,
            Self::Consent,
            Self::SelectAccount,
            Self::Create,
            Self::None,
        ]
        .into_iter()
        .find(|prompt| prompt.as_str() == value)
    }
}

/// Which token a revocation or introspection concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenTypeHint {
    /// An access token.
    AccessToken,
    /// A refresh token.
    RefreshToken,
}

impl TokenTypeHint {
    /// The wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessToken => "access_token",
            Self::RefreshToken => "refresh_token",
        }
    }
}

/// The tokens of a successful token request. Secrets stay out of `Debug`.
#[derive(Debug, Clone)]
pub struct TokenSet {
    /// The access token.
    pub access_token: SecretString,
    /// The token type, `Bearer`.
    pub token_type: String,
    /// Expiry, in unix seconds.
    pub expires_at: i64,
    /// The granted scopes.
    pub scope: Option<String>,
    /// Absent when the provider issued none (no `offline_access`, or no rotation).
    pub refresh_token: Option<SecretString>,
    /// The ID token.
    pub id_token: Option<SecretString>,
}

/// Secrets of one sign-in attempt.
///
/// The caller persists them (typically in a short-lived sealed cookie) between
/// the redirect and the callback.
#[derive(Debug, Clone)]
pub struct LoginHandshake {
    /// The `state` sent to the provider.
    pub state: SecretString,
    /// The `nonce` the ID token must echo.
    pub nonce: SecretString,
    /// The PKCE code verifier.
    pub code_verifier: SecretString,
}

/// Where to send the browser to sign in, and what to keep until it returns.
#[derive(Debug, Clone)]
pub struct LoginRequest {
    /// The authorization URL.
    pub url: String,
    /// The secrets to keep.
    pub handshake: LoginHandshake,
}

/// A completed sign-in.
#[derive(Debug, Clone)]
pub struct LoginResult {
    /// The tokens.
    pub tokens: TokenSet,
    /// The verified ID token claims, enriched from UserInfo.
    pub claims: IdTokenClaims,
    /// The provider session, only present when end-session or back-channel
    /// logout is enabled for the application.
    pub session_id: Option<String>,
}

impl LoginResult {
    /// The raw ID token.
    ///
    /// # Errors
    /// `OIDC_002` when the token response carried none.
    pub fn id_token(&self) -> Result<&SecretString> {
        self.tokens.id_token.as_ref().ok_or_else(|| {
            AuthAiError::new(ErrorCode::Oidc002)
                .with_message("The token response carries no ID token")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompts_round_trip() {
        for prompt in [
            Prompt::Login,
            Prompt::Consent,
            Prompt::SelectAccount,
            Prompt::Create,
            Prompt::None,
        ] {
            assert_eq!(Prompt::from_wire(prompt.as_str()), Some(prompt));
        }
        assert_eq!(Prompt::from_wire("bogus"), None);
    }

    #[test]
    fn handshake_debug_hides_every_secret() {
        let handshake = LoginHandshake {
            state: "state-value".into(),
            nonce: "nonce-value".into(),
            code_verifier: "verifier-value".into(),
        };
        let printed = format!("{handshake:?}");
        for secret in ["state-value", "nonce-value", "verifier-value"] {
            assert!(!printed.contains(secret));
        }
    }
}
