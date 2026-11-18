//! The error taxonomy of the SDK: one stable code per failure condition.
//!
//! Domain prefixes mirror auth-service: `CFG_` configuration, `OIDC_` protocol
//! exchanges with the identity provider, `TOK_` token and grant handling, `API_`
//! calls to the auth-service REST API, `GW_` calls to the LiteLLM gateway, `SES_`
//! browser sessions, `REQ_` invalid requests to the SDK's own routes, `SRV_`
//! unexpected failures of the SDK's own HTTP handlers.

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;

use serde::Serialize;

/// Stable identifier of a failure condition, shared with the TypeScript and
/// Python SDKs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ErrorCode {
    /// Invalid SDK configuration.
    Cfg001,
    /// Identity provider discovery failed.
    Oidc001,
    /// Invalid authorization response.
    Oidc002,
    /// Token request failed.
    Oidc003,
    /// The identity provider does not support the operation.
    Oidc004,
    /// Token verification failed.
    Tok001,
    /// No usable grant for the user.
    Tok002,
    /// Missing or malformed bearer credentials.
    Tok003,
    /// Insufficient scope.
    Tok004,
    /// auth-service rejected the request.
    Api001,
    /// Unexpected response from auth-service.
    Api002,
    /// Insufficient credit.
    Gw001,
    /// The gateway rate limit was reached.
    Gw002,
    /// The gateway refused the credentials or the resource.
    Gw003,
    /// The gateway is temporarily unavailable.
    Gw004,
    /// Unexpected response from the gateway.
    Gw005,
    /// Not signed in.
    Ses001,
    /// The sign-in attempt is missing, expired or was tampered with.
    Ses002,
    /// Sign-in could not be completed.
    Ses003,
    /// Cross-origin request refused.
    Ses004,
    /// Sign-in failed.
    Ses005,
    /// Invalid request.
    Req001,
    /// Internal error.
    Srv001,
}

impl ErrorCode {
    /// Every code of the registry.
    pub const ALL: [Self; 23] = [
        Self::Cfg001,
        Self::Oidc001,
        Self::Oidc002,
        Self::Oidc003,
        Self::Oidc004,
        Self::Tok001,
        Self::Tok002,
        Self::Tok003,
        Self::Tok004,
        Self::Api001,
        Self::Api002,
        Self::Gw001,
        Self::Gw002,
        Self::Gw003,
        Self::Gw004,
        Self::Gw005,
        Self::Ses001,
        Self::Ses002,
        Self::Ses003,
        Self::Ses004,
        Self::Ses005,
        Self::Req001,
        Self::Srv001,
    ];

    /// The wire form, e.g. `OIDC_003`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cfg001 => "CFG_001",
            Self::Oidc001 => "OIDC_001",
            Self::Oidc002 => "OIDC_002",
            Self::Oidc003 => "OIDC_003",
            Self::Oidc004 => "OIDC_004",
            Self::Tok001 => "TOK_001",
            Self::Tok002 => "TOK_002",
            Self::Tok003 => "TOK_003",
            Self::Tok004 => "TOK_004",
            Self::Api001 => "API_001",
            Self::Api002 => "API_002",
            Self::Gw001 => "GW_001",
            Self::Gw002 => "GW_002",
            Self::Gw003 => "GW_003",
            Self::Gw004 => "GW_004",
            Self::Gw005 => "GW_005",
            Self::Ses001 => "SES_001",
            Self::Ses002 => "SES_002",
            Self::Ses003 => "SES_003",
            Self::Ses004 => "SES_004",
            Self::Ses005 => "SES_005",
            Self::Req001 => "REQ_001",
            Self::Srv001 => "SRV_001",
        }
    }

    /// The generic message of the registry: safe to show to an end user.
    #[must_use]
    pub const fn default_message(self) -> &'static str {
        match self {
            Self::Cfg001 => "Invalid SDK configuration",
            Self::Oidc001 => "Identity provider discovery failed",
            Self::Oidc002 => "Invalid authorization response",
            Self::Oidc003 => "Token request failed",
            Self::Oidc004 => "The identity provider does not support this operation",
            Self::Tok001 => "Token verification failed",
            Self::Tok002 => "No usable grant for this user: sign in again",
            Self::Tok003 => "Missing or malformed bearer credentials",
            Self::Tok004 => "Insufficient scope",
            Self::Api001 => "auth-service rejected the request",
            Self::Api002 => "Unexpected response from auth-service",
            Self::Gw001 => "Insufficient credit: the wallet cannot pay for this call",
            Self::Gw002 => "The gateway rate limit was reached",
            Self::Gw003 => "The gateway refused the credentials or the resource",
            Self::Gw004 => "The gateway is temporarily unavailable",
            Self::Gw005 => "Unexpected response from the gateway",
            Self::Ses001 => "Not signed in",
            Self::Ses002 => "The sign-in attempt is missing, expired or was tampered with",
            Self::Ses003 => "Sign-in could not be completed",
            Self::Ses004 => "Cross-origin request refused",
            Self::Ses005 => "Sign-in failed",
            Self::Req001 => "Invalid request",
            Self::Srv001 => "Internal error",
        }
    }

    /// Parses the wire form of a code; `None` for anything outside the registry.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.as_str() == value)
    }

    /// Builds the error of this code with its generic message.
    #[must_use]
    pub fn error(self) -> AuthAiError {
        AuthAiError::new(self)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// A value of an error's `details`: scalars only, so that a detail can be
/// logged and serialised without leaking structured data.
#[derive(Debug, Clone, PartialEq)]
pub enum DetailValue {
    /// Text.
    Str(String),
    /// Integer.
    Int(i64),
    /// Floating point number.
    Float(f64),
    /// Boolean.
    Bool(bool),
}

impl DetailValue {
    /// The text of a [`DetailValue::Str`].
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(value) => Some(value),
            _ => None,
        }
    }
}

impl From<&str> for DetailValue {
    fn from(value: &str) -> Self {
        Self::Str(value.to_owned())
    }
}

impl From<String> for DetailValue {
    fn from(value: String) -> Self {
        Self::Str(value)
    }
}

impl From<i64> for DetailValue {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

impl From<u16> for DetailValue {
    fn from(value: u16) -> Self {
        Self::Int(i64::from(value))
    }
}

impl From<f64> for DetailValue {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

impl From<bool> for DetailValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl Serialize for DetailValue {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Str(value) => serializer.serialize_str(value),
            Self::Int(value) => serializer.serialize_i64(*value),
            Self::Float(value) => serializer.serialize_f64(*value),
            Self::Bool(value) => serializer.serialize_bool(*value),
        }
    }
}

/// Extra context of an error. It must never carry tokens, secrets or other
/// credentials: it is meant to be logged and serialised.
pub type ErrorDetails = BTreeMap<&'static str, DetailValue>;

/// What may reach an end user: the code and the registry's generic message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PublicError {
    /// Stable code.
    pub code: ErrorCode,
    /// Generic message of the registry.
    pub message: &'static str,
}

/// Every failure raised by the SDK.
///
/// `message` and `details` carry what a developer needs (a provider's
/// description, a scope name) and belong in logs, not in responses: answer with
/// [`AuthAiError::to_public_json`].
#[derive(Debug, thiserror::Error)]
#[error("{code}: {message}")]
pub struct AuthAiError {
    code: ErrorCode,
    message: String,
    details: ErrorDetails,
    #[source]
    source: Option<Box<dyn StdError + Send + Sync>>,
}

/// Result alias of the SDK.
pub type Result<T> = std::result::Result<T, AuthAiError>;

impl AuthAiError {
    /// An error carrying the generic message of its code.
    #[must_use]
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            message: code.default_message().to_owned(),
            details: ErrorDetails::new(),
            source: None,
        }
    }

    /// Replaces the generic message with one meant for developers.
    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    /// Adds one detail.
    #[must_use]
    pub fn with_detail(mut self, key: &'static str, value: impl Into<DetailValue>) -> Self {
        self.details.insert(key, value.into());
        self
    }

    /// Records the underlying cause.
    #[must_use]
    pub fn with_source(mut self, source: impl StdError + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// The stable code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// The developer-facing message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The developer-facing details.
    #[must_use]
    pub const fn details(&self) -> &ErrorDetails {
        &self.details
    }

    /// One detail by name.
    #[must_use]
    pub fn detail(&self, key: &str) -> Option<&DetailValue> {
        self.details.get(key)
    }

    /// The `oauthError` detail of a refused token request, when there is one.
    #[must_use]
    pub fn oauth_error(&self) -> Option<&str> {
        self.detail("oauthError").and_then(DetailValue::as_str)
    }

    /// The code and the registry's generic message, which may reach an end user.
    #[must_use]
    pub const fn to_public(&self) -> PublicError {
        PublicError {
            code: self.code,
            message: self.code.default_message(),
        }
    }

    /// [`AuthAiError::to_public`] as the JSON body of a response.
    #[must_use]
    pub fn to_public_json(&self) -> serde_json::Value {
        serde_json::json!({ "code": self.code, "message": self.code.default_message() })
    }

    /// The developer-facing JSON form, for logs: code, message and details.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let mut body = serde_json::Map::new();
        body.insert("code".to_owned(), serde_json::json!(self.code));
        body.insert("message".to_owned(), serde_json::json!(self.message));
        if !self.details.is_empty() {
            body.insert("details".to_owned(), serde_json::json!(self.details));
        }
        serde_json::Value::Object(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_round_trips_every_code() {
        for code in ErrorCode::ALL {
            assert_eq!(ErrorCode::from_wire(code.as_str()), Some(code));
            assert!(!code.default_message().is_empty());
        }
        assert_eq!(ErrorCode::from_wire("NOPE_001"), None);
        assert_eq!(ErrorCode::from_wire("cfg_001"), None);
    }

    #[test]
    fn public_form_never_carries_the_detailed_message() {
        let err = ErrorCode::Oidc003
            .error()
            .with_message("the provider said: client secret rejected")
            .with_detail("status", 401_u16);
        assert_eq!(
            err.to_public_json(),
            serde_json::json!({ "code": "OIDC_003", "message": "Token request failed" })
        );
        assert_eq!(err.to_json()["details"]["status"], 401);
        assert_eq!(err.message(), "the provider said: client secret rejected");
    }

    #[test]
    fn display_names_the_code() {
        assert_eq!(
            ErrorCode::Tok001.error().to_string(),
            "TOK_001: Token verification failed"
        );
    }

    #[test]
    fn source_is_exposed_through_the_standard_trait() {
        let cause = std::io::Error::other("boom");
        let err = ErrorCode::Api001.error().with_source(cause);
        assert!(StdError::source(&err).is_some());
    }

    #[test]
    fn oauth_error_reads_the_detail() {
        let err = ErrorCode::Oidc003
            .error()
            .with_detail("oauthError", "invalid_grant");
        assert_eq!(err.oauth_error(), Some("invalid_grant"));
        assert_eq!(ErrorCode::Oidc003.error().oauth_error(), None);
    }
}
