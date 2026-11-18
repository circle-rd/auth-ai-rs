//! RFC 9728 protected-resource metadata and Bearer challenges.

use serde_json::{Value, json};
use url::Url;

use crate::client::AuthClient;
use crate::error::{AuthAiError, ErrorCode, Result};

/// RFC 9728 metadata, which lets MCP and OAuth clients find the authorization server.
///
/// `resource` is the audience this API accepts: its RFC 8707 resource identifier.
#[must_use]
pub fn protected_resource_metadata(
    auth: &AuthClient,
    resource: &str,
    scopes_supported: Option<&[&str]>,
) -> Value {
    let mut metadata = serde_json::Map::new();
    metadata.insert("resource".to_owned(), json!(resource));
    metadata.insert(
        "authorization_servers".to_owned(),
        json!([auth.config().issuer()]),
    );
    metadata.insert("bearer_methods_supported".to_owned(), json!(["header"]));
    if let Some(scopes) = scopes_supported {
        metadata.insert("scopes_supported".to_owned(), json!(scopes));
    }
    Value::Object(metadata)
}

/// Where RFC 9728 §3 serves the metadata of `resource`.
///
/// The well-known segment sits between the host and the resource path.
///
/// # Errors
/// `CFG_001` when `resource` is not an absolute URL.
pub fn protected_resource_metadata_path(resource: &str) -> Result<String> {
    let url = Url::parse(resource).map_err(|err| {
        AuthAiError::new(ErrorCode::Cfg001)
            .with_message("resource must be an absolute URL")
            .with_source(err)
    })?;
    let path = if matches!(url.path(), "" | "/") {
        ""
    } else {
        url.path()
    };
    Ok(format!("/.well-known/oauth-protected-resource{path}"))
}

/// The `error` of a Bearer challenge (RFC 6750 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerError {
    /// The token is missing, expired or invalid: answer 401.
    InvalidToken,
    /// The token lacks a scope: answer 403.
    InsufficientScope,
}

impl BearerError {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidToken => "invalid_token",
            Self::InsufficientScope => "insufficient_scope",
        }
    }
}

/// Value of the `WWW-Authenticate` header of a 401 or 403 response.
///
/// `resource_metadata_url` is the absolute URL of the metadata document,
/// advertised to unauthenticated clients.
///
/// # Errors
/// `CFG_001` when a parameter could break out of its quoted string.
pub fn bearer_challenge(
    resource_metadata_url: &str,
    error: Option<BearerError>,
    scope: Option<&str>,
) -> Result<String> {
    let mut parameters = vec![("resource_metadata", resource_metadata_url)];
    if let Some(error) = error {
        parameters.push(("error", error.as_str()));
    }
    if let Some(scope) = scope.filter(|scope| !scope.is_empty()) {
        parameters.push(("scope", scope));
    }
    for (name, value) in &parameters {
        if value.chars().any(|c| matches!(c, '"' | '\\' | '\r' | '\n')) {
            return Err(AuthAiError::new(ErrorCode::Cfg001)
                .with_message(format!("Invalid {name} in a Bearer challenge")));
        }
    }
    let rendered: Vec<String> = parameters
        .iter()
        .map(|(name, value)| format!("{name}=\"{value}\""))
        .collect();
    Ok(format!("Bearer {}", rendered.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_well_known_path_sits_between_host_and_path() {
        assert_eq!(
            protected_resource_metadata_path("https://api.example.com").unwrap(),
            "/.well-known/oauth-protected-resource"
        );
        assert_eq!(
            protected_resource_metadata_path("https://api.example.com/").unwrap(),
            "/.well-known/oauth-protected-resource"
        );
        assert_eq!(
            protected_resource_metadata_path("https://api.example.com/v1/mcp").unwrap(),
            "/.well-known/oauth-protected-resource/v1/mcp"
        );
        assert!(protected_resource_metadata_path("not a url").is_err());
    }

    #[test]
    fn a_challenge_lists_its_parameters() {
        let url = "https://api.example.com/.well-known/oauth-protected-resource";
        assert_eq!(
            bearer_challenge(url, None, None).unwrap(),
            format!("Bearer resource_metadata=\"{url}\"")
        );
        assert_eq!(
            bearer_challenge(
                url,
                Some(BearerError::InsufficientScope),
                Some("reports.read")
            )
            .unwrap(),
            format!(
                "Bearer resource_metadata=\"{url}\", error=\"insufficient_scope\", scope=\"reports.read\""
            )
        );
    }

    #[test]
    fn a_challenge_refuses_parameters_that_break_the_header() {
        for bad in ["a\"b", "a\\b", "a\r\nSet-Cookie: x", "a\nb"] {
            assert!(
                bearer_challenge("https://x.example/m", None, Some(bad)).is_err(),
                "{bad:?}"
            );
            assert!(bearer_challenge(bad, None, None).is_err(), "{bad:?}");
        }
    }
}
