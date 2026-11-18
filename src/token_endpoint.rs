//! Calls to the provider's token, UserInfo, revocation and introspection endpoints.
//!
//! The client authentication follows RFC 6749 §2.3.1: Basic credentials are
//! form-urlencoded before the base64 encoding. Stateless, hence safe to share
//! between concurrent users.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use serde_json::{Map, Value};
use url::Url;
use url::form_urlencoded::byte_serialize;

use crate::config::{AuthClientConfig, TokenEndpointAuthMethod};
use crate::error::{AuthAiError, ErrorCode, Result};
use crate::secret::SecretString;
use crate::transport::{HttpRequest, HttpResponse, Method, Transport};
use crate::types::TokenSet;
use crate::util::now_unix_f64;

const TOKEN_EXPIRY_FALLBACK_SECONDS: f64 = 300.0;

/// RFC 6749 §5.1 answer of the token endpoint.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    #[serde(default)]
    expires_in: Option<f64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.is_empty())
}

fn to_token_set(response: TokenResponse) -> Result<TokenSet> {
    if !response.token_type.eq_ignore_ascii_case("bearer") {
        return Err(AuthAiError::new(ErrorCode::Oidc003)
            .with_message("The token response is not a bearer token"));
    }
    let lifetime = response
        .expires_in
        .filter(|seconds| seconds.is_finite())
        .unwrap_or(TOKEN_EXPIRY_FALLBACK_SECONDS);
    Ok(TokenSet {
        access_token: SecretString::new(response.access_token),
        token_type: response.token_type,
        expires_at: (now_unix_f64() + lifetime) as i64,
        scope: non_empty(response.scope),
        refresh_token: non_empty(response.refresh_token).map(SecretString::new),
        id_token: non_empty(response.id_token).map(SecretString::new),
    })
}

fn quote_plus(value: &str) -> String {
    byte_serialize(value.as_bytes()).collect()
}

pub(crate) struct ProviderEndpoints {
    config: AuthClientConfig,
    transport: Arc<dyn Transport>,
}

impl ProviderEndpoints {
    pub(crate) const fn new(config: AuthClientConfig, transport: Arc<dyn Transport>) -> Self {
        Self { config, transport }
    }

    /// POSTs `form` with the client's credentials. Transport errors become `OIDC_003`.
    pub(crate) async fn post(&self, url: &str, form: &[(&str, &str)]) -> Result<HttpResponse> {
        let mut request = HttpRequest::new(Method::Post, url, self.config.timeout())
            .with_header("accept", "application/json");
        let mut pairs: Vec<(&str, &str)> = form.to_vec();
        match self.config.client_secret() {
            None => pairs.push(("client_id", self.config.client_id())),
            Some(secret)
                if self.config.token_endpoint_auth_method()
                    == TokenEndpointAuthMethod::ClientSecretPost =>
            {
                pairs.push(("client_id", self.config.client_id()));
                pairs.push(("client_secret", secret.expose_secret()));
            }
            Some(secret) => {
                let credentials = format!(
                    "{}:{}",
                    quote_plus(self.config.client_id()),
                    quote_plus(secret.expose_secret())
                );
                request = request.with_header(
                    "authorization",
                    format!("Basic {}", STANDARD.encode(credentials)),
                );
            }
        }
        request = request.with_form(pairs);
        self.transport
            .send(request)
            .await
            .map_err(|err| AuthAiError::new(ErrorCode::Oidc003).with_source(err))
    }

    /// GETs UserInfo with the access token. The token never enters an error.
    pub(crate) async fn userinfo_request(
        &self,
        url: &str,
        access_token: &str,
    ) -> Result<Map<String, Value>> {
        let scheme = Url::parse(url)
            .map_err(|err| {
                AuthAiError::new(ErrorCode::Oidc003)
                    .with_message("The userinfo_endpoint is not a valid URL")
                    .with_source(err)
            })?
            .scheme()
            .to_owned();
        if scheme != "https" {
            return Err(AuthAiError::new(ErrorCode::Oidc003)
                .with_message("The userinfo_endpoint is not an HTTPS URL"));
        }
        let request = HttpRequest::new(Method::Get, url, self.config.timeout())
            .with_header("authorization", format!("Bearer {access_token}"))
            .with_header("accept", "application/json");
        let response = self.transport.send(request).await.map_err(|_| {
            AuthAiError::new(ErrorCode::Oidc003).with_message("The UserInfo request failed")
        })?;
        if !response.is_success() {
            return Err(AuthAiError::new(ErrorCode::Oidc003)
                .with_message(format!(
                    "UserInfo endpoint answered HTTP {}",
                    response.status
                ))
                .with_detail("status", response.status));
        }
        let body: Value = response.parse_json().map_err(|err| {
            AuthAiError::new(ErrorCode::Oidc003)
                .with_message("The UserInfo response is not JSON")
                .with_source(err)
        })?;
        match body {
            Value::Object(claims) => Ok(claims),
            _ => Err(AuthAiError::new(ErrorCode::Oidc003)
                .with_message("The UserInfo response has an unexpected shape")),
        }
    }

    pub(crate) async fn token_request(&self, url: &str, form: &[(&str, &str)]) -> Result<TokenSet> {
        let response = self.post(url, form).await?;
        let body = response.json_value().filter(Value::is_object);
        if !response.is_success() {
            return Err(rejection(&response, body.as_ref()));
        }
        let parsed: TokenResponse =
            serde_json::from_value(body.unwrap_or(Value::Null)).map_err(|err| {
                AuthAiError::new(ErrorCode::Oidc003)
                    .with_message("The token response has an unexpected shape")
                    .with_source(err)
            })?;
        to_token_set(parsed)
    }
}

/// Maps a refusal to `OIDC_003`, keeping only the RFC 6749 error fields (no credential).
fn rejection(response: &HttpResponse, body: Option<&Value>) -> AuthAiError {
    let status = response.status;
    if let Some(error) = body
        .and_then(|body| body.get("error"))
        .and_then(Value::as_str)
    {
        let mut err = AuthAiError::new(ErrorCode::Oidc003)
            .with_message(format!("Token endpoint rejected the request: {error}"))
            .with_detail("oauthError", error)
            .with_detail("status", status);
        if let Some(description) = body
            .and_then(|body| body.get("error_description"))
            .and_then(Value::as_str)
        {
            err = err.with_detail("description", description);
        }
        return err;
    }
    if status == 401 && response.header("www-authenticate").is_some() {
        return AuthAiError::new(ErrorCode::Oidc003)
            .with_message(format!("Token endpoint challenged the request (HTTP {status}): check client_id and client_secret"))
            .with_detail("status", status);
    }
    AuthAiError::new(ErrorCode::Oidc003)
        .with_message(format!("Token endpoint answered HTTP {status}"))
        .with_detail("status", status)
}
