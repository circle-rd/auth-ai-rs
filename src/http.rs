//! Authenticated JSON calls to the auth-service REST API.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::{AuthAiError, ErrorCode, Result};
use crate::secret::SecretString;
use crate::transport::{HttpRequest, HttpResponse, Method, Transport};
use crate::util::form_encode;

/// Supplies the bearer token of a call, by the scope or audience the endpoint requires.
#[async_trait]
pub(crate) trait HttpTokens: Send + Sync {
    async fn get_token(&self, key: &str) -> Result<SecretString>;

    /// Drops a token the API refused, so the retry mints a fresh one.
    fn invalidate(&self, key: &str);
}

#[derive(Deserialize)]
struct ApiErrorDetail {
    code: String,
    message: String,
}

#[derive(Deserialize)]
struct ApiErrorBody {
    error: ApiErrorDetail,
}

pub(crate) struct JsonHttp {
    base_url: String,
    transport: Arc<dyn Transport>,
    timeout: Duration,
    tokens: Arc<dyn HttpTokens>,
}

impl JsonHttp {
    pub(crate) fn new(
        base_url: impl Into<String>,
        transport: Arc<dyn Transport>,
        timeout: Duration,
        tokens: Arc<dyn HttpTokens>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            transport,
            timeout,
            tokens,
        }
    }

    /// `path` is relative to the base URL and its segments must already be URL-encoded.
    ///
    /// `scope` is the key passed to the token supplier: a machine scope, or an audience.
    pub(crate) async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        scope: &str,
        query: &[(&str, Option<String>)],
        body: Option<&Value>,
    ) -> Result<T> {
        let mut response = self.send(method, path, scope, query, body).await?;
        // A revoked or rotated credential surfaces as 401: retry once with a fresh token.
        if response.status == 401 {
            self.tokens.invalidate(scope);
            response = self.send(method, path, scope, query, body).await?;
        }
        if !response.is_success() {
            return Err(to_error(&response));
        }
        response
            .parse_json()
            .map_err(|err| AuthAiError::new(ErrorCode::Api002).with_source(err))
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        scope: &str,
        query: &[(&str, Option<String>)],
        body: Option<&Value>,
    ) -> Result<HttpResponse> {
        let token = self.tokens.get_token(scope).await?;
        let params: Vec<(&str, &str)> = query
            .iter()
            .filter_map(|(name, value)| value.as_deref().map(|value| (*name, value)))
            .collect();
        let mut url = format!("{}{path}", self.base_url);
        if !params.is_empty() {
            url.push('?');
            url.push_str(&form_encode(params));
        }
        let mut request = HttpRequest::new(method, url, self.timeout)
            .with_header("authorization", format!("Bearer {}", token.expose_secret()))
            .with_header("accept", "application/json");
        if let Some(body) = body {
            request = request.with_json(body);
        }
        self.transport.send(request).await.map_err(|err| {
            AuthAiError::new(ErrorCode::Api001)
                .with_message("auth-service is unreachable")
                .with_source(err)
        })
    }
}

fn to_error(response: &HttpResponse) -> AuthAiError {
    let status = response.status;
    match response.parse_json::<ApiErrorBody>() {
        Ok(parsed) => AuthAiError::new(ErrorCode::Api001)
            .with_message(format!(
                "auth-service answered {status} {}: {}",
                parsed.error.code, parsed.error.message
            ))
            .with_detail("status", status)
            .with_detail("apiCode", parsed.error.code),
        Err(_) => AuthAiError::new(ErrorCode::Api001)
            .with_message(format!("auth-service answered {status}"))
            .with_detail("status", status),
    }
}
