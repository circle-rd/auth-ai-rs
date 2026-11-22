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

#[derive(Clone)]
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
        let response = self
            .send_authenticated(method, path, scope, query, body)
            .await?;
        response
            .parse_json()
            .map_err(|err| AuthAiError::new(ErrorCode::Api002).with_source(err))
    }

    /// Same authentication and retry path as [`JsonHttp::request`], for a `204` answer.
    // The self-service endpoints answer a body today; the 204 path belongs to the client.
    #[allow(
        dead_code,
        reason = "the authenticated JSON client exposes the 204 path for endpoints that answer no body"
    )]
    pub(crate) async fn request_empty(
        &self,
        method: Method,
        path: &str,
        scope: &str,
        query: &[(&str, Option<String>)],
        body: Option<&Value>,
    ) -> Result<()> {
        self.send_authenticated(method, path, scope, query, body)
            .await
            .map(|_| ())
    }

    async fn send_authenticated(
        &self,
        method: Method,
        path: &str,
        scope: &str,
        query: &[(&str, Option<String>)],
        body: Option<&Value>,
    ) -> Result<HttpResponse> {
        let mut response = self.send(method, path, scope, query, body).await?;
        // A revoked or rotated credential surfaces as 401: retry once with a fresh token.
        if response.status == 401 {
            self.tokens.invalidate(scope);
            response = self.send(method, path, scope, query, body).await?;
        }
        if !response.is_success() {
            return Err(to_error(&response));
        }
        Ok(response)
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};

    use async_trait::async_trait;

    use super::*;
    use crate::secret::SecretString;
    use crate::transport::TransportError;

    #[derive(Debug)]
    struct Scripted {
        statuses: Mutex<Vec<u16>>,
        sent: Mutex<Vec<HttpRequest>>,
    }

    #[async_trait]
    impl Transport for Scripted {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> std::result::Result<HttpResponse, TransportError> {
            self.sent
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(request);
            let status = {
                let mut statuses = self.statuses.lock().unwrap_or_else(PoisonError::into_inner);
                if statuses.is_empty() {
                    500
                } else {
                    statuses.remove(0)
                }
            };
            Ok(HttpResponse {
                status,
                headers: Vec::new(),
                body: Vec::new(),
            })
        }
    }

    #[derive(Debug)]
    struct Tokens(AtomicU32);

    #[async_trait]
    impl HttpTokens for Tokens {
        async fn get_token(&self, _key: &str) -> Result<SecretString> {
            let count = self.0.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(SecretString::new(format!("token-{count}")))
        }

        fn invalidate(&self, _key: &str) {}
    }

    fn client(statuses: Vec<u16>) -> (JsonHttp, Arc<Scripted>, Arc<Tokens>) {
        let transport = Arc::new(Scripted {
            statuses: Mutex::new(statuses),
            sent: Mutex::new(Vec::new()),
        });
        let tokens = Arc::new(Tokens(AtomicU32::new(0)));
        let http = JsonHttp::new(
            "https://api.example",
            Arc::clone(&transport) as Arc<dyn Transport>,
            std::time::Duration::from_secs(1),
            Arc::clone(&tokens) as Arc<dyn HttpTokens>,
        );
        (http, transport, tokens)
    }

    #[tokio::test]
    async fn an_empty_answer_needs_no_body() {
        let (http, transport, _) = client(vec![204]);
        http.request_empty(
            Method::Delete,
            "/api/user/resources/1",
            "resources",
            &[],
            None,
        )
        .await
        .unwrap();
        let sent = transport
            .sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].method, Method::Delete);
    }

    #[tokio::test]
    async fn a_refused_token_is_replaced_once_before_an_empty_answer() {
        let (http, transport, tokens) = client(vec![401, 204]);
        http.request_empty(Method::Put, "/api/user/resources/1", "resources", &[], None)
            .await
            .unwrap();
        assert_eq!(tokens.0.load(Ordering::SeqCst), 2);
        assert_eq!(
            transport
                .sent
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len(),
            2
        );
    }
}
