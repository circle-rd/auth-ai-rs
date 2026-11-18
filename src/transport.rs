//! The HTTP layer every call of the SDK goes through.
//!
//! [`Transport`] is the seam to replace the default `reqwest` client: to add a
//! proxy, an observability layer or an in-memory identity provider in tests.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::de::DeserializeOwned;

use crate::error::{AuthAiError, ErrorCode, Result};
use crate::util::form_encode;

/// The largest answer the default transport reads. A bigger one is a failure.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// HTTP method: the SDK only reads and posts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

impl Method {
    /// The method token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// A request the SDK asks a [`Transport`] to send.
///
/// Redirects must not be followed: a redirect from the identity provider or the
/// gateway is refused.
#[derive(Clone)]
pub struct HttpRequest {
    /// Method.
    pub method: Method,
    /// Absolute URL.
    pub url: String,
    /// Header pairs, names in lowercase.
    pub headers: Vec<(String, String)>,
    /// Body, when there is one.
    pub body: Option<Vec<u8>>,
    /// Upper bound of the whole exchange.
    pub timeout: Duration,
}

impl HttpRequest {
    /// A request without body.
    #[must_use]
    pub fn new(method: Method, url: impl Into<String>, timeout: Duration) -> Self {
        Self {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: None,
            timeout,
        }
    }

    /// Adds a header; the name is lowercased.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_ascii_lowercase(), value.into()));
        self
    }

    /// Adds an `application/x-www-form-urlencoded` body.
    #[must_use]
    pub fn with_form<'a, I>(mut self, pairs: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        self.body = Some(form_encode(pairs).into_bytes());
        self.with_header("content-type", "application/x-www-form-urlencoded")
    }

    /// Adds a JSON body.
    #[must_use]
    pub fn with_json(mut self, body: &serde_json::Value) -> Self {
        self.body = Some(body.to_string().into_bytes());
        self.with_header("content-type", "application/json")
    }

    /// The first header of that name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        find_header(&self.headers, name)
    }
}

// Authorization and the body carry credentials: a debug print must not show them.
impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
            )
            .field("body_bytes", &self.body.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

/// An answer to an [`HttpRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Header pairs, names in lowercase.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// A response with a JSON body.
    #[must_use]
    pub fn json(status: u16, body: &serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: body.to_string().into_bytes(),
        }
    }

    /// Whether the status is 2xx.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// The first header of that name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        find_header(&self.headers, name)
    }

    /// The body as a typed JSON document.
    ///
    /// # Errors
    /// The body is not JSON of that shape.
    pub fn parse_json<T: DeserializeOwned>(&self) -> std::result::Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }

    /// The body as untyped JSON, `None` when it is not JSON.
    #[must_use]
    pub fn json_value(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// The exchange failed before a complete answer was read: connection, TLS,
/// timeout or an oversized body.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TransportError(String);

impl TransportError {
    /// A failure described for developers; it must not contain a credential.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// Sends the requests of the SDK.
#[async_trait]
pub trait Transport: Send + Sync + fmt::Debug {
    /// Performs the exchange. A non-2xx status is an answer, not an error.
    async fn send(&self, request: HttpRequest)
    -> std::result::Result<HttpResponse, TransportError>;
}

/// The default [`Transport`]: `reqwest` with rustls, HTTP/2 negotiated over TLS
/// (HTTP/1.1 fallback), gzip and brotli responses, and no redirect followed.
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Builds the client.
    ///
    /// # Errors
    /// `CFG_001` when the TLS backend cannot be initialised.
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("auth-ai-rs/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|err| {
                AuthAiError::new(ErrorCode::Cfg001)
                    .with_message("The HTTP client could not be built")
                    .with_source(err.without_url())
            })?;
        Ok(Self { client })
    }
}

#[async_trait]
impl Transport for ReqwestTransport {
    async fn send(
        &self,
        request: HttpRequest,
    ) -> std::result::Result<HttpResponse, TransportError> {
        let method = match request.method {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
        };
        let mut builder = self
            .client
            .request(method, &request.url)
            .timeout(request.timeout);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let mut response = builder.send().await.map_err(describe)?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|text| (name.as_str().to_owned(), text.to_owned()))
            })
            .collect();
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(describe)? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(TransportError::new("The response exceeds the size limit"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

// The request URL stays out of the message: it may carry an identifier a log should not.
fn describe(err: reqwest::Error) -> TransportError {
    let kind = if err.is_timeout() {
        "timed out"
    } else if err.is_connect() {
        "could not connect"
    } else if err.is_decode() {
        "answered an undecodable body"
    } else {
        "failed"
    };
    TransportError::new(format!("The HTTP exchange {kind}"))
}

/// The transport used when the caller supplies none.
///
/// # Errors
/// `CFG_001` when the TLS backend cannot be initialised.
pub fn default_transport() -> Result<Arc<dyn Transport>> {
    Ok(Arc::new(ReqwestTransport::new()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_headers_and_body() {
        let request = HttpRequest::new(
            Method::Post,
            "https://a.example/token",
            Duration::from_secs(1),
        )
        .with_header("Authorization", "Bearer sekrit")
        .with_form([("client_secret", "sekrit")]);
        let printed = format!("{request:?}");
        assert!(!printed.contains("sekrit"));
        assert!(printed.contains("authorization"));
        assert_eq!(request.header("AUTHORIZATION"), Some("Bearer sekrit"));
    }

    #[test]
    fn response_helpers_read_status_headers_and_json() {
        let response = HttpResponse::json(201, &serde_json::json!({ "a": 1 }));
        assert!(response.is_success());
        assert_eq!(response.header("Content-Type"), Some("application/json"));
        assert_eq!(response.json_value(), Some(serde_json::json!({ "a": 1 })));
        let broken = HttpResponse {
            status: 500,
            headers: vec![],
            body: b"no".to_vec(),
        };
        assert!(!broken.is_success());
        assert_eq!(broken.json_value(), None);
    }

    #[test]
    fn the_default_transport_builds() {
        assert!(default_transport().is_ok());
    }
}
