//! The framework-agnostic view of an HTTP exchange the SDK's handlers work on.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::error::AuthAiError;

/// `Cache-Control` value of every response that carries or concerns a credential.
pub const NO_STORE: &str = "no-store";

/// A boxed future, for the callbacks the SDK awaits.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Receives the failures the SDK reports instead of answering them in detail.
pub type ErrorCallback = Arc<dyn Fn(&AuthAiError) + Send + Sync>;

/// The framework-agnostic view of an incoming HTTP request.
///
/// Adapters build it from their own request type. `url` is absolute: the SDK
/// only reads its path and query, never trusts its host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebRequest {
    /// Method, in uppercase.
    pub method: String,
    /// Absolute URL.
    pub url: String,
    /// Header pairs, names in lowercase.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl WebRequest {
    /// A request without headers or body.
    #[must_use]
    pub fn new(method: &str, url: impl Into<String>) -> Self {
        Self {
            method: method.to_ascii_uppercase(),
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Adds a header; the name is lowercased.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_ascii_lowercase(), value.into()));
        self
    }

    /// Sets the body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// The first header of that name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A response the SDK asks the framework adapter to send.
///
/// Headers are a list of pairs: `Set-Cookie` may appear several times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebResponse {
    /// Status code.
    pub status: u16,
    /// Header pairs, names in lowercase.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl WebResponse {
    /// A response with no body.
    #[must_use]
    pub const fn new(status: u16, headers: Vec<(String, String)>) -> Self {
        Self {
            status,
            headers,
            body: Vec::new(),
        }
    }

    /// The first header of that name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.header_values(name).into_iter().next()
    }

    /// Every header of that name, in order.
    #[must_use]
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// The body as JSON, `None` when it is not.
    #[must_use]
    pub fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

pub(crate) fn pair(name: &str, value: &str) -> (String, String) {
    (name.to_owned(), value.to_owned())
}

/// A JSON answer, never cached.
#[must_use]
pub fn json_response(
    body: &serde_json::Value,
    status: u16,
    headers: Vec<(String, String)>,
) -> WebResponse {
    let mut all = headers;
    all.push(pair("content-type", "application/json"));
    all.push(pair("cache-control", NO_STORE));
    // Serialising a `Value` cannot fail: its keys are strings.
    WebResponse {
        status,
        headers: all,
        body: serde_json::to_vec(body).unwrap_or_default(),
    }
}

/// A redirect, never cached.
#[must_use]
pub fn redirect_response(
    location: &str,
    status: u16,
    headers: Vec<(String, String)>,
) -> WebResponse {
    let mut all = headers;
    all.push(pair("location", location));
    all.push(pair("cache-control", NO_STORE));
    WebResponse::new(status, all)
}
