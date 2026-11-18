//! Axum adapter for the backend-for-frontend routes.
//!
//! [`auth_router`] serves every route below the handlers' `base_path` (mount it
//! at the root of your application: the path the handlers see must include the
//! base path). [`AuthSession`] and [`OptionalAuthSession`] are extractors for
//! your own routes, and [`AuthError`] answers an [`AuthAiError`] with the public
//! error envelope (code and generic message only).
//!
//! The application state must give out the handlers: implement
//! `FromRef<YourState> for AuthHandlers`, or use `AuthHandlers` as the state.

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{FromRef, FromRequestParts, Request, State};
use axum::http::header::{HeaderName, HeaderValue};
use axum::http::request::Parts;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;

use crate::error::{AuthAiError, ErrorCode};
use crate::messages::{WebRequest, WebResponse};
use crate::server::MAX_BODY_BYTES;
use crate::web::{AuthHandlers, Session, error_response};

fn header_pairs(headers: &axum::http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

fn absolute_url(origin: &str, uri: &Uri) -> String {
    match uri.query() {
        Some(query) => format!("{origin}{}?{query}", uri.path()),
        None => format!("{origin}{}", uri.path()),
    }
}

/// A [`WebRequest`] built on the registered origin: the `Host` header is not trusted.
///
/// The body is read only on request, capped at the size the SDK's POST routes
/// accept: the session extractors must leave it to your route.
///
/// # Errors
/// `REQ_001` when the body is larger than the SDK's routes accept.
pub async fn to_web_request(
    request: Request<Body>,
    origin: &str,
    with_body: bool,
) -> Result<WebRequest, AuthAiError> {
    let (parts, body) = request.into_parts();
    let mut web = WebRequest::new(parts.method.as_str(), absolute_url(origin, &parts.uri));
    web.headers = header_pairs(&parts.headers);
    if with_body && parts.method != axum::http::Method::GET {
        web.body = to_bytes(body, MAX_BODY_BYTES)
            .await
            .map_err(|err| {
                AuthAiError::new(ErrorCode::Req001)
                    .with_message("The request body is too large")
                    .with_source(err)
            })?
            .to_vec();
    }
    Ok(web)
}

/// The answer the SDK built, as an axum response. Repeated headers such as
/// `Set-Cookie` are kept apart.
#[must_use]
pub fn into_response(response: WebResponse) -> Response {
    let mut sent = Response::new(Body::from(response.body));
    for (name, value) in response.headers {
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        sent.headers_mut().append(name, value);
    }
    match StatusCode::from_u16(response.status) {
        Ok(status) => *sent.status_mut() = status,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    sent
}

async fn endpoint(State(handlers): State<AuthHandlers>, request: Request<Body>) -> Response {
    let web = match to_web_request(request, handlers.origin(), true).await {
        Ok(web) => web,
        Err(err) => return into_response(error_response(&err, handlers.on_error(), Vec::new())),
    };
    match handlers.handle(&web).await {
        Some(response) => into_response(response),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The router serving every route below `handlers.base_path()`.
pub fn auth_router<S>(handlers: AuthHandlers) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::<AuthHandlers>::new()
        .route(
            &format!("{}/{{*path}}", handlers.base_path()),
            any(endpoint),
        )
        .with_state(handlers)
}

/// An [`AuthAiError`] answered with the public error envelope: the code and a
/// generic message. Return it from your own routes (`Result<_, AuthError>`).
#[derive(Debug)]
pub struct AuthError(pub AuthAiError);

impl From<AuthAiError> for AuthError {
    fn from(err: AuthAiError) -> Self {
        Self(err)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        into_response(error_response(&self.0, None, Vec::new()))
    }
}

/// The handlers the state gives out, and the session of the request they read.
async fn read_session<S>(
    parts: &Parts,
    state: &S,
) -> (AuthHandlers, Result<Option<Session>, AuthAiError>)
where
    AuthHandlers: FromRef<S>,
{
    let handlers = AuthHandlers::from_ref(state);
    let mut web = WebRequest::new(
        parts.method.as_str(),
        absolute_url(handlers.origin(), &parts.uri),
    );
    web.headers = header_pairs(&parts.headers);
    let session = handlers.get_session(&web).await;
    (handlers, session)
}

fn reject(handlers: &AuthHandlers, err: &AuthAiError) -> Response {
    into_response(error_response(err, handlers.on_error(), Vec::new()))
}

/// The session of a signed-in request; a signed-out one is answered `401 SES_001`.
#[derive(Debug, Clone)]
pub struct AuthSession(pub Session);

impl<S> FromRequestParts<S> for AuthSession
where
    AuthHandlers: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match read_session(parts, state).await {
            (_, Ok(Some(session))) => Ok(Self(session)),
            (handlers, Ok(None)) => Err(reject(&handlers, &ErrorCode::Ses001.error())),
            (handlers, Err(err)) => Err(reject(&handlers, &err)),
        }
    }
}

/// The session of the request when signed in, `None` otherwise.
#[derive(Debug, Clone)]
pub struct OptionalAuthSession(pub Option<Session>);

impl<S> FromRequestParts<S> for OptionalAuthSession
where
    AuthHandlers: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match read_session(parts, state).await {
            (_, Ok(session)) => Ok(Self(session)),
            (handlers, Err(err)) => Err(reject(&handlers, &err)),
        }
    }
}
