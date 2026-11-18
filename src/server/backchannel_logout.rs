//! Handler of the application's OIDC back-channel logout endpoint.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use jsonwebtoken::decode_header;
use serde_json::{Map, Value};

use crate::client::AuthClient;
use crate::error::{AuthAiError, ErrorCode, Result};
use crate::messages::{
    BoxFuture, ErrorCallback, NO_STORE, WebRequest, WebResponse, json_response, pair,
};
use crate::util::now_unix_f64;

/// The event a logout token must carry.
pub const LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
/// The `typ` header of a logout token.
pub const LOGOUT_TOKEN_TYP: &str = "logout+jwt";
/// auth-service issues 120 s tokens; anything far beyond is not one of its.
pub const MAX_LOGOUT_TOKEN_LIFETIME_SECONDS: f64 = 600.0;
/// The largest body the endpoint reads.
pub const MAX_BODY_BYTES: usize = 16_384;

/// Remembers the `jti` of accepted logout tokens until they expire.
///
/// Share it across replicas (e.g. a Redis `SET NX PX`): a per-process store
/// only stops replays that hit the same instance.
#[async_trait]
pub trait ReplayStore: Send + Sync {
    /// Returns `true` the first time a `jti` is claimed, `false` on a replay.
    async fn claim(&self, jti: &str, expires_at: f64) -> Result<bool>;
}

/// Keeps the `jti` values in the process.
#[derive(Debug, Default)]
pub struct MemoryReplayStore {
    seen: Mutex<HashMap<String, f64>>,
}

impl MemoryReplayStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ReplayStore for MemoryReplayStore {
    async fn claim(&self, jti: &str, expires_at: f64) -> Result<bool> {
        let now = now_unix_f64();
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.retain(|_, expiry| *expiry > now);
        if seen.contains_key(jti) {
            return Ok(false);
        }
        seen.insert(jti.to_owned(), expires_at);
        Ok(true)
    }
}

/// The claims of a valid logout token.
#[derive(Debug, Clone, PartialEq)]
pub struct LogoutTokenClaims {
    /// The provider session to end.
    pub sid: String,
    /// The user.
    pub sub: String,
    /// The token id.
    pub jti: String,
    /// Issue time, in unix seconds.
    pub iat: f64,
    /// Expiry, in unix seconds.
    pub exp: f64,
}

fn rejected(message: &str) -> AuthAiError {
    AuthAiError::new(ErrorCode::Tok001).with_message(message.to_owned())
}

fn text<'a>(payload: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    payload.get(name).and_then(Value::as_str)
}

/// Validates an OIDC Back-Channel Logout token and records its `jti`.
///
/// auth-service always names both the session and the user.
///
/// # Errors
/// `TOK_001` for any token that is not a fresh, well-formed logout token.
pub async fn verify_logout_token(
    auth: &AuthClient,
    token: &str,
    replay_store: &dyn ReplayStore,
    allow_missing_typ: bool,
) -> Result<LogoutTokenClaims> {
    let client_id = auth.config().client_id();
    let payload = if allow_missing_typ {
        let header = decode_header(token)
            .map_err(|err| rejected("The logout token is malformed").with_source(err))?;
        if let Some(typ) = header.typ.as_deref()
            && typ != LOGOUT_TOKEN_TYP
            && typ != format!("application/{LOGOUT_TOKEN_TYP}")
        {
            return Err(rejected("The logout token has an unexpected typ header"));
        }
        auth.verify_jwt(token, client_id, None).await?
    } else {
        auth.verify_jwt(token, client_id, Some(LOGOUT_TOKEN_TYP))
            .await?
    };

    if !payload
        .get("events")
        .and_then(Value::as_object)
        .is_some_and(|events| events.contains_key(LOGOUT_EVENT))
    {
        return Err(rejected(
            "The logout token lacks the back-channel logout event",
        ));
    }
    if payload.contains_key("nonce") {
        return Err(rejected("A logout token must not carry a nonce"));
    }
    let (Some(jti), Some(sid)) = (
        text(&payload, "jti").filter(|v| !v.is_empty()),
        text(&payload, "sid").filter(|v| !v.is_empty()),
    ) else {
        return Err(rejected("The logout token lacks jti or sid"));
    };
    let (Some(sub), Some(iat), Some(exp)) = (
        text(&payload, "sub"),
        payload.get("iat").and_then(Value::as_f64),
        payload.get("exp").and_then(Value::as_f64),
    ) else {
        return Err(rejected("The logout token lacks sub, iat or exp"));
    };
    let tolerance = auth.config().clock_tolerance_seconds() as f64;
    if iat > now_unix_f64() + tolerance || exp - iat > MAX_LOGOUT_TOKEN_LIFETIME_SECONDS {
        return Err(rejected("The logout token has an implausible lifetime"));
    }
    if !replay_store.claim(jti, exp).await? {
        return Err(rejected("The logout token was already used"));
    }
    Ok(LogoutTokenClaims {
        sid: sid.to_owned(),
        sub: sub.to_owned(),
        jti: jti.to_owned(),
        iat,
        exp,
    })
}

/// What the application is told when a provider session ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackchannelLogoutEvent {
    /// End every local session whose stored `sid` equals this one.
    pub sid: String,
    /// For per-user state, when you keep any.
    pub sub: String,
}

/// Called for every accepted logout token.
pub type LogoutCallback =
    Arc<dyn Fn(BackchannelLogoutEvent) -> BoxFuture<'static, Result<()>> + Send + Sync>;

fn error_body(status: u16, error: &str) -> WebResponse {
    json_response(&serde_json::json!({ "error": error }), status, Vec::new())
}

/// Handler of the application's back-channel logout endpoint.
///
/// It is called without cookies or credentials: mount it outside any session or
/// CSRF protection. `on_error` receives every rejected token and failed
/// callback: the response carries no detail.
pub struct BackchannelLogoutHandler {
    auth: AuthClient,
    on_logout: LogoutCallback,
    replay_store: Arc<dyn ReplayStore>,
    allow_missing_typ: bool,
    on_error: Option<ErrorCallback>,
}

impl std::fmt::Debug for BackchannelLogoutHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackchannelLogoutHandler")
            .finish_non_exhaustive()
    }
}

impl BackchannelLogoutHandler {
    /// A handler calling `on_logout` for every accepted token, with an in-memory replay store.
    #[must_use]
    pub fn new(auth: AuthClient, on_logout: LogoutCallback) -> Self {
        Self {
            auth,
            on_logout,
            replay_store: Arc::new(MemoryReplayStore::new()),
            allow_missing_typ: false,
            on_error: None,
        }
    }

    /// Replaces the in-memory replay store, e.g. by one shared across replicas.
    #[must_use]
    pub fn replay_store(mut self, store: Arc<dyn ReplayStore>) -> Self {
        self.replay_store = store;
        self
    }

    /// Accepts a missing `typ` header: only for a known non-conforming provider.
    #[must_use]
    pub const fn allow_missing_typ(mut self, allow: bool) -> Self {
        self.allow_missing_typ = allow;
        self
    }

    /// Receives every failure.
    #[must_use]
    pub fn on_error(mut self, callback: ErrorCallback) -> Self {
        self.on_error = Some(callback);
        self
    }

    /// Answers one request to the endpoint.
    pub async fn handle(&self, request: &WebRequest) -> WebResponse {
        if request.method != "POST" {
            return WebResponse::new(
                405,
                vec![pair("cache-control", NO_STORE), pair("allow", "POST")],
            );
        }
        let content_type = request
            .header("content-type")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !content_type.starts_with("application/x-www-form-urlencoded") {
            return error_body(400, "invalid_request");
        }
        let declared = request
            .header("content-length")
            .and_then(|length| length.parse::<usize>().ok());
        if declared.is_some_and(|length| length > MAX_BODY_BYTES)
            || request.body.len() > MAX_BODY_BYTES
        {
            return error_body(400, "invalid_request");
        }
        let Some(logout_token) = url::form_urlencoded::parse(&request.body)
            .find(|(name, _)| name == "logout_token")
            .map(|(_, value)| value.into_owned())
            .filter(|value| !value.is_empty())
        else {
            return error_body(400, "invalid_request");
        };

        let claims = match verify_logout_token(
            &self.auth,
            &logout_token,
            self.replay_store.as_ref(),
            self.allow_missing_typ,
        )
        .await
        {
            Ok(claims) => claims,
            Err(err) => {
                self.report(&err);
                return error_body(400, "invalid_request");
            }
        };
        if let Err(err) = (self.on_logout)(BackchannelLogoutEvent {
            sid: claims.sid,
            sub: claims.sub,
        })
        .await
        {
            self.report(&err);
            return error_body(500, "server_error");
        }
        WebResponse::new(200, vec![pair("cache-control", NO_STORE)])
    }

    fn report(&self, err: &AuthAiError) {
        if let Some(callback) = &self.on_error {
            callback(err);
        }
    }
}
