//! Backend-for-frontend sign-in: the browser holds an opaque session cookie, never a token.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use url::Url;

use crate::ai::AiClient;
use crate::client::AuthClient;
use crate::error::{AuthAiError, ErrorCode, Result};
use crate::grants::GrantManager;
use crate::messages::{BoxFuture, ErrorCallback, WebRequest, WebResponse, pair};
use crate::secret::SecretString;
use crate::server::{MemoryReplayStore, ReplayStore};
use crate::web::ai_routes;
use crate::web::cookies::cookie_name;
use crate::web::http::error_response;
use crate::web::seal::{SealKey, derive_seal_key};
use crate::web::sessions::{Session, SessionStore};

/// Lifetime of the sealed sign-in and sign-out cookies.
pub const HANDSHAKE_TTL_SECONDS: i64 = 600;
/// Absolute lifetime of a session unless configured otherwise: 8 hours.
pub const DEFAULT_SESSION_TTL_SECONDS: i64 = 8 * 3600;
/// How often claims are renewed unless configured otherwise: 15 minutes.
pub const DEFAULT_CLAIMS_RENEW_SECONDS: i64 = 900;

/// Called after sessions end (sign-out or back-channel logout): close sockets, drop caches.
pub type SessionsEndedCallback =
    Arc<dyn Fn(Vec<Session>) -> BoxFuture<'static, Result<()>> + Send + Sync>;

pub(super) struct Inner {
    pub(super) auth: AuthClient,
    pub(super) grants: GrantManager,
    pub(super) sessions: Arc<dyn SessionStore>,
    pub(super) default_redirect: String,
    pub(super) session_ttl: i64,
    pub(super) renew_seconds: i64,
    pub(super) require_provider_session: bool,
    pub(super) allow_missing_logout_token_typ: bool,
    pub(super) error_redirect: Option<String>,
    pub(super) ai: Option<AiClient>,
    pub(super) replay_store: Arc<dyn ReplayStore>,
    pub(super) on_sessions_ended: Option<SessionsEndedCallback>,
    pub(super) on_error: Option<ErrorCallback>,
    pub(super) origin: String,
    pub(super) base_path: String,
    pub(super) secure: bool,
    pub(super) key: SealKey,
    pub(super) session_cookie: String,
    pub(super) login_cookie: String,
    pub(super) logout_cookie: String,
    // Two simultaneous requests of one session share a single renewal.
    pub(super) renewing: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

/// Backend-for-frontend sign-in: the browser holds an opaque session cookie, never a token.
///
/// Mount [`AuthHandlers::handle`] on every request below `base_path`. The
/// `redirect_uri` of the client must be `<origin><base_path>/callback`. Clones
/// share their state.
#[derive(Clone)]
pub struct AuthHandlers {
    pub(super) inner: Arc<Inner>,
}

impl std::fmt::Debug for AuthHandlers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthHandlers")
            .field("origin", &self.inner.origin)
            .field("base_path", &self.inner.base_path)
            .finish_non_exhaustive()
    }
}

/// Collects the options of [`AuthHandlers`]; [`build`](Self::build) validates them.
///
/// - `secret`: at least 32 random characters, seals the sign-in cookie. Keep it
///   out of source control.
/// - `base_path`: where the routes are mounted, `/auth` by default.
/// - `default_redirect`: where users land after sign-in or sign-out without a target.
/// - `session_ttl_seconds`: absolute lifetime of a session.
/// - `claims_renew_seconds`: how often claims (roles, features…) are renewed.
/// - `require_provider_session`: refuse an ID token without `sid`: no
///   back-channel logout could ever reach it.
/// - `allow_missing_logout_token_typ`: accept a missing `typ` only for a known
///   non-conforming provider; leave disabled by default.
/// - `error_redirect`: redirect target of a failed sign-in, with
///   `?error=<code>`; JSON when unset.
/// - `ai`: adds `/wallet`, `/wallet/stats` and `/models` for the frontend, read
///   with the user's tokens.
/// - `on_sessions_ended`: called after sessions end.
/// - `on_error`: receives unexpected failures and the ones the response must
///   not detail.
pub struct AuthHandlersBuilder {
    auth: AuthClient,
    grants: GrantManager,
    sessions: Arc<dyn SessionStore>,
    secret: SecretString,
    base_path: String,
    default_redirect: String,
    session_ttl: i64,
    renew_seconds: i64,
    require_provider_session: bool,
    allow_missing_logout_token_typ: bool,
    error_redirect: Option<String>,
    ai: Option<AiClient>,
    replay_store: Option<Arc<dyn ReplayStore>>,
    on_sessions_ended: Option<SessionsEndedCallback>,
    on_error: Option<ErrorCallback>,
}

impl AuthHandlersBuilder {
    /// Sets where the routes are mounted.
    #[must_use]
    pub fn base_path(mut self, base_path: impl Into<String>) -> Self {
        self.base_path = base_path.into();
        self
    }

    /// Sets where users land without a target.
    #[must_use]
    pub fn default_redirect(mut self, path: impl Into<String>) -> Self {
        self.default_redirect = path.into();
        self
    }

    /// Sets the absolute lifetime of a session.
    #[must_use]
    pub const fn session_ttl_seconds(mut self, seconds: i64) -> Self {
        self.session_ttl = seconds;
        self
    }

    /// Sets how often claims are renewed.
    #[must_use]
    pub const fn claims_renew_seconds(mut self, seconds: i64) -> Self {
        self.renew_seconds = seconds;
        self
    }

    /// Accepts or refuses an ID token without `sid` (refused by default).
    #[must_use]
    pub const fn require_provider_session(mut self, require: bool) -> Self {
        self.require_provider_session = require;
        self
    }

    /// Accepts a logout token without `typ`: only for a known non-conforming provider.
    #[must_use]
    pub const fn allow_missing_logout_token_typ(mut self, allow: bool) -> Self {
        self.allow_missing_logout_token_typ = allow;
        self
    }

    /// Redirects a failed sign-in to this path with `?error=<code>` instead of answering JSON.
    #[must_use]
    pub fn error_redirect(mut self, path: impl Into<String>) -> Self {
        self.error_redirect = Some(path.into());
        self
    }

    /// Adds `/wallet`, `/wallet/stats` and `/models`.
    #[must_use]
    pub fn ai(mut self, ai: AiClient) -> Self {
        self.ai = Some(ai);
        self
    }

    /// Replaces the in-memory replay store of back-channel logout tokens.
    #[must_use]
    pub fn replay_store(mut self, store: Arc<dyn ReplayStore>) -> Self {
        self.replay_store = Some(store);
        self
    }

    /// Called after sessions end.
    #[must_use]
    pub fn on_sessions_ended(mut self, callback: SessionsEndedCallback) -> Self {
        self.on_sessions_ended = Some(callback);
        self
    }

    /// Receives unexpected failures and the ones the response must not detail.
    #[must_use]
    pub fn on_error(mut self, callback: ErrorCallback) -> Self {
        self.on_error = Some(callback);
        self
    }

    /// Validates the options.
    ///
    /// # Errors
    /// `CFG_001` for a `base_path` that is not like `/auth`, a `redirect_uri`
    /// that does not end with `<base_path>/callback`, or a short secret.
    pub fn build(self) -> Result<AuthHandlers> {
        let base_path = self.base_path;
        let valid_path = base_path.starts_with('/')
            && !base_path.ends_with('/')
            && base_path
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-'));
        if !valid_path {
            return Err(AuthAiError::new(ErrorCode::Cfg001)
                .with_message("base_path must look like /auth, with no trailing slash"));
        }
        let redirect = Url::parse(self.auth.config().redirect_uri()).map_err(|err| {
            AuthAiError::new(ErrorCode::Cfg001)
                .with_message("Invalid redirect_uri")
                .with_source(err)
        })?;
        if redirect.path() != format!("{base_path}/callback") {
            return Err(AuthAiError::new(ErrorCode::Cfg001)
                .with_message(format!("redirect_uri must end with {base_path}/callback")));
        }
        let secure = redirect.scheme() == "https";
        Ok(AuthHandlers {
            inner: Arc::new(Inner {
                key: derive_seal_key(self.secret.expose_secret())?,
                // Built on the registered origin: never from a request header.
                origin: redirect.origin().ascii_serialization(),
                session_cookie: cookie_name("aai_session", secure),
                login_cookie: cookie_name("aai_login", secure),
                logout_cookie: cookie_name("aai_logout", secure),
                secure,
                base_path,
                auth: self.auth,
                grants: self.grants,
                sessions: self.sessions,
                default_redirect: self.default_redirect,
                session_ttl: self.session_ttl,
                renew_seconds: self.renew_seconds,
                require_provider_session: self.require_provider_session,
                allow_missing_logout_token_typ: self.allow_missing_logout_token_typ,
                error_redirect: self.error_redirect,
                ai: self.ai,
                replay_store: self
                    .replay_store
                    .unwrap_or_else(|| Arc::new(MemoryReplayStore::new())),
                on_sessions_ended: self.on_sessions_ended,
                on_error: self.on_error,
                renewing: Mutex::new(HashMap::new()),
            }),
        })
    }
}

/// The routes the handlers serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Login,
    Callback,
    Me,
    Logout,
    LogoutCallback,
    BackchannelLogout,
    Wallet,
    WalletStats,
    Models,
}

impl Route {
    fn from_path(path: &str, with_ai: bool) -> Option<Self> {
        match path {
            "/login" => Some(Self::Login),
            "/callback" => Some(Self::Callback),
            "/me" => Some(Self::Me),
            "/logout" => Some(Self::Logout),
            "/logout/callback" => Some(Self::LogoutCallback),
            "/backchannel-logout" => Some(Self::BackchannelLogout),
            "/wallet" if with_ai => Some(Self::Wallet),
            "/wallet/stats" if with_ai => Some(Self::WalletStats),
            "/models" if with_ai => Some(Self::Models),
            _ => None,
        }
    }

    const fn method(self) -> &'static str {
        match self {
            Self::Logout | Self::BackchannelLogout => "POST",
            _ => "GET",
        }
    }
}

/// The first value of each query parameter of a request.
pub(super) fn query_of(request: &WebRequest) -> Result<HashMap<String, String>> {
    let url = Url::parse(&request.url).map_err(|err| {
        AuthAiError::new(ErrorCode::Req001)
            .with_message("The request URL is not absolute")
            .with_source(err)
    })?;
    let mut query = HashMap::new();
    for (name, value) in url.query_pairs() {
        if !value.is_empty() {
            query
                .entry(name.into_owned())
                .or_insert_with(|| value.into_owned());
        }
    }
    Ok(query)
}

impl AuthHandlers {
    /// Starts the options from the four mandatory members.
    #[must_use]
    pub fn builder(
        auth: AuthClient,
        grants: GrantManager,
        sessions: Arc<dyn SessionStore>,
        secret: impl Into<SecretString>,
    ) -> AuthHandlersBuilder {
        AuthHandlersBuilder {
            auth,
            grants,
            sessions,
            secret: secret.into(),
            base_path: "/auth".to_owned(),
            default_redirect: "/".to_owned(),
            session_ttl: DEFAULT_SESSION_TTL_SECONDS,
            renew_seconds: DEFAULT_CLAIMS_RENEW_SECONDS,
            require_provider_session: true,
            allow_missing_logout_token_typ: false,
            error_redirect: None,
            ai: None,
            replay_store: None,
            on_sessions_ended: None,
            on_error: None,
        }
    }

    /// The origin the SDK builds URLs on: that of `redirect_uri`, never a request header.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.inner.origin
    }

    /// Where the routes are mounted.
    #[must_use]
    pub fn base_path(&self) -> &str {
        &self.inner.base_path
    }

    /// The failure callback, for adapters that answer errors themselves.
    #[must_use]
    pub fn on_error(&self) -> Option<&ErrorCallback> {
        self.inner.on_error.as_ref()
    }

    pub(super) fn report(&self, err: &AuthAiError) {
        if let Some(callback) = &self.inner.on_error {
            callback(err);
        }
    }

    /// Serves the routes below `base_path`; `None` for any other path.
    pub async fn handle(&self, request: &WebRequest) -> Option<WebResponse> {
        let Ok(url) = Url::parse(&request.url) else {
            let err =
                AuthAiError::new(ErrorCode::Req001).with_message("The request URL is not absolute");
            return Some(error_response(&err, self.on_error(), Vec::new()));
        };
        let route = Route::from_path(
            url.path().strip_prefix(self.base_path())?,
            self.inner.ai.is_some(),
        )?;
        if request.method != route.method() {
            return Some(WebResponse::new(
                405,
                vec![
                    pair("allow", route.method()),
                    pair("cache-control", "no-store"),
                ],
            ));
        }
        let outcome = match route {
            Route::Login => self.login(request).await,
            Route::Callback => Ok(self.callback(request).await),
            Route::Me => self.me(request).await,
            Route::Logout => self.logout(request).await,
            Route::LogoutCallback => self.logout_callback(request),
            Route::BackchannelLogout => Ok(self.backchannel_logout(request).await),
            Route::Wallet | Route::WalletStats | Route::Models => {
                self.ai_route(route, request).await
            }
        };
        Some(outcome.unwrap_or_else(|err| error_response(&err, self.on_error(), Vec::new())))
    }

    async fn ai_route(&self, route: Route, request: &WebRequest) -> Result<WebResponse> {
        let session = self.require_session(request).await?;
        let ai = self
            .inner
            .ai
            .as_ref()
            .ok_or_else(|| AuthAiError::new(ErrorCode::Srv001))?;
        match route {
            Route::Wallet => ai_routes::wallet(ai, &session).await,
            Route::WalletStats => ai_routes::wallet_stats(ai, &session, request).await,
            _ => ai_routes::models(ai, &session).await,
        }
    }

    /// Like [`AuthHandlers::get_session`], failing with `SES_001` when signed out.
    ///
    /// # Errors
    /// `SES_001` when signed out.
    pub async fn require_session(&self, request: &WebRequest) -> Result<Session> {
        self.get_session(request)
            .await?
            .ok_or_else(|| AuthAiError::new(ErrorCode::Ses001))
    }
}
