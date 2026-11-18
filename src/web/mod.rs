//! Backend-for-frontend sign-in handlers, sealed cookies and the session store contract.

mod ai_routes;
mod cookies;
mod handlers;
mod http;
mod lifecycle;
mod routes;
mod seal;
mod sessions;

pub use cookies::{clear_cookie, cookie_name, parse_cookies, serialize_cookie};
pub use handlers::{
    AuthHandlers, AuthHandlersBuilder, DEFAULT_CLAIMS_RENEW_SECONDS, DEFAULT_SESSION_TTL_SECONDS,
    HANDSHAKE_TTL_SECONDS, SessionsEndedCallback,
};
pub use http::{error_response, is_cross_site, safe_redirect_path, status_for};
pub use seal::{MIN_SECRET_LENGTH, SealKey, derive_seal_key, seal, unseal};
pub use sessions::{MemorySessionStore, Session, SessionStore};
