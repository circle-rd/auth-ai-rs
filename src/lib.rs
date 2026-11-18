//! Rust SDK for applications relying on a CIRCLE auth-service identity provider.
//!
//! OIDC sign-in as a backend-for-frontend, entitlements, billing, the credit
//! wallet, the LiteLLM gateway and resource sharing. It is the Rust port of
//! `@circle-rd/auth-ai` and of the `auth-ai` Python package: same behaviours,
//! same wire contract, same error codes.
//!
//! | Module | What it gives you |
//! | --- | --- |
//! | crate root | OIDC client, grants, claims helpers, wallet and gateway clients, error registry |
//! | [`server`] | Bearer verification, back-channel logout, protected-resource metadata, machine API |
//! | [`web`] | Sign-in handlers (`WebRequest` → `WebResponse`), session store contract |
//! | `axum` (feature) | Router and extractors for axum |
//!
//! The quick start lives in the repository README; every snippet of it is a doctest of this crate.

mod ai;
mod claims;
mod client;
mod config;
mod error;
mod gateway;
mod gateway_errors;
mod grants;
mod http;
mod id_token;
mod introspection;
mod jws;
mod jwt;
mod messages;
mod provider;
mod secret;
mod session_user;
mod token_endpoint;
mod transport;
mod types;
mod util;
mod wallet;

#[cfg(feature = "axum")]
pub mod axum;
pub mod server;
pub mod web;

pub use ai::{AiClient, UserAi};
pub use claims::{
    AccessTokenClaims, AddressClaim, Audience, EntitlementClaims, FeatureValue, IdTokenClaims,
    PermissionAction, UserInfoClaims, get_feature, has_feature, has_permission, has_role,
};
pub use client::AuthClient;
pub use config::{
    AuthClientConfig, AuthClientConfigBuilder, DEFAULT_SCOPES, TokenEndpointAuthMethod,
    WALLET_SELF_SCOPE,
};
pub use error::{AuthAiError, DetailValue, ErrorCode, ErrorDetails, PublicError, Result};
pub use gateway::{GatewayAgent, GatewayClient, GatewayMcpServer, GatewayModel};
pub use gateway_errors::{is_insufficient_credit, is_insufficient_credit_status, to_gateway_error};
pub use grants::{
    AccessToken, DEFAULT_EXPIRY_SKEW_SECONDS, GrantAuth, GrantLock, GrantManager,
    GrantManagerBuilder, GrantStore, InProcessGrantLock, LockGuard, MemoryGrantStore,
};
pub use introspection::IntrospectionResult;
pub use messages::{
    BoxFuture, ErrorCallback, NO_STORE, WebRequest, WebResponse, json_response, redirect_response,
};
pub use secret::SecretString;
pub use session_user::{SessionUser, to_session_user};
pub use transport::{
    HttpRequest, HttpResponse, MAX_RESPONSE_BYTES, Method, ReqwestTransport, Transport,
    TransportError, default_transport,
};
pub use types::{LoginHandshake, LoginRequest, LoginResult, Prompt, TokenSet, TokenTypeHint};
pub use wallet::{
    Amount, ApplicationUsage, Currency, DailyPoint, DailyUsage, KindUsage, MICRO_PER_EUR,
    ModelUsage, TopupOptions, WalletAccount, WalletClient, WalletSessionUsage, WalletStats,
    WalletTransaction, WalletTransactionPage, WalletTransactionType, format_euros,
};

/// The version of this SDK.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Runs the README snippets as doctests without publishing the README as API documentation.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
