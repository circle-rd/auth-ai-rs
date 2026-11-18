---
name: auth-ai-rs
description: "Use when: integrating, configuring or troubleshooting auth-ai (crates.io package `auth-ai`, imported as `auth_ai`), the Rust SDK for Tokio backends that sign users in through a CIRCLE auth-service (backend-for-frontend OIDC sign-in with axum or framework-agnostic handlers, bearer token verification, back-channel logout, wallet, LiteLLM gateway, billing, consumption and resource sharing), or when an AuthAiError code such as SES_005, TOK_002 or GW_001 appears."
---

# CIRCLE auth-ai (Rust)

Rust SDK (`auth-ai` on crates.io, imported as `auth_ai`, MIT, Rust >= 1.89, edition 2024, async on Tokio only) for applications that rely on a CIRCLE auth-service identity provider. It is the Rust port of the TypeScript SDK `@circle-rd/auth-ai` (documented at https://docs.circle-cyber.com/auth-ai/typescript/) and shares its wire contract: the BFF routes, the sealed login cookie, the cookie names and the error codes.

Full documentation: https://docs.circle-cyber.com/auth-ai/rust/ . Every page is also served as markdown under `/raw/`, for example https://docs.circle-cyber.com/auth-ai/rust/raw/docs/concepts/architecture.md ; the whole text is at https://docs.circle-cyber.com/auth-ai/rust/llms-full.txt and a page index at https://docs.circle-cyber.com/auth-ai/rust/llms.txt . The documentation also exposes an MCP server at https://docs.circle-cyber.com/auth-ai/rust/mcp . Version 0.x: the API is not stable.

It is built for auth-service. It is not a client for arbitrary OIDC providers and not an identity provider. It has no debit API (the LiteLLM gateway debits the wallet), no adapter for a framework other than axum (the framework-agnostic handlers cover the rest), no blocking facade, and no frontend code: pair it with the TypeScript browser client and React/Vue bindings of `@circle-rd/auth-ai`.

## Getting started

```sh
cargo add auth-ai --features axum   # the axum feature is optional
cargo add axum
cargo add tokio --features macros,rt-multi-thread,net
cargo add serde_json
# Pre-releases: cargo add auth-ai@=X.Y.Z-dev.YYYYMMDDHHMM (see the release channels page)
```

Features: `axum` (the `auth_ai::axum` module, axum 0.8). Needs a C toolchain to build `aws-lc-sys`.

Modules (the import paths that exist):

| Module | Purpose |
| --- | --- |
| `auth_ai` | `AuthClient`, `AuthClientConfig`, `GrantManager`, `AiClient`, `UserAi`, claims helpers, `format_euros`, `AuthAiError`/`ErrorCode`, `WebRequest`/`WebResponse`, `Transport` |
| `auth_ai::web` | `AuthHandlers`, `MemorySessionStore`, `SessionStore`, `Session`, `safe_redirect_path`, `status_for`, `error_response`, sealed cookies |
| `auth_ai::axum` | `auth_router`, `AuthSession`, `OptionalAuthSession`, `AuthError`, `to_web_request`, `into_response` (needs the `axum` feature) |
| `auth_ai::server` | `BearerVerifier`, `require_scopes`, `protected_resource_metadata`, `BackchannelLogoutHandler`, `MachineApi` |

## Register the application in auth-service first

- Confidential application, redirect URI `<origin><base_path>/callback` (`base_path` defaults to `/auth`).
- Post-logout redirect URI `<origin><base_path>/logout/callback`, passed as `post_logout_redirect_uri`.
- Back-channel logout URI `<origin><base_path>/backchannel-logout` (HTTPS, reachable by auth-service) and/or end-session enabled: sign-in refuses an ID token without `sid`.
- **LiteLLM support** on when `gateway_url` is set.
- Machine scopes `billing:read`, `consumption:read`, `consumption:write`, `resources:validate` for the machine API (default for new confidential apps; a superadmin must set them on older apps). `resources:authorize` and `resources:usage:write` are never defaults: a superadmin grants them to a trusted platform component only.

## Minimal axum backend

```rust
use std::sync::Arc;

use auth_ai::axum::{AuthSession, auth_router};
use auth_ai::web::{AuthHandlers, MemorySessionStore, SessionStore};
use auth_ai::{AuthClient, AuthClientConfig, GrantManager, MemoryGrantStore};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};

async fn profile(AuthSession(session): AuthSession) -> Json<Value> {
    Json(json!({
        "sub": session.claims.sub,
        "roles": session.claims.roles.unwrap_or_default(),
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // An unset variable stops the process: without a client secret the SDK
    // would silently act as a public client.
    let config = AuthClientConfig::builder(
        std::env::var("AUTH_ISSUER")?, // HTTPS, as auth-service advertises it
        "my-app",
        "https://app.example.com/auth/callback",
    )
    .client_secret(std::env::var("AUTH_CLIENT_SECRET")?)
    .post_logout_redirect_uri("https://app.example.com/auth/logout/callback")
    .build()?;
    let auth = AuthClient::new(config)?;
    let grants = GrantManager::new(auth.clone(), MemoryGrantStore::new()); // demo only
    let sessions: Arc<dyn SessionStore> = Arc::new(MemorySessionStore::new()); // demo only
    let handlers =
        AuthHandlers::builder(auth, grants, sessions, std::env::var("AUTH_COOKIE_SECRET")?) // >= 32 random characters
            .build()?;

    let app = Router::new()
        .merge(auth_router::<AuthHandlers>(handlers.clone())) // /auth/login /callback /me /logout /logout/callback /backchannel-logout
        .route("/api/profile", get(profile))
        .with_state(handlers);
    axum::serve(tokio::net::TcpListener::bind("0.0.0.0:3000").await?, app).await?;
    Ok(())
}
```

`AuthClient` is cheap to clone and there is nothing to close. Mount `auth_router` at the root with `merge` (not `nest`): the path the handlers see must include the base path. Return `Result<_, AuthError>` from your own routes to answer an `AuthAiError` with the public envelope. Other frameworks: build a `WebRequest` on `handlers.origin()` (never the `Host` header), call `handlers.handle(&request).await` (an `Option<WebResponse>`), and send every header pair of the response, `Set-Cookie` included. See the "Other frameworks" page.

## Common tasks

- **Configuration** is `AuthClientConfig::builder(issuer, client_id, redirect_uri)` plus the methods `client_secret`, `token_endpoint_auth_method`, `post_logout_redirect_uri`, `scopes`, `resources`, `gateway_url`, `clock_tolerance_seconds`, `timeout`; `build()` validates and returns `AuthAiError` with code `CFG_001` naming every invalid option. Errors are values: `?` them, never unwrap.
- **Entitlements**: `has_role(&claims, "admin")`, `has_permission(&claims, "reports", PermissionAction::Write)` (write implies read), `has_feature(&claims, "beta")`, `get_feature(&claims, "seats")`. Enforce on the server.
- **Wallet and gateway** (needs `gateway_url`): `let user = AiClient::new(auth, grants).for_user(sub)?;` `user.wallet.get_account().await?` (amounts are `i128` micro-euros: use `format_euros(balance, 2)?`; decide with `can_spend`); `user.gateway()?.post_json("/v1/chat/completions", &json!({"model": .., "messages": [..], "metadata": {"session_id": ..}})).await?`; OpenAI-compatible SDK: `base_url = gateway.openai_base_url()` and a fresh `gateway.access_token().await?` for every request. `402` is `GW_001` (`is_insufficient_credit`), `429` is `GW_002`.
- **Billing and consumption** (backend only, needs a client secret): `let machine = MachineApi::new(&auth)?;` `machine.billing.get_subscription(sub).await?`, `.get_usage(sub)`, `.list_invoices(sub, Some(50), None)`; `machine.consumption.report(sub, "exports", 1_i64, Some("job-1")).await?`, `.list_aggregates(sub)`, `.get_aggregate(sub, key)`.
- **Resource sharing** (backend only, needs a client secret and an auth-service with `RESOURCE_SHARING_ENABLED`): `machine.resources.authorize(&AuthorizeRequest { subject_id, client_id, resource_uri, audience, request_id: None, source: None }).await` returns `AuthorizeDecision::Allowed(..)` or `Denied` (take the three ids from a verified token; only `Allowed` admits, and a returned error is a denial), `.list_accessible(subject_id, None)`, `.validate(resource_id, ValidationResult::Validated, None, None)` and `.invalidate(resource_id, reason)` for the validator of a resource scheme, `.record_usage(&UsageRecord { .. })` (scope `resources:usage:write`, platform metering components only; `request_id` is 64 lowercase hex characters and makes it idempotent). `machine.resources` is a field, not a method.
- **Protect an API**: `let verifier = BearerVerifier::new(auth.clone(), "https://api.example.com")?;` then `let token = verifier.verify_header(authorization).await?;` (`authorization: Option<&str>`) and `require_scopes(&token, &["roles"])?`; serve `protected_resource_metadata(&auth, resource, None)` at `protected_resource_metadata_path(resource)?` and answer 401/403 with `bearer_challenge(&metadata_url, Some(BearerError::InvalidToken), None)?`.
- **Frontend**: not in this package. Use `createBrowserAuth()` and the React/Vue bindings of `@circle-rd/auth-ai`; the browser only holds an opaque session cookie.

## Production rules

- Implement `SessionStore` and `GrantStore` (encrypted refresh tokens) on your database (`MemorySessionStore` and `MemoryGrantStore` are for demos and one process). They are `#[async_trait]` traits: add the `async-trait` crate.
- With several replicas, pass a distributed `GrantLock` (`async fn hold(&self, grant_id) -> Result<LockGuard>`) through `GrantManager::builder(auth, store).lock(..).build()` and a shared `ReplayStore` to `AuthHandlers::builder(..).replay_store(..)`.
- Cookie secret >= 32 random characters from the environment; the SDK reads no environment variable itself.
- Set `on_error` and log `err.to_json()`; answer users with `err.to_public_json()` only. Do not log query strings (the callback carries the authorization code).
- Check `Origin` on your own state-changing routes (`auth_ai::web::is_cross_site`).
- Every request goes through the `Transport` trait (reqwest with rustls by default): replace it with `AuthClient::with_transport` for a proxy or tracing.

## Troubleshooting by error code

| Code | Likely cause and fix |
| --- | --- |
| `CFG_001` | Invalid config: `issuer` not HTTPS, `redirect_uri` path not `<base_path>/callback`, cookie secret < 32 chars, machine API without a client secret, `gateway_url` missing for `.gateway()`. |
| `SES_005` | Every failed `/auth/callback` answers this; the real cause is passed to `on_error` (look for `SES_003`: ID token without `sid`, `OIDC_003`: wrong client secret, `SES_002`: expired or foreign handshake cookie). |
| `OIDC_001` | Discovery failed: check `issuer` is reachable and matches the discovery document. |
| `TOK_002` | No usable grant: the user must sign in again. |
| `TOK_004` | Missing scope: `details["missing"]` for `require_scopes`, `details["scope"]` for a machine scope a superadmin must grant. |
| `GW_001` | Wallet empty (402): send the user to `wallet.topup_url()`. |
| `GW_003` | Gateway refused credentials or resource (401/403): check LiteLLM support and the user's plan. |

More: https://docs.circle-cyber.com/auth-ai/rust/docs/reference/error-codes
