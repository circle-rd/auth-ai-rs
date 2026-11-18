# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

Sections, when present, appear in this order: `Added`, `Changed`, `Removed`,
`Fixed`, `Security`. Per our no-backward-compatibility policy
([CONTRIBUTING.md](CONTRIBUTING.md#2-versioning-and-breaking-changes)) there is no
`Deprecated` section: incompatible changes go straight to `Removed` and bump the version.

## [Unreleased]

<!-- Add user-visible changes here. Move to a dated section at release time. -->

## [0.1.0] - 2026-11-18

First release: the Rust port of `@circle-rd/auth-ai` and of the `auth-ai` Python package,
aligned with their 0.4.0 (resource sharing included). Same behaviours, same wire contract,
same error codes; the sealed login cookie is interoperable with both. The machine calls for
resource sharing need an auth-service with `RESOURCE_SHARING_ENABLED`.

### Added

- **Core (`auth_ai`)**: `AuthClient` (discovery cache, PKCE login, callback with ID-token
  verification, refresh with RFC 8707 resource narrowing, logout URL, revoke, introspect,
  `client_credentials`), `GrantManager` (serialized refresh-token rotation, per-audience access
  tokens, pluggable `GrantStore` and `GrantLock`), typed claims with `has_role` /
  `has_permission` / `has_feature` / `get_feature`, the error registry (`CFG_`, `OIDC_`, `TOK_`,
  `API_`, `GW_`, `SES_`, `REQ_`, `SRV_`) with `to_public_json()`.
- **Wallet and gateway**: `WalletClient` (balance, statistics, per-session usage, transactions,
  top-up options and link; `i128` micro-euros, `format_euros`), `GatewayClient` (origin-locked
  requests, OpenAI-compatible base URL, models, agents, MCP servers, MCP URLs, `post_json`,
  gateway error mapping), `AiClient::for_user()`, and the `gateway_url` option that adds the
  gateway and auth-service audiences and the `wallet:self:read` scope.
- **Server (`auth_ai::server`)**: Bearer-token verifier, back-channel logout handler with replay
  protection, RFC 9728 protected-resource metadata and `WWW-Authenticate` challenges, machine API
  (subscription, metered usage, invoices, consumption reporting, resource sharing: `authorize`,
  `list_accessible`, `validate`, `invalidate`).
- **Backend-for-frontend (`auth_ai::web`, `auth_ai::axum`)**: `AuthHandlers` (`/login`,
  `/callback`, `/me`, `/logout`, `/backchannel-logout`, optional `/wallet`, `/wallet/stats`,
  `/models`), sealed one-shot login cookie (interoperable with the TypeScript and Python SDKs),
  hashed session ids, `SessionStore` contract, scheduled claims renewal; axum adapter with
  `auth_router`, `AuthSession`, `OptionalAuthSession` and `AuthError` (`axum` feature).
- **`Transport`**: the single HTTP seam of the SDK, with a `reqwest` + rustls default (HTTP/2,
  gzip, brotli, no redirect followed, bounded response bodies), to plug a proxy, mTLS or tracing.

### Security

- Every failed sign-in callback answers one generic `403 SES_005`; messages and details stay in
  the application's logs.
- `__Host-` cookies, same-origin redirect targets, refused cross-site logout, URLs built on the
  registered origin, client credentials form-urlencoded per RFC 6749 §2.3.1, constant-time
  comparison of `state` and `nonce`.
- A refresh-token rotation and a revocation run to completion even when the calling future is
  dropped, so the provider is never left with a rotated token this process did not store.
- JWTs are verified against the single algorithm the provider advertises among ES256, ES384,
  RS256/384/512 and PS256/384/512; `none`, HMAC and `EdDSA` (RFC 9864) are refused. `Ed25519`,
  `Ed448` and `ES512` are not supported yet: a provider that only advertises them fails
  discovery with `OIDC_001`.
- Credentials are `SecretString`s (redacted `Debug`, zeroed on drop); the crate forbids `unsafe`.

[Unreleased]: https://github.com/circle-rd/auth-ai-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/circle-rd/auth-ai-rs/releases/tag/v0.1.0
