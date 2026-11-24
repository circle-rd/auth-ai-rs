# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

Sections, when present, appear in this order: `Added`, `Changed`, `Removed`,
`Fixed`, `Security`. Per our no-backward-compatibility policy
([CONTRIBUTING.md](CONTRIBUTING.md#2-versioning-and-breaking-changes)) there is no
`Deprecated` section: incompatible changes go straight to `Removed` and bump the version.

## [Unreleased]

## [0.3.0] - 2026-11-25

Aligns the resource-sharing clients with application-scoped resources in auth-service: an
application sees and uses the resources it owns or that were shared with it, never everything
a user owns. This breaks 0.2.0 callers of the machine API.

### Added

- **`ResourcePermission`, `Read` or `Write`** (closed enum; `Write` covers `Read`).
  `CreateGrant::permission` accepts it (`Read` when absent, and left out of the request),
  `Grant::permission` is now typed, and `AccessibleResource::permission` carries the level
  the user holds. An unknown value on the wire fails to parse (`API_002`).
- **`user.resources.update_grant(resource_id, grant_id, permission)`** changes the level of an
  active grant without revoking it (`RES_014` for a level the scheme does not support,
  `RES_015` for an inactive grant).
- **`user.resources.delete_grant(resource_id, grant_id)`** deletes a revoked or expired grant
  for good (`RES_020` for an active one).
- **`user.resources.share_with_application(resource_ids, &ShareWithApplication)`** shares up to
  100 resources with one application in a call and returns one `BulkShareResult` per resource
  (`resource_id`, `grant_id`, `code`). `Resource::permissions` lists the levels a scheme
  supports on single-resource answers.
- **`GrantSubjectType::Application`** on `create_grant`: `subject_id` is the application slug.
- **`AuthorizeRequest::permission`** asks for a level (`Read` by default); an `Allowed` answer
  carries `permission`, `decision_id` and `expires_at`.
- **Webhook events `resource.grant.updated` and `resource.deleted`.** `ResourceEvent` is now an
  enum tagged by `type`: `GrantCreated`, `GrantRevoked` and `GrantUpdated` carry a
  `ResourceGrantEvent` with `grant.permission` and `grant.previous_permission`; `Deleted`
  carries a `ResourceDeletedEvent` with the resource only. `ResourceEvent::kind()` and
  `event_id()` read the type and the identifier to deduplicate on.

### Changed

- **`AuthorizeRequest` no longer takes `client_id`.** The application asking is the machine
  credential; pass the client the end user came through as the optional `actor_client_id`,
  which is recorded for audit and never decides anything.
- **`UsageRecord` takes `decision_id` and `started_at` instead of `subject_id` and
  `client_id`.** The decision returned by `authorize` names the person and the application, so
  a usage event can no longer claim either. `started_at` must fall within the decision's
  lifetime (`RES_016` otherwise).
- **`Allowed::owner_id` and `AccessibleResource::owner_id` are `Option<String>`**, set only for
  the application that owns the resource.
- **`list_accessible` is scoped to the calling application** on the machine and the user
  client: it returns what the application owns or was granted, not everything a user can reach.
- **`user.resources.delete()` deletes for good and returns the `Resource`** (it used to return
  `DeletedResource` after disabling). It fails with `RES_019` while the relay still serves the
  model.
- **A user bearer token is confined to its client's application**: the self-service client
  sees that application's resources only.
- **`ResourceEvent` is no longer a struct**: match on its variants. `WebhookResource::owner_id`
  is `Option<String>`.
- `JsonHttp::request_empty` (the `204` path) now serves `delete_grant`.

### Removed

- `DeletedResource`, its `removed` flag, and the `use` permission value.
- **`user.resources.get()` is removed; use `get_resource()`.** `list` is a Python builtin, so
  every SDK names its listings and lookups after their noun (`get_resource`, next to
  `list_owned` and `list_organizations`). The call and its `CFG_001` validation are unchanged.
  This breaks 0.2.0 callers.

## [0.2.0] - 2026-11-22

Adds the self-service side of resource sharing and the verification of the resource
webhooks auth-service delivers.

### Added

- **`user.resources`** (`auth_ai::ResourceSharingClient`, reachable as
  `ai.for_user(id)?.resources`): the signed-in user shares their own resources.
  `list_member_applications`, `list_organizations`, `list_owned`, `get`, `create`,
  `update`, `delete`, `request_validation`, `list_grants`, `create_grant`,
  `revoke_grant`, `list_accessible` and `get_catalogue`. Set
  `AuthClientConfig::builder(..).resource_sharing(true)` to ask at sign-in for the
  `resources:self:manage` scope and the auth-service audience. A user grant accepts
  an e-mail (`subject_email`) resolved by auth-service among active members; an
  organization grant requires the owner to belong to it. Inputs are validated before
  any request (`CFG_001`).
- **`ResourceAudience`** names who a resource is shared with at creation time: a user
  id, a user e-mail, an organization, a plan or everyone.
- **`verify_resource_event`** and **`ResourceWebhookVerifier`** (`auth_ai::server`)
  verify and parse the signed `X-Auth-Service-Signature` callback auth-service sends
  to an application's `resourceWebhookUrl` (`resource.grant.created`,
  `resource.grant.revoked`). The timestamp is bounded (300 seconds by default,
  configurable) and the payload is typed (`ResourceEvent`, with recipient and grant
  models). Deduplicate on `event_id`.

### Changed

- **`JsonHttp` supports `PUT`, `PATCH` and `DELETE`**, plus a `204` path
  (`request_empty`). Existing methods are unchanged.
- `AuthClientConfig` gains `resource_sharing()`, and `RESOURCE_SELF_SCOPE` is exported
  as `"resources:self:manage"`.

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
  `list_accessible`, `validate`, `invalidate`, `record_usage`).
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
- JWTs are verified against the single algorithm the provider advertises among ES256/384/512,
  RS256/384/512, PS256/384/512 and the fully specified `Ed25519`; `none`, HMAC and `EdDSA`
  (RFC 9864) are refused, following better-auth issue #11348. `Ed448` is not supported: a
  provider that only advertises it fails discovery with `OIDC_001`. The verifier is an
  in-crate layer over `aws-lc-rs` (see AGENTS.md §10).
- Credentials are `SecretString`s (redacted `Debug`, zeroed on drop); the crate forbids `unsafe`.

[Unreleased]: https://github.com/circle-rd/auth-ai-rs/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/circle-rd/auth-ai-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/circle-rd/auth-ai-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/circle-rd/auth-ai-rs/releases/tag/v0.1.0
