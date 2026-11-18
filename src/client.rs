//! The OIDC relying party for auth-service.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{Map, Value};
use url::Url;

use crate::claims::{IdTokenClaims, UserInfoClaims};
use crate::config::AuthClientConfig;
use crate::error::{AuthAiError, ErrorCode, Result};
use crate::id_token::check_id_token_binding;
use crate::introspection::IntrospectionResult;
use crate::provider::{Provider, ProviderLoader};
use crate::secret::SecretString;
use crate::token_endpoint::ProviderEndpoints;
use crate::transport::{Transport, default_transport};
use crate::types::{LoginHandshake, LoginRequest, LoginResult, Prompt, TokenSet, TokenTypeHint};
use crate::util::{b64url, random_token, secrets_equal, sha256, with_query};

const PKCE_VERIFIER_BYTES: usize = 48;
const RANDOM_BYTES: usize = 32;

/// UserInfo may repeat these ID-token claims. Security-sensitive token claims
/// (`sid`, `azp`, `iss`, `aud`, `exp`, `iat`) are never copied from UserInfo.
const USERINFO_MERGEABLE_CLAIMS: [&str; 24] = [
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "address",
    "updated_at",
    "email",
    "email_verified",
    "phone_number",
    "phone_number_verified",
    "roles",
    "permissions",
    "features",
    "plan",
    "org_id",
];

/// OIDC relying party for auth-service.
///
/// Authorization-code grant with PKCE, refresh with RFC 8707 resource
/// narrowing, logout, revocation and introspection. It keeps no session:
/// callers persist the handshake, the tokens and the claims where it suits them.
///
/// The client is cheap to clone: clones share the discovery cache and the
/// transport.
#[derive(Clone)]
pub struct AuthClient {
    inner: Arc<Inner>,
}

struct Inner {
    config: AuthClientConfig,
    transport: Arc<dyn Transport>,
    provider: ProviderLoader,
    endpoints: ProviderEndpoints,
}

impl std::fmt::Debug for AuthClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthClient")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

impl AuthClient {
    /// Builds a client on the default `reqwest` transport.
    ///
    /// # Errors
    /// `CFG_001` when the HTTP client cannot be built.
    pub fn new(config: AuthClientConfig) -> Result<Self> {
        Ok(Self::with_transport(config, default_transport()?))
    }

    /// Builds a client on a transport of your own, e.g. to add a proxy or an
    /// observability layer.
    #[must_use]
    pub fn with_transport(config: AuthClientConfig, transport: Arc<dyn Transport>) -> Self {
        Self {
            inner: Arc::new(Inner {
                provider: ProviderLoader::new(config.clone(), Arc::clone(&transport)),
                endpoints: ProviderEndpoints::new(config.clone(), Arc::clone(&transport)),
                config,
                transport,
            }),
        }
    }

    /// The validated configuration.
    #[must_use]
    pub fn config(&self) -> &AuthClientConfig {
        &self.inner.config
    }

    /// The transport every request goes through, shared with the REST API clients built on this one.
    #[must_use]
    pub fn transport(&self) -> Arc<dyn Transport> {
        Arc::clone(&self.inner.transport)
    }

    /// The authorization URL to redirect the browser to, and the secrets to keep until it returns.
    ///
    /// # Errors
    /// `OIDC_001` when discovery fails.
    pub async fn start_login(
        &self,
        prompt: Option<Prompt>,
        login_hint: Option<&str>,
    ) -> Result<LoginRequest> {
        let provider = self.inner.provider.get().await?;
        let handshake = LoginHandshake {
            state: SecretString::new(random_token(RANDOM_BYTES)?),
            nonce: SecretString::new(random_token(RANDOM_BYTES)?),
            code_verifier: SecretString::new(random_token(PKCE_VERIFIER_BYTES)?),
        };
        let config = self.config();
        let scope = config.scopes().join(" ");
        let challenge = s256_challenge(handshake.code_verifier.expose_secret());
        let mut parameters: Vec<(&str, &str)> = vec![
            ("response_type", "code"),
            ("client_id", config.client_id()),
            ("redirect_uri", config.redirect_uri()),
            ("scope", &scope),
            ("state", handshake.state.expose_secret()),
            ("nonce", handshake.nonce.expose_secret()),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ];
        if let Some(prompt) = prompt {
            parameters.push(("prompt", prompt.as_str()));
        }
        if let Some(hint) = login_hint.filter(|hint| !hint.is_empty()) {
            parameters.push(("login_hint", hint));
        }
        parameters.extend(
            config
                .resources()
                .iter()
                .map(|resource| ("resource", resource.as_str())),
        );
        let url = with_query(&provider.metadata.authorization_endpoint, parameters)?;
        Ok(LoginRequest { url, handshake })
    }

    /// Completes the sign-in from the callback URL.
    ///
    /// `resource` is deliberately not sent on the code exchange: the token is
    /// then issued for every audience requested at sign-in and each refresh
    /// narrows it to one.
    ///
    /// # Errors
    /// `OIDC_002` for an invalid authorization response, `OIDC_003` when the
    /// token request fails, `TOK_001` when the ID token does not verify.
    pub async fn handle_callback(
        &self,
        callback_url: &str,
        handshake: &LoginHandshake,
    ) -> Result<LoginResult> {
        let provider = self.inner.provider.get().await?;
        let code = authorization_code(callback_url, handshake, &provider)?;
        let tokens = self
            .inner
            .endpoints
            .token_request(
                &provider.metadata.token_endpoint,
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("redirect_uri", self.config().redirect_uri()),
                    ("code_verifier", handshake.code_verifier.expose_secret()),
                ],
            )
            .await?;
        let Some(id_token) = &tokens.id_token else {
            return Err(AuthAiError::new(ErrorCode::Oidc002)
                .with_message("The token response carries no ID token"));
        };
        let claims = self
            .verify_id_token_with(
                &provider,
                id_token.expose_secret(),
                Some(handshake.nonce.expose_secret()),
            )
            .await?;
        let claims = self
            .apply_userinfo_with(&provider, claims, tokens.access_token.expose_secret())
            .await?;
        let session_id = claims.sid.clone();
        Ok(LoginResult {
            tokens,
            claims,
            session_id,
        })
    }

    /// Verifies an ID token of this client.
    ///
    /// # Errors
    /// `TOK_001` when it does not verify.
    pub async fn verify_id_token(&self, id_token: &str) -> Result<IdTokenClaims> {
        let provider = self.inner.provider.get().await?;
        self.verify_id_token_with(&provider, id_token, None).await
    }

    /// Reads UserInfo with the access token, for the current provider session.
    ///
    /// # Errors
    /// `OIDC_004` when the provider has no UserInfo endpoint, `OIDC_003` when the request fails.
    pub async fn fetch_userinfo(&self, access_token: &str) -> Result<UserInfoClaims> {
        let provider = self.inner.provider.get().await?;
        let Some(endpoint) = provider.metadata.userinfo_endpoint.as_deref() else {
            return Err(AuthAiError::new(ErrorCode::Oidc004)
                .with_message("The provider advertises no userinfo_endpoint"));
        };
        let body = self
            .inner
            .endpoints
            .userinfo_request(endpoint, access_token)
            .await?;
        parse_userinfo(body)
    }

    /// Fills claims the ID token omits from UserInfo, without replacing values.
    ///
    /// The provider may keep email out of the ID token when it issues an access
    /// token; UserInfo is then the authoritative source for the profile and
    /// email claims. Registered and entitlement claims already present in the
    /// ID token are never overwritten.
    ///
    /// # Errors
    /// `OIDC_003` when UserInfo fails, `TOK_001` when it belongs to another user.
    pub async fn apply_userinfo(
        &self,
        claims: IdTokenClaims,
        access_token: &str,
    ) -> Result<IdTokenClaims> {
        let provider = self.inner.provider.get().await?;
        self.apply_userinfo_with(&provider, claims, access_token)
            .await
    }

    /// Exchanges a refresh token for fresh tokens.
    ///
    /// The provider rotates the refresh token on every use: the returned one
    /// replaces the presented one, and a replayed stale token revokes the whole
    /// family. Concurrent callers should go through a
    /// [`GrantManager`](crate::GrantManager). `scope` is never sent: the rotated
    /// token would be left with the scopes of that request only.
    ///
    /// # Errors
    /// `OIDC_003` when the provider refuses.
    pub async fn refresh(&self, refresh_token: &str, resource: Option<&str>) -> Result<TokenSet> {
        let provider = self.inner.provider.get().await?;
        let mut form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ];
        if let Some(resource) = resource.filter(|resource| !resource.is_empty()) {
            form.push(("resource", resource));
        }
        self.inner
            .endpoints
            .token_request(&provider.metadata.token_endpoint, &form)
            .await
    }

    /// URL ending the provider session (RP-initiated logout).
    ///
    /// # Errors
    /// `OIDC_004` when the provider advertises no `end_session_endpoint`.
    pub async fn logout_url(
        &self,
        id_token_hint: Option<&str>,
        state: Option<&str>,
    ) -> Result<String> {
        let provider = self.inner.provider.get().await?;
        let Some(endpoint) = provider.metadata.end_session_endpoint.as_deref() else {
            return Err(AuthAiError::new(ErrorCode::Oidc004)
                .with_message("The provider advertises no end_session_endpoint"));
        };
        let mut parameters = vec![("client_id", self.config().client_id())];
        if let Some(uri) = self.config().post_logout_redirect_uri() {
            parameters.push(("post_logout_redirect_uri", uri));
        }
        if let Some(hint) = id_token_hint.filter(|hint| !hint.is_empty()) {
            parameters.push(("id_token_hint", hint));
        }
        if let Some(state) = state.filter(|state| !state.is_empty()) {
            parameters.push(("state", state));
        }
        with_query(endpoint, parameters)
    }

    /// Revokes a token at the provider (RFC 7009).
    ///
    /// # Errors
    /// `OIDC_004` when the provider has no revocation endpoint, `OIDC_003` when it refuses.
    pub async fn revoke(&self, token: &str, hint: Option<TokenTypeHint>) -> Result<()> {
        let provider = self.inner.provider.get().await?;
        let Some(endpoint) = provider.metadata.revocation_endpoint.as_deref() else {
            return Err(AuthAiError::new(ErrorCode::Oidc004)
                .with_message("The provider advertises no revocation_endpoint"));
        };
        let response = self
            .inner
            .endpoints
            .post(endpoint, &token_form(token, hint))
            .await?;
        if !response.is_success() {
            return Err(AuthAiError::new(ErrorCode::Oidc003)
                .with_message(format!(
                    "Revocation endpoint answered HTTP {}",
                    response.status
                ))
                .with_detail("status", response.status));
        }
        Ok(())
    }

    /// Introspects a token at the provider (RFC 7662).
    ///
    /// # Errors
    /// `OIDC_004` when the provider has no introspection endpoint, `OIDC_003` when it refuses.
    pub async fn introspect(
        &self,
        token: &str,
        hint: Option<TokenTypeHint>,
    ) -> Result<IntrospectionResult> {
        let provider = self.inner.provider.get().await?;
        let Some(endpoint) = provider.metadata.introspection_endpoint.as_deref() else {
            return Err(AuthAiError::new(ErrorCode::Oidc004)
                .with_message("The provider advertises no introspection_endpoint"));
        };
        let response = self
            .inner
            .endpoints
            .post(endpoint, &token_form(token, hint))
            .await?;
        if !response.is_success() {
            return Err(AuthAiError::new(ErrorCode::Oidc003)
                .with_message(format!(
                    "Introspection endpoint answered HTTP {}",
                    response.status
                ))
                .with_detail("status", response.status));
        }
        response.parse_json().map_err(|err| {
            AuthAiError::new(ErrorCode::Oidc003)
                .with_message("The introspection response has an unexpected shape")
                .with_source(err)
        })
    }

    /// Verifies the signature, issuer, audience and expiry of a JWT signed by the provider.
    ///
    /// Low-level: prefer the bearer and logout token verifiers. Returns the claims.
    ///
    /// # Errors
    /// `TOK_001` when it does not verify.
    pub async fn verify_jwt(
        &self,
        token: &str,
        audience: &str,
        typ: Option<&str>,
    ) -> Result<Map<String, Value>> {
        let provider = self.inner.provider.get().await?;
        provider.jwt.verify(token, audience, typ).await
    }

    /// `client_credentials` grant for the application itself.
    ///
    /// No user is bound to the token. Needs a confidential client.
    ///
    /// # Errors
    /// `CFG_001` for a public client, `OIDC_003` when the provider refuses.
    pub async fn client_credentials(
        &self,
        scope: Option<&str>,
        resource: Option<&str>,
    ) -> Result<TokenSet> {
        if self.config().client_secret().is_none() {
            return Err(AuthAiError::new(ErrorCode::Cfg001)
                .with_message("client_credentials requires a client_secret"));
        }
        let provider = self.inner.provider.get().await?;
        let mut form = vec![("grant_type", "client_credentials")];
        if let Some(scope) = scope.filter(|scope| !scope.is_empty()) {
            form.push(("scope", scope));
        }
        if let Some(resource) = resource.filter(|resource| !resource.is_empty()) {
            form.push(("resource", resource));
        }
        self.inner
            .endpoints
            .token_request(&provider.metadata.token_endpoint, &form)
            .await
    }

    async fn apply_userinfo_with(
        &self,
        provider: &Provider,
        claims: IdTokenClaims,
        access_token: &str,
    ) -> Result<IdTokenClaims> {
        let Some(endpoint) = provider.metadata.userinfo_endpoint.as_deref() else {
            return Ok(claims);
        };
        let userinfo = parse_userinfo(
            self.inner
                .endpoints
                .userinfo_request(endpoint, access_token)
                .await?,
        )?;
        if userinfo.sub != claims.sub {
            return Err(AuthAiError::new(ErrorCode::Tok001)
                .with_message("The UserInfo response belongs to another user"));
        }
        let shape_error = |err: serde_json::Error| {
            AuthAiError::new(ErrorCode::Oidc003)
                .with_message("The UserInfo response has an unexpected shape")
                .with_source(err)
        };
        let Value::Object(mut merged) = serde_json::to_value(&claims).map_err(shape_error)? else {
            return Ok(claims);
        };
        let Value::Object(offered) = serde_json::to_value(&userinfo).map_err(shape_error)? else {
            return Ok(claims);
        };
        let mut updated = false;
        for (name, value) in offered {
            if USERINFO_MERGEABLE_CLAIMS.contains(&name.as_str())
                && !value.is_null()
                && merged.get(&name).is_none_or(Value::is_null)
            {
                merged.insert(name, value);
                updated = true;
            }
        }
        if !updated {
            return Ok(claims);
        }
        serde_json::from_value(Value::Object(merged)).map_err(shape_error)
    }

    async fn verify_id_token_with(
        &self,
        provider: &Provider,
        id_token: &str,
        nonce: Option<&str>,
    ) -> Result<IdTokenClaims> {
        let claims = provider
            .jwt
            .verify(id_token, self.config().client_id(), None)
            .await?;
        check_id_token_binding(&claims, self.config().client_id(), nonce)?;
        serde_json::from_value(Value::Object(claims)).map_err(|err| {
            AuthAiError::new(ErrorCode::Tok001)
                .with_message("The ID token claims have an unexpected shape")
                .with_source(err)
        })
    }
}

fn parse_userinfo(body: Map<String, Value>) -> Result<UserInfoClaims> {
    serde_json::from_value(Value::Object(body)).map_err(|err| {
        AuthAiError::new(ErrorCode::Oidc003)
            .with_message("The UserInfo response has an unexpected shape")
            .with_source(err)
    })
}

fn s256_challenge(code_verifier: &str) -> String {
    b64url(&sha256(code_verifier.as_bytes()))
}

fn token_form(token: &str, hint: Option<TokenTypeHint>) -> Vec<(&str, &str)> {
    let mut form = vec![("token", token)];
    if let Some(hint) = hint {
        form.push(("token_type_hint", hint.as_str()));
    }
    form
}

fn invalid_response(reason: &'static str) -> AuthAiError {
    AuthAiError::new(ErrorCode::Oidc002).with_detail("reason", reason)
}

/// Checks the authorization response (RFC 6749 §4.1.2, RFC 9207) and returns its code.
fn authorization_code(
    callback_url: &str,
    handshake: &LoginHandshake,
    provider: &Provider,
) -> Result<String> {
    let url = Url::parse(callback_url)
        .map_err(|err| invalid_response("invalid_callback_url").with_source(err))?;
    let mut params: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in url.query_pairs() {
        if params
            .insert(name.into_owned(), value.into_owned())
            .is_some()
        {
            return Err(invalid_response("repeated_parameter"));
        }
    }
    if let Some(error) = params.get("error") {
        return Err(AuthAiError::new(ErrorCode::Oidc002)
            .with_message(format!("Authorization failed: {error}"))
            .with_detail("oauthError", error.as_str()));
    }
    match params.get("iss") {
        None if provider
            .metadata
            .authorization_response_iss_parameter_supported =>
        {
            return Err(invalid_response("missing_iss"));
        }
        Some(issuer) if *issuer != provider.metadata.issuer => {
            return Err(invalid_response("iss_mismatch"));
        }
        _ => {}
    }
    match params.get("state") {
        Some(state) if secrets_equal(state, handshake.state.expose_secret()) => {}
        _ => return Err(invalid_response("state_mismatch")),
    }
    params
        .remove("code")
        .filter(|code| !code.is_empty())
        .ok_or_else(|| invalid_response("missing_code"))
}
