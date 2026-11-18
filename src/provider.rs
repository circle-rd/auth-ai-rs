//! OIDC discovery and the cached provider it yields.

use std::sync::Arc;

use serde::Deserialize;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::config::AuthClientConfig;
use crate::error::{AuthAiError, ErrorCode, Result};
use crate::jwt::{JwtVerifier, RemoteJwks, supported_algorithm};
use crate::transport::{HttpRequest, Method, Transport};

/// Discovery and keys change rarely; an hour keeps rotation picked up without a restart.
const PROVIDER_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

/// The members of the discovery document the SDK relies on.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderMetadata {
    /// The issuer identifier.
    pub issuer: String,
    /// Where the browser is sent to sign in.
    pub authorization_endpoint: String,
    /// Where codes and refresh tokens are exchanged.
    pub token_endpoint: String,
    /// The UserInfo endpoint.
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    /// The published signing keys.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// The RFC 7662 endpoint.
    #[serde(default)]
    pub introspection_endpoint: Option<String>,
    /// The RFC 7009 endpoint.
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    /// The RP-initiated logout endpoint.
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    /// The signing algorithms of ID tokens.
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Whether authorization responses carry `iss` (RFC 9207).
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
}

/// A discovered provider: its metadata and the verifier of its JWTs.
pub(crate) struct Provider {
    pub(crate) metadata: ProviderMetadata,
    pub(crate) jwt: JwtVerifier,
}

async fn discover(config: &AuthClientConfig, transport: &Arc<dyn Transport>) -> Result<Provider> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        config.issuer().trim_end_matches('/')
    );
    let request = HttpRequest::new(Method::Get, url, config.timeout())
        .with_header("accept", "application/json");
    let response = transport
        .send(request)
        .await
        .map_err(|err| AuthAiError::new(ErrorCode::Oidc001).with_source(err))?;
    if !response.is_success() {
        return Err(AuthAiError::new(ErrorCode::Oidc001).with_detail("status", response.status));
    }
    let metadata: ProviderMetadata = response
        .parse_json()
        .map_err(|err| AuthAiError::new(ErrorCode::Oidc001).with_source(err))?;
    if metadata.issuer != config.issuer() {
        return Err(AuthAiError::new(ErrorCode::Oidc001)
            .with_message("The discovery document names another issuer"));
    }
    let algorithm = metadata
        .id_token_signing_alg_values_supported
        .iter()
        .find_map(|name| supported_algorithm(name));
    let (Some(algorithm), Some(jwks_uri)) = (algorithm, metadata.jwks_uri.clone()) else {
        return Err(AuthAiError::new(ErrorCode::Oidc001).with_message(
            "The provider advertises no supported asymmetric ID token algorithm (ES256, ES384, RS*, PS*) or no jwks_uri",
        ));
    };
    let jwks = RemoteJwks::new(jwks_uri, Arc::clone(transport), config.timeout(), algorithm);
    Ok(Provider {
        metadata,
        jwt: JwtVerifier::new(
            config.issuer().to_owned(),
            jwks,
            algorithm,
            config.clock_tolerance_seconds(),
        ),
    })
}

/// Discovers the provider once and again after an hour. A failed load is not cached.
pub(crate) struct ProviderLoader {
    config: AuthClientConfig,
    transport: Arc<dyn Transport>,
    cached: Mutex<Option<(Instant, Arc<Provider>)>>,
}

impl ProviderLoader {
    pub(crate) fn new(config: AuthClientConfig, transport: Arc<dyn Transport>) -> Self {
        Self {
            config,
            transport,
            cached: Mutex::new(None),
        }
    }

    pub(crate) async fn get(&self) -> Result<Arc<Provider>> {
        let mut cached = self.cached.lock().await;
        if let Some((loaded_at, provider)) = cached.as_ref()
            && loaded_at.elapsed() < PROVIDER_TTL
        {
            return Ok(Arc::clone(provider));
        }
        let provider = Arc::new(discover(&self.config, &self.transport).await?);
        *cached = Some((Instant::now(), Arc::clone(&provider)));
        Ok(provider)
    }
}
