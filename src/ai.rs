//! What an application does for one signed-in user: read the wallet, call the gateway.

use std::sync::Arc;

use async_trait::async_trait;

use crate::client::AuthClient;
use crate::error::{AuthAiError, ErrorCode, Result};
use crate::gateway::{GatewayClient, GatewayTokens};
use crate::grants::GrantManager;
use crate::http::{HttpTokens, JsonHttp};
use crate::secret::SecretString;
use crate::wallet::WalletClient;

/// Mints the access token of one user for one audience, from the grant manager.
///
/// Serves both the wallet (a single audience, so the key is ignored) and the gateway.
struct AudienceTokens {
    grants: GrantManager,
    grant_id: String,
    resource: String,
}

impl AudienceTokens {
    async fn mint(&self) -> Result<SecretString> {
        Ok(self
            .grants
            .get_access_token(&self.grant_id, Some(&self.resource))
            .await?
            .access_token)
    }

    fn drop_cached(&self) {
        self.grants.invalidate(&self.grant_id, Some(&self.resource));
    }
}

#[async_trait]
impl HttpTokens for AudienceTokens {
    async fn get_token(&self, _key: &str) -> Result<SecretString> {
        self.mint().await
    }

    fn invalidate(&self, _key: &str) {
        self.drop_cached();
    }
}

#[async_trait]
impl GatewayTokens for AudienceTokens {
    async fn get_token(&self) -> Result<SecretString> {
        self.mint().await
    }

    fn invalidate(&self) {
        self.drop_cached();
    }
}

/// What an application does for one signed-in user: read the wallet, call the gateway.
#[derive(Debug)]
pub struct UserAi {
    /// The user's wallet.
    pub wallet: WalletClient,
    gateway: Option<GatewayClient>,
}

impl UserAi {
    /// The gateway, which needs `gateway_url` in the client configuration.
    ///
    /// # Errors
    /// `CFG_001` when the configuration names no gateway.
    pub fn gateway(&self) -> Result<&GatewayClient> {
        self.gateway.as_ref().ok_or_else(|| {
            AuthAiError::new(ErrorCode::Cfg001)
                .with_message("The gateway requires `gateway_url` in the configuration")
        })
    }
}

/// Wallet and gateway clients bound to a user's grant.
///
/// Each call mints (or reuses) a short-lived access token for the right
/// audience: the wallet is served by auth-service, the gateway by its own URL.
#[derive(Debug, Clone)]
pub struct AiClient {
    auth: AuthClient,
    grants: GrantManager,
}

impl AiClient {
    /// Binds the OIDC client to the grant manager that mints the tokens.
    #[must_use]
    pub const fn new(auth: AuthClient, grants: GrantManager) -> Self {
        Self { auth, grants }
    }

    /// `grant_id` is the key the user's refresh token was saved under (typically `sub`).
    ///
    /// # Errors
    /// `CFG_001` when the configured gateway URL cannot be used.
    pub fn for_user(&self, grant_id: &str) -> Result<UserAi> {
        let config = self.auth.config();
        let tokens = |resource: &str| {
            Arc::new(AudienceTokens {
                grants: self.grants.clone(),
                grant_id: grant_id.to_owned(),
                resource: resource.to_owned(),
            })
        };
        let wallet = WalletClient::new(
            JsonHttp::new(
                config.issuer(),
                self.auth.transport(),
                config.timeout(),
                tokens(config.issuer()),
            ),
            config.issuer(),
        );
        let gateway = config
            .gateway_url()
            .map(|url| {
                GatewayClient::new(url, tokens(url), self.auth.transport(), config.timeout())
            })
            .transpose()?;
        Ok(UserAi { wallet, gateway })
    }
}
