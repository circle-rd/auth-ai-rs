//! `client_credentials` tokens of the application, one per scope.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;

use crate::client::AuthClient;
use crate::error::{AuthAiError, ErrorCode, Result};
use crate::http::HttpTokens;
use crate::secret::SecretString;
use crate::util::now_unix;

/// A cached token is renewed this long before it expires.
const EXPIRY_SKEW_SECONDS: i64 = 30;

/// `client_credentials` tokens of the application, one per scope set.
///
/// They are cached until shortly before they expire, and concurrent callers
/// wait on one request to the token endpoint instead of sending their own.
pub(crate) struct MachineTokenProvider {
    auth: AuthClient,
    cache: Mutex<HashMap<String, (SecretString, i64)>>,
    gates: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl MachineTokenProvider {
    pub(crate) fn new(auth: AuthClient) -> Self {
        Self {
            auth,
            cache: Mutex::new(HashMap::new()),
            gates: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, scope: &str) -> Option<SecretString> {
        let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        cache
            .get(scope)
            .filter(|(_, expires_at)| expires_at - EXPIRY_SKEW_SECONDS > now_unix())
            .map(|(token, _)| token.clone())
    }

    async fn mint(&self, scope: &str) -> Result<SecretString> {
        let tokens = self
            .auth
            .client_credentials(Some(scope), None)
            .await
            .map_err(|err| {
                // The scope goes in `details` (for logs); the message stays generic.
                if err.oauth_error() == Some("invalid_scope") {
                    AuthAiError::new(ErrorCode::Tok004)
                        .with_detail("scope", scope.to_owned())
                        .with_source(err)
                } else {
                    err
                }
            })?;
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                scope.to_owned(),
                (tokens.access_token.clone(), tokens.expires_at),
            );
        Ok(tokens.access_token)
    }
}

#[async_trait]
impl HttpTokens for MachineTokenProvider {
    async fn get_token(&self, scope: &str) -> Result<SecretString> {
        if let Some(token) = self.cached(scope) {
            return Ok(token);
        }
        let gate = Arc::clone(
            self.gates
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(scope.to_owned())
                .or_default(),
        );
        let _turn = gate.lock().await;
        // Another caller may have minted while this one waited for its turn.
        if let Some(token) = self.cached(scope) {
            return Ok(token);
        }
        self.mint(scope).await
    }

    fn invalidate(&self, scope: &str) {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(scope);
    }
}
