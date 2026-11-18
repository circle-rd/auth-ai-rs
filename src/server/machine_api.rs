//! The auth-service REST API as the application's backend.

use std::sync::Arc;

use crate::client::AuthClient;
use crate::error::{AuthAiError, ErrorCode, Result};
use crate::http::JsonHttp;
use crate::server::billing::BillingApi;
use crate::server::consumption::ConsumptionApi;
use crate::server::machine_tokens::MachineTokenProvider;
use crate::server::resources::ResourcesApi;

/// The auth-service REST API as the application's backend.
///
/// Every call carries a `client_credentials` token minted from the
/// application's own secret. The scopes `billing:read`, `consumption:read`,
/// `consumption:write` and `resources:validate` are granted to new
/// confidential applications; older applications, and the platform scope
/// `resources:authorize`, need a superadmin.
#[derive(Debug, Clone)]
pub struct MachineApi {
    /// Subscription, usage and invoices.
    pub billing: BillingApi,
    /// Usage reporting.
    pub consumption: ConsumptionApi,
    /// Resource sharing.
    pub resources: ResourcesApi,
}

impl MachineApi {
    /// Builds the machine API on a confidential client.
    ///
    /// # Errors
    /// `CFG_001` when the client has no secret.
    pub fn new(auth: &AuthClient) -> Result<Self> {
        let config = auth.config();
        if config.client_secret().is_none() {
            return Err(AuthAiError::new(ErrorCode::Cfg001)
                .with_message("The machine API requires a confidential client"));
        }
        let http = Arc::new(JsonHttp::new(
            config.issuer(),
            auth.transport(),
            config.timeout(),
            Arc::new(MachineTokenProvider::new(auth.clone())),
        ));
        Ok(Self {
            billing: BillingApi::new(Arc::clone(&http)),
            consumption: ConsumptionApi::new(Arc::clone(&http)),
            resources: ResourcesApi::new(http),
        })
    }
}
