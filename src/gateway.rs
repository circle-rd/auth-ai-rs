//! The LiteLLM gateway on behalf of a signed-in user.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use url::{Origin, Url};

use crate::error::{AuthAiError, ErrorCode, Result};
use crate::gateway_errors::to_gateway_error;
use crate::secret::SecretString;
use crate::transport::{HttpRequest, Method, Transport};

const MAX_SERVER_NAME_LENGTH: usize = 128;
// The gateway's own `/v1/mcp/...` routes own this segment: no server can be named so.
const RESERVED_SERVER_NAME: &str = "v1";

/// A model the user may call. Members LiteLLM adds across versions are kept in `extra`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatewayModel {
    /// Model id, to pass as `model`.
    pub id: String,
    /// Always `model` for LiteLLM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// Creation time, in unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<i64>,
    /// The owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owned_by: Option<String>,
    /// Members this SDK does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Deserialize)]
struct ModelList {
    data: Vec<GatewayModel>,
}

/// An agent the user may reach.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatewayAgent {
    /// Agent id.
    pub agent_id: String,
    /// Agent name.
    pub agent_name: String,
    /// Members this SDK does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An MCP server the user may reach.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatewayMcpServer {
    /// Server id.
    pub server_id: String,
    /// Server name, usable with [`GatewayClient::mcp_url`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    /// Alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Transport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Members this SDK does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Supplies the access token minted for the gateway audience.
#[async_trait]
pub(crate) trait GatewayTokens: Send + Sync {
    async fn get_token(&self) -> Result<SecretString>;

    /// Drops the token the gateway refused, so the next call mints a fresh one.
    fn invalidate(&self);
}

/// The LiteLLM gateway on behalf of a signed-in user.
///
/// The user's access token is the API key: it lives one hour, so it is minted
/// per call (and cached by the grant manager) and never stored. The gateway
/// bills the user's wallet.
///
/// The token is only ever sent to the gateway's own origin. To stream a
/// completion with an OpenAI-compatible SDK, give it
/// [`GatewayClient::openai_base_url`] and a token from
/// [`GatewayClient::access_token`], fetched again for every request.
pub struct GatewayClient {
    gateway_url: String,
    origin: Origin,
    tokens: Arc<dyn GatewayTokens>,
    transport: Arc<dyn Transport>,
    timeout: Duration,
}

impl std::fmt::Debug for GatewayClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayClient")
            .field("gateway_url", &self.gateway_url)
            .finish_non_exhaustive()
    }
}

impl GatewayClient {
    pub(crate) fn new(
        gateway_url: &str,
        tokens: Arc<dyn GatewayTokens>,
        transport: Arc<dyn Transport>,
        timeout: Duration,
    ) -> Result<Self> {
        let origin = Url::parse(gateway_url)
            .map_err(|err| {
                AuthAiError::new(ErrorCode::Cfg001)
                    .with_message("Invalid gateway URL")
                    .with_source(err)
            })?
            .origin();
        Ok(Self {
            gateway_url: gateway_url.to_owned(),
            origin,
            tokens,
            transport,
            timeout,
        })
    }

    /// `base_url` of an OpenAI-compatible SDK.
    #[must_use]
    pub fn openai_base_url(&self) -> String {
        format!("{}/v1", self.gateway_url)
    }

    /// A fresh access token, for clients that sign their own requests.
    ///
    /// # Errors
    /// `TOK_002` when the user has no usable grant.
    pub async fn access_token(&self) -> Result<SecretString> {
        self.tokens.get_token().await
    }

    /// Drops the cached token after the gateway answered 401 to a request you
    /// signed yourself: the next [`GatewayClient::access_token`] mints a new one.
    pub fn invalidate_token(&self) {
        self.tokens.invalidate();
    }

    /// The models the user may call: the ones they own or that are shared with them.
    ///
    /// # Errors
    /// A gateway error (`GW_*`).
    pub async fn list_models(&self) -> Result<Vec<GatewayModel>> {
        Ok(self.get_json::<ModelList>("/v1/models").await?.data)
    }

    /// The agents the user may reach.
    ///
    /// # Errors
    /// A gateway error (`GW_*`).
    pub async fn list_agents(&self) -> Result<Vec<GatewayAgent>> {
        self.get_json("/v1/agents").await
    }

    /// The MCP servers the user may reach.
    ///
    /// # Errors
    /// A gateway error (`GW_*`).
    pub async fn list_mcp_servers(&self) -> Result<Vec<GatewayMcpServer>> {
        self.get_json("/v1/mcp/server").await
    }

    /// Endpoint of the gateway's MCP server, or of one registered server.
    ///
    /// Connect an MCP client to it with the `Authorization: Bearer` header of
    /// [`GatewayClient::access_token`].
    ///
    /// # Errors
    /// `CFG_001` for an invalid server name.
    pub fn mcp_url(&self, server_name: Option<&str>) -> Result<String> {
        let Some(name) = server_name else {
            return Ok(format!("{}/mcp", self.gateway_url));
        };
        if !is_server_name(name) || name.eq_ignore_ascii_case(RESERVED_SERVER_NAME) {
            return Err(AuthAiError::new(ErrorCode::Cfg001).with_message("Invalid MCP server name"));
        }
        Ok(format!("{}/{name}/mcp", self.gateway_url))
    }

    /// POSTs JSON to a gateway route (`/v1/chat/completions`, `/v1/embeddings`…).
    ///
    /// Returns the parsed answer, which the caller validates. A refusal becomes
    /// a gateway error: `GW_001` when the wallet cannot pay (402).
    ///
    /// # Errors
    /// `CFG_001` when `path` would leave the gateway, a gateway error otherwise.
    pub async fn post_json(&self, path: &str, body: &Value) -> Result<Value> {
        self.send(Method::Post, path, Some(body)).await
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let body = self.send(Method::Get, path, None).await?;
        serde_json::from_value(body)
            .map_err(|err| AuthAiError::new(ErrorCode::Gw005).with_source(err))
    }

    async fn send(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        let url = format!("{}{path}", self.gateway_url);
        // The token goes to the gateway and nowhere else, whatever the path says.
        let stays = path.starts_with('/')
            && Url::parse(&url).is_ok_and(|parsed| parsed.origin() == self.origin);
        if !stays {
            return Err(AuthAiError::new(ErrorCode::Cfg001)
                .with_message("This client only serves requests to the gateway"));
        }
        let token = self.tokens.get_token().await?;
        let mut request = HttpRequest::new(method, url, self.timeout)
            .with_header("authorization", format!("Bearer {}", token.expose_secret()))
            .with_header("accept", "application/json");
        if let Some(body) = body {
            request = request.with_json(body);
        }
        let response = self.transport.send(request).await.map_err(|err| {
            AuthAiError::new(ErrorCode::Gw004)
                .with_message("The gateway is unreachable")
                .with_source(err)
        })?;
        if response.status == 401 {
            self.tokens.invalidate();
        }
        let parsed = response.json_value();
        if !response.is_success() {
            return Err(to_gateway_error(
                response.status,
                parsed.as_ref(),
                &response.headers,
            ));
        }
        parsed.ok_or_else(|| {
            AuthAiError::new(ErrorCode::Gw005)
                .with_message("The gateway answered a body that is not JSON")
        })
    }
}

fn is_server_name(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        && name.len() <= MAX_SERVER_NAME_LENGTH
        && characters.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}
