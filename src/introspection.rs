//! RFC 7662 token introspection answer.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::claims::Audience;

/// RFC 7662 answer. Unknown members are kept in `extra`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntrospectionResult {
    /// Whether the token is currently active.
    pub active: bool,
    /// Space-separated scopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The OAuth client the token was issued to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// The subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// A human-readable identifier of the subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// The audience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<Audience>,
    /// Expiry, in unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<f64>,
    /// Issue time, in unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<f64>,
    /// Members this SDK does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}
