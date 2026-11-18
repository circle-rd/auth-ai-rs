//! Resource sharing from the side of an adapter service or of a scheme owner.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::error::{AuthAiError, ErrorCode, Result};
use crate::http::JsonHttp;
use crate::transport::Method;
use crate::util::encode_segment;

/// Machine scope that reaches every user and every resource of the instance.
pub const AUTHORIZE_SCOPE: &str = "resources:authorize";
/// Machine scope of the validator bound to a resource scheme.
pub const VALIDATE_SCOPE: &str = "resources:validate";
const GATEWAY_PATH: &str = "/api/internal/gateway";
const RESOURCES_PATH: &str = "/api/internal/gateway/resources";
const MAX_REASON_LENGTH: usize = 500;

/// Who owns a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OwnerType {
    /// A user.
    User,
    /// An application.
    Application,
}

/// Why a user may use a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessKind {
    /// The user owns it.
    Owner,
    /// It was shared with the user.
    Grant,
}

/// Who a grant targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GrantSubjectType {
    /// One user.
    User,
    /// An organization.
    Organization,
    /// A plan.
    Plan,
    /// Everyone.
    Everyone,
}

/// Where a resource stands in its validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceStatus {
    /// Waiting for its scheme's validator.
    PendingValidation,
    /// The validator refused it.
    ValidationFailed,
    /// Usable.
    Validated,
    /// Withdrawn.
    Disabled,
}

/// What produced an access event, recorded in the access log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventSource {
    /// The LiteLLM gateway (the default).
    Gateway,
    /// The SSH gateway.
    Ssh,
    /// Any other enforcement point.
    External,
    /// A direct API call.
    Api,
}

/// The outcome of an ownership check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationResult {
    /// Ownership was proven.
    Validated,
    /// It was not.
    ValidationFailed,
}

/// The user may use the resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Allowed {
    /// The resource id.
    pub resource_id: String,
    /// The resource URI.
    pub resource_uri: String,
    /// The application the resource belongs to.
    pub application_slug: String,
    /// Who owns the resource.
    pub owner_type: OwnerType,
    /// The owner's id.
    pub owner_id: String,
    /// Why the user may use it.
    pub access_kind: AccessKind,
}

/// The answer to an authorization request.
///
/// Only `Allowed` carries data; a decision this SDK does not know fails to
/// parse, so an unexpected answer can never read as an admission. A denial
/// carries no reason, on purpose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "lowercase")]
pub enum AuthorizeDecision {
    /// The user may use the resource.
    #[serde(rename = "allow")]
    Allowed(Allowed),
    /// The user may not use the resource.
    #[serde(rename = "deny")]
    Denied,
}

impl AuthorizeDecision {
    /// The admission, when there is one.
    #[must_use]
    pub const fn allowed(&self) -> Option<&Allowed> {
        match self {
            Self::Allowed(allowed) => Some(allowed),
            Self::Denied => None,
        }
    }
}

/// A resource a user may use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessibleResource {
    /// The resource id.
    pub resource_id: String,
    /// The resource URI.
    pub resource_uri: String,
    /// The URI scheme.
    pub scheme: String,
    /// Display name.
    pub display_name: String,
    /// The application id.
    pub application_id: String,
    /// The application slug.
    pub application_slug: String,
    /// The application name.
    pub application_name: String,
    /// Who owns the resource.
    pub owner_type: OwnerType,
    /// The owner's id.
    pub owner_id: String,
    /// Why the user may use it.
    pub access_kind: AccessKind,
    /// Set when `access_kind` is `grant`.
    #[serde(default)]
    pub grant_subject_type: Option<GrantSubjectType>,
}

#[derive(Deserialize)]
struct AccessibleList {
    resources: Vec<AccessibleResource>,
}

/// A resource as the validator sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceState {
    /// The resource id.
    pub id: String,
    /// The resource URI.
    pub uri: String,
    /// Its validation status.
    pub status: ResourceStatus,
    /// Why validation failed, when it did.
    pub validation_error: Option<String>,
}

#[derive(Deserialize)]
struct ResourceResponse {
    resource: ResourceState,
}

fn invalid(what: &str, issues: &[String]) -> AuthAiError {
    AuthAiError::new(ErrorCode::Cfg001)
        .with_message(format!("Invalid {what}: {}", issues.join("; ")))
}

fn length_between(issues: &mut Vec<String>, field: &str, value: &str, min: usize, max: usize) {
    let length = value.chars().count();
    if length < min || length > max {
        issues.push(format!("{field}: must be {min} to {max} characters"));
    }
}

fn is_uuid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, length)| {
            group.len() == length && group.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

fn is_scheme(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase())
        && value.len() <= 50
        && characters.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn check_resource_id(issues: &mut Vec<String>, resource_id: &str) {
    if !is_uuid(resource_id) {
        issues.push("resource_id: must be a UUID".to_owned());
    }
}

/// Resource sharing from the side of an adapter service or of a scheme owner.
///
/// The decision point stays auth-service: these calls ask it, they never decide.
///
/// `resources:authorize` reaches every user and every resource of the instance,
/// so a superadmin grants it only to a trusted enforcement point.
/// `resources:validate` is granted to new confidential applications and acts
/// only for the resource schemes bound to the calling client.
#[derive(Clone)]
pub struct ResourcesApi {
    http: Arc<JsonHttp>,
}

impl std::fmt::Debug for ResourcesApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourcesApi").finish_non_exhaustive()
    }
}

/// The members of an authorization request.
#[derive(Debug, Clone, Default)]
pub struct AuthorizeRequest<'a> {
    /// The user, from a token you verified.
    pub subject_id: &'a str,
    /// The OAuth client of that token.
    pub client_id: &'a str,
    /// The resource the user asks for.
    pub resource_uri: &'a str,
    /// The audience of that token.
    pub audience: &'a str,
    /// Correlates the access event with your own request id.
    pub request_id: Option<&'a str>,
    /// Recorded in the access log (`gateway` by default).
    pub source: Option<EventSource>,
}

impl ResourcesApi {
    pub(crate) const fn new(http: Arc<JsonHttp>) -> Self {
        Self { http }
    }

    /// Asks whether a user may use a resource. Needs `resources:authorize`.
    ///
    /// Take `subject_id`, `client_id` and `audience` from a token you verified,
    /// never from the request body. Anything other than an
    /// [`AuthorizeDecision::Allowed`] answer is a refusal, and so is a raised
    /// error: fail closed. A denial carries no reason, so it cannot be used to
    /// probe.
    ///
    /// # Errors
    /// `CFG_001` for an invalid request (checked before any request), `API_001`
    /// for a refusal, `API_002` for an answer that is neither a known deny nor a
    /// complete allow.
    pub async fn authorize(&self, request: &AuthorizeRequest<'_>) -> Result<AuthorizeDecision> {
        let mut issues = Vec::new();
        length_between(&mut issues, "subject_id", request.subject_id, 1, 256);
        length_between(&mut issues, "client_id", request.client_id, 1, 256);
        length_between(&mut issues, "resource_uri", request.resource_uri, 3, 512);
        length_between(&mut issues, "audience", request.audience, 1, 2048);
        if let Some(request_id) = request.request_id {
            length_between(&mut issues, "request_id", request_id, 1, 256);
        }
        if !issues.is_empty() {
            return Err(invalid("authorize request", &issues));
        }
        let mut body = Map::new();
        body.insert("subjectId".to_owned(), json!(request.subject_id));
        body.insert("clientId".to_owned(), json!(request.client_id));
        body.insert("resourceUri".to_owned(), json!(request.resource_uri));
        body.insert("audience".to_owned(), json!(request.audience));
        if let Some(request_id) = request.request_id {
            body.insert("requestId".to_owned(), json!(request_id));
        }
        if let Some(source) = request.source {
            body.insert("source".to_owned(), json!(source));
        }
        let body = Value::Object(body);
        self.http
            .request(
                Method::Post,
                &format!("{GATEWAY_PATH}/authorize"),
                AUTHORIZE_SCOPE,
                &[],
                Some(&body),
            )
            .await
    }

    /// Every validated resource a user may use, across applications.
    ///
    /// Use it to filter a listing, never as the admission of a request: call
    /// [`ResourcesApi::authorize`] for that. `scheme` narrows the list, e.g.
    /// `llm`. Needs `resources:authorize`.
    ///
    /// # Errors
    /// `CFG_001` for an invalid query, `API_001` for a refusal, `API_002` for an
    /// unexpected answer.
    pub async fn list_accessible(
        &self,
        subject_id: &str,
        scheme: Option<&str>,
    ) -> Result<Vec<AccessibleResource>> {
        let mut issues = Vec::new();
        length_between(&mut issues, "subject_id", subject_id, 1, 256);
        if scheme.is_some_and(|scheme| !is_scheme(scheme)) {
            issues.push("scheme: must be a lowercase scheme of 50 characters at most".to_owned());
        }
        if !issues.is_empty() {
            return Err(invalid("accessible query", &issues));
        }
        let query = [
            ("subjectId", Some(subject_id.to_owned())),
            ("scheme", scheme.map(str::to_owned)),
        ];
        let response: AccessibleList = self
            .http
            .request(
                Method::Get,
                &format!("{RESOURCES_PATH}/accessible"),
                AUTHORIZE_SCOPE,
                &query,
                None,
            )
            .await?;
        Ok(response.resources)
    }

    /// Reports the outcome of the ownership check the validator ran on a resource.
    ///
    /// Only the client bound to the resource's scheme may call it; auth-service
    /// refuses any other with `AUTH_011`. `reason` (500 characters at most) is
    /// shown to the owner when validation failed. `evidence` is the proof the
    /// validator gathered: never put a secret in it. Needs `resources:validate`.
    ///
    /// # Errors
    /// `CFG_001` for an invalid outcome, `API_001` for a refusal, `API_002` for
    /// an unexpected answer.
    pub async fn validate(
        &self,
        resource_id: &str,
        result: ValidationResult,
        reason: Option<&str>,
        evidence: Option<&Map<String, Value>>,
    ) -> Result<ResourceState> {
        let mut issues = Vec::new();
        check_resource_id(&mut issues, resource_id);
        let reason = reason.map(str::trim);
        if let Some(reason) = reason {
            length_between(&mut issues, "reason", reason, 0, MAX_REASON_LENGTH);
        }
        if !issues.is_empty() {
            return Err(invalid("validation outcome", &issues));
        }
        let mut body = Map::new();
        body.insert("result".to_owned(), json!(result));
        if let Some(reason) = reason {
            body.insert("reason".to_owned(), json!(reason));
        }
        if let Some(evidence) = evidence {
            body.insert("evidence".to_owned(), Value::Object(evidence.clone()));
        }
        let body = Value::Object(body);
        let path = format!("{RESOURCES_PATH}/{}/validate", encode_segment(resource_id));
        let response: ResourceResponse = self
            .http
            .request(Method::Post, &path, VALIDATE_SCOPE, &[], Some(&body))
            .await?;
        Ok(response.resource)
    }

    /// Disables a resource whose ownership was lost (a host key changed, the object deleted).
    ///
    /// New access is refused at once. The reason is kept in the audit trail.
    /// Only the client bound to the scheme may call it. Needs `resources:validate`.
    ///
    /// # Errors
    /// `CFG_001` for an invalid reason, `API_001` for a refusal, `API_002` for an
    /// unexpected answer.
    pub async fn invalidate(&self, resource_id: &str, reason: &str) -> Result<ResourceState> {
        let mut issues = Vec::new();
        check_resource_id(&mut issues, resource_id);
        let reason = reason.trim();
        length_between(&mut issues, "reason", reason, 1, MAX_REASON_LENGTH);
        if !issues.is_empty() {
            return Err(invalid("invalidation reason", &issues));
        }
        let path = format!(
            "{RESOURCES_PATH}/{}/invalidate",
            encode_segment(resource_id)
        );
        let response: ResourceResponse = self
            .http
            .request(
                Method::Post,
                &path,
                VALIDATE_SCOPE,
                &[],
                Some(&json!({ "reason": reason })),
            )
            .await?;
        Ok(response.resource)
    }
}
