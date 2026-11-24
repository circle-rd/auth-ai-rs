//! Verification of the signed resource-sharing webhooks auth-service delivers.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::{AuthAiError, ErrorCode, Result};
use crate::secret::SecretString;
use crate::server::resources::{GrantSubjectType, OwnerType, ResourcePermission, ResourceStatus};
use crate::util::{hex_lower, hmac_sha256, now_unix, secrets_equal};

/// The signature header auth-service sends with a resource webhook.
pub const SIGNATURE_HEADER: &str = "x-auth-service-signature";
/// How far the webhook timestamp may be from now, by default.
pub const DEFAULT_TOLERANCE_SECONDS: u64 = 300;

/// What happened to a resource or one of its grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceEventType {
    /// A grant was created.
    #[serde(rename = "resource.grant.created")]
    GrantCreated,
    /// A grant was revoked.
    #[serde(rename = "resource.grant.revoked")]
    GrantRevoked,
    /// The level of a grant changed.
    #[serde(rename = "resource.grant.updated")]
    GrantUpdated,
    /// The resource was deleted.
    #[serde(rename = "resource.deleted")]
    Deleted,
}

/// The application the event belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookApplication {
    /// The application id.
    pub id: String,
    /// The application slug.
    pub slug: String,
}

/// The resource the grant targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookResource {
    /// The resource id.
    pub id: String,
    /// The resource URI.
    pub uri: String,
    /// The URI scheme.
    pub scheme: String,
    /// Display name.
    pub display_name: String,
    /// Who owns the resource.
    pub owner_type: OwnerType,
    /// The owner's id; sent only to the application that owns the resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    /// Where the resource stands in its validation.
    pub status: ResourceStatus,
}

/// The resource a deletion removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookDeletedResource {
    /// The resource id.
    pub id: String,
    /// The resource URI.
    pub uri: String,
    /// The URI scheme.
    pub scheme: String,
    /// Display name.
    pub display_name: String,
    /// Who owned the resource.
    pub owner_type: OwnerType,
    /// The owner's id; sent only to the application that owns the resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
}

/// The grant the event concerns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookGrant {
    /// The grant id.
    pub id: String,
    /// Who the grant targets.
    pub subject_type: GrantSubjectType,
    /// The target id, when there is one.
    #[serde(default)]
    pub subject_id: Option<String>,
    /// The level the grant carries.
    pub permission: ResourcePermission,
    /// The level before a `resource.grant.updated` event.
    #[serde(default)]
    pub previous_permission: Option<ResourcePermission>,
    /// When the grant expires.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

/// Who the receiver should notify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookRecipients {
    /// The users to notify; `None` with `all_members` means the whole application.
    #[serde(default)]
    pub user_ids: Option<Vec<String>>,
    /// Whether the event concerns every member of the application.
    #[serde(default)]
    pub all_members: bool,
}

/// A grant event: `resource.grant.created`, `resource.grant.revoked` or `resource.grant.updated`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceGrantEvent {
    /// The event id: deduplicate on it, delivery is at least once.
    pub event_id: String,
    /// When it happened.
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    /// The application.
    pub application: WebhookApplication,
    /// The resource.
    pub resource: WebhookResource,
    /// The grant.
    pub grant: WebhookGrant,
    /// Who to notify.
    pub recipients: WebhookRecipients,
}

/// A `resource.deleted` event: it carries the resource only, no grant and no recipients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDeletedEvent {
    /// The event id: deduplicate on it, delivery is at least once.
    pub event_id: String,
    /// When it happened.
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    /// The application.
    pub application: WebhookApplication,
    /// The resource that was removed.
    pub resource: WebhookDeletedResource,
}

/// A signed resource-sharing event delivered by auth-service, tagged by its `type`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ResourceEvent {
    /// A grant was created.
    #[serde(rename = "resource.grant.created")]
    GrantCreated(ResourceGrantEvent),
    /// A grant was revoked.
    #[serde(rename = "resource.grant.revoked")]
    GrantRevoked(ResourceGrantEvent),
    /// The level of a grant changed.
    #[serde(rename = "resource.grant.updated")]
    GrantUpdated(ResourceGrantEvent),
    /// The resource was deleted.
    #[serde(rename = "resource.deleted")]
    Deleted(ResourceDeletedEvent),
}

impl ResourceEvent {
    /// What happened.
    #[must_use]
    pub const fn kind(&self) -> ResourceEventType {
        match self {
            Self::GrantCreated(_) => ResourceEventType::GrantCreated,
            Self::GrantRevoked(_) => ResourceEventType::GrantRevoked,
            Self::GrantUpdated(_) => ResourceEventType::GrantUpdated,
            Self::Deleted(_) => ResourceEventType::Deleted,
        }
    }

    /// The event id: deduplicate on it, delivery is at least once.
    #[must_use]
    pub fn event_id(&self) -> &str {
        match self {
            Self::GrantCreated(event) | Self::GrantRevoked(event) | Self::GrantUpdated(event) => {
                &event.event_id
            }
            Self::Deleted(event) => &event.event_id,
        }
    }
}

/// Verifies a resource webhook with the default 300-second timestamp window.
///
/// The header is `t=<unix seconds>,v1=<hex HMAC-SHA256>` over `<t>.<raw body>`.
/// Idempotency is the receiver's responsibility: deduplicate on `event_id`.
///
/// # Errors
/// `REQ_001` when the header is missing or malformed, the timestamp is outside
/// the window, the signature does not match, or the body is not a complete
/// [`ResourceEvent`].
pub fn verify_resource_event(
    headers: &[(String, String)],
    body: &[u8],
    secret: &str,
) -> Result<ResourceEvent> {
    ResourceWebhookVerifier::new(secret).verify(headers, body)
}

/// Verifies resource webhooks with a custom timestamp window.
#[derive(Clone)]
pub struct ResourceWebhookVerifier {
    secret: SecretString,
    tolerance_seconds: u64,
}

impl std::fmt::Debug for ResourceWebhookVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceWebhookVerifier")
            .field("tolerance_seconds", &self.tolerance_seconds)
            .finish_non_exhaustive()
    }
}

impl ResourceWebhookVerifier {
    /// A verifier for one application's webhook secret.
    #[must_use]
    pub fn new(secret: impl Into<SecretString>) -> Self {
        Self {
            secret: secret.into(),
            tolerance_seconds: DEFAULT_TOLERANCE_SECONDS,
        }
    }

    /// Replaces the accepted timestamp window, in seconds.
    #[must_use]
    pub const fn tolerance_seconds(mut self, seconds: u64) -> Self {
        self.tolerance_seconds = seconds;
        self
    }

    /// Verifies and parses one delivery.
    ///
    /// # Errors
    /// `REQ_001` under the conditions of [`verify_resource_event`].
    pub fn verify(&self, headers: &[(String, String)], body: &[u8]) -> Result<ResourceEvent> {
        self.verify_at(headers, body, now_unix())
    }

    fn verify_at(
        &self,
        headers: &[(String, String)],
        body: &[u8],
        now: i64,
    ) -> Result<ResourceEvent> {
        let header = find_header(headers, SIGNATURE_HEADER)
            .ok_or_else(|| invalid(format!("Missing {SIGNATURE_HEADER} header")))?;
        let (timestamp, signatures) = parse_header(header)?;
        let signed_at: i64 = timestamp
            .parse()
            .map_err(|err| invalid("Malformed webhook timestamp").with_source(err))?;
        let skew = i128::from(now) - i128::from(signed_at);
        if skew.unsigned_abs() > u128::from(self.tolerance_seconds) {
            return Err(invalid("Webhook timestamp is outside the accepted window"));
        }
        let mut signed = Vec::with_capacity(timestamp.len() + 1 + body.len());
        signed.extend_from_slice(timestamp.as_bytes());
        signed.push(b'.');
        signed.extend_from_slice(body);
        let expected = hex_lower(&hmac_sha256(
            self.secret.expose_secret().as_bytes(),
            &signed,
        ));
        if !signatures
            .iter()
            .any(|candidate| secrets_equal(&expected, candidate))
        {
            return Err(invalid("Webhook signature does not match"));
        }
        serde_json::from_slice(body)
            .map_err(|err| invalid("Webhook body has an unexpected shape").with_source(err))
    }
}

fn invalid(message: impl Into<String>) -> AuthAiError {
    AuthAiError::new(ErrorCode::Req001).with_message(message)
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn parse_header(header: &str) -> Result<(&str, Vec<&str>)> {
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for part in header.split(',') {
        let Some((name, value)) = part.trim().split_once('=') else {
            continue;
        };
        match name.trim() {
            "t" => timestamp = Some(value.trim()),
            "v1" => signatures.push(value.trim()),
            _ => {}
        }
    }
    let Some(timestamp) = timestamp.filter(|value| !value.is_empty()) else {
        return Err(invalid("Malformed X-Auth-Service-Signature header"));
    };
    if signatures.iter().all(|signature| signature.is_empty()) {
        return Err(invalid("Malformed X-Auth-Service-Signature header"));
    }
    Ok((timestamp, signatures))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::util::hex_lower;

    const SECRET: &str = "whsec_test_123";
    const NOW: i64 = 1_800_000_000;

    fn event() -> Value {
        json!({
            "eventId": "6f1c0f1e-2c3b-4a5d-8e9f-0a1b2c3d4e5f",
            "type": "resource.grant.created",
            "occurredAt": "2026-11-20T10:00:00Z",
            "application": { "id": "app-1", "slug": "gine" },
            "resource": {
                "id": "4b1f6f3e-5a6c-4d0e-9c53-0a4c6f0f7a11",
                "uri": "gine://job-1",
                "scheme": "gine",
                "displayName": "Firmware",
                "ownerType": "user",
                "ownerId": "user-1",
                "status": "validated"
            },
            "grant": {
                "id": "9c8b7a6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
                "subjectType": "user",
                "subjectId": "user-2",
                "permission": "read",
                "previousPermission": null,
                "expiresAt": null
            },
            "recipients": { "userIds": ["user-2"], "allMembers": false }
        })
    }

    fn sign(body: &[u8], timestamp: i64, secret: &str) -> String {
        let mut signed = format!("{timestamp}.").into_bytes();
        signed.extend_from_slice(body);
        format!(
            "t={timestamp},v1={}",
            hex_lower(&hmac_sha256(secret.as_bytes(), &signed))
        )
    }

    fn headers(value: String) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_owned(), value)]
    }

    #[test]
    fn parses_a_valid_delivery() {
        let body = serde_json::to_vec(&event()).unwrap();
        let parsed = ResourceWebhookVerifier::new(SECRET)
            .verify_at(&headers(sign(&body, NOW, SECRET)), &body, NOW)
            .unwrap();
        assert_eq!(parsed.kind(), ResourceEventType::GrantCreated);
        let ResourceEvent::GrantCreated(created) = parsed else {
            panic!("expected a created grant event");
        };
        assert_eq!(created.resource.uri, "gine://job-1");
        assert_eq!(created.recipients.user_ids, Some(vec!["user-2".to_owned()]));
    }

    #[test]
    fn accepts_a_mixed_case_header_and_one_matching_signature() {
        let body = serde_json::to_vec(&event()).unwrap();
        let header = format!("{},v1=deadbeef", sign(&body, NOW, SECRET));
        let headers = vec![("X-Auth-Service-Signature".to_owned(), header)];
        let parsed = ResourceWebhookVerifier::new(SECRET)
            .verify_at(&headers, &body, NOW)
            .unwrap();
        let ResourceEvent::GrantCreated(created) = parsed else {
            panic!("expected a created grant event");
        };
        assert_eq!(created.application.slug, "gine");
    }

    #[test]
    fn refuses_a_tampered_body() {
        let body = serde_json::to_vec(&event()).unwrap();
        let header = sign(&body, NOW, SECRET);
        let mut tampered = body.clone();
        tampered.push(b' ');
        let err = ResourceWebhookVerifier::new(SECRET)
            .verify_at(&headers(header), &tampered, NOW)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Req001);
    }

    #[test]
    fn refuses_a_wrong_secret_and_a_stale_timestamp() {
        let body = serde_json::to_vec(&event()).unwrap();
        assert!(
            ResourceWebhookVerifier::new(SECRET)
                .verify_at(&headers(sign(&body, NOW, "other")), &body, NOW)
                .is_err()
        );
        assert!(
            ResourceWebhookVerifier::new(SECRET)
                .verify_at(&headers(sign(&body, NOW - 3_600, SECRET)), &body, NOW)
                .is_err()
        );
        assert!(
            ResourceWebhookVerifier::new(SECRET)
                .tolerance_seconds(7_200)
                .verify_at(&headers(sign(&body, NOW - 3_600, SECRET)), &body, NOW)
                .is_ok()
        );
    }

    #[test]
    fn refuses_a_missing_or_malformed_header() {
        let body = serde_json::to_vec(&event()).unwrap();
        assert!(
            ResourceWebhookVerifier::new(SECRET)
                .verify_at(&[], &body, NOW)
                .is_err()
        );
        for header in ["", "t=nope,v1=aa", "v1=aa", "t=1", "t=1,v1=", "junk"] {
            assert!(
                ResourceWebhookVerifier::new(SECRET)
                    .verify_at(&headers(header.to_owned()), &body, NOW)
                    .is_err(),
                "{header}"
            );
        }
    }

    #[test]
    fn refuses_an_unexpected_shape() {
        let body = br#"{"eventId":"x"}"#.to_vec();
        let err = ResourceWebhookVerifier::new(SECRET)
            .verify_at(&headers(sign(&body, NOW, SECRET)), &body, NOW)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Req001);
    }
}
