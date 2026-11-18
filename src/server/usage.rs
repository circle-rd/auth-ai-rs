//! Reporting the usage a provider billed for a shared resource.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::resources::{ResourcesApi, invalid, is_uuid, length_between};
use crate::error::{AuthAiError, ErrorCode, Result};
use crate::transport::Method;

/// Machine scope that records the usage of a shared resource.
pub const USAGE_SCOPE: &str = "resources:usage:write";
const USAGE_PATH: &str = "/api/internal/gateway/usage";
const FUTURE_TOLERANCE: Duration = Duration::from_secs(5 * 60);
const PAST_WINDOW: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const REQUEST_ID_LENGTH: usize = 64;

/// Where the figures of a usage event come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UsageSource {
    /// The provider reported a cost: `cost_usd` is required.
    Provider,
    /// The provider reports nothing: no cost and no tokens.
    Unsupported,
}

/// One usage event of a shared resource.
///
/// `request_id` is the event's trusted identifier (64 lowercase hex characters):
/// replaying the same event is idempotent.
#[derive(Debug, Clone)]
pub struct UsageRecord<'a> {
    /// The user, from a token you verified.
    pub subject_id: &'a str,
    /// The OAuth client of that token.
    pub client_id: &'a str,
    /// The resource id.
    pub resource_id: &'a str,
    /// The resource URI.
    pub resource_uri: &'a str,
    /// The trusted event id: 64 lowercase hex characters.
    pub request_id: &'a str,
    /// When the usage happened: at most five minutes ahead, at most 30 days back.
    pub occurred_at: SystemTime,
    /// Where the figures come from.
    pub source: UsageSource,
    /// The gross cost in USD as a plain decimal (`"0.0042"`), required for `Provider`.
    pub cost_usd: Option<&'a str>,
    /// Prompt tokens, when the provider reports them.
    pub prompt_tokens: Option<u64>,
    /// Completion tokens, when the provider reports them.
    pub completion_tokens: Option<u64>,
    /// Total tokens, when the provider reports them.
    pub total_tokens: Option<u64>,
}

/// The stored usage event.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedUsage {
    /// The event's id in auth-service.
    pub id: String,
    /// The resource id.
    pub resource_id: String,
    /// The trusted event id.
    pub request_id: String,
    /// When the usage happened (RFC 3339).
    pub occurred_at: String,
}

/// The answer to a usage report.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UsageReceipt {
    /// The stored event.
    pub usage: RecordedUsage,
    /// `true` when the event had already been recorded.
    pub replayed: bool,
}

fn is_plain_decimal(value: &str) -> bool {
    let (whole, fraction) = value
        .split_once('.')
        .map_or((value, None), |(whole, fraction)| (whole, Some(fraction)));
    let whole_ok = whole == "0"
        || (whole.len() <= 18
            && whole.bytes().all(|b| b.is_ascii_digit())
            && !whole.starts_with('0')
            && !whole.is_empty());
    let fraction_ok = fraction
        .is_none_or(|f| (1..=18).contains(&f.len()) && f.bytes().all(|b| b.is_ascii_digit()));
    whole_ok && fraction_ok
}

fn is_event_id(value: &str) -> bool {
    value.len() == REQUEST_ID_LENGTH
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn check_window(issues: &mut Vec<String>, occurred_at: SystemTime) {
    let now = SystemTime::now();
    let too_late = occurred_at
        .duration_since(now)
        .is_ok_and(|ahead| ahead > FUTURE_TOLERANCE);
    let too_early = now
        .duration_since(occurred_at)
        .is_ok_and(|behind| behind > PAST_WINDOW);
    if too_late || too_early {
        issues.push("occurred_at: outside the accepted accounting window".to_owned());
    }
}

fn validate(record: &UsageRecord<'_>) -> Vec<String> {
    let mut issues = Vec::new();
    length_between(&mut issues, "subject_id", record.subject_id, 1, 256);
    length_between(&mut issues, "client_id", record.client_id, 1, 256);
    length_between(&mut issues, "resource_uri", record.resource_uri, 3, 512);
    if !is_uuid(record.resource_id) {
        issues.push("resource_id: must be a UUID".to_owned());
    }
    if !is_event_id(record.request_id) {
        issues.push("request_id: must be 64 lowercase hex characters".to_owned());
    }
    check_window(&mut issues, record.occurred_at);
    if let Some(cost) = record.cost_usd
        && !is_plain_decimal(cost)
    {
        issues.push("cost_usd: must be a plain decimal".to_owned());
    }
    let has_tokens = [
        record.prompt_tokens,
        record.completion_tokens,
        record.total_tokens,
    ]
    .iter()
    .any(Option::is_some);
    match record.source {
        UsageSource::Unsupported if record.cost_usd.is_some() || has_tokens => {
            issues.push("source: unsupported usage must not carry cost or tokens".to_owned());
        }
        UsageSource::Provider if record.cost_usd.is_none() => {
            issues.push("cost_usd: provider usage requires a reported cost".to_owned());
        }
        _ => {}
    }
    issues
}

impl ResourcesApi {
    /// Records the usage a provider billed for a shared resource. Needs `resources:usage:write`.
    ///
    /// auth-service owns accounting; this is the only write. The scope is granted
    /// to the platform's metering components, never by default. Replaying an event
    /// is safe: the receipt carries `replayed: true`. A payload that conflicts with
    /// the stored event for the same `request_id` is refused (`RES_012`), and so is
    /// a caller with no access to the resource (`RES_011`).
    ///
    /// # Errors
    /// `CFG_001` for an invalid record (checked before any request), `API_001` for a
    /// refusal, `API_002` for an unexpected answer.
    pub async fn record_usage(&self, record: &UsageRecord<'_>) -> Result<UsageReceipt> {
        let issues = validate(record);
        if !issues.is_empty() {
            return Err(invalid("usage record", &issues));
        }
        let occurred_at = OffsetDateTime::from(record.occurred_at)
            .format(&Rfc3339)
            .map_err(|error| {
                AuthAiError::new(ErrorCode::Cfg001)
                    .with_message(format!("Invalid usage record: {error}"))
            })?;
        let body = json!({
            "subjectId": record.subject_id,
            "clientId": record.client_id,
            "resourceId": record.resource_id,
            "resourceUri": record.resource_uri,
            "requestId": record.request_id,
            "occurredAt": occurred_at,
            "usageSource": record.source,
            "costUsd": record.cost_usd,
            "promptTokens": record.prompt_tokens,
            "completionTokens": record.completion_tokens,
            "totalTokens": record.total_tokens,
        });
        self.http()
            .request(Method::Post, USAGE_PATH, USAGE_SCOPE, &[], Some(&body))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_decimals_follow_the_server_grammar() {
        for good in [
            "0",
            "0.1",
            "12",
            "0.0042",
            "123456789012345678",
            "1.123456789012345678",
        ] {
            assert!(is_plain_decimal(good), "{good}");
        }
        for bad in [
            "",
            "01",
            "1.",
            ".5",
            "-1",
            "1e3",
            "1.1234567890123456789",
            "1234567890123456789",
            " 1",
            "1,5",
        ] {
            assert!(!is_plain_decimal(bad), "{bad}");
        }
    }

    #[test]
    fn event_ids_are_64_lowercase_hex_characters() {
        assert!(is_event_id(&"a1".repeat(32)));
        assert!(!is_event_id(&"A1".repeat(32)));
        assert!(!is_event_id(&"a1".repeat(31)));
        assert!(!is_event_id(&"g1".repeat(32)));
    }
}
