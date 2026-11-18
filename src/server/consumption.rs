//! Usage the application reports for its users, for features billed on consumption.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{AuthAiError, ErrorCode, Result};
use crate::http::JsonHttp;
use crate::transport::Method;
use crate::util::encode_segment;

const WRITE_SCOPE: &str = "consumption:write";
const READ_SCOPE: &str = "consumption:read";
const MAX_KEY_LENGTH: usize = 64;
const MAX_IDEMPOTENCY_KEY_LENGTH: usize = 200;

/// A running total of a feature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumptionTotal {
    /// The feature key.
    pub key: String,
    /// A decimal string: the running total is not bounded by a double.
    pub total: String,
}

/// A running total, with its last update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumptionAggregate {
    /// The feature key.
    pub key: String,
    /// A decimal string: the running total is not bounded by a double.
    pub total: String,
    /// When it was last updated.
    pub updated_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReportResponse {
    success: bool,
    #[serde(default)]
    metered: bool,
    aggregate: ConsumptionTotal,
}

#[derive(Deserialize)]
struct AggregateList {
    aggregates: Vec<ConsumptionAggregate>,
}

#[derive(Deserialize)]
struct AggregateOne {
    aggregate: ConsumptionAggregate,
}

/// The outcome of a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumptionResult {
    /// The new running total.
    pub aggregate: ConsumptionTotal,
    /// True when the key prices a metered feature and was billed through Stripe.
    pub metered: bool,
}

/// An amount of units: an integer or a finite fraction. May be negative to credit back.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConsumptionValue {
    /// A whole number of units.
    Int(i64),
    /// A fractional number of units.
    Float(f64),
}

impl From<i64> for ConsumptionValue {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

impl From<i32> for ConsumptionValue {
    fn from(value: i32) -> Self {
        Self::Int(i64::from(value))
    }
}

impl From<u32> for ConsumptionValue {
    fn from(value: u32) -> Self {
        Self::Int(i64::from(value))
    }
}

impl From<f64> for ConsumptionValue {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

impl ConsumptionValue {
    fn to_json(self) -> Option<Value> {
        match self {
            Self::Int(value) => Some(json!(value)),
            Self::Float(value) => serde_json::Number::from_f64(value).map(Value::Number),
        }
    }
}

fn user_path(user_id: &str) -> String {
    format!("/api/app/consumption/users/{}", encode_segment(user_id))
}

fn invalid_report(issues: &[&str]) -> AuthAiError {
    AuthAiError::new(ErrorCode::Cfg001)
        .with_message(format!("Invalid consumption report: {}", issues.join("; ")))
}

/// Usage the application reports for its users, for features billed on consumption.
///
/// The application is the one behind the machine token.
#[derive(Clone)]
pub struct ConsumptionApi {
    http: Arc<JsonHttp>,
}

impl std::fmt::Debug for ConsumptionApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsumptionApi").finish_non_exhaustive()
    }
}

impl ConsumptionApi {
    pub(crate) const fn new(http: Arc<JsonHttp>) -> Self {
        Self { http }
    }

    /// Reports `value` units of `key` for a user.
    ///
    /// `key` is alphanumeric and dots, 64 characters at most. The same
    /// `idempotency_key` reported twice counts once: set it to make retries safe.
    ///
    /// # Errors
    /// `CFG_001` for an invalid report (checked before any request), `API_001`
    /// for a refusal, `API_002` for an unexpected answer.
    pub async fn report(
        &self,
        user_id: &str,
        key: &str,
        value: impl Into<ConsumptionValue>,
        idempotency_key: Option<&str>,
    ) -> Result<ConsumptionResult> {
        let mut issues = Vec::new();
        if user_id.is_empty() {
            issues.push("user_id: must not be empty");
        }
        if key.is_empty()
            || key.chars().count() > MAX_KEY_LENGTH
            || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '.')
        {
            issues.push("key: must be 1 to 64 alphanumeric characters or dots");
        }
        let number = value.into().to_json();
        if number.is_none() {
            issues.push("value: must be a finite number");
        }
        let idempotency_key = idempotency_key.map(str::trim);
        if idempotency_key
            .is_some_and(|key| key.is_empty() || key.chars().count() > MAX_IDEMPOTENCY_KEY_LENGTH)
        {
            issues.push("idempotency_key: must be 1 to 200 characters");
        }
        let Some(number) = number.filter(|_| issues.is_empty()) else {
            return Err(invalid_report(&issues));
        };
        let mut body = serde_json::Map::new();
        body.insert("key".to_owned(), json!(key));
        body.insert("value".to_owned(), number);
        if let Some(idempotency_key) = idempotency_key {
            body.insert("idempotencyKey".to_owned(), json!(idempotency_key));
        }
        let body = Value::Object(body);
        let response: ReportResponse = self
            .http
            .request(
                Method::Post,
                &user_path(user_id),
                WRITE_SCOPE,
                &[],
                Some(&body),
            )
            .await?;
        if !response.success {
            return Err(AuthAiError::new(ErrorCode::Api002));
        }
        Ok(ConsumptionResult {
            aggregate: response.aggregate,
            metered: response.metered,
        })
    }

    /// Every running total of a user.
    ///
    /// # Errors
    /// `API_001` for a refusal, `API_002` for an unexpected answer.
    pub async fn list_aggregates(&self, user_id: &str) -> Result<Vec<ConsumptionAggregate>> {
        let response: AggregateList = self
            .http
            .request(Method::Get, &user_path(user_id), READ_SCOPE, &[], None)
            .await?;
        Ok(response.aggregates)
    }

    /// One running total; rejects (`API_001`, `CONS_003`) when the key was never reported.
    ///
    /// # Errors
    /// `API_001` for a refusal, `API_002` for an unexpected answer.
    pub async fn get_aggregate(&self, user_id: &str, key: &str) -> Result<ConsumptionAggregate> {
        let path = format!("{}/{}", user_path(user_id), encode_segment(key));
        let response: AggregateOne = self
            .http
            .request(Method::Get, &path, READ_SCOPE, &[], None)
            .await?;
        Ok(response.aggregate)
    }
}
