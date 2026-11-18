//! What a user holds and has consumed in this application.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::http::JsonHttp;
use crate::transport::Method;
use crate::util::encode_segment;

const SCOPE: &str = "billing:read";

/// A plan reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanRef {
    /// Plan id.
    pub id: String,
    /// Plan name.
    pub name: String,
}

/// The subscription of a user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionView {
    /// The plan.
    pub plan: PlanRef,
    /// Whether the subscription is active.
    pub is_active: bool,
    /// When it expires.
    pub expires_at: Option<String>,
    /// The Stripe status.
    pub stripe_status: Option<String>,
    /// Start of the current period.
    pub current_period_start: Option<String>,
    /// End of the current period.
    pub current_period_end: Option<String>,
    /// Whether it ends with the current period.
    pub cancel_at_period_end: bool,
    /// When it was canceled.
    pub canceled_at: Option<String>,
}

/// Consumption of one metered feature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeatureUsage {
    /// The feature key.
    pub feature_key: String,
    /// The unit.
    pub unit: Option<String>,
    /// The plan's hard cap for the period; -1 means unlimited.
    pub usage_limit: f64,
    /// Units used.
    pub used: f64,
    /// Units left before the cap; `None` when unlimited.
    pub remaining: Option<f64>,
}

/// The usage of a user in the current period.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageView {
    /// Start of the period.
    pub period_start: String,
    /// Per feature.
    pub features: Vec<FeatureUsage>,
}

/// An invoice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvoiceView {
    /// Invoice id.
    pub id: String,
    /// Status.
    pub status: String,
    /// Why it was issued.
    pub billing_reason: Option<String>,
    /// Currency.
    pub currency: String,
    /// Amount due, in cents.
    pub amount_due: i64,
    /// Amount paid, in cents.
    pub amount_paid: i64,
    /// Amount remaining, in cents.
    pub amount_remaining: i64,
    /// Start of the period.
    pub period_start: Option<String>,
    /// End of the period.
    pub period_end: Option<String>,
    /// Creation time.
    pub created_at: String,
    /// Hosted invoice page.
    pub hosted_invoice_url: Option<String>,
    /// PDF.
    pub invoice_pdf: Option<String>,
}

/// A page of invoices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvoicePage {
    /// Invoices, newest first.
    pub items: Vec<InvoiceView>,
    /// Pass it back until it is `None`.
    pub next_cursor: Option<String>,
}

#[derive(Deserialize)]
struct SubscriptionResponse {
    subscription: Option<SubscriptionView>,
}

fn user_path(user_id: &str) -> String {
    format!("/api/app/billing/users/{}", encode_segment(user_id))
}

/// What a user holds and has consumed in this application.
///
/// The application is the one behind the machine token: it cannot read another one.
#[derive(Clone)]
pub struct BillingApi {
    http: Arc<JsonHttp>,
}

impl std::fmt::Debug for BillingApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BillingApi").finish_non_exhaustive()
    }
}

impl BillingApi {
    pub(crate) const fn new(http: Arc<JsonHttp>) -> Self {
        Self { http }
    }

    /// The user's subscription, `None` when the user holds none.
    ///
    /// # Errors
    /// `API_001` for a refusal, `API_002` for an unexpected answer.
    pub async fn get_subscription(&self, user_id: &str) -> Result<Option<SubscriptionView>> {
        let response: SubscriptionResponse = self
            .http
            .request(
                Method::Get,
                &format!("{}/subscription", user_path(user_id)),
                SCOPE,
                &[],
                None,
            )
            .await?;
        Ok(response.subscription)
    }

    /// The user's usage in the current period.
    ///
    /// # Errors
    /// `API_001` for a refusal, `API_002` for an unexpected answer.
    pub async fn get_usage(&self, user_id: &str) -> Result<UsageView> {
        self.http
            .request(
                Method::Get,
                &format!("{}/usage", user_path(user_id)),
                SCOPE,
                &[],
                None,
            )
            .await
    }

    /// Newest first, keyset-paginated: pass `next_cursor` back until it is `None`.
    ///
    /// `limit` is 1 to 100.
    ///
    /// # Errors
    /// `API_001` for a refusal, `API_002` for an unexpected answer.
    pub async fn list_invoices(
        &self,
        user_id: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<InvoicePage> {
        let query = [
            ("limit", limit.map(|limit| limit.to_string())),
            ("cursor", cursor.map(str::to_owned)),
        ];
        self.http
            .request(
                Method::Get,
                &format!("{}/invoices", user_path(user_id)),
                SCOPE,
                &query,
                None,
            )
            .await
    }
}
