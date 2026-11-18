//! The signed-in user's own credit wallet, read with their access token.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::error::{AuthAiError, ErrorCode, Result};
use crate::http::JsonHttp;
use crate::transport::Method;

/// 1 EUR in the ledger unit.
pub const MICRO_PER_EUR: i128 = 1_000_000;

/// Key handed to the token supplier: the wallet audience of auth-service.
pub(crate) const WALLET_SCOPE_KEY: &str = "wallet";

const MAX_AMOUNT_DIGITS: usize = 19;

/// A ledger amount in micro-euros. Amounts travel as integer strings: a JSON
/// number cannot carry them exactly.
pub type Amount = i128;

mod amount {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    use super::MAX_AMOUNT_DIGITS;

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<i128, D::Error> {
        let text = String::deserialize(deserializer)?;
        let digits = text.strip_prefix('-').unwrap_or(&text);
        if digits.is_empty()
            || digits.len() > MAX_AMOUNT_DIGITS
            || !digits.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(D::Error::custom("must be an integer string of micro-euros"));
        }
        text.parse().map_err(D::Error::custom)
    }

    pub(super) fn serialize<S: Serializer>(value: &i128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }
}

/// Currency of the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Currency {
    /// Euro.
    Eur,
}

/// What a ledger entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WalletTransactionType {
    /// A purchase of credit.
    Topup,
    /// Credit granted by an administrator.
    Grant,
    /// A refund.
    Refund,
    /// Spending through the gateway.
    Usage,
    /// A manual adjustment.
    Adjust,
    /// The reversal of an entry.
    Reversal,
}

impl WalletTransactionType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Topup => "topup",
            Self::Grant => "grant",
            Self::Refund => "refund",
            Self::Usage => "usage",
            Self::Adjust => "adjust",
            Self::Reversal => "reversal",
        }
    }
}

/// The balance of the wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletAccount {
    /// Negative when usage or a refund exceeded the credit.
    #[serde(with = "amount")]
    pub balance: Amount,
    /// Whether the account has no spending limit.
    pub is_unlimited: bool,
    /// Whether new spending is allowed: unlimited, or a strictly positive balance.
    pub can_spend: bool,
    /// Currency.
    pub currency: Currency,
}

/// One entry of the ledger.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletTransaction {
    /// Entry id.
    pub id: String,
    /// What the entry records.
    #[serde(rename = "type")]
    pub kind: WalletTransactionType,
    /// Absolute amount.
    #[serde(with = "amount")]
    pub amount: Amount,
    /// Signed change of the balance.
    #[serde(with = "amount")]
    pub delta: Amount,
    /// Balance after the entry.
    #[serde(with = "amount")]
    pub balance_after: Amount,
    /// The application that caused the entry.
    pub application_id: Option<String>,
    /// Entry metadata.
    pub metadata: Map<String, Value>,
    /// When the entry was recorded.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// A page of the ledger.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletTransactionPage {
    /// Entries, newest first.
    pub items: Vec<WalletTransaction>,
    /// Pass it back until it is `None`.
    pub next_cursor: Option<String>,
}

/// Spending on one model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelUsage {
    /// `mcp` for tool calls, `other` when the gateway reported no model.
    pub model: String,
    /// Amount spent.
    #[serde(with = "amount")]
    pub amount: Amount,
    /// Number of calls.
    pub count: u64,
    /// Prompt tokens.
    pub prompt_tokens: u64,
    /// Completion tokens.
    pub completion_tokens: u64,
    /// Total tokens.
    pub total_tokens: u64,
}

/// Spending through one application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationUsage {
    /// Application id.
    pub application_id: Option<String>,
    /// Application name.
    pub name: Option<String>,
    /// Application slug.
    pub slug: Option<String>,
    /// Amount spent.
    #[serde(with = "amount")]
    pub amount: Amount,
    /// Number of calls.
    pub count: u64,
}

/// Spending on one day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DailyPoint {
    /// The day.
    pub date: String,
    /// Amount spent.
    #[serde(with = "amount")]
    pub amount: Amount,
    /// Number of calls.
    pub count: u64,
}

/// Spending of one kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KindUsage {
    /// The kind.
    pub kind: String,
    /// Amount spent.
    #[serde(with = "amount")]
    pub amount: Amount,
    /// Number of calls.
    pub count: u64,
}

/// Spending on one day, broken down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DailyUsage {
    /// The day.
    pub date: String,
    /// Amount spent.
    #[serde(with = "amount")]
    pub amount: Amount,
    /// Number of calls.
    pub count: u64,
    /// Per application.
    pub by_application: Vec<ApplicationUsage>,
    /// Per model.
    pub by_model: Vec<ModelUsage>,
}

/// Spending statistics of a period.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletStats {
    /// Length of the period, in days.
    pub days: u32,
    /// Total spent.
    #[serde(with = "amount")]
    pub total: Amount,
    /// Part of `total` never deducted: usage on an unlimited account.
    #[serde(with = "amount")]
    pub not_billed: Amount,
    /// Number of calls.
    pub calls: u64,
    /// Spending per day.
    pub series: Vec<DailyPoint>,
    /// Per application.
    pub by_application: Vec<ApplicationUsage>,
    /// Per kind.
    pub by_kind: Vec<KindUsage>,
    /// Per model.
    pub by_model: Vec<ModelUsage>,
    /// Per day, broken down.
    pub daily: Vec<DailyUsage>,
}

/// What one chat session spent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletSessionUsage {
    /// The session id passed to the gateway as `metadata.session_id`.
    pub session_id: String,
    /// The calling application.
    pub application_slug: Option<String>,
    /// Length of the period, in days.
    pub days: u32,
    /// Total spent.
    #[serde(with = "amount")]
    pub total: Amount,
    /// Part of `total` never deducted.
    #[serde(with = "amount")]
    pub not_billed: Amount,
    /// Number of calls.
    pub calls: u64,
    /// Per model.
    pub by_model: Vec<ModelUsage>,
}

/// Whether and how the user may buy credit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopupOptions {
    /// Whether top-ups are enabled.
    pub enabled: bool,
    /// Currency.
    pub currency: Currency,
    /// Smallest purchase, in cents.
    pub min_cents: u64,
    /// Largest purchase, in cents.
    pub max_cents: u64,
}

/// Exact decimal euros of a micro-euro amount, e.g. `5_000_000` gives `"5.00"`.
///
/// The amount is truncated toward zero at `fraction_digits` (0 to 6): rounding
/// up could show a user more credit than they hold.
///
/// # Errors
/// `CFG_001` when `fraction_digits` is above 6.
pub fn format_euros(amount: Amount, fraction_digits: u8) -> Result<String> {
    if fraction_digits > 6 {
        return Err(AuthAiError::new(ErrorCode::Cfg001)
            .with_message("fraction_digits must be an integer from 0 to 6"));
    }
    let unit = MICRO_PER_EUR.unsigned_abs();
    let magnitude = amount.unsigned_abs();
    let (whole, micro) = (magnitude / unit, magnitude % unit);
    let mut text = whole.to_string();
    if fraction_digits > 0 {
        let fraction = format!("{micro:06}");
        text.push('.');
        text.extend(fraction.chars().take(usize::from(fraction_digits)));
    }
    // A negative amount truncated to zero is not a debt worth a minus sign.
    if amount < 0 && text.chars().any(|c| matches!(c, '1'..='9')) {
        Ok(format!("-{text}"))
    } else {
        Ok(text)
    }
}

/// The signed-in user's own wallet, read with their access token.
///
/// The token is minted for the auth-service audience with the `wallet:self:read`
/// scope. Debits are made by the gateway after each call: an application only
/// reads, and refills by sending the user to [`WalletClient::topup_url`].
pub struct WalletClient {
    http: JsonHttp,
    issuer: String,
}

impl std::fmt::Debug for WalletClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletClient")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl WalletClient {
    pub(crate) fn new(http: JsonHttp, issuer: impl Into<String>) -> Self {
        Self {
            http,
            issuer: issuer.into(),
        }
    }

    /// The balance. Decide with `can_spend` rather than recomputing it from the balance.
    ///
    /// # Errors
    /// `API_001` for a refusal, `API_002` for an unexpected answer.
    pub async fn get_account(&self) -> Result<WalletAccount> {
        self.http
            .request(Method::Get, "/api/user/wallet", WALLET_SCOPE_KEY, &[], None)
            .await
    }

    /// Spending statistics; `days` is 1 to 90, 30 by default.
    ///
    /// # Errors
    /// `API_001` for a refusal, `API_002` for an unexpected answer.
    pub async fn get_stats(&self, days: Option<u32>) -> Result<WalletStats> {
        let query = [("days", days.map(|days| days.to_string()))];
        self.http
            .request(
                Method::Get,
                "/api/user/wallet/stats",
                WALLET_SCOPE_KEY,
                &query,
                None,
            )
            .await
    }

    /// What one chat session spent, for the calling application only.
    ///
    /// The id is the one passed to the gateway as `metadata.session_id`.
    ///
    /// # Errors
    /// `API_001` for a refusal, `API_002` for an unexpected answer.
    pub async fn get_session_usage(
        &self,
        session_id: &str,
        days: Option<u32>,
    ) -> Result<WalletSessionUsage> {
        let query = [
            ("sessionId", Some(session_id.to_owned())),
            ("days", days.map(|days| days.to_string())),
        ];
        self.http
            .request(
                Method::Get,
                "/api/user/wallet/usage",
                WALLET_SCOPE_KEY,
                &query,
                None,
            )
            .await
    }

    /// Newest first, keyset-paginated: pass `next_cursor` back until it is `None`.
    ///
    /// # Errors
    /// `API_001` for a refusal, `API_002` for an unexpected answer.
    pub async fn list_transactions(
        &self,
        limit: Option<u32>,
        cursor: Option<&str>,
        kind: Option<WalletTransactionType>,
    ) -> Result<WalletTransactionPage> {
        let query = [
            ("limit", limit.map(|limit| limit.to_string())),
            ("cursor", cursor.map(str::to_owned)),
            ("type", kind.map(|kind| kind.as_str().to_owned())),
        ];
        self.http
            .request(
                Method::Get,
                "/api/user/wallet/transactions",
                WALLET_SCOPE_KEY,
                &query,
                None,
            )
            .await
    }

    /// Whether and how the user may buy credit.
    ///
    /// # Errors
    /// `API_001` for a refusal, `API_002` for an unexpected answer.
    pub async fn get_topup_options(&self) -> Result<TopupOptions> {
        self.http
            .request(
                Method::Get,
                "/api/user/wallet/topup-options",
                WALLET_SCOPE_KEY,
                &[],
                None,
            )
            .await
    }

    /// The Credit tab of the user's profile.
    ///
    /// Checkout needs the user's session, not a bearer token, so an application
    /// links there instead of creating it.
    #[must_use]
    pub fn topup_url(&self) -> String {
        format!("{}/profile", self.issuer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn euros_are_truncated_never_rounded() {
        assert_eq!(format_euros(5_000_000, 2).unwrap(), "5.00");
        assert_eq!(format_euros(1_999_999, 2).unwrap(), "1.99");
        assert_eq!(format_euros(1_999_999, 6).unwrap(), "1.999999");
        assert_eq!(format_euros(1_999_999, 0).unwrap(), "1");
    }

    #[test]
    fn debts_keep_their_sign_unless_they_truncate_to_zero() {
        assert_eq!(format_euros(-2_500_000, 2).unwrap(), "-2.50");
        assert_eq!(format_euros(-1, 2).unwrap(), "0.00");
        assert_eq!(format_euros(0, 2).unwrap(), "0.00");
    }

    #[test]
    fn fraction_digits_are_bounded() {
        assert_eq!(format_euros(1, 7).unwrap_err().code(), ErrorCode::Cfg001);
    }

    #[test]
    fn amounts_round_trip_as_strings() {
        let account: WalletAccount = serde_json::from_value(serde_json::json!({
            "balance": "-9999999999999999999", "isUnlimited": false, "canSpend": false, "currency": "eur"
        }))
        .unwrap();
        assert_eq!(account.balance, -9_999_999_999_999_999_999);
        assert_eq!(
            serde_json::to_value(&account).unwrap()["balance"],
            "-9999999999999999999"
        );
    }

    #[test]
    fn amounts_must_be_integer_strings() {
        for bad in [
            serde_json::json!(5),
            serde_json::json!("1.5"),
            serde_json::json!("abc"),
            serde_json::json!(""),
            serde_json::json!("-"),
            serde_json::json!("12345678901234567890"),
        ] {
            let body = serde_json::json!({ "balance": bad, "isUnlimited": false, "canSpend": true, "currency": "eur" });
            assert!(serde_json::from_value::<WalletAccount>(body).is_err());
        }
    }
}
