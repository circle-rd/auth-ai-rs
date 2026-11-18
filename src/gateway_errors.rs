//! Mapping of a refused gateway call to the SDK's error registry.

use serde_json::Value;

use crate::error::{AuthAiError, ErrorCode};

/// The `type` and `message` of an OpenAI-style error body, when well formed.
fn error_fields(body: Option<&Value>) -> (Option<&str>, Option<&str>) {
    let Some(error) = body
        .and_then(|body| body.get("error"))
        .and_then(Value::as_object)
    else {
        return (None, None);
    };
    (
        error.get("type").and_then(Value::as_str),
        error.get("message").and_then(Value::as_str),
    )
}

/// Maps a failed gateway answer to the SDK registry.
///
/// Branch on the status first: LiteLLM serialises the final body itself, so
/// only the status is a contract. The message is the gateway's own and carries
/// no credential.
#[must_use]
pub fn to_gateway_error(
    status: u16,
    body: Option<&Value>,
    headers: &[(String, String)],
) -> AuthAiError {
    let (kind, message) = error_fields(body);
    let code = match status {
        402 => ErrorCode::Gw001,
        429 => ErrorCode::Gw002,
        401 | 403 => ErrorCode::Gw003,
        503 => ErrorCode::Gw004,
        _ => ErrorCode::Gw005,
    };
    let mut err = AuthAiError::new(code).with_detail("status", status);
    if let Some(kind) = kind.filter(|kind| !kind.is_empty()) {
        err = err.with_detail("type", kind);
    }
    if status == 429
        && let Some(retry_after) = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
            .and_then(|(_, value)| value.trim().parse::<f64>().ok())
            .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
    {
        err = err.with_detail("retryAfterSeconds", retry_after);
    }
    match (message.filter(|message| !message.is_empty()), code) {
        (Some(message), _) => err.with_message(message),
        (None, ErrorCode::Gw005) => err.with_message(format!("The gateway answered {status}")),
        (None, _) => err,
    }
}

/// True for the error of a call refused because the wallet is empty.
#[must_use]
pub fn is_insufficient_credit(err: &AuthAiError) -> bool {
    err.code() == ErrorCode::Gw001
}

/// Same test for the HTTP status of an OpenAI-compatible SDK's error: the
/// gateway answers 402 when the balance is zero or negative.
#[must_use]
pub const fn is_insufficient_credit_status(status: u16) -> bool {
    status == 402
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn statuses_map_to_the_registry() {
        let cases = [
            (402, ErrorCode::Gw001),
            (429, ErrorCode::Gw002),
            (401, ErrorCode::Gw003),
            (403, ErrorCode::Gw003),
            (503, ErrorCode::Gw004),
            (500, ErrorCode::Gw005),
            (418, ErrorCode::Gw005),
        ];
        for (status, code) in cases {
            assert_eq!(to_gateway_error(status, None, &[]).code(), code, "{status}");
        }
    }

    #[test]
    fn the_gateways_message_and_type_are_kept() {
        let body = json!({ "error": { "type": "budget_exceeded", "message": "No credit left" } });
        let err = to_gateway_error(402, Some(&body), &[]);
        assert_eq!(err.message(), "No credit left");
        assert_eq!(err.to_json()["details"]["type"], "budget_exceeded");
        assert!(is_insufficient_credit(&err));
        assert!(is_insufficient_credit_status(402));
        assert!(!is_insufficient_credit_status(429));
    }

    #[test]
    fn an_unknown_failure_names_its_status() {
        assert_eq!(
            to_gateway_error(502, None, &[]).message(),
            "The gateway answered 502"
        );
        assert_eq!(
            to_gateway_error(402, None, &[]).message(),
            ErrorCode::Gw001.default_message()
        );
    }

    #[test]
    fn retry_after_is_read_only_when_sane() {
        let err = to_gateway_error(429, None, &headers(&[("Retry-After", "12")]));
        assert_eq!(err.to_json()["details"]["retryAfterSeconds"], 12.0);
        for bad in ["-1", "soon", "inf", "NaN"] {
            let err = to_gateway_error(429, None, &headers(&[("retry-after", bad)]));
            assert!(err.detail("retryAfterSeconds").is_none(), "{bad}");
        }
        let other = to_gateway_error(503, None, &headers(&[("retry-after", "3")]));
        assert!(other.detail("retryAfterSeconds").is_none());
    }

    #[test]
    fn a_malformed_body_is_ignored() {
        for body in [
            json!("text"),
            json!({ "error": "flat" }),
            json!({ "error": { "type": 3, "message": 4 } }),
        ] {
            let err = to_gateway_error(402, Some(&body), &[]);
            assert_eq!(err.message(), ErrorCode::Gw001.default_message());
        }
    }
}
