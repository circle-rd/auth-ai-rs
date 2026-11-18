//! The OIDC Core §3.1.3.7 checks a JWT verifier does not make.

use serde_json::{Map, Value};

use crate::error::{AuthAiError, ErrorCode, Result};
use crate::util::secrets_equal;

fn reject(message: &str, reason: &'static str) -> AuthAiError {
    AuthAiError::new(ErrorCode::Tok001)
        .with_message(message.to_owned())
        .with_detail("reason", reason)
}

/// The signature, issuer, audience and expiry are the verifier's business. Here:
/// the `nonce` echoes the one sent at sign-in (when there was one), and the
/// authorized party names this client (it is required when the audience is not
/// this client alone).
pub(crate) fn check_id_token_binding(
    claims: &Map<String, Value>,
    client_id: &str,
    nonce: Option<&str>,
) -> Result<()> {
    if let Some(expected) = nonce {
        let Some(received) = claims.get("nonce").and_then(Value::as_str) else {
            return Err(reject("The ID token carries no nonce", "missing_nonce"));
        };
        if !secrets_equal(received, expected) {
            return Err(reject("ID token nonce mismatch", "nonce_mismatch"));
        }
    }

    let sole_audience = match claims.get("aud") {
        Some(Value::String(audience)) => audience == client_id,
        Some(Value::Array(audiences)) => {
            matches!(audiences.as_slice(), [Value::String(audience)] if audience == client_id)
        }
        _ => false,
    };
    match claims.get("azp") {
        None if sole_audience => Ok(()),
        None => Err(reject("The ID token lacks azp", "missing_azp")),
        Some(Value::String(party)) if party == client_id => Ok(()),
        Some(_) => Err(reject(
            "The ID token was issued to another party",
            "azp_mismatch",
        )),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn claims(value: Value) -> Map<String, Value> {
        value.as_object().cloned().unwrap_or_default()
    }

    fn reason(err: &AuthAiError) -> &str {
        err.detail("reason")
            .and_then(crate::error::DetailValue::as_str)
            .unwrap_or_default()
    }

    #[test]
    fn a_matching_nonce_and_sole_audience_pass() {
        let ok = claims(json!({ "aud": "app", "nonce": "n1" }));
        assert!(check_id_token_binding(&ok, "app", Some("n1")).is_ok());
        let listed = claims(json!({ "aud": ["app"] }));
        assert!(check_id_token_binding(&listed, "app", None).is_ok());
    }

    #[test]
    fn a_missing_or_wrong_nonce_is_refused() {
        let missing = check_id_token_binding(&claims(json!({ "aud": "app" })), "app", Some("n1"));
        assert_eq!(reason(&missing.unwrap_err()), "missing_nonce");
        let wrong = check_id_token_binding(
            &claims(json!({ "aud": "app", "nonce": "n2" })),
            "app",
            Some("n1"),
        );
        assert_eq!(reason(&wrong.unwrap_err()), "nonce_mismatch");
    }

    #[test]
    fn azp_is_required_for_a_multi_audience_token() {
        let multi = claims(json!({ "aud": ["app", "api"] }));
        let err = check_id_token_binding(&multi, "app", None).unwrap_err();
        assert_eq!(reason(&err), "missing_azp");
        let with_azp = claims(json!({ "aud": ["app", "api"], "azp": "app" }));
        assert!(check_id_token_binding(&with_azp, "app", None).is_ok());
    }

    #[test]
    fn a_foreign_authorized_party_is_refused() {
        let other = claims(json!({ "aud": "app", "azp": "other" }));
        assert_eq!(
            reason(&check_id_token_binding(&other, "app", None).unwrap_err()),
            "azp_mismatch"
        );
        let not_text = claims(json!({ "aud": "app", "azp": 7 }));
        assert!(check_id_token_binding(&not_text, "app", None).is_err());
    }
}
