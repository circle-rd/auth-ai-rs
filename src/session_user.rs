//! What a signed-in user looks like to the application's frontend.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::claims::{FeatureValue, IdTokenClaims};

/// Profile and entitlements, with the absent claims normalised to empty values.
///
/// Tokens, `sid` and timestamps never reach the browser. Serialised, the
/// members are camelCase, as the browser clients expect.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionUser {
    /// The user id.
    pub sub: String,
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether the email address was verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Picture URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// Roles.
    pub roles: Vec<String>,
    /// Permissions.
    pub permissions: Vec<String>,
    /// Plan features.
    pub features: BTreeMap<String, FeatureValue>,
    /// Plan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    /// Organization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
}

impl SessionUser {
    /// The JSON form sent to the browser.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// The browser-facing view of verified claims.
#[must_use]
pub fn to_session_user(claims: &IdTokenClaims) -> SessionUser {
    SessionUser {
        sub: claims.sub.clone(),
        name: claims.name.clone(),
        email: claims.email.clone(),
        email_verified: claims.email_verified,
        picture: claims.picture.clone(),
        roles: claims.roles.clone().unwrap_or_default(),
        permissions: claims.permissions.clone().unwrap_or_default(),
        features: claims.features.clone().unwrap_or_default(),
        plan: claims.plan.clone(),
        org_id: claims.org_id.clone(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn absent_entitlements_become_empty_and_secrets_are_dropped() {
        let claims: IdTokenClaims = serde_json::from_value(json!({
            "iss": "i", "sub": "u1", "aud": "a", "exp": 2, "iat": 1, "sid": "sess-1",
            "email": "a@b.c"
        }))
        .unwrap();
        let wire = to_session_user(&claims).to_json();
        assert_eq!(
            wire,
            json!({ "sub": "u1", "email": "a@b.c", "roles": [], "permissions": [], "features": {} })
        );
    }

    #[test]
    fn members_are_camel_case() {
        let claims: IdTokenClaims = serde_json::from_value(json!({
            "iss": "i", "sub": "u1", "aud": "a", "exp": 2, "iat": 1,
            "email_verified": true, "org_id": "org-1"
        }))
        .unwrap();
        let wire = to_session_user(&claims).to_json();
        assert_eq!(wire["emailVerified"], true);
        assert_eq!(wire["orgId"], "org-1");
    }
}
