//! Typed claims of the tokens auth-service issues, and the entitlement helpers.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// A plan feature value: a flag, a limit or a label.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FeatureValue {
    /// A flag.
    Bool(bool),
    /// An integer limit.
    Int(i64),
    /// A fractional limit.
    Float(f64),
    /// A label.
    Text(String),
}

impl FeatureValue {
    /// Whether the feature counts as enabled: neither `false`, `0` nor `""`.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        match self {
            Self::Bool(value) => *value,
            Self::Int(value) => *value != 0,
            Self::Float(value) => *value != 0.0,
            Self::Text(value) => !value.is_empty(),
        }
    }
}

/// The `aud` claim: one audience or several.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// A single audience.
    One(String),
    /// Several audiences.
    Many(Vec<String>),
}

impl Audience {
    /// Every audience, as a list.
    #[must_use]
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Self::One(audience) => vec![audience.clone()],
            Self::Many(audiences) => audiences.clone(),
        }
    }

    /// Whether `audience` is one of them.
    #[must_use]
    pub fn contains(&self, audience: &str) -> bool {
        match self {
            Self::One(single) => single == audience,
            Self::Many(many) => many.iter().any(|candidate| candidate == audience),
        }
    }
}

/// Claims of an ID token issued by auth-service. Unknown claims are kept in `extra`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer.
    pub iss: String,
    /// Subject: the user id.
    pub sub: String,
    /// Audience.
    pub aud: Audience,
    /// Expiry, in unix seconds.
    pub exp: f64,
    /// Issue time, in unix seconds.
    pub iat: f64,
    /// Present only when the `roles` scope was granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// Present only when the `permissions` scope was granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
    /// Present only when the `features` scope was granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub features: Option<BTreeMap<String, FeatureValue>>,
    /// The user's plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    /// The user's organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// The provider session, which a back-channel logout names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// The authorized party.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
    /// Display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Picture URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// Given name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// Family name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// Company.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    /// Last profile update, in unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<f64>,
    /// Email address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether the email address was verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Phone number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    /// Claims this SDK does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The `address` claim (OpenID Connect Core 1.0 §5.1.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AddressClaim {
    /// Full mailing address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    /// Street address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    /// City.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    /// State or region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Zip or postal code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    /// Country.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Members this SDK does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Standard claims returned by the UserInfo endpoint.
///
/// UserInfo carries no registered token claims (`iss`, `aud`, `exp`, `iat`);
/// entitlements are repeated because the endpoint may return them as well.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserInfoClaims {
    /// Subject: the user id.
    pub sub: String,
    /// Display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Given name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// Family name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// Middle name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    /// Nickname.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    /// Preferred username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// Profile page URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Picture URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// Website URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    /// Gender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,
    /// Birthdate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<String>,
    /// Time zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,
    /// Locale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Postal address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<AddressClaim>,
    /// Last profile update, in unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<f64>,
    /// Email address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether the email address was verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Phone number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    /// Whether the phone number was verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
    /// Roles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// Permissions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
    /// Plan features.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub features: Option<BTreeMap<String, FeatureValue>>,
    /// Plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    /// Organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// Company.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    /// Claims this SDK does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Claims of a JWT access token.
///
/// `azp` is the OAuth client that obtained the token and `scope` is a
/// space-separated list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Issuer.
    pub iss: String,
    /// Subject: the user, or the client itself for a `client_credentials` token.
    pub sub: String,
    /// Audience.
    pub aud: Audience,
    /// Expiry, in unix seconds.
    pub exp: f64,
    /// Issue time, in unix seconds.
    pub iat: f64,
    /// The OAuth client the token was issued to.
    pub azp: String,
    /// Space-separated scopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Roles, when the token carries them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// Permissions, when the token carries them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
    /// Features, when the token carries them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub features: Option<BTreeMap<String, FeatureValue>>,
    /// Plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    /// Organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// The provider session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// Claims this SDK does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Whether a token or UserInfo answer grants an action on a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionAction {
    /// Read access.
    Read,
    /// Write access, which implies read.
    Write,
}

/// Claims that carry entitlements.
pub trait EntitlementClaims {
    /// Roles, when the claim is present.
    fn roles(&self) -> Option<&[String]>;
    /// Permissions, when the claim is present.
    fn permissions(&self) -> Option<&[String]>;
    /// Plan features, when the claim is present.
    fn features(&self) -> Option<&BTreeMap<String, FeatureValue>>;
}

macro_rules! entitlements {
    ($claims:ty) => {
        impl EntitlementClaims for $claims {
            fn roles(&self) -> Option<&[String]> {
                self.roles.as_deref()
            }

            fn permissions(&self) -> Option<&[String]> {
                self.permissions.as_deref()
            }

            fn features(&self) -> Option<&BTreeMap<String, FeatureValue>> {
                self.features.as_ref()
            }
        }
    };
}

entitlements!(IdTokenClaims);
entitlements!(UserInfoClaims);
entitlements!(AccessTokenClaims);

/// Whether the claims hold `role`.
#[must_use]
pub fn has_role(claims: &impl EntitlementClaims, role: &str) -> bool {
    claims
        .roles()
        .is_some_and(|roles| roles.iter().any(|candidate| candidate == role))
}

/// `resource` grants read access and `resource.write` grants write access,
/// which also implies read: auth-service keeps only the highest action.
#[must_use]
pub fn has_permission(
    claims: &impl EntitlementClaims,
    resource: &str,
    action: PermissionAction,
) -> bool {
    let Some(permissions) = claims.permissions() else {
        return false;
    };
    let holds = |name: &str| permissions.iter().any(|candidate| candidate == name);
    if holds(&format!("{resource}.write")) {
        return true;
    }
    action == PermissionAction::Read && holds(resource)
}

/// A feature is enabled when present and neither `false` nor `0` nor `""`.
#[must_use]
pub fn has_feature(claims: &impl EntitlementClaims, key: &str) -> bool {
    get_feature(claims, key).is_some_and(FeatureValue::is_enabled)
}

/// The value of a feature, when the claims carry it.
#[must_use]
pub fn get_feature<'a>(claims: &'a impl EntitlementClaims, key: &str) -> Option<&'a FeatureValue> {
    claims.features().and_then(|features| features.get(key))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn claims(extra: Value) -> IdTokenClaims {
        let mut body = json!({
            "iss": "https://auth.example.com", "sub": "u1", "aud": "app", "exp": 2_000_000_000, "iat": 1_700_000_000
        });
        if let (Some(base), Some(more)) = (body.as_object_mut(), extra.as_object()) {
            base.extend(more.clone());
        }
        serde_json::from_value(body).unwrap()
    }

    #[test]
    fn unknown_claims_are_kept() {
        let parsed = claims(json!({ "custom": [1, 2] }));
        assert_eq!(parsed.extra.get("custom"), Some(&json!([1, 2])));
        assert_eq!(
            serde_json::to_value(&parsed).unwrap()["custom"],
            json!([1, 2])
        );
    }

    #[test]
    fn required_claims_are_enforced() {
        let missing = json!({ "iss": "i", "sub": "s", "aud": "a", "exp": 1 });
        assert!(serde_json::from_value::<IdTokenClaims>(missing).is_err());
    }

    #[test]
    fn audience_accepts_one_or_many() {
        let one = claims(json!({}));
        assert!(one.aud.contains("app"));
        let many = claims(json!({ "aud": ["a", "b"] }));
        assert!(many.aud.contains("b") && !many.aud.contains("c"));
        assert_eq!(many.aud.to_vec(), ["a", "b"]);
    }

    #[test]
    fn roles_are_exact_matches() {
        let parsed = claims(json!({ "roles": ["admin"] }));
        assert!(has_role(&parsed, "admin"));
        assert!(!has_role(&parsed, "adm"));
        assert!(!has_role(&claims(json!({})), "admin"));
    }

    #[test]
    fn write_permission_implies_read_but_not_the_reverse() {
        let writer = claims(json!({ "permissions": ["reports.write"] }));
        assert!(has_permission(&writer, "reports", PermissionAction::Read));
        assert!(has_permission(&writer, "reports", PermissionAction::Write));
        let reader = claims(json!({ "permissions": ["reports"] }));
        assert!(has_permission(&reader, "reports", PermissionAction::Read));
        assert!(!has_permission(&reader, "reports", PermissionAction::Write));
        assert!(!has_permission(
            &claims(json!({})),
            "reports",
            PermissionAction::Read
        ));
    }

    #[test]
    fn falsy_features_are_disabled() {
        let parsed = claims(json!({ "features": {
            "on": true, "off": false, "zero": 0, "limit": 5, "empty": "", "label": "pro", "frac": 0.0
        } }));
        assert!(has_feature(&parsed, "on"));
        assert!(has_feature(&parsed, "limit"));
        assert!(has_feature(&parsed, "label"));
        for key in ["off", "zero", "empty", "frac", "missing"] {
            assert!(!has_feature(&parsed, key), "{key}");
        }
        assert_eq!(get_feature(&parsed, "limit"), Some(&FeatureValue::Int(5)));
        assert_eq!(get_feature(&parsed, "missing"), None);
    }

    #[test]
    fn access_token_claims_need_an_authorized_party() {
        let body = json!({ "iss": "i", "sub": "s", "aud": ["a"], "exp": 2, "iat": 1 });
        assert!(serde_json::from_value::<AccessTokenClaims>(body.clone()).is_err());
        let mut with_azp = body;
        with_azp["azp"] = json!("client");
        assert!(serde_json::from_value::<AccessTokenClaims>(with_azp).is_ok());
    }
}
