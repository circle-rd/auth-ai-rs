//! Models of the signed-in user's resources and shares.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use crate::server::resources::{is_uuid, length_between};
use crate::server::{
    AccessibleResource, GrantSubjectType, OwnerType, ResourcePermission, ResourceStatus,
};

/// A resource owned by a user or an application.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    /// The resource id.
    pub id: String,
    /// The application id.
    pub application_id: String,
    /// The application slug.
    #[serde(default)]
    pub application_slug: Option<String>,
    /// The application name.
    #[serde(default)]
    pub application_name: Option<String>,
    /// The URI scheme.
    pub scheme: String,
    /// The scheme display name.
    #[serde(default)]
    pub scheme_display_name: Option<String>,
    /// The levels the scheme supports; present on single-resource answers.
    #[serde(default)]
    pub permissions: Option<Vec<ResourcePermission>>,
    /// The locator inside the scheme.
    #[serde(default)]
    pub locator: Option<String>,
    /// The resource URI.
    pub uri: String,
    /// Display name.
    pub display_name: String,
    /// Who owns the resource.
    pub owner_type: OwnerType,
    /// The owner's id.
    pub owner_id: String,
    /// Where the resource stands in its validation.
    pub status: ResourceStatus,
    /// Whether it is listed in the application's catalogue.
    pub listed: bool,
    /// Application metadata.
    #[serde(default)]
    pub metadata: Option<Map<String, Value>>,
    /// When validation was last requested.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub validation_requested_at: Option<OffsetDateTime>,
    /// When ownership was proven.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub validated_at: Option<OffsetDateTime>,
    /// Why validation failed, when it did.
    #[serde(default)]
    pub validation_error: Option<String>,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Last update time.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// A share of a resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    /// The grant id.
    pub id: String,
    /// The resource id.
    pub resource_id: String,
    /// Who the grant targets.
    pub subject_type: GrantSubjectType,
    /// The target id, when there is one.
    #[serde(default)]
    pub subject_id: Option<String>,
    /// The permission the grant carries.
    pub permission: ResourcePermission,
    /// When the grant expires.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    /// When the grant was revoked.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    /// Who created the grant.
    pub created_by: String,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// An organization the user belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Organization {
    /// The organization id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// The organization slug.
    #[serde(default)]
    pub slug: Option<String>,
    /// Logo URL.
    #[serde(default)]
    pub logo: Option<String>,
    /// The user's role in the organization.
    pub role: String,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// An application the user may declare a resource into.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberApplication {
    /// The application id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// The application slug.
    pub slug: String,
    /// Description.
    #[serde(default)]
    pub description: Option<String>,
    /// Icon URL.
    #[serde(default)]
    pub icon: Option<String>,
    /// Whether the user may create a resource in it.
    pub can_create: bool,
}

/// An application of the resource catalogue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogueApplication {
    /// The application slug.
    pub slug: String,
    /// Display name.
    pub name: String,
}

/// Every application and resource the user may reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Catalogue {
    /// The applications that share resources.
    pub applications: Vec<CatalogueApplication>,
    /// The validated resources the user may use.
    pub resources: Vec<AccessibleResource>,
    /// The resource schemes enabled on the instance.
    pub enabled_schemes: Vec<String>,
}

/// The answer to a validation request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationRequest {
    /// The resource as auth-service now holds it.
    pub resource: Resource,
    /// Where the validator listens, when validation is still pending.
    #[serde(default)]
    pub validator_url: Option<String>,
    /// The command that starts the validator, when relevant.
    #[serde(default)]
    pub validation_command: Option<String>,
}

/// The outcome of one resource in a `share_with_application` call.
///
/// `grant_id` is set when the resource was shared, `code` (such as `RES_014`)
/// when it was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkShareResult {
    /// The resource id.
    pub resource_id: String,
    /// The grant that was created.
    pub grant_id: Option<String>,
    /// Why the resource was not shared.
    pub code: Option<String>,
}

/// The members of a resource declaration.
#[derive(Debug, Clone)]
pub struct CreateResource<'a> {
    /// The application the resource belongs to.
    pub application_id: &'a str,
    /// The resource scheme.
    pub scheme: &'a str,
    /// Display name.
    pub display_name: &'a str,
    /// The locator inside the scheme.
    pub locator: Option<&'a str>,
    /// Application metadata.
    pub metadata: Option<&'a Map<String, Value>>,
    /// Share the resource in the same call.
    pub audience: Option<&'a ResourceAudience>,
}

/// The fields of a resource update; at least one is required.
#[derive(Debug, Clone, Default)]
pub struct UpdateResource<'a> {
    /// New display name.
    pub display_name: Option<&'a str>,
    /// Whether the resource is listed in the application's catalogue.
    pub listed: Option<bool>,
    /// New metadata.
    pub metadata: Option<&'a Map<String, Value>>,
}

/// The members of a grant.
#[derive(Debug, Clone)]
pub struct CreateGrant<'a> {
    /// Who the grant targets; `Application` shares the resource with another
    /// application, named by its slug in `subject_id`.
    pub subject_type: GrantSubjectType,
    /// The target id.
    pub subject_id: Option<&'a str>,
    /// The e-mail of a user target, resolved by auth-service.
    pub subject_email: Option<&'a str>,
    /// `read` by default; `write` also covers `read`. A scheme may support `read` only.
    pub permission: Option<ResourcePermission>,
    /// When the grant expires; must be in the future.
    pub expires_at: Option<OffsetDateTime>,
}

/// The members of a share with an application.
#[derive(Debug, Clone)]
pub struct ShareWithApplication<'a> {
    /// The slug of the application that receives the resources.
    pub application_slug: &'a str,
    /// `read` by default; `write` also covers `read`.
    pub permission: Option<ResourcePermission>,
    /// When the shares expire; must be in the future.
    pub expires_at: Option<OffsetDateTime>,
}

/// Who a resource is shared with at creation time.
///
/// A user is named by id or by e-mail, never both: auth-service resolves the
/// e-mail among the application's active members and gives the same answer for
/// an unknown address and a non-member, so it cannot enumerate accounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceAudience {
    /// A user named by id.
    User {
        /// The user id.
        user_id: String,
    },
    /// A user named by e-mail.
    Email {
        /// The e-mail address.
        email: String,
    },
    /// An organization.
    Organization {
        /// The organization id.
        organization_id: String,
    },
    /// A plan.
    Plan {
        /// The plan id.
        plan_id: String,
    },
    /// Everyone who can reach the application.
    Everyone,
}

impl ResourceAudience {
    /// Names a user by id.
    #[must_use]
    pub fn user(user_id: impl Into<String>) -> Self {
        Self::User {
            user_id: user_id.into(),
        }
    }

    /// Names a user by e-mail.
    #[must_use]
    pub fn email(email: impl Into<String>) -> Self {
        Self::Email {
            email: email.into(),
        }
    }

    /// Targets an organization.
    #[must_use]
    pub fn organization(organization_id: impl Into<String>) -> Self {
        Self::Organization {
            organization_id: organization_id.into(),
        }
    }

    /// Targets a plan.
    #[must_use]
    pub fn plan(plan_id: impl Into<String>) -> Self {
        Self::Plan {
            plan_id: plan_id.into(),
        }
    }

    /// Targets everyone.
    #[must_use]
    pub const fn everyone() -> Self {
        Self::Everyone
    }

    pub(crate) fn check(&self, issues: &mut Vec<String>) {
        match self {
            Self::User { user_id } => length_between(issues, "audience.user_id", user_id, 1, 128),
            Self::Email { email } => {
                length_between(issues, "audience.email", email.trim(), 1, 320);
            }
            Self::Organization { organization_id } => {
                length_between(issues, "audience.organization_id", organization_id, 1, 128)
            }
            Self::Plan { plan_id } => {
                if !is_uuid(plan_id) {
                    issues.push("audience.plan_id: must be a UUID".to_owned());
                }
            }
            Self::Everyone => {}
        }
    }

    pub(crate) fn to_wire(&self) -> Value {
        match self {
            Self::User { user_id } => json!({ "type": "user", "userId": user_id }),
            Self::Email { email } => json!({ "type": "user", "email": email.trim() }),
            Self::Organization { organization_id } => json!({
                "type": "organization",
                "organizationId": organization_id,
            }),
            Self::Plan { plan_id } => json!({ "type": "plan", "planId": plan_id }),
            Self::Everyone => json!({ "type": "everyone" }),
        }
    }
}
