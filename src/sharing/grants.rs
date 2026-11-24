//! Grants of a resource: sharing, changing the level, revoking and deleting.

use serde::Deserialize;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::UtcOffset;
use time::format_description::well_known::Rfc3339;

use super::client::{ResourceSharingClient, SCOPE_KEY, USER_PATH, check_id, resource_path};
use super::models::{BulkShareResult, CreateGrant, Grant, ShareWithApplication};
use crate::error::{AuthAiError, ErrorCode, Result};
use crate::server::GrantSubjectType;
use crate::server::resources::{ResourcePermission, invalid, is_uuid, length_between};
use crate::transport::Method;
use crate::util::encode_segment;

const MAX_EMAIL_LENGTH: usize = 320;
const MAX_SUBJECT_ID_LENGTH: usize = 256;
const MAX_APPLICATION_SLUG_LENGTH: usize = 256;
const BULK_SHARE_LIMIT: usize = 100;

#[derive(Deserialize)]
struct Grants {
    grants: Vec<Grant>,
}

#[derive(Deserialize)]
struct GrantResponse {
    grant: Grant,
}

#[derive(Deserialize)]
struct BulkShareResponse {
    results: Vec<BulkShareResult>,
}

fn grant_path(resource_id: &str, grant_id: &str) -> String {
    format!(
        "{}/grants/{}",
        resource_path(resource_id),
        encode_segment(grant_id)
    )
}

fn format_expiry(expires_at: OffsetDateTime, what: &str) -> Result<String> {
    expires_at
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|error| {
            AuthAiError::new(ErrorCode::Cfg001).with_message(format!("Invalid {what}: {error}"))
        })
}

fn check_future(issues: &mut Vec<String>, expires_at: Option<OffsetDateTime>) {
    if expires_at.is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc()) {
        issues.push("expires_at: must be in the future".to_owned());
    }
}

impl ResourceSharingClient {
    /// The grants of a resource the user owns or administers.
    ///
    /// # Errors
    /// `CFG_001` for an invalid id (checked before any request), `API_001` for
    /// a refusal, `API_002` for an unexpected answer.
    pub async fn list_grants(&self, resource_id: &str) -> Result<Vec<Grant>> {
        check_id(resource_id, "resource id")?;
        let path = format!("{}/grants", resource_path(resource_id));
        let response: Grants = self
            .http
            .request(Method::Get, &path, SCOPE_KEY, &[], None)
            .await?;
        Ok(response.grants)
    }

    /// Shares a resource the user owns.
    ///
    /// A `user` subject is named by id or by e-mail, never both; an
    /// `application` subject is named by its slug. `permission` is `read` when
    /// absent and `write` also covers `read`. `expires_at` must be in the future.
    ///
    /// # Errors
    /// `CFG_001` for an invalid id or grant (checked before any request),
    /// `API_001` for a refusal, `API_002` for an unexpected answer.
    pub async fn create_grant(&self, resource_id: &str, input: &CreateGrant<'_>) -> Result<Grant> {
        check_id(resource_id, "resource id")?;
        let subject_email = input.subject_email.map(str::trim);
        let mut issues = Vec::new();
        match input.subject_type {
            GrantSubjectType::Everyone => {
                if input.subject_id.is_some() || input.subject_email.is_some() {
                    issues.push("subject: everyone takes no subject".to_owned());
                }
            }
            GrantSubjectType::User => match (input.subject_id, subject_email) {
                (Some(_), Some(_)) => {
                    issues.push("subject: give either subject_id or subject_email".to_owned());
                }
                (None, Some(email)) => {
                    length_between(&mut issues, "subject_email", email, 1, MAX_EMAIL_LENGTH);
                }
                (Some(subject_id), None) => {
                    length_between(
                        &mut issues,
                        "subject_id",
                        subject_id,
                        1,
                        MAX_SUBJECT_ID_LENGTH,
                    );
                }
                (None, None) => {
                    issues.push("subject_id: a subject is required".to_owned());
                }
            },
            GrantSubjectType::Organization
            | GrantSubjectType::Plan
            | GrantSubjectType::Application => {
                if subject_email.is_some() {
                    issues.push("subject_email: only a user grant accepts an e-mail".to_owned());
                }
                match input.subject_id {
                    Some(subject_id) => length_between(
                        &mut issues,
                        "subject_id",
                        subject_id,
                        1,
                        MAX_SUBJECT_ID_LENGTH,
                    ),
                    None => issues.push("subject_id: a subject is required".to_owned()),
                }
            }
        }
        check_future(&mut issues, input.expires_at);
        if !issues.is_empty() {
            return Err(invalid("grant", &issues));
        }
        let mut body = Map::new();
        body.insert("subjectType".to_owned(), json!(input.subject_type));
        if let Some(subject_id) = input.subject_id {
            body.insert("subjectId".to_owned(), json!(subject_id));
        }
        if let Some(subject_email) = subject_email {
            body.insert("subjectEmail".to_owned(), json!(subject_email));
        }
        if let Some(permission) = input.permission {
            body.insert("permission".to_owned(), json!(permission));
        }
        if let Some(expires_at) = input.expires_at {
            body.insert(
                "expiresAt".to_owned(),
                json!(format_expiry(expires_at, "grant")?),
            );
        }
        let path = format!("{}/grants", resource_path(resource_id));
        let response: GrantResponse = self
            .http
            .request(
                Method::Post,
                &path,
                SCOPE_KEY,
                &[],
                Some(&Value::Object(body)),
            )
            .await?;
        Ok(response.grant)
    }

    /// Changes the level of an active grant without revoking it.
    ///
    /// A level the resource's scheme does not support is refused with `RES_014`,
    /// and an inactive grant with `RES_015`.
    ///
    /// # Errors
    /// `CFG_001` for an invalid id (checked before any request), `API_001` for
    /// a refusal, `API_002` for an unexpected answer.
    pub async fn update_grant(
        &self,
        resource_id: &str,
        grant_id: &str,
        permission: ResourcePermission,
    ) -> Result<Grant> {
        check_id(resource_id, "resource id")?;
        check_id(grant_id, "grant id")?;
        let response: GrantResponse = self
            .http
            .request(
                Method::Patch,
                &grant_path(resource_id, grant_id),
                SCOPE_KEY,
                &[],
                Some(&json!({ "permission": permission })),
            )
            .await?;
        Ok(response.grant)
    }

    /// Revokes an active grant: access ends at once and the row stays as history.
    ///
    /// # Errors
    /// `CFG_001` for an invalid id (checked before any request), `API_001` for
    /// a refusal, `API_002` for an unexpected answer.
    pub async fn revoke_grant(&self, resource_id: &str, grant_id: &str) -> Result<Grant> {
        check_id(resource_id, "resource id")?;
        check_id(grant_id, "grant id")?;
        let response: GrantResponse = self
            .http
            .request(
                Method::Delete,
                &grant_path(resource_id, grant_id),
                SCOPE_KEY,
                &[],
                None,
            )
            .await?;
        Ok(response.grant)
    }

    /// Deletes a grant that is already revoked or expired.
    ///
    /// An active grant is refused with `RES_020`: revoke it first.
    ///
    /// # Errors
    /// `CFG_001` for an invalid id (checked before any request), `API_001` for
    /// a refusal.
    pub async fn delete_grant(&self, resource_id: &str, grant_id: &str) -> Result<()> {
        check_id(resource_id, "resource id")?;
        check_id(grant_id, "grant id")?;
        self.http
            .request_empty(
                Method::Delete,
                &grant_path(resource_id, grant_id),
                SCOPE_KEY,
                &[("permanent", Some("true".to_owned()))],
                None,
            )
            .await
    }

    /// Shares up to 100 of the user's resources with one application in a single call.
    ///
    /// Each resource is checked like a single grant: a refusal is reported on
    /// its own entry (`code`) and does not stop the others.
    ///
    /// # Errors
    /// `CFG_001` for an invalid input (checked before any request), `API_001`
    /// for a refusal, `API_002` for an unexpected answer.
    pub async fn share_with_application<S: AsRef<str>>(
        &self,
        resource_ids: &[S],
        input: &ShareWithApplication<'_>,
    ) -> Result<Vec<BulkShareResult>> {
        let application_slug = input.application_slug.trim();
        let mut issues = Vec::new();
        if resource_ids.is_empty() || resource_ids.len() > BULK_SHARE_LIMIT {
            issues.push(format!(
                "resource_ids: must hold 1 to {BULK_SHARE_LIMIT} resources"
            ));
        }
        if resource_ids
            .iter()
            .any(|resource_id| !is_uuid(resource_id.as_ref()))
        {
            issues.push("resource_ids: every id must be a UUID".to_owned());
        }
        length_between(
            &mut issues,
            "application_slug",
            application_slug,
            1,
            MAX_APPLICATION_SLUG_LENGTH,
        );
        check_future(&mut issues, input.expires_at);
        if !issues.is_empty() {
            return Err(invalid("resource share", &issues));
        }
        let ids: Vec<&str> = resource_ids.iter().map(AsRef::as_ref).collect();
        let mut body = Map::new();
        body.insert("resourceIds".to_owned(), json!(ids));
        body.insert("applicationSlug".to_owned(), json!(application_slug));
        if let Some(permission) = input.permission {
            body.insert("permission".to_owned(), json!(permission));
        }
        if let Some(expires_at) = input.expires_at {
            body.insert(
                "expiresAt".to_owned(),
                json!(format_expiry(expires_at, "resource share")?),
            );
        }
        let response: BulkShareResponse = self
            .http
            .request(
                Method::Post,
                &format!("{USER_PATH}/resource-shares"),
                SCOPE_KEY,
                &[],
                Some(&Value::Object(body)),
            )
            .await?;
        Ok(response.results)
    }
}
