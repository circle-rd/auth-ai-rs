//! The signed-in user's own resources and shares.

use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::models::{
    Catalogue, CreateResource, MemberApplication, Organization, Resource, UpdateResource,
    ValidationRequest,
};
use crate::error::Result;
use crate::http::JsonHttp;
use crate::server::AccessibleResource;
use crate::server::resources::{invalid, is_uuid, length_between};
use crate::transport::Method;
use crate::util::encode_segment;

pub(super) const USER_PATH: &str = "/api/user";
const RESOURCES_PATH: &str = "/api/user/resources";
pub(super) const SCOPE_KEY: &str = "resources";
const MAX_DISPLAY_NAME_LENGTH: usize = 200;
const MAX_LOCATOR_LENGTH: usize = 255;

#[derive(Deserialize)]
struct Applications {
    applications: Vec<MemberApplication>,
}

#[derive(Deserialize)]
struct Organizations {
    organizations: Vec<Organization>,
}

#[derive(Deserialize)]
struct Resources {
    resources: Vec<Resource>,
}

#[derive(Deserialize)]
struct ResourceResponse {
    resource: Resource,
}

#[derive(Deserialize)]
struct AccessibleList {
    resources: Vec<AccessibleResource>,
}

/// The signed-in user's own resources and shares.
///
/// Every call uses the user's access token for the auth-service audience with
/// the `resources:self:manage` scope, which `resource_sharing(true)` adds at
/// sign-in. The token belongs to the user and is confined to the calling
/// application: the client acts only on what that user owns or administers in it.
#[derive(Clone)]
pub struct ResourceSharingClient {
    pub(super) http: JsonHttp,
}

impl std::fmt::Debug for ResourceSharingClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceSharingClient")
            .finish_non_exhaustive()
    }
}

impl ResourceSharingClient {
    pub(crate) const fn new(http: JsonHttp) -> Self {
        Self { http }
    }

    /// The applications the user may declare a resource into.
    ///
    /// # Errors
    /// `API_001` for a refusal, `API_002` for an unexpected answer.
    pub async fn list_member_applications(&self) -> Result<Vec<MemberApplication>> {
        let response: Applications = self
            .http
            .request(
                Method::Get,
                &format!("{USER_PATH}/resource-applications"),
                SCOPE_KEY,
                &[],
                None,
            )
            .await?;
        Ok(response.applications)
    }

    /// The organizations the user belongs to, for an organization audience.
    ///
    /// # Errors
    /// `API_001` for a refusal, `API_002` for an unexpected answer.
    pub async fn list_organizations(&self) -> Result<Vec<Organization>> {
        let response: Organizations = self
            .http
            .request(
                Method::Get,
                &format!("{USER_PATH}/organizations"),
                SCOPE_KEY,
                &[],
                None,
            )
            .await?;
        Ok(response.organizations)
    }

    /// Every resource the user owns.
    ///
    /// # Errors
    /// `API_001` for a refusal, `API_002` for an unexpected answer.
    pub async fn list_owned(&self) -> Result<Vec<Resource>> {
        let response: Resources = self
            .http
            .request(Method::Get, RESOURCES_PATH, SCOPE_KEY, &[], None)
            .await?;
        Ok(response.resources)
    }

    /// One resource the user owns or administers.
    ///
    /// # Errors
    /// `CFG_001` when the id is not a UUID (checked before any request),
    /// `API_001` for a refusal, `API_002` for an unexpected answer.
    pub async fn get_resource(&self, resource_id: &str) -> Result<Resource> {
        check_id(resource_id, "resource id")?;
        let path = format!("{RESOURCES_PATH}/{}", encode_segment(resource_id));
        let response: ResourceResponse = self
            .http
            .request(Method::Get, &path, SCOPE_KEY, &[], None)
            .await?;
        Ok(response.resource)
    }

    /// Declares a resource owned by the user.
    ///
    /// The resource starts in `pending_validation`; the application that owns
    /// the scheme validates it. `audience` shares it in the same call, so a
    /// refused audience never leaves a half-declared resource behind.
    ///
    /// # Errors
    /// `CFG_001` for an invalid input (checked before any request), `API_001`
    /// for a refusal, `API_002` for an unexpected answer.
    pub async fn create(&self, input: &CreateResource<'_>) -> Result<Resource> {
        let display_name = input.display_name.trim();
        let locator = input.locator.map(str::trim);
        let mut issues = Vec::new();
        if !is_uuid(input.application_id) {
            issues.push("application_id: must be a UUID".to_owned());
        }
        if !is_scheme(input.scheme) {
            issues.push("scheme: must be a lowercase scheme of 50 characters at most".to_owned());
        }
        length_between(
            &mut issues,
            "display_name",
            display_name,
            1,
            MAX_DISPLAY_NAME_LENGTH,
        );
        if let Some(locator) = locator {
            length_between(&mut issues, "locator", locator, 1, MAX_LOCATOR_LENGTH);
        }
        if let Some(audience) = input.audience {
            audience.check(&mut issues);
        }
        if !issues.is_empty() {
            return Err(invalid("resource", &issues));
        }
        let mut body = Map::new();
        body.insert("applicationId".to_owned(), json!(input.application_id));
        body.insert("scheme".to_owned(), json!(input.scheme));
        body.insert("displayName".to_owned(), json!(display_name));
        if let Some(locator) = locator {
            body.insert("locator".to_owned(), json!(locator));
        }
        if let Some(metadata) = input.metadata {
            body.insert("metadata".to_owned(), Value::Object(metadata.clone()));
        }
        if let Some(audience) = input.audience {
            body.insert("audience".to_owned(), audience.to_wire());
        }
        let response: ResourceResponse = self
            .http
            .request(
                Method::Post,
                RESOURCES_PATH,
                SCOPE_KEY,
                &[],
                Some(&Value::Object(body)),
            )
            .await?;
        Ok(response.resource)
    }

    /// Updates the display name, the listing or the metadata of a resource.
    ///
    /// # Errors
    /// `CFG_001` for an invalid id or an empty update (checked before any
    /// request), `API_001` for a refusal, `API_002` for an unexpected answer.
    pub async fn update(&self, resource_id: &str, input: &UpdateResource<'_>) -> Result<Resource> {
        check_id(resource_id, "resource id")?;
        let display_name = input.display_name.map(str::trim);
        let mut issues = Vec::new();
        if display_name.is_none() && input.listed.is_none() && input.metadata.is_none() {
            issues.push("update: at least one field is required".to_owned());
        }
        if let Some(display_name) = display_name {
            length_between(
                &mut issues,
                "display_name",
                display_name,
                1,
                MAX_DISPLAY_NAME_LENGTH,
            );
        }
        if !issues.is_empty() {
            return Err(invalid("resource update", &issues));
        }
        let mut body = Map::new();
        if let Some(display_name) = display_name {
            body.insert("displayName".to_owned(), json!(display_name));
        }
        if let Some(listed) = input.listed {
            body.insert("listed".to_owned(), json!(listed));
        }
        if let Some(metadata) = input.metadata {
            body.insert("metadata".to_owned(), Value::Object(metadata.clone()));
        }
        let path = format!("{RESOURCES_PATH}/{}", encode_segment(resource_id));
        let response: ResourceResponse = self
            .http
            .request(
                Method::Patch,
                &path,
                SCOPE_KEY,
                &[],
                Some(&Value::Object(body)),
            )
            .await?;
        Ok(response.resource)
    }

    /// Deletes a resource the user owns for good, with its grants and invitations.
    ///
    /// Refused with `RES_019` while the relay still serves the model.
    ///
    /// # Errors
    /// `CFG_001` for an invalid id (checked before any request), `API_001` for
    /// a refusal, `API_002` for an unexpected answer.
    pub async fn delete(&self, resource_id: &str) -> Result<Resource> {
        check_id(resource_id, "resource id")?;
        let response: ResourceResponse = self
            .http
            .request(
                Method::Delete,
                &resource_path(resource_id),
                SCOPE_KEY,
                &[],
                None,
            )
            .await?;
        Ok(response.resource)
    }

    /// Asks the scheme's validator to check the resource.
    ///
    /// # Errors
    /// `CFG_001` for an invalid id (checked before any request), `API_001` for
    /// a refusal, `API_002` for an unexpected answer.
    pub async fn request_validation(&self, resource_id: &str) -> Result<ValidationRequest> {
        check_id(resource_id, "resource id")?;
        let path = format!(
            "{RESOURCES_PATH}/{}/validation-request",
            encode_segment(resource_id)
        );
        self.http
            .request(Method::Post, &path, SCOPE_KEY, &[], None)
            .await
    }

    /// The validated resources the user may use through the calling application,
    /// each with the `permission` the user holds. A listing filter, not an admission.
    ///
    /// # Errors
    /// `CFG_001` for an invalid query (checked before any request), `API_001`
    /// for a refusal, `API_002` for an unexpected answer.
    pub async fn list_accessible(
        &self,
        scheme: Option<&str>,
        application_id: Option<&str>,
    ) -> Result<Vec<AccessibleResource>> {
        let mut issues = Vec::new();
        if scheme.is_some_and(|scheme| !is_scheme(scheme)) {
            issues.push("scheme: must be a lowercase scheme of 50 characters at most".to_owned());
        }
        if application_id.is_some_and(|id| !is_uuid(id)) {
            issues.push("application_id: must be a UUID".to_owned());
        }
        if !issues.is_empty() {
            return Err(invalid("accessible query", &issues));
        }
        let query = [
            ("scheme", scheme.map(str::to_owned)),
            ("applicationId", application_id.map(str::to_owned)),
        ];
        let response: AccessibleList = self
            .http
            .request(
                Method::Get,
                &format!("{USER_PATH}/accessible-resources"),
                SCOPE_KEY,
                &query,
                None,
            )
            .await?;
        Ok(response.resources)
    }

    /// The applications and resources the user may reach.
    ///
    /// # Errors
    /// `API_001` for a refusal, `API_002` for an unexpected answer.
    pub async fn get_catalogue(&self) -> Result<Catalogue> {
        self.http
            .request(
                Method::Get,
                &format!("{USER_PATH}/resource-catalogue"),
                SCOPE_KEY,
                &[],
                None,
            )
            .await
    }
}

pub(super) fn check_id(value: &str, what: &str) -> Result<()> {
    if is_uuid(value) {
        Ok(())
    } else {
        Err(invalid(what, &["must be a UUID".to_owned()]))
    }
}

pub(super) fn resource_path(resource_id: &str) -> String {
    format!("{RESOURCES_PATH}/{}", encode_segment(resource_id))
}

fn is_scheme(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase())
        && value.len() <= 50
        && characters.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}
