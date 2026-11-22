#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The signed-in user's own resources and shares.

mod support;

use std::sync::Arc;

use auth_ai::{
    AiClient, CreateGrant, CreateResource, ErrorCode, GrantManager, GrantSubjectType,
    MemoryGrantStore, ResourceAudience, SecretString, UpdateResource, UserAi,
};
use serde_json::{Value, json};
use support::{ISSUER, MockIdp, auth_with, config, form_of, json_of, path_of, query_of, respond};

const RESOURCE_ID: &str = "4b1f6f3e-5a6c-4d0e-9c53-0a4c6f0f7a11";
const GRANT_ID: &str = "9c8b7a6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
const APP_ID: &str = "1d2c3b4a-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
const ORG_ID: &str = "org-1";

fn resource(overrides: Value) -> Value {
    let mut value = json!({
        "id": RESOURCE_ID,
        "applicationId": APP_ID,
        "applicationSlug": "gine",
        "applicationName": "GINE",
        "scheme": "gine",
        "schemeDisplayName": "GINE project",
        "locator": "job-1",
        "uri": "gine://job-1",
        "displayName": "Firmware",
        "ownerType": "user",
        "ownerId": "user-1",
        "status": "validated",
        "listed": false,
        "validationRequestedAt": null,
        "validatedAt": "2026-11-20T10:00:00Z",
        "validationError": null,
        "createdAt": "2026-11-20T09:00:00Z",
        "updatedAt": "2026-11-20T10:00:00Z"
    });
    if let (Some(target), Some(extra)) = (value.as_object_mut(), overrides.as_object()) {
        for (name, value) in extra {
            target.insert(name.clone(), value.clone());
        }
    }
    value
}

fn grant() -> Value {
    json!({
        "id": GRANT_ID,
        "resourceId": RESOURCE_ID,
        "subjectType": "user",
        "subjectId": "user-2",
        "permission": "use",
        "expiresAt": null,
        "revokedAt": null,
        "createdBy": "user-1",
        "createdAt": "2026-11-20T10:00:00Z"
    })
}

async fn user() -> (Arc<MockIdp>, UserAi) {
    let idp = MockIdp::new();
    idp.on_token(|_| {
        respond(
            200,
            &json!({
                "access_token": "user-token", "token_type": "Bearer", "expires_in": 3600,
                "refresh_token": "refresh-next"
            }),
        )
    });
    let auth = auth_with(&idp, config().resource_sharing(true));
    let grants = GrantManager::new(auth.clone(), MemoryGrantStore::new());
    grants
        .save("user-1", &SecretString::new("refresh-1"))
        .await
        .unwrap();
    (idp, AiClient::new(auth, grants).for_user("user-1").unwrap())
}

#[tokio::test]
async fn lists_applications_organizations_and_owned_resources() {
    let (idp, user) = user().await;
    idp.on_api(|request| match path_of(request).as_str() {
        "/api/user/resource-applications" => respond(
            200,
            &json!({ "applications": [{
                "id": APP_ID, "name": "GINE", "slug": "gine",
                "description": null, "icon": null, "canCreate": true
            }] }),
        ),
        "/api/user/organizations" => respond(
            200,
            &json!({ "organizations": [{
                "id": ORG_ID, "name": "CIRCLE", "slug": "circle",
                "logo": null, "role": "member", "createdAt": "2026-01-01T00:00:00Z"
            }] }),
        ),
        _ => respond(200, &json!({ "resources": [resource(json!({}))] })),
    });

    assert_eq!(
        user.resources.list_member_applications().await.unwrap()[0].slug,
        "gine"
    );
    assert_eq!(
        user.resources.list_organizations().await.unwrap()[0].id,
        ORG_ID
    );
    let owned = user.resources.list_owned().await.unwrap();
    assert_eq!(owned[0].locator.as_deref(), Some("job-1"));
    assert_eq!(
        idp.requests_to("/api/user/resources")[0].header("authorization"),
        Some("Bearer user-token")
    );
    assert_eq!(form_of(&idp.requests_to("/token")[0])["resource"], ISSUER);
}

#[tokio::test]
async fn declares_updates_and_deletes_a_resource() {
    let (idp, user) = user().await;
    idp.on_api(|request| match request.method {
        auth_ai::Method::Post => respond(201, &json!({ "resource": resource(json!({})) })),
        auth_ai::Method::Patch => respond(
            200,
            &json!({ "resource": resource(json!({ "displayName": "Renamed" })) }),
        ),
        _ => respond(
            200,
            &json!({ "resource": resource(json!({})), "removed": true }),
        ),
    });
    let metadata = serde_json::Map::from_iter([("jobId".to_owned(), json!("job-1"))]);

    user.resources
        .create(&CreateResource {
            application_id: APP_ID,
            scheme: "gine",
            display_name: " Firmware ",
            locator: Some(" job-1 "),
            metadata: Some(&metadata),
            audience: Some(&ResourceAudience::email("colleague@example.com")),
        })
        .await
        .unwrap();
    let created = &idp.requests_to("/api/user/resources")[0];
    assert_eq!(created.method, auth_ai::Method::Post);
    assert_eq!(
        json_of(created),
        json!({
            "applicationId": APP_ID,
            "scheme": "gine",
            "displayName": "Firmware",
            "locator": "job-1",
            "metadata": { "jobId": "job-1" },
            "audience": { "type": "user", "email": "colleague@example.com" }
        })
    );

    let updated = user
        .resources
        .update(
            RESOURCE_ID,
            &UpdateResource {
                display_name: Some(" Renamed "),
                listed: Some(true),
                metadata: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.display_name, "Renamed");
    let request = &idp.requests_to(&format!("/api/user/resources/{RESOURCE_ID}"))[0];
    assert_eq!(request.method, auth_ai::Method::Patch);
    assert_eq!(
        json_of(request),
        json!({ "displayName": "Renamed", "listed": true })
    );

    let deleted = user.resources.delete(RESOURCE_ID).await.unwrap();
    assert!(deleted.removed);
    let request = &idp.requests_to(&format!("/api/user/resources/{RESOURCE_ID}"))[1];
    assert_eq!(request.method, auth_ai::Method::Delete);
}

#[tokio::test]
async fn shares_and_revokes_grants() {
    let (idp, user) = user().await;
    idp.on_api(|request| match request.method {
        auth_ai::Method::Get => respond(200, &json!({ "grants": [grant()] })),
        auth_ai::Method::Delete => respond(200, &json!({ "grant": grant() })),
        _ => respond(201, &json!({ "grant": grant() })),
    });

    assert_eq!(
        user.resources
            .create_grant(
                RESOURCE_ID,
                &CreateGrant {
                    subject_type: GrantSubjectType::User,
                    subject_id: None,
                    subject_email: Some(" user@example.com "),
                    expires_at: None,
                }
            )
            .await
            .unwrap()
            .id,
        GRANT_ID
    );
    let request = &idp.requests_to(&format!("/api/user/resources/{RESOURCE_ID}/grants"))[0];
    assert_eq!(request.method, auth_ai::Method::Post);
    assert_eq!(
        json_of(request),
        json!({ "subjectType": "user", "subjectEmail": "user@example.com" })
    );

    let grants = user.resources.list_grants(RESOURCE_ID).await.unwrap();
    assert_eq!(grants[0].subject_id.as_deref(), Some("user-2"));

    user.resources
        .revoke_grant(RESOURCE_ID, GRANT_ID)
        .await
        .unwrap();
    let path = format!("/api/user/resources/{RESOURCE_ID}/grants/{GRANT_ID}");
    assert_eq!(idp.requests_to(&path)[0].method, auth_ai::Method::Delete);
}

#[tokio::test]
async fn requests_validation_reads_filters_and_the_catalogue() {
    let (idp, user) = user().await;
    idp.on_api(|request| match path_of(request).as_str() {
        p if p.ends_with("/validation-request") => respond(
            200,
            &json!({
                "resource": resource(json!({ "status": "pending_validation" })),
                "validatorUrl": "https://validator.example",
                "validationCommand": "validate x"
            }),
        ),
        "/api/user/accessible-resources" => respond(
            200,
            &json!({ "resources": [{
                "resourceId": RESOURCE_ID, "resourceUri": "gine://job-1", "scheme": "gine",
                "displayName": "Firmware", "applicationId": APP_ID, "applicationSlug": "gine",
                "applicationName": "GINE", "ownerType": "user", "ownerId": "user-1",
                "accessKind": "grant", "grantSubjectType": "user"
            }] }),
        ),
        _ => respond(
            200,
            &json!({
                "applications": [{ "slug": "gine", "name": "GINE" }],
                "resources": [],
                "enabledSchemes": ["gine"]
            }),
        ),
    });

    let pending = user
        .resources
        .request_validation(RESOURCE_ID)
        .await
        .unwrap();
    assert_eq!(
        pending.resource.status,
        auth_ai::ResourceStatus::PendingValidation
    );
    assert_eq!(
        pending.validator_url.as_deref(),
        Some("https://validator.example")
    );

    let accessible = user
        .resources
        .list_accessible(Some("gine"), Some(APP_ID))
        .await
        .unwrap();
    assert_eq!(accessible[0].resource_uri, "gine://job-1");
    let url = &idp.requests_to("/api/user/accessible-resources")[0].url;
    assert_eq!(query_of(url)["scheme"], vec!["gine".to_owned()]);
    assert_eq!(query_of(url)["applicationId"], vec![APP_ID.to_owned()]);

    let catalogue = user.resources.get_catalogue().await.unwrap();
    assert_eq!(catalogue.enabled_schemes, ["gine"]);
}

#[tokio::test]
async fn invalid_inputs_are_refused_before_any_request() {
    let (idp, user) = user().await;

    for error in [
        user.resources.get("not-a-uuid").await.unwrap_err(),
        user.resources
            .update(RESOURCE_ID, &UpdateResource::default())
            .await
            .unwrap_err(),
        user.resources
            .create(&CreateResource {
                application_id: "nope",
                scheme: "GINE",
                display_name: "",
                locator: None,
                metadata: None,
                audience: None,
            })
            .await
            .unwrap_err(),
        user.resources
            .create_grant(
                RESOURCE_ID,
                &CreateGrant {
                    subject_type: GrantSubjectType::User,
                    subject_id: Some("user-2"),
                    subject_email: Some("user@example.com"),
                    expires_at: None,
                },
            )
            .await
            .unwrap_err(),
        user.resources
            .create_grant(
                RESOURCE_ID,
                &CreateGrant {
                    subject_type: GrantSubjectType::Everyone,
                    subject_id: Some("user-2"),
                    subject_email: None,
                    expires_at: None,
                },
            )
            .await
            .unwrap_err(),
        user.resources
            .create_grant(
                RESOURCE_ID,
                &CreateGrant {
                    subject_type: GrantSubjectType::Plan,
                    subject_id: None,
                    subject_email: None,
                    expires_at: None,
                },
            )
            .await
            .unwrap_err(),
        user.resources
            .list_accessible(Some("GINE"), Some("nope"))
            .await
            .unwrap_err(),
    ] {
        assert_eq!(error.code(), ErrorCode::Cfg001);
    }
    assert!(idp.requests().is_empty(), "no request was sent");
}
