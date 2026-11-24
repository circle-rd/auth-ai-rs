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
    AiClient, CreateGrant, CreateResource, ErrorCode, GrantManager, GrantSubjectType, HttpResponse,
    MemoryGrantStore, ResourceAudience, ResourcePermission, SecretString, ShareWithApplication,
    UpdateResource, UserAi,
};
use serde_json::{Value, json};
use support::{ISSUER, MockIdp, auth_with, config, form_of, json_of, path_of, query_of, respond};
use time::{Duration, OffsetDateTime};

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
        "permission": "read",
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
        _ => respond(200, &json!({ "resource": resource(json!({})) })),
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
    assert_eq!(deleted.id, RESOURCE_ID);
    let request = &idp.requests_to(&format!("/api/user/resources/{RESOURCE_ID}"))[1];
    assert_eq!(request.method, auth_ai::Method::Delete);
}

#[tokio::test]
async fn deleting_a_served_resource_surfaces_the_server_code() {
    let (idp, user) = user().await;
    idp.on_api(|_| {
        respond(
            409,
            &json!({ "error": { "code": "RES_019", "message": "served" } }),
        )
    });
    let err = user.resources.delete(RESOURCE_ID).await.unwrap_err();
    assert_eq!(err.to_json()["details"]["apiCode"], "RES_019");
}

#[tokio::test]
async fn reads_the_levels_a_scheme_supports() {
    let (idp, user) = user().await;
    idp.on_api(|_| {
        respond(
            200,
            &json!({ "resource": resource(json!({ "permissions": ["read", "write"] })) }),
        )
    });
    let found = user.resources.get_resource(RESOURCE_ID).await.unwrap();
    assert_eq!(
        found.permissions,
        Some(vec![ResourcePermission::Read, ResourcePermission::Write])
    );
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
                    permission: None,
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
async fn sends_the_permission_only_when_given() {
    let (idp, user) = user().await;
    idp.on_api(|_| respond(201, &json!({ "grant": grant() })));
    let path = format!("/api/user/resources/{RESOURCE_ID}/grants");

    user.resources
        .create_grant(
            RESOURCE_ID,
            &CreateGrant {
                subject_type: GrantSubjectType::User,
                subject_id: Some("user-2"),
                subject_email: None,
                permission: Some(ResourcePermission::Write),
                expires_at: None,
            },
        )
        .await
        .unwrap();
    user.resources
        .create_grant(
            RESOURCE_ID,
            &CreateGrant {
                subject_type: GrantSubjectType::Application,
                subject_id: Some("chat"),
                subject_email: None,
                permission: None,
                expires_at: None,
            },
        )
        .await
        .unwrap();

    let sent = idp.requests_to(&path);
    assert_eq!(
        json_of(&sent[0]),
        json!({ "subjectType": "user", "subjectId": "user-2", "permission": "write" })
    );
    assert_eq!(
        json_of(&sent[1]),
        json!({ "subjectType": "application", "subjectId": "chat" })
    );
}

#[tokio::test]
async fn changes_the_level_of_a_grant_without_revoking_it() {
    let (idp, user) = user().await;
    idp.on_api(|_| {
        let mut updated = grant();
        updated["permission"] = json!("write");
        respond(200, &json!({ "grant": updated }))
    });
    let updated = user
        .resources
        .update_grant(RESOURCE_ID, GRANT_ID, ResourcePermission::Write)
        .await
        .unwrap();
    assert_eq!(updated.permission, ResourcePermission::Write);
    let path = format!("/api/user/resources/{RESOURCE_ID}/grants/{GRANT_ID}");
    let sent = &idp.requests_to(&path)[0];
    assert_eq!(sent.method, auth_ai::Method::Patch);
    assert_eq!(json_of(sent), json!({ "permission": "write" }));
}

#[tokio::test]
async fn deletes_a_past_grant_for_good() {
    let (idp, user) = user().await;
    idp.on_api(|_| HttpResponse {
        status: 204,
        headers: Vec::new(),
        body: Vec::new(),
    });
    user.resources
        .delete_grant(RESOURCE_ID, GRANT_ID)
        .await
        .unwrap();
    let path = format!("/api/user/resources/{RESOURCE_ID}/grants/{GRANT_ID}");
    let sent = &idp.requests_to(&path)[0];
    assert_eq!(sent.method, auth_ai::Method::Delete);
    assert_eq!(query_of(&sent.url)["permanent"], vec!["true".to_owned()]);
}

#[tokio::test]
async fn revoking_a_grant_does_not_delete_it() {
    let (idp, user) = user().await;
    idp.on_api(|_| respond(200, &json!({ "grant": grant() })));
    user.resources
        .revoke_grant(RESOURCE_ID, GRANT_ID)
        .await
        .unwrap();
    let path = format!("/api/user/resources/{RESOURCE_ID}/grants/{GRANT_ID}");
    assert!(!query_of(&idp.requests_to(&path)[0].url).contains_key("permanent"));
}

#[tokio::test]
async fn refusing_to_delete_an_active_grant_surfaces_the_server_code() {
    let (idp, user) = user().await;
    idp.on_api(|_| {
        respond(
            409,
            &json!({ "error": { "code": "RES_020", "message": "active" } }),
        )
    });
    let err = user
        .resources
        .delete_grant(RESOURCE_ID, GRANT_ID)
        .await
        .unwrap_err();
    assert_eq!(err.to_json()["details"]["apiCode"], "RES_020");
}

#[tokio::test]
async fn shares_several_resources_with_an_application() {
    let (idp, user) = user().await;
    idp.on_api(|_| {
        respond(
            200,
            &json!({ "results": [
                { "resourceId": RESOURCE_ID, "grantId": GRANT_ID, "code": null },
                { "resourceId": APP_ID, "grantId": null, "code": "RES_014" }
            ] }),
        )
    });
    let expires_at = OffsetDateTime::now_utc() + Duration::days(1);
    let results = user
        .resources
        .share_with_application(
            &[RESOURCE_ID, APP_ID],
            &ShareWithApplication {
                application_slug: " chat ",
                permission: Some(ResourcePermission::Write),
                expires_at: Some(expires_at),
            },
        )
        .await
        .unwrap();
    assert_eq!(results[0].grant_id.as_deref(), Some(GRANT_ID));
    assert_eq!(results[0].code, None);
    assert_eq!(results[1].grant_id, None);
    assert_eq!(results[1].code.as_deref(), Some("RES_014"));

    let sent = &idp.requests_to("/api/user/resource-shares")[0];
    assert_eq!(sent.method, auth_ai::Method::Post);
    let body = json_of(sent);
    assert_eq!(body["resourceIds"], json!([RESOURCE_ID, APP_ID]));
    assert_eq!(body["applicationSlug"], "chat");
    assert_eq!(body["permission"], "write");
    assert!(body["expiresAt"].as_str().unwrap().ends_with('Z'));
}

#[tokio::test]
async fn a_share_omits_what_is_not_given() {
    let (idp, user) = user().await;
    idp.on_api(|_| respond(200, &json!({ "results": [] })));
    user.resources
        .share_with_application(
            &[RESOURCE_ID.to_owned()],
            &ShareWithApplication {
                application_slug: "chat",
                permission: None,
                expires_at: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        json_of(&idp.requests_to("/api/user/resource-shares")[0]),
        json!({ "resourceIds": [RESOURCE_ID], "applicationSlug": "chat" })
    );
}

#[tokio::test]
async fn invalid_shares_are_refused_before_any_request() {
    let (idp, user) = user().await;
    let share = |application_slug, expires_at| ShareWithApplication {
        application_slug,
        permission: None,
        expires_at,
    };
    let hundred_and_one = vec![RESOURCE_ID; 101];
    for (ids, input) in [
        (Vec::new(), share("chat", None)),
        (hundred_and_one, share("chat", None)),
        (vec!["nope"], share("chat", None)),
        (vec![RESOURCE_ID], share(" ", None)),
        (
            vec![RESOURCE_ID],
            share("chat", Some(OffsetDateTime::UNIX_EPOCH)),
        ),
    ] {
        let err = user
            .resources
            .share_with_application(&ids, &input)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cfg001);
    }
    assert!(idp.requests().is_empty(), "no request was sent");
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
                "accessKind": "grant", "permission": "write", "grantSubjectType": "user"
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
    assert_eq!(accessible[0].permission, ResourcePermission::Write);
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
        user.resources.get_resource("not-a-uuid").await.unwrap_err(),
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
                    permission: None,
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
                    permission: None,
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
                    permission: None,
                    expires_at: None,
                },
            )
            .await
            .unwrap_err(),
        user.resources
            .create_grant(
                RESOURCE_ID,
                &CreateGrant {
                    subject_type: GrantSubjectType::Application,
                    subject_id: None,
                    subject_email: None,
                    permission: None,
                    expires_at: None,
                },
            )
            .await
            .unwrap_err(),
        user.resources
            .create_grant(
                RESOURCE_ID,
                &CreateGrant {
                    subject_type: GrantSubjectType::User,
                    subject_id: Some("user-2"),
                    subject_email: None,
                    permission: None,
                    expires_at: Some(OffsetDateTime::UNIX_EPOCH),
                },
            )
            .await
            .unwrap_err(),
        user.resources
            .update_grant("nope", GRANT_ID, ResourcePermission::Write)
            .await
            .unwrap_err(),
        user.resources
            .update_grant(RESOURCE_ID, "nope", ResourcePermission::Write)
            .await
            .unwrap_err(),
        user.resources
            .delete_grant(RESOURCE_ID, "nope")
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
