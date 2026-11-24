#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Verification of signed resource-sharing webhooks.

use std::time::{SystemTime, UNIX_EPOCH};

use auth_ai::ErrorCode;
use auth_ai::server::{
    DEFAULT_TOLERANCE_SECONDS, ResourceEvent, ResourceEventType, ResourcePermission,
    ResourceWebhookVerifier, SIGNATURE_HEADER, verify_resource_event,
};
use aws_lc_rs::hmac;
use serde_json::{Value, json};

const SECRET: &str = "whsec_test_123";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn event() -> Value {
    json!({
        "eventId": "6f1c0f1e-2c3b-4a5d-8e9f-0a1b2c3d4e5f",
        "type": "resource.grant.revoked",
        "occurredAt": "2026-11-20T10:00:00Z",
        "application": { "id": "app-1", "slug": "gine" },
        "resource": {
            "id": "4b1f6f3e-5a6c-4d0e-9c53-0a4c6f0f7a11",
            "uri": "gine://job-1",
            "scheme": "gine",
            "displayName": "Firmware",
            "ownerType": "user",
            "ownerId": "user-1",
            "status": "validated"
        },
        "grant": {
            "id": "9c8b7a6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
            "subjectType": "organization",
            "subjectId": "org-1",
            "permission": "read",
            "previousPermission": null,
            "expiresAt": null
        },
        "recipients": { "userIds": null, "allMembers": true }
    })
}

fn deleted_event() -> Value {
    json!({
        "eventId": "5e2a0c4e-6b7f-4a1d-8e2c-3f5b6a7c8d90",
        "type": "resource.deleted",
        "occurredAt": "2026-11-20T10:05:00Z",
        "application": { "id": "app-2", "slug": "chat" },
        "resource": {
            "id": "4b1f6f3e-5a6c-4d0e-9c53-0a4c6f0f7a11",
            "uri": "gine://job-1",
            "scheme": "gine",
            "displayName": "Firmware",
            "ownerType": "user"
        }
    })
}

fn signature(body: &[u8], timestamp: i64, secret: &str) -> String {
    let mut signed = format!("{timestamp}.").into_bytes();
    signed.extend_from_slice(body);
    let tag = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes()),
        &signed,
    );
    let mut hex = String::new();
    for byte in tag.as_ref() {
        hex.push_str(&format!("{byte:02x}"));
    }
    format!("t={timestamp},v1={hex}")
}

fn headers(header: String) -> Vec<(String, String)> {
    vec![(SIGNATURE_HEADER.to_owned(), header)]
}

#[test]
fn a_valid_delivery_is_verified_and_typed() {
    let body = serde_json::to_vec(&event()).unwrap();
    let parsed =
        verify_resource_event(&headers(signature(&body, now(), SECRET)), &body, SECRET).unwrap();
    assert_eq!(parsed.kind(), ResourceEventType::GrantRevoked);
    let ResourceEvent::GrantRevoked(revoked) = parsed else {
        panic!("expected a revoked grant event");
    };
    assert_eq!(
        revoked.grant.subject_type,
        auth_ai::GrantSubjectType::Organization
    );
    assert_eq!(revoked.grant.permission, ResourcePermission::Read);
    assert_eq!(revoked.grant.previous_permission, None);
    assert_eq!(revoked.resource.owner_id.as_deref(), Some("user-1"));
    assert!(revoked.recipients.all_members);
    assert_eq!(revoked.recipients.user_ids, None);
}

#[test]
fn a_level_change_carries_the_previous_level() {
    let mut updated = event();
    updated["type"] = json!("resource.grant.updated");
    updated["grant"]["permission"] = json!("write");
    updated["grant"]["previousPermission"] = json!("read");
    let body = serde_json::to_vec(&updated).unwrap();
    let parsed =
        verify_resource_event(&headers(signature(&body, now(), SECRET)), &body, SECRET).unwrap();
    let ResourceEvent::GrantUpdated(event) = parsed else {
        panic!("expected an updated grant event");
    };
    assert_eq!(event.grant.permission, ResourcePermission::Write);
    assert_eq!(
        event.grant.previous_permission,
        Some(ResourcePermission::Read)
    );
}

#[test]
fn a_deletion_carries_the_resource_only() {
    let body = serde_json::to_vec(&deleted_event()).unwrap();
    let parsed =
        verify_resource_event(&headers(signature(&body, now(), SECRET)), &body, SECRET).unwrap();
    assert_eq!(parsed.kind(), ResourceEventType::Deleted);
    assert_eq!(parsed.event_id(), "5e2a0c4e-6b7f-4a1d-8e2c-3f5b6a7c8d90");
    let ResourceEvent::Deleted(deleted) = parsed else {
        panic!("expected a deletion event");
    };
    assert_eq!(deleted.resource.uri, "gine://job-1");
    assert_eq!(deleted.resource.owner_id, None);
}

#[test]
fn a_grant_event_without_a_permission_is_refused() {
    let mut incomplete = event();
    incomplete["grant"]
        .as_object_mut()
        .unwrap()
        .remove("permission");
    let mut legacy = event();
    legacy["grant"]["permission"] = json!("use");
    let mut grant_without_grant = event();
    grant_without_grant.as_object_mut().unwrap().remove("grant");
    let mut unknown = deleted_event();
    unknown["type"] = json!("resource.moved");
    for payload in [incomplete, legacy, grant_without_grant, unknown] {
        let body = serde_json::to_vec(&payload).unwrap();
        let err = verify_resource_event(&headers(signature(&body, now(), SECRET)), &body, SECRET)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Req001);
    }
}

#[test]
fn the_timestamp_window_is_bounded_and_configurable() {
    let body = serde_json::to_vec(&event()).unwrap();
    let stale = headers(signature(
        &body,
        now() - DEFAULT_TOLERANCE_SECONDS as i64 - 60,
        SECRET,
    ));

    let err = verify_resource_event(&stale, &body, SECRET).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Req001);

    let verifier =
        ResourceWebhookVerifier::new(SECRET).tolerance_seconds(DEFAULT_TOLERANCE_SECONDS + 120);
    assert!(verifier.verify(&stale, &body).is_ok());
}
