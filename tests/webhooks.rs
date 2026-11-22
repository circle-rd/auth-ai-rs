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
    DEFAULT_TOLERANCE_SECONDS, ResourceEventType, ResourceWebhookVerifier, SIGNATURE_HEADER,
    verify_resource_event,
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
            "expiresAt": null
        },
        "recipients": { "userIds": null, "allMembers": true }
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
    assert_eq!(parsed.kind, ResourceEventType::GrantRevoked);
    assert_eq!(
        parsed.grant.subject_type,
        auth_ai::GrantSubjectType::Organization
    );
    assert!(parsed.recipients.all_members);
    assert_eq!(parsed.recipients.user_ids, None);
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
