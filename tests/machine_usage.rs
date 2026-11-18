#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Reporting resource usage to auth-service.

mod support;

use std::time::{Duration, SystemTime};

use auth_ai::ErrorCode;
use auth_ai::server::{UsageRecord, UsageSource};
use serde_json::json;
use support::{bearer, json_of, machine, respond};

const RESOURCE: &str = "0f9d6a3e-5c1b-4d52-9a47-2b8f3c6e1a90";
const EVENT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PATH: &str = "/api/internal/gateway/usage";

fn record() -> UsageRecord<'static> {
    UsageRecord {
        subject_id: "user-1",
        client_id: "gateway",
        resource_id: RESOURCE,
        resource_uri: "llm://models/gpt",
        request_id: EVENT,
        occurred_at: SystemTime::now(),
        source: UsageSource::Provider,
        cost_usd: Some("0.0042"),
        prompt_tokens: Some(120),
        completion_tokens: Some(30),
        total_tokens: Some(150),
    }
}

fn receipt(replayed: bool) -> serde_json::Value {
    json!({
        "usage": { "id": "u-1", "resourceId": RESOURCE, "requestId": EVENT, "occurredAt": "2026-11-18T10:00:00.000Z" },
        "replayed": replayed,
    })
}

#[tokio::test]
async fn a_usage_event_is_sent_with_the_usage_scope_and_every_member() {
    let (idp, api, _) = machine();
    idp.on_api(|_| respond(201, &receipt(false)));

    let result = api.resources.record_usage(&record()).await.unwrap();

    assert!(!result.replayed);
    assert_eq!(result.usage.id, "u-1");
    assert_eq!(result.usage.request_id, EVENT);
    let sent = &idp.requests_to(PATH)[0];
    assert_eq!(bearer(sent), "Bearer machine-1-resources:usage:write");
    let body = json_of(sent);
    assert_eq!(body["usageSource"], "provider");
    assert_eq!(body["costUsd"], "0.0042");
    assert_eq!(body["promptTokens"], 120);
    assert_eq!(body["requestId"], EVENT);
    assert!(body["occurredAt"].as_str().unwrap().ends_with('Z'));
}

#[tokio::test]
async fn an_unsupported_provider_sends_explicit_nulls() {
    let (idp, api, _) = machine();
    idp.on_api(|_| respond(201, &receipt(false)));
    let unsupported = UsageRecord {
        source: UsageSource::Unsupported,
        cost_usd: None,
        prompt_tokens: None,
        completion_tokens: None,
        total_tokens: None,
        ..record()
    };

    api.resources.record_usage(&unsupported).await.unwrap();

    let body = json_of(&idp.requests_to(PATH)[0]);
    assert_eq!(body["usageSource"], "unsupported");
    for member in ["costUsd", "promptTokens", "completionTokens", "totalTokens"] {
        assert!(body[member].is_null(), "{member}");
    }
}

#[tokio::test]
async fn a_replayed_event_is_reported_as_such() {
    let (idp, api, _) = machine();
    idp.on_api(|_| respond(200, &receipt(true)));
    assert!(
        api.resources
            .record_usage(&record())
            .await
            .unwrap()
            .replayed
    );
}

#[tokio::test]
async fn a_refusal_is_an_error() {
    let (idp, api, _) = machine();
    for (status, code) in [(403, "RES_011"), (409, "RES_012")] {
        idp.on_api(move |_| {
            respond(
                status,
                &json!({ "error": { "code": code, "message": "no" } }),
            )
        });
        let err = api.resources.record_usage(&record()).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::Api001);
    }
}

#[tokio::test]
async fn an_unexpected_answer_is_api_002() {
    let (idp, api, _) = machine();
    idp.on_api(|_| respond(201, &json!({ "usage": "stored" })));
    assert_eq!(
        api.resources
            .record_usage(&record())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Api002
    );
}

#[tokio::test]
async fn an_invalid_record_is_refused_before_any_request() {
    let (idp, api, minted) = machine();
    let day = Duration::from_secs(24 * 60 * 60);
    let too_old = SystemTime::now() - 31 * day;
    let too_far = SystemTime::now() + Duration::from_secs(10 * 60);
    let upper = EVENT.to_uppercase();
    let bad = [
        UsageRecord {
            subject_id: "",
            ..record()
        },
        UsageRecord {
            client_id: "",
            ..record()
        },
        UsageRecord {
            resource_id: "not-a-uuid",
            ..record()
        },
        UsageRecord {
            resource_uri: "x",
            ..record()
        },
        UsageRecord {
            request_id: "short",
            ..record()
        },
        UsageRecord {
            request_id: &upper,
            ..record()
        },
        UsageRecord {
            occurred_at: too_old,
            ..record()
        },
        UsageRecord {
            occurred_at: too_far,
            ..record()
        },
        UsageRecord {
            cost_usd: None,
            ..record()
        },
        UsageRecord {
            cost_usd: Some("-1"),
            ..record()
        },
        UsageRecord {
            cost_usd: Some("1e3"),
            ..record()
        },
        UsageRecord {
            cost_usd: Some("007"),
            ..record()
        },
        UsageRecord {
            source: UsageSource::Unsupported,
            ..record()
        },
        UsageRecord {
            source: UsageSource::Unsupported,
            cost_usd: None,
            ..record()
        },
    ];
    for usage in &bad {
        let err = api.resources.record_usage(usage).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cfg001, "{usage:?}");
    }
    assert!(idp.requests().is_empty());
    assert_eq!(minted.load(std::sync::atomic::Ordering::SeqCst), 0);
}
