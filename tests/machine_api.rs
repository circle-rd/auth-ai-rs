#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The machine API: client-credentials tokens, billing, consumption and resource sharing.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use auth_ai::AuthClientConfig;
use auth_ai::ErrorCode;
use auth_ai::server::{
    AccessKind, AuthorizeDecision, AuthorizeRequest, EventSource, MachineApi, OwnerType,
    ResourceStatus, ValidationResult,
};
use serde_json::{Map, Value, json};
use support::{
    CLIENT_ID, ISSUER, MockIdp, REDIRECT_URI, form_of, json_of, path_of, respond, test_auth,
    token_response,
};

const RESOURCE: &str = "0f9d6a3e-5c1b-4d52-9a47-2b8f3c6e1a90";

fn machine() -> (Arc<MockIdp>, MachineApi, Arc<AtomicU32>) {
    let idp = MockIdp::new();
    let minted = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&minted);
    idp.on_token(move |request| {
        let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
        let scope = form_of(request).get("scope").cloned().unwrap_or_default();
        token_response(&json!({ "access_token": format!("machine-{n}-{scope}") }))
    });
    let api = MachineApi::new(&test_auth(&idp)).unwrap();
    (idp, api, minted)
}

fn bearer(request: &auth_ai::HttpRequest) -> String {
    request.header("authorization").unwrap().to_owned()
}

// ── tokens ──

#[tokio::test]
async fn it_needs_a_confidential_client() {
    let idp = MockIdp::new();
    let public = auth_ai::AuthClient::with_transport(
        AuthClientConfig::builder(ISSUER, CLIENT_ID, REDIRECT_URI)
            .build()
            .unwrap(),
        idp,
    );
    assert_eq!(
        MachineApi::new(&public).unwrap_err().code(),
        ErrorCode::Cfg001
    );
}

#[tokio::test]
async fn a_token_is_minted_per_scope_and_cached() {
    let (idp, api, minted) = machine();
    idp.on_api(|_| respond(200, &json!({ "subscription": null })));

    api.billing.get_subscription("u1").await.unwrap();
    api.billing.get_subscription("u2").await.unwrap();
    assert_eq!(
        minted.load(Ordering::SeqCst),
        1,
        "the second call reuses the cached token"
    );
    assert_eq!(
        bearer(&idp.requests_to("/api/app/billing/users/u1/subscription")[0]),
        "Bearer machine-1-billing:read"
    );

    idp.on_api(|_| respond(200, &json!({ "aggregates": [] })));
    api.consumption.list_aggregates("u1").await.unwrap();
    assert_eq!(
        minted.load(Ordering::SeqCst),
        2,
        "another scope needs its own token"
    );
    assert_eq!(
        form_of(&idp.requests_to("/token")[1])["scope"],
        "consumption:read"
    );
    assert_eq!(
        form_of(&idp.requests_to("/token")[1])["grant_type"],
        "client_credentials"
    );
}

#[tokio::test]
async fn concurrent_callers_share_one_token_request() {
    let (idp, api, minted) = machine();
    idp.set_token_delay(Duration::from_millis(60));
    idp.on_api(|_| respond(200, &json!({ "subscription": null })));

    let calls = (0..6).map(|n| {
        let api = api.clone();
        tokio::spawn(async move {
            api.billing
                .get_subscription(&format!("u{n}"))
                .await
                .unwrap()
        })
    });
    for call in calls {
        call.await.unwrap();
    }
    assert_eq!(minted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_unknown_scope_is_tok_004_with_the_scope_in_the_details_only() {
    let (idp, api, _) = machine();
    idp.on_token(|_| respond(400, &json!({ "error": "invalid_scope" })));
    let err = api.billing.get_subscription("u1").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Tok004);
    assert_eq!(err.to_json()["details"]["scope"], "billing:read");
    assert!(!err.message().contains("billing:read"));
}

#[tokio::test]
async fn a_refused_token_is_replaced_once_and_the_call_retried() {
    let (idp, api, minted) = machine();
    let calls = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&calls);
    idp.on_api(move |_| {
        if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            respond(
                401,
                &json!({ "error": { "code": "AUTH_001", "message": "rotated" } }),
            )
        } else {
            respond(200, &json!({ "subscription": null }))
        }
    });
    api.billing.get_subscription("u1").await.unwrap();
    assert_eq!(minted.load(Ordering::SeqCst), 2);
    let requests = idp.requests_to("/api/app/billing/users/u1/subscription");
    assert_ne!(bearer(&requests[0]), bearer(&requests[1]));
}

// ── billing ──

#[tokio::test]
async fn the_subscription_the_usage_and_the_invoices_are_read() {
    let (idp, api, _) = machine();
    idp.on_api(|request| match path_of(request).as_str() {
        "/api/app/billing/users/a%2Fb%20c/subscription" => respond(
            200,
            &json!({ "subscription": {
                "plan": { "id": "p1", "name": "Pro" }, "isActive": true, "expiresAt": null, "stripeStatus": "active",
                "currentPeriodStart": "2026-11-01", "currentPeriodEnd": "2026-12-01", "cancelAtPeriodEnd": false,
                "canceledAt": null
            } }),
        ),
        "/api/app/billing/users/a%2Fb%20c/usage" => respond(
            200,
            &json!({ "periodStart": "2026-11-01", "features": [
                { "featureKey": "audits", "unit": "call", "usageLimit": 100, "used": 12.5, "remaining": 87.5 },
                { "featureKey": "free", "unit": null, "usageLimit": -1, "used": 3, "remaining": null }
            ] }),
        ),
        _ => respond(
            200,
            &json!({ "items": [{
                "id": "in_1", "status": "paid", "billingReason": null, "currency": "eur", "amountDue": 1000,
                "amountPaid": 1000, "amountRemaining": 0, "periodStart": null, "periodEnd": null,
                "createdAt": "2026-11-01", "hostedInvoiceUrl": null, "invoicePdf": null
            }], "nextCursor": null }),
        ),
    });

    let subscription = api
        .billing
        .get_subscription("a/b c")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (subscription.plan.name.as_str(), subscription.is_active),
        ("Pro", true)
    );
    let usage = api.billing.get_usage("a/b c").await.unwrap();
    assert_eq!(usage.features[0].remaining, Some(87.5));
    assert_eq!(usage.features[1].usage_limit, -1.0);
    let invoices = api
        .billing
        .list_invoices("a/b c", Some(5), Some("cur"))
        .await
        .unwrap();
    assert_eq!(invoices.items[0].amount_paid, 1000);
    assert!(
        idp.requests()
            .last()
            .unwrap()
            .url
            .ends_with("/invoices?limit=5&cursor=cur")
    );
}

#[tokio::test]
async fn a_user_without_a_subscription_is_none() {
    let (idp, api, _) = machine();
    idp.on_api(|_| respond(200, &json!({ "subscription": null })));
    assert!(api.billing.get_subscription("u1").await.unwrap().is_none());
    idp.on_api(|_| respond(200, &json!({})));
    assert!(api.billing.get_subscription("u1").await.unwrap().is_none());
}

#[tokio::test]
async fn billing_errors_are_api_001_and_odd_answers_api_002() {
    let (idp, api, _) = machine();
    idp.on_api(|_| {
        respond(
            404,
            &json!({ "error": { "code": "USR_001", "message": "User not found" } }),
        )
    });
    let err = api.billing.get_usage("ghost").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Api001);
    assert_eq!(err.to_json()["details"]["apiCode"], "USR_001");
    idp.on_api(|_| respond(200, &json!({ "unexpected": true })));
    assert_eq!(
        api.billing.get_usage("u1").await.unwrap_err().code(),
        ErrorCode::Api002
    );
}

// ── consumption ──

fn aggregate(key: &str, total: &str) -> Value {
    json!({ "key": key, "total": total, "updatedAt": "2026-11-18T00:00:00Z" })
}

#[tokio::test]
async fn a_report_posts_the_key_the_value_and_the_idempotency_key() {
    let (idp, api, _) = machine();
    idp.on_api(|_| respond(200, &json!({ "success": true, "metered": true, "aggregate": { "key": "audits", "total": "43" } })));

    let result = api
        .consumption
        .report("u/1", "audits", 1_i64, Some("  audit-42 "))
        .await
        .unwrap();

    assert!(result.metered);
    assert_eq!(result.aggregate.total, "43");
    let request = &idp.requests_to("/api/app/consumption/users/u%2F1")[0];
    assert_eq!(
        json_of(request),
        json!({ "key": "audits", "value": 1, "idempotencyKey": "audit-42" })
    );
    assert_eq!(bearer(request), "Bearer machine-1-consumption:write");

    api.consumption
        .report("u1", "tokens.in", 2.5_f64, None)
        .await
        .unwrap();
    assert_eq!(
        json_of(&idp.requests().last().unwrap().clone()),
        json!({ "key": "tokens.in", "value": 2.5 })
    );
    api.consumption
        .report("u1", "refund", -3_i32, None)
        .await
        .unwrap();
    assert_eq!(
        json_of(&idp.requests().last().unwrap().clone())["value"],
        -3
    );
}

#[tokio::test]
async fn an_invalid_report_is_cfg_001_and_sends_nothing() {
    let (idp, api, _) = machine();
    let long_key = "a".repeat(65);
    let long_idempotency = "k".repeat(201);
    let cases: Vec<(&str, &str, auth_ai::server::ConsumptionValue, Option<&str>)> = vec![
        ("", "audits", 1_i64.into(), None),
        ("u", "", 1_i64.into(), None),
        ("u", "bad key", 1_i64.into(), None),
        ("u", "bad-key", 1_i64.into(), None),
        ("u", "ünï", 1_i64.into(), None),
        ("u", &long_key, 1_i64.into(), None),
        ("u", "audits", f64::NAN.into(), None),
        ("u", "audits", f64::INFINITY.into(), None),
        ("u", "audits", 1_i64.into(), Some("   ")),
        ("u", "audits", 1_i64.into(), Some(&long_idempotency)),
    ];
    for (user, key, value, idempotency) in cases {
        let err = api
            .consumption
            .report(user, key, value, idempotency)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cfg001, "{user:?} {key:?}");
    }
    assert!(
        idp.requests().is_empty(),
        "nothing leaves the process for an invalid report"
    );
}

#[tokio::test]
async fn an_unsuccessful_report_is_api_002() {
    let (idp, api, _) = machine();
    idp.on_api(|_| {
        respond(
            200,
            &json!({ "success": false, "aggregate": { "key": "a", "total": "0" } }),
        )
    });
    assert_eq!(
        api.consumption
            .report("u", "a", 1_i64, None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Api002
    );
}

#[tokio::test]
async fn running_totals_are_listed_and_read_by_key() {
    let (idp, api, _) = machine();
    idp.on_api(|request| {
        if path_of(request).ends_with("/audits") {
            respond(200, &json!({ "aggregate": aggregate("audits", "7") }))
        } else {
            respond(200, &json!({ "aggregates": [aggregate("audits", "7"), aggregate("tokens", "9007199254740993")] }))
        }
    });
    let all = api.consumption.list_aggregates("u1").await.unwrap();
    assert_eq!(
        all[1].total, "9007199254740993",
        "totals stay decimal strings"
    );
    assert_eq!(
        api.consumption
            .get_aggregate("u1", "audits")
            .await
            .unwrap()
            .total,
        "7"
    );

    idp.on_api(|_| {
        respond(
            404,
            &json!({ "error": { "code": "CONS_003", "message": "never reported" } }),
        )
    });
    let err = api
        .consumption
        .get_aggregate("u1", "never")
        .await
        .unwrap_err();
    assert_eq!(err.to_json()["details"]["apiCode"], "CONS_003");
}

// ── resource sharing ──

fn request<'a>() -> AuthorizeRequest<'a> {
    AuthorizeRequest {
        subject_id: "user-1",
        client_id: "gateway",
        resource_uri: "llm://models/gpt",
        audience: "https://llm.test",
        request_id: None,
        source: None,
    }
}

fn allow_answer() -> Value {
    json!({
        "decision": "allow", "resourceId": RESOURCE, "resourceUri": "llm://models/gpt", "applicationSlug": "llm-app",
        "ownerType": "user", "ownerId": "owner-1", "accessKind": "grant", "extra": "ignored"
    })
}

#[tokio::test]
async fn an_allowed_user_gets_the_resource_and_why() {
    let (idp, api, _) = machine();
    idp.on_api(|_| respond(200, &allow_answer()));
    let mut asked = request();
    asked.request_id = Some("req-1");
    asked.source = Some(EventSource::Ssh);

    let decision = api.resources.authorize(&asked).await.unwrap();

    let allowed = decision.allowed().unwrap();
    assert_eq!(allowed.resource_id, RESOURCE);
    assert_eq!(
        (allowed.owner_type, allowed.access_kind),
        (OwnerType::User, AccessKind::Grant)
    );
    assert_eq!(allowed.application_slug, "llm-app");
    let sent = &idp.requests_to("/api/internal/gateway/authorize")[0];
    assert_eq!(
        json_of(sent),
        json!({
            "subjectId": "user-1", "clientId": "gateway", "resourceUri": "llm://models/gpt",
            "audience": "https://llm.test", "requestId": "req-1", "source": "ssh"
        })
    );
    assert_eq!(bearer(sent), "Bearer machine-1-resources:authorize");
}

#[tokio::test]
async fn optional_members_are_left_out_of_the_request() {
    let (idp, api, _) = machine();
    idp.on_api(|_| respond(200, &json!({ "decision": "deny" })));
    api.resources.authorize(&request()).await.unwrap();
    let body = json_of(&idp.requests_to("/api/internal/gateway/authorize")[0]);
    assert!(body.get("requestId").is_none() && body.get("source").is_none());
}

#[tokio::test]
async fn a_denial_carries_no_reason() {
    let (idp, api, _) = machine();
    idp.on_api(|_| respond(200, &json!({ "decision": "deny", "reason": "not_found" })));
    assert_eq!(
        api.resources.authorize(&request()).await.unwrap(),
        AuthorizeDecision::Denied
    );
}

#[tokio::test]
async fn anything_that_is_not_a_complete_allow_or_a_deny_can_never_read_as_an_admission() {
    let (idp, api, _) = machine();
    let mut incomplete = allow_answer();
    incomplete.as_object_mut().unwrap().remove("ownerId");
    let mut bad_kind = allow_answer();
    bad_kind["accessKind"] = json!("admin");
    for body in [
        json!({ "decision": "maybe" }),
        json!({ "decision": "ALLOW" }),
        json!({ "decision": true }),
        json!({}),
        json!({ "allowed": true }),
        json!("allow"),
        json!(null),
        incomplete,
        bad_kind,
    ] {
        idp.on_api(move |_| respond(200, &body));
        let err = api.resources.authorize(&request()).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::Api002);
    }
}

#[tokio::test]
async fn a_refusal_or_an_outage_is_an_error_never_an_admission() {
    let (idp, api, _) = machine();
    idp.on_api(|_| {
        respond(
            403,
            &json!({ "error": { "code": "AUTH_011", "message": "scope" } }),
        )
    });
    assert_eq!(
        api.resources
            .authorize(&request())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Api001
    );
    idp.go_offline();
    assert!(api.resources.authorize(&request()).await.is_err());
}

#[tokio::test]
async fn authorize_validates_its_input_before_any_request() {
    let (idp, api, _) = machine();
    let long = "x".repeat(257);
    let uri = "u".repeat(513);
    let audience = "a".repeat(2049);
    let bad: Vec<AuthorizeRequest<'_>> = vec![
        AuthorizeRequest {
            subject_id: "",
            ..request()
        },
        AuthorizeRequest {
            subject_id: &long,
            ..request()
        },
        AuthorizeRequest {
            client_id: "",
            ..request()
        },
        AuthorizeRequest {
            resource_uri: "ab",
            ..request()
        },
        AuthorizeRequest {
            resource_uri: &uri,
            ..request()
        },
        AuthorizeRequest {
            audience: "",
            ..request()
        },
        AuthorizeRequest {
            audience: &audience,
            ..request()
        },
        AuthorizeRequest {
            request_id: Some(""),
            ..request()
        },
        AuthorizeRequest {
            request_id: Some(&long),
            ..request()
        },
    ];
    for asked in bad {
        assert_eq!(
            api.resources.authorize(&asked).await.unwrap_err().code(),
            ErrorCode::Cfg001
        );
    }
    assert!(idp.requests().is_empty());
}

fn accessible() -> Value {
    json!({ "resources": [{
        "resourceId": RESOURCE, "resourceUri": "llm://models/gpt", "scheme": "llm", "displayName": "GPT",
        "applicationId": "app-1", "applicationSlug": "llm-app", "applicationName": "LLM", "ownerType": "application",
        "ownerId": "app-1", "accessKind": "grant", "grantSubjectType": "everyone"
    }, {
        "resourceId": RESOURCE, "resourceUri": "ssh://host", "scheme": "ssh", "displayName": "Host",
        "applicationId": "app-2", "applicationSlug": "ssh-app", "applicationName": "SSH", "ownerType": "user",
        "ownerId": "u", "accessKind": "owner"
    }] })
}

#[tokio::test]
async fn accessible_resources_are_listed_with_an_optional_scheme() {
    let (idp, api, _) = machine();
    idp.on_api(|_| respond(200, &accessible()));

    let listed = api
        .resources
        .list_accessible("user 1", Some("llm"))
        .await
        .unwrap();

    assert_eq!(listed.len(), 2);
    assert_eq!(
        listed[0].grant_subject_type,
        Some(auth_ai::server::GrantSubjectType::Everyone)
    );
    assert_eq!(listed[1].grant_subject_type, None);
    assert_eq!(listed[1].access_kind, AccessKind::Owner);
    let sent = &idp.requests_to("/api/internal/gateway/resources/accessible")[0];
    assert!(sent.url.ends_with("?subjectId=user+1&scheme=llm"));
    assert_eq!(bearer(sent), "Bearer machine-1-resources:authorize");

    api.resources.list_accessible("u", None).await.unwrap();
    assert!(idp.requests().last().unwrap().url.ends_with("?subjectId=u"));
}

#[tokio::test]
async fn an_invalid_accessible_query_is_cfg_001() {
    let (idp, api, _) = machine();
    for (subject, scheme) in [
        ("", None),
        ("u", Some("LLM")),
        ("u", Some("1llm")),
        ("u", Some("a-b")),
        ("u", Some("")),
    ] {
        assert_eq!(
            api.resources
                .list_accessible(subject, scheme)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::Cfg001
        );
    }
    assert!(idp.requests().is_empty());
}

fn state(status: &str) -> Value {
    json!({ "resource": { "id": RESOURCE, "uri": "ssh://host", "status": status, "validationError": null } })
}

#[tokio::test]
async fn a_validator_reports_the_outcome_of_the_ownership_check() {
    let (idp, api, _) = machine();
    idp.on_api(|_| respond(200, &state("validated")));
    let evidence: Map<String, Value> = json!({ "fingerprint": "SHA256:abc" })
        .as_object()
        .unwrap()
        .clone();

    let resource = api
        .resources
        .validate(
            RESOURCE,
            ValidationResult::Validated,
            Some("  checked  "),
            Some(&evidence),
        )
        .await
        .unwrap();

    assert_eq!(resource.status, ResourceStatus::Validated);
    assert_eq!(resource.validation_error, None);
    let sent = &idp.requests_to(&format!(
        "/api/internal/gateway/resources/{RESOURCE}/validate"
    ))[0];
    assert_eq!(
        json_of(sent),
        json!({ "result": "validated", "reason": "checked", "evidence": { "fingerprint": "SHA256:abc" } })
    );
    assert_eq!(bearer(sent), "Bearer machine-1-resources:validate");

    api.resources
        .validate(RESOURCE, ValidationResult::ValidationFailed, None, None)
        .await
        .unwrap();
    assert_eq!(
        json_of(idp.requests().last().unwrap()),
        json!({ "result": "validation_failed" })
    );
}

#[tokio::test]
async fn a_validator_can_invalidate_a_resource_whose_ownership_was_lost() {
    let (idp, api, _) = machine();
    idp.on_api(|_| respond(200, &state("disabled")));
    let resource = api
        .resources
        .invalidate(RESOURCE, "  host key changed ")
        .await
        .unwrap();
    assert_eq!(resource.status, ResourceStatus::Disabled);
    let sent = &idp.requests_to(&format!(
        "/api/internal/gateway/resources/{RESOURCE}/invalidate"
    ))[0];
    assert_eq!(json_of(sent), json!({ "reason": "host key changed" }));
    assert_eq!(bearer(sent), "Bearer machine-1-resources:validate");
}

#[tokio::test]
async fn validation_inputs_are_checked_before_any_request() {
    let (idp, api, _) = machine();
    let long = "x".repeat(501);
    for id in [
        "",
        "not-a-uuid",
        "0f9d6a3e-5c1b-4d52-9a47-2b8f3c6e1a9",
        "../../x",
        "0f9d6a3e5c1b4d529a472b8f3c6e1a90zzzz",
    ] {
        let err = api
            .resources
            .validate(id, ValidationResult::Validated, None, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cfg001, "{id:?}");
        assert_eq!(
            api.resources
                .invalidate(id, "reason")
                .await
                .unwrap_err()
                .code(),
            ErrorCode::Cfg001
        );
    }
    assert_eq!(
        api.resources
            .validate(RESOURCE, ValidationResult::Validated, Some(&long), None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Cfg001
    );
    for reason in ["", "   ", &long] {
        assert_eq!(
            api.resources
                .invalidate(RESOURCE, reason)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::Cfg001
        );
    }
    assert!(idp.requests().is_empty());
}

#[tokio::test]
async fn only_the_bound_client_may_validate_and_the_refusal_is_reported() {
    let (idp, api, _) = machine();
    idp.on_api(|_| {
        respond(
            403,
            &json!({ "error": { "code": "AUTH_011", "message": "Not your scheme" } }),
        )
    });
    let err = api
        .resources
        .validate(RESOURCE, ValidationResult::Validated, None, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Api001);
    assert_eq!(err.to_json()["details"]["apiCode"], "AUTH_011");
}
