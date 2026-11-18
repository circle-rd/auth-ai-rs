#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The wallet and the gateway on behalf of a signed-in user.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use auth_ai::{
    AiClient, AuthAiError, ErrorCode, GrantManager, MICRO_PER_EUR, MemoryGrantStore, SecretString,
    UserAi, WalletTransactionType, format_euros, is_insufficient_credit,
};
use serde_json::{Value, json};
use support::{GATEWAY_URL, ISSUER, MockIdp, auth_with, config, form_of, path_of, respond};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// A provider answering `access-for-<resource>` for each refresh.
async fn user_ai(gateway: bool) -> (Arc<MockIdp>, UserAi) {
    let idp = MockIdp::new();
    idp.on_token(|request| {
        let resource = form_of(request).get("resource").cloned().unwrap_or_default();
        respond(
            200,
            &json!({
                "access_token": format!("access-for-{resource}"), "token_type": "Bearer", "expires_in": 3600,
                "refresh_token": "refresh-next"
            }),
        )
    });
    let builder = if gateway {
        config().gateway_url(GATEWAY_URL)
    } else {
        config()
    };
    let auth = auth_with(&idp, builder);
    let grants = GrantManager::new(auth.clone(), MemoryGrantStore::new());
    grants
        .save("user-1", &SecretString::new("refresh-1"))
        .await
        .unwrap();
    (idp, AiClient::new(auth, grants).for_user("user-1").unwrap())
}

fn account(balance: &str) -> Value {
    json!({ "balance": balance, "isUnlimited": false, "canSpend": true, "currency": "eur" })
}

fn api_error(err: &AuthAiError) -> Option<&str> {
    err.detail("apiCode").and_then(auth_ai::DetailValue::as_str)
}

// ── wallet ──

#[tokio::test]
async fn the_wallet_is_read_with_a_token_minted_for_auth_service() {
    let (idp, ai) = user_ai(false).await;
    idp.on_api(|_| respond(200, &account("12345678901234567")));

    let wallet = ai.wallet.get_account().await.unwrap();

    assert_eq!(
        wallet.balance, 12_345_678_901_234_567,
        "amounts stay exact beyond a double's 2^53"
    );
    assert!(wallet.can_spend && !wallet.is_unlimited);
    let request = &idp.requests_to("/api/user/wallet")[0];
    assert_eq!(
        request.header("authorization"),
        Some("Bearer access-for-https://idp.test")
    );
    assert_eq!(form_of(&idp.requests_to("/token")[0])["resource"], ISSUER);
}

#[tokio::test]
async fn statistics_and_session_usage_carry_their_query() {
    let (idp, ai) = user_ai(false).await;
    let by_model = json!({ "model": "m", "amount": "5", "count": 1, "promptTokens": 1, "completionTokens": 2, "totalTokens": 3 });
    let by_app =
        json!({ "applicationId": null, "name": null, "slug": "app", "amount": "5", "count": 1 });
    idp.on_api(move |request| match path_of(request).as_str() {
        "/api/user/wallet/stats" => respond(
            200,
            &json!({
                "days": 7, "total": "5", "notBilled": "0", "calls": 1,
                "series": [{ "date": "2026-11-01", "amount": "5", "count": 1 }],
                "byApplication": [by_app], "byKind": [{ "kind": "llm", "amount": "5", "count": 1 }],
                "byModel": [by_model], "daily": []
            }),
        ),
        _ => respond(
            200,
            &json!({ "sessionId": "s-1", "applicationSlug": "app", "days": 30, "total": "5", "notBilled": "0", "calls": 1, "byModel": [by_model] }),
        ),
    });

    let stats = ai.wallet.get_stats(Some(7)).await.unwrap();
    assert_eq!(stats.total, 5);
    assert_eq!(stats.by_model[0].total_tokens, 3);
    assert!(
        idp.requests_to("/api/user/wallet/stats")[0]
            .url
            .ends_with("?days=7")
    );

    ai.wallet.get_stats(None).await.unwrap();
    assert!(
        idp.requests_to("/api/user/wallet/stats")[1]
            .url
            .ends_with("/stats"),
        "an absent option is not sent"
    );

    let usage = ai.wallet.get_session_usage("s 1", Some(3)).await.unwrap();
    assert_eq!(usage.session_id, "s-1");
    assert!(
        idp.requests_to("/api/user/wallet/usage")[0]
            .url
            .ends_with("?sessionId=s+1&days=3")
    );
}

#[tokio::test]
async fn transactions_are_keyset_paginated_and_filterable() {
    let (idp, ai) = user_ai(false).await;
    idp.on_api(|_| {
        respond(
            200,
            &json!({
                "items": [{
                    "id": "t1", "type": "usage", "amount": "10", "delta": "-10", "balanceAfter": "90",
                    "applicationId": null, "metadata": { "model": "m" }, "createdAt": "2026-11-18T10:00:00.000Z"
                }],
                "nextCursor": "c2"
            }),
        )
    });

    let page = ai
        .wallet
        .list_transactions(Some(10), Some("c1"), Some(WalletTransactionType::Usage))
        .await
        .unwrap();

    assert_eq!(page.next_cursor.as_deref(), Some("c2"));
    let entry = &page.items[0];
    assert_eq!(
        (entry.amount, entry.delta, entry.balance_after),
        (10, -10, 90)
    );
    assert_eq!(entry.kind, WalletTransactionType::Usage);
    assert_eq!(entry.metadata["model"], "m");
    let recorded = OffsetDateTime::parse("2026-11-18T10:00:00Z", &Rfc3339).unwrap();
    assert_eq!(entry.created_at, recorded);
    assert!(
        idp.requests_to("/api/user/wallet/transactions")[0]
            .url
            .ends_with("?limit=10&cursor=c1&type=usage")
    );
}

#[tokio::test]
async fn top_up_options_and_the_top_up_link() {
    let (idp, ai) = user_ai(false).await;
    idp.on_api(|_| {
        respond(
            200,
            &json!({ "enabled": true, "currency": "eur", "minCents": 500, "maxCents": 50000 }),
        )
    });
    let options = ai.wallet.get_topup_options().await.unwrap();
    assert!(options.enabled);
    assert_eq!((options.min_cents, options.max_cents), (500, 50_000));
    assert_eq!(ai.wallet.topup_url(), "https://idp.test/profile");
}

#[tokio::test]
async fn a_refused_token_is_replaced_and_the_call_retried_once() {
    let (idp, ai) = user_ai(false).await;
    let calls = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&calls);
    idp.on_api(move |_| {
        if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            respond(
                401,
                &json!({ "error": { "code": "AUTH_001", "message": "expired" } }),
            )
        } else {
            respond(200, &account("1"))
        }
    });
    assert_eq!(ai.wallet.get_account().await.unwrap().balance, 1);
    assert_eq!(
        idp.requests_to("/token").len(),
        2,
        "the cached token was dropped and a new one minted"
    );
}

#[tokio::test]
async fn a_second_refusal_is_reported_not_retried_again() {
    let (idp, ai) = user_ai(false).await;
    idp.on_api(|_| {
        respond(
            401,
            &json!({ "error": { "code": "AUTH_001", "message": "nope" } }),
        )
    });
    let err = ai.wallet.get_account().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Api001);
    assert_eq!(idp.requests_to("/api/user/wallet").len(), 2);
}

#[tokio::test]
async fn api_errors_keep_status_and_code_in_the_details_only() {
    let (idp, ai) = user_ai(false).await;
    idp.on_api(|_| {
        respond(
            403,
            &json!({ "error": { "code": "WAL_002", "message": "Wallet frozen" } }),
        )
    });
    let err = ai.wallet.get_account().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Api001);
    assert_eq!(api_error(&err), Some("WAL_002"));
    assert_eq!(err.to_json()["details"]["status"], 403);
    assert!(err.message().contains("Wallet frozen"));
    assert!(!err.to_public_json().to_string().contains("frozen"));

    idp.on_api(|_| respond(500, &json!("plain")));
    let plain = ai.wallet.get_account().await.unwrap_err();
    assert_eq!(plain.message(), "auth-service answered 500");
}

#[tokio::test]
async fn unexpected_answers_are_api_002() {
    let (idp, ai) = user_ai(false).await;
    for body in [
        json!({ "balance": 5, "isUnlimited": false, "canSpend": true, "currency": "eur" }),
        json!({}),
        json!([]),
        account("1.5"),
    ] {
        idp.on_api(move |_| respond(200, &body));
        assert_eq!(
            ai.wallet.get_account().await.unwrap_err().code(),
            ErrorCode::Api002
        );
    }
    idp.on_api(|_| {
        let mut response = respond(200, &json!({}));
        response.body = b"<html>".to_vec();
        response
    });
    assert_eq!(
        ai.wallet.get_account().await.unwrap_err().code(),
        ErrorCode::Api002
    );
}

#[tokio::test]
async fn an_unreachable_auth_service_is_api_001() {
    let (idp, ai) = user_ai(false).await;
    ai.wallet.get_account().await.unwrap_err();
    idp.go_offline();
    assert_eq!(
        ai.wallet.get_account().await.unwrap_err().code(),
        ErrorCode::Api001
    );
}

#[tokio::test]
async fn a_user_without_a_grant_cannot_read_the_wallet() {
    let (idp, ai) = user_ai(false).await;
    let stranger = AiClient::new(
        auth_with(&idp, config()),
        GrantManager::new(auth_with(&idp, config()), MemoryGrantStore::new()),
    )
    .for_user("stranger")
    .unwrap();
    assert_eq!(
        stranger.wallet.get_account().await.unwrap_err().code(),
        ErrorCode::Tok002
    );
    drop(ai);
}

#[test]
fn euros_format_from_micro_euros() {
    assert_eq!(format_euros(5 * MICRO_PER_EUR, 2).unwrap(), "5.00");
}

// ── gateway ──

#[tokio::test]
async fn the_gateway_needs_a_gateway_url() {
    let (_idp, ai) = user_ai(false).await;
    assert_eq!(ai.gateway().unwrap_err().code(), ErrorCode::Cfg001);
}

#[tokio::test]
async fn models_are_listed_with_a_token_minted_for_the_gateway_audience() {
    let (idp, ai) = user_ai(true).await;
    idp.on_gateway(|_| {
        respond(200, &json!({ "data": [{ "id": "gpt", "object": "model", "owned_by": "me", "max_tokens": 9 }, { "id": "other" }] }))
    });
    let gateway = ai.gateway().unwrap();

    let models = gateway.list_models().await.unwrap();

    assert_eq!(
        models.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
        ["gpt", "other"]
    );
    assert_eq!(
        models[0].extra["max_tokens"], 9,
        "members LiteLLM adds are kept"
    );
    let request = &idp.gateway_requests()[0];
    assert_eq!(request.url, "https://llm.test/v1/models");
    assert_eq!(
        request.header("authorization"),
        Some("Bearer access-for-https://llm.test")
    );
    assert_eq!(gateway.openai_base_url(), "https://llm.test/v1");
}

#[tokio::test]
async fn the_gateway_token_is_cached_until_the_gateway_refuses_it() {
    let (idp, ai) = user_ai(true).await;
    let calls = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&calls);
    idp.on_gateway(move |_| {
        if counter.fetch_add(1, Ordering::SeqCst) == 1 {
            respond(401, &json!({ "error": { "message": "expired" } }))
        } else {
            respond(200, &json!({ "data": [] }))
        }
    });
    let gateway = ai.gateway().unwrap();
    gateway.list_models().await.unwrap();
    gateway.list_models().await.unwrap_err();
    gateway.list_models().await.unwrap();
    assert_eq!(
        idp.requests_to("/token").len(),
        2,
        "a 401 drops the token: the next call mints a new one"
    );
}

#[tokio::test]
async fn gateway_refusals_map_to_the_registry() {
    let (idp, ai) = user_ai(true).await;
    let gateway = ai.gateway().unwrap();
    let cases = [
        (402, ErrorCode::Gw001, "Insufficient credit"),
        (429, ErrorCode::Gw002, "slow down"),
        (403, ErrorCode::Gw003, "denied"),
        (503, ErrorCode::Gw004, "down"),
        (500, ErrorCode::Gw005, "boom"),
    ];
    for (status, code, message) in cases {
        idp.on_gateway(move |_| {
            let mut response = respond(
                status,
                &json!({ "error": { "type": "x", "message": message } }),
            );
            response
                .headers
                .push(("retry-after".to_owned(), "7".to_owned()));
            response
        });
        let err = gateway
            .post_json("/v1/chat/completions", &json!({ "model": "m" }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), code, "{status}");
        assert_eq!(err.message(), message);
        if status == 429 {
            assert_eq!(err.to_json()["details"]["retryAfterSeconds"], 7.0);
        }
    }
    idp.on_gateway(|_| respond(402, &json!({})));
    assert!(is_insufficient_credit(
        &gateway.list_models().await.unwrap_err()
    ));
}

#[tokio::test]
async fn an_unreachable_gateway_is_gw_004() {
    let (idp, ai) = user_ai(true).await;
    let gateway = ai.gateway().unwrap();
    gateway.access_token().await.unwrap();
    idp.go_offline();
    assert_eq!(
        gateway.list_models().await.unwrap_err().code(),
        ErrorCode::Gw004
    );
}

#[tokio::test]
async fn a_malformed_listing_is_gw_005() {
    let (idp, ai) = user_ai(true).await;
    let gateway = ai.gateway().unwrap();
    for body in [json!({ "data": [{ "no_id": 1 }] }), json!({}), json!([1])] {
        idp.on_gateway(move |_| respond(200, &body));
        assert_eq!(
            gateway.list_models().await.unwrap_err().code(),
            ErrorCode::Gw005
        );
    }
    idp.on_gateway(|_| {
        let mut response = respond(200, &json!({}));
        response.body = b"not json".to_vec();
        response
    });
    assert_eq!(
        gateway
            .post_json("/v1/embeddings", &json!({}))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Gw005
    );
}

#[tokio::test]
async fn agents_and_mcp_servers_are_listed() {
    let (idp, ai) = user_ai(true).await;
    idp.on_gateway(|request| {
        if request.url.ends_with("/v1/agents") {
            respond(200, &json!([{ "agent_id": "a1", "agent_name": "Helper" }]))
        } else {
            respond(
                200,
                &json!([{ "server_id": "s1", "server_name": "files", "transport": "http" }]),
            )
        }
    });
    let gateway = ai.gateway().unwrap();
    assert_eq!(gateway.list_agents().await.unwrap()[0].agent_name, "Helper");
    let servers = gateway.list_mcp_servers().await.unwrap();
    assert_eq!(servers[0].server_name.as_deref(), Some("files"));
    assert!(idp.gateway_requests()[1].url.ends_with("/v1/mcp/server"));
}

#[tokio::test]
async fn post_json_sends_the_body_and_returns_the_answer() {
    let (idp, ai) = user_ai(true).await;
    idp.on_gateway(|request| respond(200, &json!({ "echo": support::json_of(request) })));
    let answer = ai
        .gateway()
        .unwrap()
        .post_json("/v1/chat/completions", &json!({ "model": "m" }))
        .await
        .unwrap();
    assert_eq!(answer["echo"]["model"], "m");
    assert_eq!(
        idp.gateway_requests()[0].header("content-type"),
        Some("application/json")
    );
}

#[tokio::test]
async fn the_token_never_leaves_the_gateway_origin() {
    let (idp, ai) = user_ai(true).await;
    let gateway = ai.gateway().unwrap();
    for path in [
        "@evil.test/x",
        "evil.test",
        "",
        "http://evil.test/",
        "\\\\evil.test",
        ".evil.test/x",
    ] {
        let err = gateway.post_json(path, &json!({})).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cfg001, "{path:?}");
    }
    assert!(idp.gateway_requests().is_empty());
    assert!(
        idp.requests_to("/token").is_empty(),
        "no token is even minted for a request that cannot be sent"
    );
}

#[tokio::test]
async fn mcp_urls_validate_the_server_name() {
    let (_idp, ai) = user_ai(true).await;
    let gateway = ai.gateway().unwrap();
    assert_eq!(gateway.mcp_url(None).unwrap(), "https://llm.test/mcp");
    assert_eq!(
        gateway.mcp_url(Some("files-1.v2_x")).unwrap(),
        "https://llm.test/files-1.v2_x/mcp"
    );
    for bad in [
        "",
        "v1",
        "V1",
        "-x",
        "a/b",
        "a b",
        "a?b",
        "../x",
        "é",
        &"a".repeat(129),
    ] {
        assert_eq!(
            gateway.mcp_url(Some(bad)).unwrap_err().code(),
            ErrorCode::Cfg001,
            "{bad:?}"
        );
    }
    assert!(gateway.mcp_url(Some(&"a".repeat(128))).is_ok());
}

#[tokio::test]
async fn invalidate_token_lets_a_self_signing_client_recover_from_a_401() {
    let (idp, ai) = user_ai(true).await;
    let gateway = ai.gateway().unwrap();
    gateway.access_token().await.unwrap();
    gateway.access_token().await.unwrap();
    assert_eq!(idp.requests_to("/token").len(), 1);
    gateway.invalidate_token();
    gateway.access_token().await.unwrap();
    assert_eq!(idp.requests_to("/token").len(), 2);
}
