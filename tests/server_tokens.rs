#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Bearer verification, protected-resource metadata and back-channel logout.

mod support;

use std::sync::{Arc, Mutex};

use auth_ai::server::{
    BackchannelLogoutEvent, BackchannelLogoutHandler, BearerError, BearerVerifier, LOGOUT_EVENT,
    MAX_BODY_BYTES, MemoryReplayStore, ReplayStore, bearer_challenge, protected_resource_metadata,
    require_scopes, verify_logout_token,
};
use auth_ai::{AuthAiError, ErrorCallback, ErrorCode, WebRequest};
use serde_json::{Value, json};
use support::{CLIENT_ID, ISSUER, MockIdp, merge, now, test_auth};

const API: &str = "https://api.test";

fn api_token(idp: &Arc<MockIdp>, extra: &Value) -> String {
    let mut claims = json!({
        "iss": ISSUER, "sub": "user-1", "aud": [API, "https://other.test"], "azp": "client-1",
        "scope": "reports.read reports.write", "iat": now(), "exp": now() + 300
    });
    merge(&mut claims, extra);
    idp.sign_jwt(&claims)
}

fn verifier(idp: &Arc<MockIdp>) -> BearerVerifier {
    BearerVerifier::new(test_auth(idp), API).unwrap()
}

// ── bearer ──

#[tokio::test]
async fn a_user_token_yields_the_user_the_client_and_the_scopes() {
    let idp = MockIdp::new();
    let verified = verifier(&idp)
        .verify(&api_token(&idp, &json!({})))
        .await
        .unwrap();

    assert_eq!(verified.user_id.as_deref(), Some("user-1"));
    assert_eq!(verified.client_id, "client-1");
    assert_eq!(verified.scopes, ["reports.read", "reports.write"]);
    assert_eq!(verified.audiences, [API, "https://other.test"]);
    assert_eq!(verified.claims.iss, ISSUER);
}

#[tokio::test]
async fn a_client_credentials_token_has_no_user() {
    let idp = MockIdp::new();
    let token = api_token(&idp, &json!({ "sub": "client-1", "aud": API }));
    let verified = verifier(&idp).verify(&token).await.unwrap();
    assert_eq!(verified.user_id, None);
    assert_eq!(verified.audiences, [API]);
}

#[tokio::test]
async fn a_token_without_scope_has_no_scopes() {
    let idp = MockIdp::new();
    let mut claims = json!({ "iss": ISSUER, "sub": "u", "aud": API, "azp": "c", "iat": now(), "exp": now() + 60 });
    claims.as_object_mut().unwrap().remove("scope");
    let verified = verifier(&idp).verify(&idp.sign_jwt(&claims)).await.unwrap();
    assert!(verified.scopes.is_empty());
}

#[tokio::test]
async fn tokens_that_are_not_for_this_api_are_refused() {
    let idp = MockIdp::new();
    let bearer = verifier(&idp);
    let cases = [
        api_token(&idp, &json!({ "aud": "https://elsewhere.test" })),
        api_token(&idp, &json!({ "exp": now() - 3600 })),
        api_token(&idp, &json!({ "iss": "https://evil.test" })),
        "opaque-access-token".to_owned(),
        "a.b".to_owned(),
        String::new(),
    ];
    for token in cases {
        assert_eq!(
            bearer.verify(&token).await.unwrap_err().code(),
            ErrorCode::Tok001,
            "{token}"
        );
    }
    let mut claims =
        json!({ "iss": ISSUER, "sub": "u", "aud": API, "iat": now(), "exp": now() + 60 });
    claims.as_object_mut().unwrap().remove("azp");
    let err = bearer.verify(&idp.sign_jwt(&claims)).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Tok001);
    assert!(err.message().contains("not bound to a client"));
}

#[tokio::test]
async fn the_authorization_header_is_parsed_before_verification() {
    let idp = MockIdp::new();
    let bearer = verifier(&idp);
    let token = api_token(&idp, &json!({}));
    assert!(
        bearer
            .verify_header(Some(&format!("Bearer {token}")))
            .await
            .is_ok()
    );
    for header in [None, Some("Basic abc"), Some("Bearer"), Some("Bearer a b")] {
        assert_eq!(
            bearer.verify_header(header).await.unwrap_err().code(),
            ErrorCode::Tok003,
            "{header:?}"
        );
    }
}

#[tokio::test]
async fn the_audience_must_be_the_url_of_this_api() {
    let idp = MockIdp::new();
    for audience in ["", "api", "/path", "urn:x"] {
        assert_eq!(
            BearerVerifier::new(test_auth(&idp), audience)
                .unwrap_err()
                .code(),
            ErrorCode::Cfg001,
            "{audience}"
        );
    }
}

#[tokio::test]
async fn missing_scopes_are_named_in_the_error() {
    let idp = MockIdp::new();
    let verified = verifier(&idp)
        .verify(&api_token(&idp, &json!({})))
        .await
        .unwrap();
    assert!(require_scopes(&verified, &["reports.read"]).is_ok());
    assert!(require_scopes(&verified, &[]).is_ok());
    let err = require_scopes(&verified, &["reports.read", "admin", "billing"]).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Tok004);
    assert_eq!(err.to_json()["details"]["missing"], "admin billing");
    assert!(!err.to_public_json().to_string().contains("admin"));
}

// ── protected-resource metadata ──

#[test]
fn metadata_advertises_the_authorization_server() {
    let idp = MockIdp::new();
    let auth = test_auth(&idp);
    assert_eq!(
        protected_resource_metadata(&auth, API, None),
        json!({ "resource": API, "authorization_servers": [ISSUER], "bearer_methods_supported": ["header"] })
    );
    let scoped = protected_resource_metadata(&auth, API, Some(&["a", "b"]));
    assert_eq!(scoped["scopes_supported"], json!(["a", "b"]));
    assert!(
        bearer_challenge("https://api.test/m", Some(BearerError::InvalidToken), None)
            .unwrap()
            .contains("invalid_token")
    );
}

// ── back-channel logout ──

struct Harness {
    idp: Arc<MockIdp>,
    handler: BackchannelLogoutHandler,
    events: Arc<Mutex<Vec<BackchannelLogoutEvent>>>,
    errors: Arc<Mutex<Vec<ErrorCode>>>,
}

fn harness(allow_missing_typ: bool, fail_callback: bool) -> Harness {
    let idp = MockIdp::new();
    let events = Arc::new(Mutex::new(Vec::new()));
    let errors = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    let error_sink = Arc::clone(&errors);
    let on_error: ErrorCallback =
        Arc::new(move |err: &AuthAiError| error_sink.lock().unwrap().push(err.code()));
    let handler = BackchannelLogoutHandler::new(
        test_auth(&idp),
        Arc::new(move |event| {
            let sink = Arc::clone(&sink);
            Box::pin(async move {
                if fail_callback {
                    return Err(ErrorCode::Srv001.error());
                }
                sink.lock().unwrap().push(event);
                Ok(())
            })
        }),
    )
    .allow_missing_typ(allow_missing_typ)
    .on_error(on_error);
    Harness {
        idp,
        handler,
        events,
        errors,
    }
}

fn logout_claims(extra: &Value) -> Value {
    let mut claims = json!({
        "iss": ISSUER, "aud": CLIENT_ID, "sub": "user-1", "sid": "sid-1", "jti": format!("jti-{}", rand_suffix()),
        "iat": now(), "exp": now() + 120, "events": { LOGOUT_EVENT: {} }
    });
    merge(&mut claims, extra);
    claims
}

fn rand_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::SeqCst)
}

fn post(token: &str) -> WebRequest {
    WebRequest::new("POST", "https://app.test/auth/backchannel-logout")
        .with_header("content-type", "application/x-www-form-urlencoded")
        .with_body(format!("logout_token={token}"))
}

fn logout_jwt(h: &Harness, claims: &Value) -> String {
    h.idp
        .signer()
        .sign(claims, Some("key-1"), Some("logout+jwt"), false)
}

#[tokio::test]
async fn a_valid_logout_token_ends_the_session_and_answers_200() {
    let h = harness(false, false);
    let response = h
        .handler
        .handle(&post(&logout_jwt(&h, &logout_claims(&json!({})))))
        .await;

    assert_eq!(response.status, 200);
    assert_eq!(response.header("cache-control"), Some("no-store"));
    assert_eq!(
        *h.events.lock().unwrap(),
        [BackchannelLogoutEvent {
            sid: "sid-1".into(),
            sub: "user-1".into()
        }]
    );
    assert!(h.errors.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_replayed_logout_token_is_refused() {
    let h = harness(false, false);
    let request = post(&logout_jwt(&h, &logout_claims(&json!({ "jti": "once" }))));
    assert_eq!(h.handler.handle(&request).await.status, 200);
    let replay = h.handler.handle(&request).await;
    assert_eq!(replay.status, 400);
    assert_eq!(
        replay.json().unwrap(),
        json!({ "error": "invalid_request" })
    );
    assert_eq!(
        h.events.lock().unwrap().len(),
        1,
        "the session must not be ended twice"
    );
    assert_eq!(*h.errors.lock().unwrap(), [ErrorCode::Tok001]);
}

#[tokio::test]
async fn tokens_that_are_not_logout_tokens_are_refused_without_detail() {
    let cases = [
        ("without the event", logout_claims(&json!({ "events": {} }))),
        (
            "with another event",
            logout_claims(&json!({ "events": { "other": {} } })),
        ),
        ("with a nonce", logout_claims(&json!({ "nonce": "n" }))),
        ("without jti", logout_claims(&json!({ "jti": "" }))),
        ("without sid", logout_claims(&json!({ "sid": "" }))),
        ("with a numeric sid", logout_claims(&json!({ "sid": 5 }))),
        ("without sub", logout_claims(&json!({ "sub": null }))),
        ("with a string iat", logout_claims(&json!({ "iat": "now" }))),
        (
            "for another audience",
            logout_claims(&json!({ "aud": "another-app" })),
        ),
        (
            "from the future",
            logout_claims(&json!({ "iat": now() + 3600, "exp": now() + 3700 })),
        ),
        (
            "living too long",
            logout_claims(&json!({ "exp": now() + 86_400 })),
        ),
        (
            "expired",
            logout_claims(&json!({ "iat": now() - 7200, "exp": now() - 3600 })),
        ),
    ];
    for (label, claims) in cases {
        let h = harness(false, false);
        let response = h.handler.handle(&post(&logout_jwt(&h, &claims))).await;
        assert_eq!(response.status, 400, "{label}");
        assert_eq!(
            response.json().unwrap(),
            json!({ "error": "invalid_request" }),
            "{label}"
        );
        assert!(h.events.lock().unwrap().is_empty(), "{label}");
        assert_eq!(h.errors.lock().unwrap().len(), 1, "{label}");
    }
}

#[tokio::test]
async fn the_typ_header_is_enforced_unless_a_non_conforming_provider_is_allowed() {
    let strict = harness(false, false);
    let claims = logout_claims(&json!({}));
    for typ in [None, Some("JWT")] {
        let token = strict
            .idp
            .signer()
            .sign(&claims, Some("key-1"), typ, typ.is_none());
        assert_eq!(
            strict.handler.handle(&post(&token)).await.status,
            400,
            "{typ:?}"
        );
    }
    let accepted = strict.idp.signer().sign(
        &logout_claims(&json!({})),
        Some("key-1"),
        Some("application/logout+jwt"),
        false,
    );
    assert_eq!(strict.handler.handle(&post(&accepted)).await.status, 200);

    let lenient = harness(true, false);
    let missing = lenient
        .idp
        .signer()
        .sign(&logout_claims(&json!({})), Some("key-1"), None, true);
    assert_eq!(lenient.handler.handle(&post(&missing)).await.status, 200);
    let wrong = lenient.idp.signer().sign(
        &logout_claims(&json!({})),
        Some("key-1"),
        Some("JWT"),
        false,
    );
    assert_eq!(
        lenient.handler.handle(&post(&wrong)).await.status,
        400,
        "a present but wrong typ is still refused"
    );
}

#[tokio::test]
async fn a_forged_logout_token_is_refused() {
    let h = harness(false, false);
    let forger = support::Signer::generate("key-1");
    let forged = forger.sign(
        &logout_claims(&json!({})),
        Some("key-1"),
        Some("logout+jwt"),
        false,
    );
    assert_eq!(h.handler.handle(&post(&forged)).await.status, 400);
    assert_eq!(h.handler.handle(&post("not-a-jwt")).await.status, 400);
    assert!(h.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_failing_callback_answers_500_and_is_reported() {
    let h = harness(false, true);
    let response = h
        .handler
        .handle(&post(&logout_jwt(&h, &logout_claims(&json!({})))))
        .await;
    assert_eq!(response.status, 500);
    assert_eq!(response.json().unwrap(), json!({ "error": "server_error" }));
    assert_eq!(*h.errors.lock().unwrap(), [ErrorCode::Srv001]);
}

#[tokio::test]
async fn only_form_posts_of_a_sane_size_are_read() {
    let h = harness(false, false);
    let token = logout_jwt(&h, &logout_claims(&json!({})));

    let get = h
        .handler
        .handle(&WebRequest::new(
            "GET",
            "https://app.test/auth/backchannel-logout",
        ))
        .await;
    assert_eq!(get.status, 405);
    assert_eq!(get.header("allow"), Some("POST"));

    let json_body = WebRequest::new("POST", "https://app.test/x")
        .with_header("content-type", "application/json")
        .with_body(format!("logout_token={token}"));
    assert_eq!(h.handler.handle(&json_body).await.status, 400);
    let no_type =
        WebRequest::new("POST", "https://app.test/x").with_body(format!("logout_token={token}"));
    assert_eq!(h.handler.handle(&no_type).await.status, 400);
    assert_eq!(h.handler.handle(&post("")).await.status, 400);
    let other_field = post(&token).with_body(format!("token={token}"));
    assert_eq!(h.handler.handle(&other_field).await.status, 400);

    let oversized = post(&token).with_body(vec![b'a'; MAX_BODY_BYTES + 1]);
    assert_eq!(h.handler.handle(&oversized).await.status, 400);
    let declared = post(&token).with_header("content-length", (MAX_BODY_BYTES + 1).to_string());
    assert_eq!(h.handler.handle(&declared).await.status, 400);
    assert!(h.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn verify_logout_token_returns_the_claims_and_uses_the_given_replay_store() {
    let h = harness(false, false);
    let auth = test_auth(&h.idp);
    let store = MemoryReplayStore::new();
    let token = logout_jwt(&h, &logout_claims(&json!({ "jti": "j-1" })));

    let claims = verify_logout_token(&auth, &token, &store, false)
        .await
        .unwrap();
    assert_eq!(
        (
            claims.sid.as_str(),
            claims.sub.as_str(),
            claims.jti.as_str()
        ),
        ("sid-1", "user-1", "j-1")
    );
    assert_eq!(
        verify_logout_token(&auth, &token, &store, false)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Tok001
    );
    assert!(
        !store.claim("j-1", now() as f64 + 60.0).await.unwrap(),
        "the jti stays claimed until it expires"
    );
    assert!(store.claim("j-2", now() as f64 + 60.0).await.unwrap());
}

#[tokio::test]
async fn expired_jti_entries_are_forgotten() {
    let store = MemoryReplayStore::new();
    assert!(store.claim("j", now() as f64 - 1.0).await.unwrap());
    assert!(
        store.claim("j", now() as f64 + 60.0).await.unwrap(),
        "an expired entry no longer blocks the id"
    );
}
