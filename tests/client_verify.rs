#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The OIDC relying party: ID token verification, key rotation, UserInfo, logout.

mod support;

use std::sync::Arc;

use auth_ai::{AuthAiError, ErrorCode, TokenTypeHint};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use support::*;

// ── ID token verification ──

async fn id_token_error(idp: &Arc<MockIdp>, token: String) -> AuthAiError {
    let auth = client(idp);
    let handshake = auth.start_login(None, None).await.unwrap().handshake;
    idp.on_token(move |_| token_response(&json!({ "id_token": token })));
    auth.handle_callback(&callback_url(&handshake, ""), &handshake)
        .await
        .unwrap_err()
}

#[tokio::test]
async fn an_id_token_with_another_nonce_is_refused() {
    let idp = MockIdp::new();
    let token = idp.id_token(json!({ "nonce": "someone-elses", "sid": "s" }));
    let err = id_token_error(&idp, token).await;
    assert_eq!(err.code(), ErrorCode::Tok001);
    assert_eq!(detail(&err, "reason"), Some("nonce_mismatch"));
}

#[tokio::test]
async fn an_id_token_without_a_nonce_is_refused() {
    let idp = MockIdp::new();
    let err = id_token_error(&idp, idp.id_token(json!({}))).await;
    assert_eq!(detail(&err, "reason"), Some("missing_nonce"));
}

#[tokio::test]
async fn an_id_token_signed_by_a_foreign_key_is_refused() {
    let idp = MockIdp::new();
    let foreign = Signer::generate("key-1");
    let claims = json!({ "iss": ISSUER, "sub": "u", "aud": CLIENT_ID, "iat": now(), "exp": now() + 300, "nonce": "n" });
    let err = id_token_error(&idp, foreign.sign(&claims, Some("key-1"), None, false)).await;
    assert_eq!(err.code(), ErrorCode::Tok001);
    assert_eq!(detail(&err, "reason"), Some("invalid_signature"));
}

#[tokio::test]
async fn expired_wrong_audience_and_wrong_issuer_tokens_are_refused() {
    let idp = MockIdp::new();
    let base =
        json!({ "iss": ISSUER, "sub": "u", "aud": CLIENT_ID, "iat": now(), "exp": now() + 300 });
    let cases = [
        ("expired_token", json!({ "exp": now() - 3600 })),
        ("invalid_audience", json!({ "aud": "another-app" })),
        ("invalid_issuer", json!({ "iss": "https://evil.test" })),
    ];
    for (reason, change) in cases {
        let mut claims = base.clone();
        merge(&mut claims, &change);
        let err = id_token_error(&idp, idp.sign_jwt(&claims)).await;
        assert_eq!(err.code(), ErrorCode::Tok001, "{reason}");
        assert_eq!(detail(&err, "reason"), Some(reason));
    }
}

#[tokio::test]
async fn tokens_missing_required_claims_are_refused() {
    let idp = MockIdp::new();
    for missing in ["exp", "iss", "sub", "aud"] {
        let mut claims = json!({ "iss": ISSUER, "sub": "u", "aud": CLIENT_ID, "iat": now(), "exp": now() + 300 });
        claims.as_object_mut().unwrap().remove(missing);
        let err = id_token_error(&idp, idp.sign_jwt(&claims)).await;
        assert_eq!(err.code(), ErrorCode::Tok001, "{missing}");
    }
}

#[tokio::test]
async fn a_hmac_token_keyed_with_the_public_material_is_refused() {
    let idp = MockIdp::new();
    let claims = json!({ "iss": ISSUER, "sub": "u", "aud": CLIENT_ID, "iat": now(), "exp": now() + 300, "nonce": "n" });
    let jwk = idp.signer().jwk().to_string();
    for secret in [jwk.as_bytes(), b"anything".as_slice()] {
        let err = id_token_error(&idp, hs256_token(&claims, secret)).await;
        assert_eq!(err.code(), ErrorCode::Tok001);
        assert_eq!(detail(&err, "reason"), Some("invalid_algorithm"));
    }
}

#[tokio::test]
async fn an_unsigned_token_is_refused() {
    let idp = MockIdp::new();
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","kid":"key-1"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        json!({ "iss": ISSUER, "sub": "u", "aud": CLIENT_ID, "iat": now(), "exp": now() + 300 })
            .to_string(),
    );
    let err = id_token_error(&idp, format!("{header}.{payload}.")).await;
    assert_eq!(err.code(), ErrorCode::Tok001);
}

#[tokio::test]
async fn a_multi_audience_id_token_needs_this_client_as_authorized_party() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    let handshake = auth.start_login(None, None).await.unwrap().handshake;
    let nonce = handshake.nonce.expose_secret().to_owned();

    let without_azp =
        idp.id_token(json!({ "aud": [CLIENT_ID, "https://llm.test"], "nonce": nonce }));
    idp.on_token(move |_| token_response(&json!({ "id_token": without_azp })));
    let err = auth
        .handle_callback(&callback_url(&handshake, ""), &handshake)
        .await
        .unwrap_err();
    assert_eq!(detail(&err, "reason"), Some("missing_azp"));

    let other = idp.id_token(json!({ "aud": [CLIENT_ID, "x"], "azp": "other", "nonce": nonce }));
    idp.on_token(move |_| token_response(&json!({ "id_token": other })));
    let err = auth
        .handle_callback(&callback_url(&handshake, ""), &handshake)
        .await
        .unwrap_err();
    assert_eq!(detail(&err, "reason"), Some("azp_mismatch"));

    let ok = idp.id_token(json!({ "aud": [CLIENT_ID, "x"], "azp": CLIENT_ID, "nonce": nonce }));
    idp.on_token(move |_| token_response(&json!({ "id_token": ok })));
    assert!(
        auth.handle_callback(&callback_url(&handshake, ""), &handshake)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_token_response_without_an_id_token_is_oidc_002() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    let handshake = auth.start_login(None, None).await.unwrap().handshake;
    idp.on_token(|_| token_response(&json!({})));
    let err = auth
        .handle_callback(&callback_url(&handshake, ""), &handshake)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Oidc002);
}

#[tokio::test]
async fn verify_id_token_checks_the_audience_but_has_no_nonce_to_compare() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    let claims = auth
        .verify_id_token(&idp.id_token(json!({ "sid": "s1" })))
        .await
        .unwrap();
    assert_eq!(claims.sid.as_deref(), Some("s1"));
    let other_audience = idp.id_token(json!({ "aud": "another-app" }));
    assert_eq!(
        auth.verify_id_token(&other_audience)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Tok001
    );
}

// ── key rotation ──

#[tokio::test]
async fn a_token_signed_by_a_rotated_in_key_is_accepted_after_one_refresh() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    auth.verify_id_token(&idp.id_token(json!({})))
        .await
        .unwrap();
    assert_eq!(idp.requests_to("/jwks").len(), 1);

    let rotated = Signer::generate("key-2");
    idp.set_jwks(vec![idp.signer().jwk(), rotated.jwk()]);
    let claims =
        json!({ "iss": ISSUER, "sub": "u", "aud": CLIENT_ID, "iat": now(), "exp": now() + 300 });
    let token = rotated.sign(&claims, Some("key-2"), None, false);
    assert!(auth.verify_id_token(&token).await.is_ok());
    assert_eq!(idp.requests_to("/jwks").len(), 2);
}

#[tokio::test]
async fn unknown_key_ids_cannot_force_a_refetch_storm() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    auth.verify_id_token(&idp.id_token(json!({})))
        .await
        .unwrap();
    let stranger = Signer::generate("ghost");
    let claims =
        json!({ "iss": ISSUER, "sub": "u", "aud": CLIENT_ID, "iat": now(), "exp": now() + 300 });
    let token = stranger.sign(&claims, Some("ghost"), None, false);

    for _ in 0..5 {
        let err = auth.verify_id_token(&token).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::Tok001);
    }
    assert!(
        idp.requests_to("/jwks").len() <= 2,
        "one refetch for the first unknown kid, then the cooldown"
    );
}

#[tokio::test]
async fn keys_that_do_not_fit_the_pinned_algorithm_are_ignored() {
    let idp = MockIdp::new();
    let rsa_like = json!({ "kty": "RSA", "n": "AQAB", "e": "AQAB", "kid": "key-1", "use": "sig" });
    let mut wrong_use = idp.signer().jwk();
    wrong_use["use"] = json!("enc");
    idp.set_jwks(vec![rsa_like, wrong_use]);
    let err = client(&idp)
        .verify_id_token(&idp.id_token(json!({})))
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Tok001);
}

#[tokio::test]
async fn a_jwks_that_cannot_be_fetched_is_tok_001() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    idp.set_jwks(vec![]);
    let err = auth
        .verify_id_token(&idp.id_token(json!({})))
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Tok001);
}

// ── UserInfo ──

#[tokio::test]
async fn userinfo_fills_claims_the_id_token_omits_without_overwriting() {
    let idp = MockIdp::new();
    idp.on_userinfo(|_| {
        respond(
            200,
            &json!({
                "sub": "user-1", "email": "a@b.c", "email_verified": true, "name": "From UserInfo",
                "roles": ["admin"], "sid": "evil-sid", "iss": "evil", "address": { "country": "FR" }
            }),
        )
    });
    let auth = client(&idp);
    let result = sign_in(&idp, &auth, &json!({ "name": "From Token" })).await;

    assert_eq!(result.claims.email.as_deref(), Some("a@b.c"));
    assert_eq!(result.claims.email_verified, Some(true));
    assert_eq!(
        result.claims.name.as_deref(),
        Some("From Token"),
        "an ID token value is never replaced"
    );
    assert_eq!(
        result.claims.roles.as_deref(),
        Some(&["editor".to_owned()][..])
    );
    assert_eq!(
        result.claims.sid.as_deref(),
        Some("sid-1"),
        "registered claims are never copied"
    );
    assert_eq!(result.claims.iss, ISSUER);
    assert_eq!(result.claims.extra["address"]["country"], "FR");

    let request = &idp.requests_to("/userinfo")[0];
    assert_eq!(request.header("authorization"), Some("Bearer access-1"));
}

#[tokio::test]
async fn userinfo_of_another_user_fails_the_sign_in() {
    let idp = MockIdp::new();
    idp.on_userinfo(|_| respond(200, &json!({ "sub": "someone-else", "email": "x@y.z" })));
    let auth = client(&idp);
    let handshake = auth.start_login(None, None).await.unwrap().handshake;
    respond_with_tokens(&idp, &handshake, &json!({}));
    let err = auth
        .handle_callback(&callback_url(&handshake, ""), &handshake)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Tok001);
}

#[tokio::test]
async fn userinfo_failures_are_oidc_003_and_never_carry_the_token() {
    for (status, body) in [
        (500, json!({})),
        (200, json!(["x"])),
        (200, json!({ "no_sub": 1 })),
    ] {
        let idp = MockIdp::new();
        idp.on_userinfo(move |_| respond(status, &body));
        let auth = client(&idp);
        let handshake = auth.start_login(None, None).await.unwrap().handshake;
        respond_with_tokens(&idp, &handshake, &json!({}));
        let err = auth
            .handle_callback(&callback_url(&handshake, ""), &handshake)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Oidc003);
        assert!(!err.to_json().to_string().contains("access-1"));
    }
}

#[tokio::test]
async fn userinfo_is_only_called_over_https() {
    let idp = MockIdp::new();
    idp.update_metadata(&[("userinfo_endpoint", json!("http://idp.test/userinfo"))]);
    let auth = client(&idp);
    let handshake = auth.start_login(None, None).await.unwrap().handshake;
    respond_with_tokens(&idp, &handshake, &json!({}));
    let err = auth
        .handle_callback(&callback_url(&handshake, ""), &handshake)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Oidc003);
    assert!(
        idp.requests_to("/userinfo").is_empty(),
        "the access token must not travel over http"
    );
}

#[tokio::test]
async fn a_provider_without_userinfo_signs_in_with_the_id_token_claims() {
    let idp = MockIdp::new();
    idp.update_metadata(&[("userinfo_endpoint", Value::Null)]);
    let auth = client(&idp);
    assert_eq!(sign_in(&idp, &auth, &json!({})).await.claims.sub, "user-1");
    assert_eq!(
        auth.fetch_userinfo("a").await.unwrap_err().code(),
        ErrorCode::Oidc004
    );
}

#[tokio::test]
async fn fetch_userinfo_reads_the_endpoint() {
    let idp = MockIdp::new();
    idp.on_userinfo(|_| respond(200, &json!({ "sub": "user-1", "locale": "fr" })));
    let info = client(&idp).fetch_userinfo("tok").await.unwrap();
    assert_eq!(info.locale.as_deref(), Some("fr"));
}

// ── logout, revocation, introspection ──

#[tokio::test]
async fn logout_url_carries_the_client_and_the_hints() {
    let idp = MockIdp::new();
    let url = client(&idp)
        .logout_url(Some("the-id-token"), Some("st"))
        .await
        .unwrap();
    let params = query_of(&url);
    assert!(url.starts_with(&format!("{ISSUER}/end-session?")));
    assert_eq!(params["client_id"], [CLIENT_ID]);
    assert_eq!(params["post_logout_redirect_uri"], ["https://app.test/"]);
    assert_eq!(params["id_token_hint"], ["the-id-token"]);
    assert_eq!(params["state"], ["st"]);
    let bare = query_of(&client(&idp).logout_url(None, None).await.unwrap());
    assert!(!bare.contains_key("id_token_hint") && !bare.contains_key("state"));
}

#[tokio::test]
async fn unsupported_operations_are_oidc_004() {
    let idp = MockIdp::new();
    idp.update_metadata(&[
        ("end_session_endpoint", Value::Null),
        ("revocation_endpoint", Value::Null),
        ("introspection_endpoint", Value::Null),
    ]);
    let auth = client(&idp);
    assert_eq!(
        auth.logout_url(None, None).await.unwrap_err().code(),
        ErrorCode::Oidc004
    );
    assert_eq!(
        auth.revoke("t", None).await.unwrap_err().code(),
        ErrorCode::Oidc004
    );
    assert_eq!(
        auth.introspect("t", None).await.unwrap_err().code(),
        ErrorCode::Oidc004
    );
}

#[tokio::test]
async fn revocation_posts_the_token_with_its_hint() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    auth.revoke("r-1", Some(TokenTypeHint::RefreshToken))
        .await
        .unwrap();
    let form = form_of(&idp.requests_to("/revoke")[0]);
    assert_eq!(form["token"], "r-1");
    assert_eq!(form["token_type_hint"], "refresh_token");

    idp.set_revocation_status(503);
    let err = auth.revoke("r-1", None).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Oidc003);
}

#[tokio::test]
async fn introspection_returns_the_rfc_7662_answer() {
    let idp = MockIdp::new();
    idp.set_introspection(json!({ "active": true, "scope": "a b", "client_id": CLIENT_ID, "aud": ["x"], "custom": 1 }));
    let result = client(&idp)
        .introspect("t", Some(TokenTypeHint::AccessToken))
        .await
        .unwrap();
    assert!(result.active);
    assert_eq!(result.scope.as_deref(), Some("a b"));
    assert_eq!(result.extra["custom"], 1);

    idp.set_introspection(json!({ "scope": "no active member" }));
    assert_eq!(
        client(&idp).introspect("t", None).await.unwrap_err().code(),
        ErrorCode::Oidc003
    );
}

#[tokio::test]
async fn verify_jwt_pins_the_type_when_asked() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    let claims = json!({ "iss": ISSUER, "sub": "u", "aud": "https://api.test", "iat": now(), "exp": now() + 60 });
    let typed = idp
        .signer()
        .sign(&claims, Some("key-1"), Some("at+jwt"), false);
    assert!(
        auth.verify_jwt(&typed, "https://api.test", Some("application/at+jwt"))
            .await
            .is_ok()
    );
    assert!(
        auth.verify_jwt(&typed, "https://api.test", Some("logout+jwt"))
            .await
            .is_err()
    );
    assert!(
        auth.verify_jwt(&typed, "https://api.test", None)
            .await
            .is_ok()
    );
    assert!(
        auth.verify_jwt(&typed, "https://other.test", None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn the_client_debug_output_hides_the_secret() {
    let idp = MockIdp::new();
    assert!(!format!("{:?}", client(&idp)).contains(CLIENT_SECRET));
}
