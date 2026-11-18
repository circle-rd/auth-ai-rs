#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

//! The OIDC relying party against a scripted identity provider.

mod support;

use std::sync::Arc;

use auth_ai::{
    AuthAiError, AuthClient, ErrorCode, LoginHandshake, Prompt, TokenEndpointAuthMethod, TokenTypeHint,
};
use aws_lc_rs::digest::{SHA256, digest};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use support::{
    CLIENT_ID, CLIENT_SECRET, ISSUER, MockIdp, REDIRECT_URI, Signer, auth_with, config, form_of, hs256_token, merge,
    now, query_of, respond, test_auth, token_response,
};

const RESOURCES: [&str; 2] = ["https://app.test", "https://llm.test"];

fn client(idp: &Arc<MockIdp>) -> AuthClient {
    auth_with(idp, config().post_logout_redirect_uri("https://app.test/").resources(RESOURCES))
}

fn callback_url(handshake: &LoginHandshake, extra: &str) -> String {
    format!("{REDIRECT_URI}?code=abc&state={}&iss={ISSUER}{extra}", handshake.state.expose_secret())
}

fn respond_with_tokens(idp: &Arc<MockIdp>, handshake: &LoginHandshake, claims: &Value) {
    let mut payload = json!({
        "nonce": handshake.nonce.expose_secret(), "sid": "sid-1", "roles": ["editor"], "features": { "maxProjects": 10 }
    });
    merge(&mut payload, claims);
    let id_token = idp.id_token(payload);
    idp.on_token(move |_| {
        respond(
            200,
            &json!({
                "access_token": "access-1", "token_type": "Bearer", "expires_in": 3600,
                "refresh_token": "refresh-1", "scope": "openid roles", "id_token": id_token
            }),
        )
    });
}

fn detail<'a>(err: &'a AuthAiError, key: &str) -> Option<&'a str> {
    err.detail(key).and_then(auth_ai::DetailValue::as_str)
}

async fn sign_in(idp: &Arc<MockIdp>, auth: &AuthClient, claims: &Value) -> auth_ai::LoginResult {
    let handshake = auth.start_login(None, None).await.unwrap().handshake;
    respond_with_tokens(idp, &handshake, claims);
    auth.handle_callback(&callback_url(&handshake, ""), &handshake).await.unwrap()
}

// ── start_login ──

#[tokio::test]
async fn start_login_builds_a_pkce_url_requesting_every_resource() {
    let idp = MockIdp::new();
    let request = client(&idp).start_login(Some(Prompt::Login), None).await.unwrap();
    let params = query_of(&request.url);

    assert!(request.url.starts_with(&format!("{ISSUER}/authorize?")));
    assert_eq!(params["client_id"], [CLIENT_ID]);
    assert_eq!(params["response_type"], ["code"]);
    assert_eq!(params["redirect_uri"], [REDIRECT_URI]);
    assert!(params["scope"][0].contains("offline_access"));
    assert_eq!(params["state"], [request.handshake.state.expose_secret()]);
    assert_eq!(params["nonce"], [request.handshake.nonce.expose_secret()]);
    assert_eq!(params["prompt"], ["login"]);
    assert_eq!(params["resource"], RESOURCES);
    assert_eq!(params["code_challenge_method"], ["S256"]);
    let challenge = URL_SAFE_NO_PAD.encode(digest(&SHA256, request.handshake.code_verifier.expose_secret().as_bytes()));
    assert_eq!(params["code_challenge"], [challenge]);
}

#[tokio::test]
async fn start_login_creates_distinct_secrets_and_discovers_once() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    let first = auth.start_login(None, None).await.unwrap();
    let second = auth.start_login(None, Some("a@b.c")).await.unwrap();

    assert_ne!(first.handshake.state.expose_secret(), second.handshake.state.expose_secret());
    assert_ne!(first.handshake.code_verifier.expose_secret(), second.handshake.code_verifier.expose_secret());
    assert_eq!(query_of(&second.url)["login_hint"], ["a@b.c"]);
    assert_eq!(idp.requests_to("/.well-known/openid-configuration").len(), 1);
    assert!(first.handshake.code_verifier.expose_secret().len() >= 43, "RFC 7636 minimum verifier length");
}

// ── discovery ──

#[tokio::test]
async fn discovery_supports_a_path_based_issuer_with_a_trailing_slash() {
    let idp = MockIdp::new();
    let issuer = "https://www.example.org/test/a/rp/";
    idp.update_metadata(&[
        ("issuer", json!(issuer)),
        ("authorization_endpoint", json!(format!("{issuer}authorize"))),
        ("token_endpoint", json!(format!("{issuer}token"))),
        ("jwks_uri", json!(format!("{issuer}jwks"))),
    ]);
    let auth = auth_with(&idp, auth_ai::AuthClientConfig::builder(issuer, CLIENT_ID, REDIRECT_URI));

    let request = auth.start_login(None, None).await.unwrap();

    assert!(request.url.starts_with(&format!("{issuer}authorize?")));
    assert_eq!(idp.requests_to("/test/a/rp/.well-known/openid-configuration").len(), 1);
}

#[tokio::test]
async fn a_failed_discovery_is_oidc_001_and_is_not_cached() {
    let idp = MockIdp::new();
    idp.fail_discovery(1);
    let auth = client(&idp);

    assert_eq!(auth.start_login(None, None).await.unwrap_err().code(), ErrorCode::Oidc001);
    assert!(auth.start_login(None, None).await.is_ok());
}

#[tokio::test]
async fn discovery_refuses_a_document_naming_another_issuer() {
    let idp = MockIdp::new();
    idp.update_metadata(&[("issuer", json!("https://other.test"))]);
    let err = client(&idp).start_login(None, None).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Oidc001);
    assert!(err.message().contains("another issuer"));
}

#[tokio::test]
async fn discovery_refuses_a_provider_without_a_supported_algorithm() {
    for algorithms in [json!([]), json!(["HS256"]), json!(["EdDSA"]), json!(["none"]), json!(["Ed25519", "ES512"])] {
        let idp = MockIdp::new();
        idp.update_metadata(&[("id_token_signing_alg_values_supported", algorithms.clone())]);
        let err = client(&idp).start_login(None, None).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::Oidc001, "{algorithms}");
    }
}

#[tokio::test]
async fn discovery_picks_the_first_supported_algorithm_the_provider_lists() {
    let idp = MockIdp::new();
    idp.update_metadata(&[("id_token_signing_alg_values_supported", json!(["EdDSA", "ES256", "RS256"]))]);
    let auth = client(&idp);
    let result = sign_in(&idp, &auth, &json!({})).await;
    assert_eq!(result.claims.sub, "user-1");
}

#[tokio::test]
async fn discovery_without_a_jwks_uri_is_oidc_001() {
    let idp = MockIdp::new();
    idp.update_metadata(&[("jwks_uri", Value::Null)]);
    assert_eq!(client(&idp).start_login(None, None).await.unwrap_err().code(), ErrorCode::Oidc001);
}

// ── callback ──

#[tokio::test]
async fn the_callback_exchanges_the_code_and_verifies_the_id_token() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    let result = sign_in(&idp, &auth, &json!({})).await;

    assert_eq!(result.tokens.access_token.expose_secret(), "access-1");
    assert_eq!(result.tokens.refresh_token.as_ref().unwrap().expose_secret(), "refresh-1");
    assert_eq!(result.claims.sub, "user-1");
    assert_eq!(result.claims.roles.as_deref(), Some(&["editor".to_owned()][..]));
    assert_eq!(result.session_id.as_deref(), Some("sid-1"));
    assert!(result.id_token().is_ok());

    let [request] = idp.requests_to("/token").try_into().unwrap();
    let form = form_of(&request);
    assert_eq!(form["grant_type"], "authorization_code");
    assert_eq!(form["code"], "abc");
    assert_eq!(form["redirect_uri"], REDIRECT_URI);
    assert!(form.contains_key("code_verifier"));
    assert!(!form.contains_key("resource"), "the code exchange must not narrow the audience");
    assert!(!form.contains_key("client_secret"));
}

#[tokio::test]
async fn basic_credentials_are_form_urlencoded_before_base64() {
    let idp = MockIdp::new();
    let auth = auth_with(&idp, auth_ai::AuthClientConfig::builder(ISSUER, "app:1", REDIRECT_URI).client_secret("p@ss w/rd"));
    let handshake = auth.start_login(None, None).await.unwrap().handshake;
    idp.on_token(|_| token_response(&json!({ "id_token": "x" })));
    let _ = auth.handle_callback(&callback_url(&handshake, ""), &handshake).await;

    let header = idp.requests_to("/token")[0].header("authorization").unwrap().to_owned();
    let decoded = String::from_utf8(STANDARD.decode(header.strip_prefix("Basic ").unwrap()).unwrap()).unwrap();
    assert_eq!(decoded, "app%3A1:p%40ss+w%2Frd");
}

#[tokio::test]
async fn client_secret_post_sends_the_credentials_in_the_form() {
    let idp = MockIdp::new();
    let auth = auth_with(&idp, config().token_endpoint_auth_method(TokenEndpointAuthMethod::ClientSecretPost));
    idp.on_token(|_| token_response(&json!({})));
    auth.refresh("r", None).await.unwrap();

    let request = &idp.requests_to("/token")[0];
    let form = form_of(request);
    assert_eq!(form["client_id"], CLIENT_ID);
    assert_eq!(form["client_secret"], CLIENT_SECRET);
    assert!(request.header("authorization").is_none());
}

#[tokio::test]
async fn a_public_client_sends_only_its_id() {
    let idp = MockIdp::new();
    let auth = auth_with(&idp, auth_ai::AuthClientConfig::builder(ISSUER, CLIENT_ID, REDIRECT_URI));
    idp.on_token(|_| token_response(&json!({})));
    auth.refresh("r", None).await.unwrap();

    let request = &idp.requests_to("/token")[0];
    assert_eq!(form_of(request)["client_id"], CLIENT_ID);
    assert!(request.header("authorization").is_none());
    assert!(!form_of(request).contains_key("client_secret"));
}

async fn callback_error(idp: &Arc<MockIdp>, url: impl FnOnce(&LoginHandshake) -> String) -> AuthAiError {
    let auth = client(idp);
    let handshake = auth.start_login(None, None).await.unwrap().handshake;
    respond_with_tokens(idp, &handshake, &json!({}));
    auth.handle_callback(&url(&handshake), &handshake).await.unwrap_err()
}

#[tokio::test]
async fn the_callback_refuses_a_forged_or_missing_state() {
    let idp = MockIdp::new();
    let forged = callback_error(&idp, |_| format!("{REDIRECT_URI}?code=abc&state=forged&iss={ISSUER}")).await;
    assert_eq!(forged.code(), ErrorCode::Oidc002);
    assert_eq!(detail(&forged, "reason"), Some("state_mismatch"));

    let missing = callback_error(&idp, |_| format!("{REDIRECT_URI}?code=abc&iss={ISSUER}")).await;
    assert_eq!(detail(&missing, "reason"), Some("state_mismatch"));
    assert!(idp.requests_to("/token").is_empty(), "no code may be exchanged after a bad state");
}

#[tokio::test]
async fn the_callback_refuses_a_missing_code() {
    let idp = MockIdp::new();
    let err = callback_error(&idp, |h| format!("{REDIRECT_URI}?state={}&iss={ISSUER}", h.state.expose_secret())).await;
    assert_eq!(detail(&err, "reason"), Some("missing_code"));
}

#[tokio::test]
async fn the_callback_reports_an_authorization_error() {
    let idp = MockIdp::new();
    let err = callback_error(&idp, |h| callback_url(h, "&error=access_denied").replace("code=abc&", "")).await;
    assert_eq!(err.code(), ErrorCode::Oidc002);
    assert_eq!(detail(&err, "oauthError"), Some("access_denied"));
}

#[tokio::test]
async fn the_callback_refuses_a_repeated_parameter() {
    let idp = MockIdp::new();
    for extra in ["&code=other", "&state=again", "&iss=again"] {
        let err = callback_error(&idp, |h| callback_url(h, extra)).await;
        assert_eq!(detail(&err, "reason"), Some("repeated_parameter"), "{extra}");
    }
}

#[tokio::test]
async fn the_callback_checks_the_issuer_parameter_rfc_9207() {
    let idp = MockIdp::new();
    let missing = callback_error(&idp, |h| format!("{REDIRECT_URI}?code=abc&state={}", h.state.expose_secret())).await;
    assert_eq!(detail(&missing, "reason"), Some("missing_iss"));
    let wrong = callback_error(&idp, |h| {
        format!("{REDIRECT_URI}?code=abc&state={}&iss=https://evil.test", h.state.expose_secret())
    })
    .await;
    assert_eq!(detail(&wrong, "reason"), Some("iss_mismatch"));

    idp.update_metadata(&[("authorization_response_iss_parameter_supported", json!(false))]);
    let auth = client(&idp);
    let handshake = auth.start_login(None, None).await.unwrap().handshake;
    respond_with_tokens(&idp, &handshake, &json!({}));
    let url = format!("{REDIRECT_URI}?code=abc&state={}", handshake.state.expose_secret());
    assert!(auth.handle_callback(&url, &handshake).await.is_ok(), "iss is optional when the provider does not advertise it");
}

#[tokio::test]
async fn the_callback_refuses_a_malformed_url() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    let handshake = auth.start_login(None, None).await.unwrap().handshake;
    let err = auth.handle_callback("not a url", &handshake).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Oidc002);
}

// ── token endpoint ──

#[tokio::test]
async fn an_oauth_error_keeps_only_the_rfc_6749_fields() {
    let idp = MockIdp::new();
    idp.on_token(|_| {
        respond(400, &json!({ "error": "invalid_grant", "error_description": "expired", "secret": "leak-me" }))
    });
    let err = client(&idp).refresh("r", None).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Oidc003);
    assert_eq!(err.oauth_error(), Some("invalid_grant"));
    assert_eq!(detail(&err, "description"), Some("expired"));
    assert!(!err.to_json().to_string().contains("leak-me"));
}

#[tokio::test]
async fn a_basic_challenge_points_at_the_client_credentials() {
    let idp = MockIdp::new();
    idp.on_token(|_| {
        let mut response = respond(401, &json!({}));
        response.body = b"nope".to_vec();
        response.headers.push(("www-authenticate".to_owned(), "Basic".to_owned()));
        response
    });
    let err = client(&idp).refresh("r", None).await.unwrap_err();
    assert!(err.message().contains("client_secret"));
}

#[tokio::test]
async fn a_plain_failure_is_oidc_003_with_its_status() {
    let idp = MockIdp::new();
    let err = client(&idp).refresh("r", None).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Oidc003);
    assert_eq!(err.to_json()["details"]["status"], 500);
}

#[tokio::test]
async fn a_token_response_must_be_a_bearer_token_of_the_right_shape() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    idp.on_token(|_| token_response(&json!({ "token_type": "mac" })));
    assert_eq!(auth.refresh("r", None).await.unwrap_err().code(), ErrorCode::Oidc003);
    idp.on_token(|_| respond(200, &json!({ "token_type": "Bearer" })));
    assert_eq!(auth.refresh("r", None).await.unwrap_err().code(), ErrorCode::Oidc003);
    idp.on_token(|_| respond(200, &json!(["not", "an", "object"])));
    assert_eq!(auth.refresh("r", None).await.unwrap_err().code(), ErrorCode::Oidc003);
}

#[tokio::test]
async fn an_unreachable_provider_is_oidc_003_without_a_request_in_the_message() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    auth.start_login(None, None).await.unwrap();
    idp.go_offline();
    let err = auth.refresh("secret-refresh-token", None).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Oidc003);
    assert!(!err.to_json().to_string().contains("secret-refresh-token"));
}

#[tokio::test]
async fn the_expiry_defaults_to_five_minutes_and_empty_members_are_absent() {
    let idp = MockIdp::new();
    idp.on_token(|_| respond(200, &json!({ "access_token": "a", "token_type": "bearer", "scope": "", "refresh_token": "" })));
    let tokens = client(&idp).refresh("r", None).await.unwrap();
    assert!((tokens.expires_at - (now() + 300)).abs() <= 2);
    assert!(tokens.scope.is_none() && tokens.refresh_token.is_none() && tokens.id_token.is_none());
}

#[tokio::test]
async fn refresh_narrows_to_one_resource_and_never_sends_a_scope() {
    let idp = MockIdp::new();
    idp.on_token(|_| token_response(&json!({})));
    let auth = client(&idp);
    auth.refresh("r-1", Some("https://llm.test")).await.unwrap();
    auth.refresh("r-2", None).await.unwrap();

    let forms: Vec<_> = idp.requests_to("/token").iter().map(form_of).collect();
    assert_eq!(forms[0]["grant_type"], "refresh_token");
    assert_eq!(forms[0]["refresh_token"], "r-1");
    assert_eq!(forms[0]["resource"], "https://llm.test");
    assert!(!forms[1].contains_key("resource"));
    assert!(forms.iter().all(|form| !form.contains_key("scope")));
}

#[tokio::test]
async fn client_credentials_needs_a_confidential_client() {
    let idp = MockIdp::new();
    idp.on_token(|_| token_response(&json!({})));
    let public = auth_with(&idp, auth_ai::AuthClientConfig::builder(ISSUER, CLIENT_ID, REDIRECT_URI));
    assert_eq!(public.client_credentials(None, None).await.unwrap_err().code(), ErrorCode::Cfg001);

    test_auth(&idp).client_credentials(Some("billing:read"), Some("https://api.test")).await.unwrap();
    let form = form_of(&idp.requests_to("/token")[0]);
    assert_eq!(form["grant_type"], "client_credentials");
    assert_eq!(form["scope"], "billing:read");
    assert_eq!(form["resource"], "https://api.test");
}

// ── ID token verification ──

async fn id_token_error(idp: &Arc<MockIdp>, token: String) -> AuthAiError {
    let auth = client(idp);
    let handshake = auth.start_login(None, None).await.unwrap().handshake;
    idp.on_token(move |_| token_response(&json!({ "id_token": token })));
    auth.handle_callback(&callback_url(&handshake, ""), &handshake).await.unwrap_err()
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
    let base = json!({ "iss": ISSUER, "sub": "u", "aud": CLIENT_ID, "iat": now(), "exp": now() + 300 });
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
        json!({ "iss": ISSUER, "sub": "u", "aud": CLIENT_ID, "iat": now(), "exp": now() + 300 }).to_string(),
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

    let without_azp = idp.id_token(json!({ "aud": [CLIENT_ID, "https://llm.test"], "nonce": nonce }));
    idp.on_token(move |_| token_response(&json!({ "id_token": without_azp })));
    let err = auth.handle_callback(&callback_url(&handshake, ""), &handshake).await.unwrap_err();
    assert_eq!(detail(&err, "reason"), Some("missing_azp"));

    let other = idp.id_token(json!({ "aud": [CLIENT_ID, "x"], "azp": "other", "nonce": nonce }));
    idp.on_token(move |_| token_response(&json!({ "id_token": other })));
    let err = auth.handle_callback(&callback_url(&handshake, ""), &handshake).await.unwrap_err();
    assert_eq!(detail(&err, "reason"), Some("azp_mismatch"));

    let ok = idp.id_token(json!({ "aud": [CLIENT_ID, "x"], "azp": CLIENT_ID, "nonce": nonce }));
    idp.on_token(move |_| token_response(&json!({ "id_token": ok })));
    assert!(auth.handle_callback(&callback_url(&handshake, ""), &handshake).await.is_ok());
}

#[tokio::test]
async fn a_token_response_without_an_id_token_is_oidc_002() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    let handshake = auth.start_login(None, None).await.unwrap().handshake;
    idp.on_token(|_| token_response(&json!({})));
    let err = auth.handle_callback(&callback_url(&handshake, ""), &handshake).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Oidc002);
}

#[tokio::test]
async fn verify_id_token_checks_the_audience_but_has_no_nonce_to_compare() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    let claims = auth.verify_id_token(&idp.id_token(json!({ "sid": "s1" }))).await.unwrap();
    assert_eq!(claims.sid.as_deref(), Some("s1"));
    let other_audience = idp.id_token(json!({ "aud": "another-app" }));
    assert_eq!(auth.verify_id_token(&other_audience).await.unwrap_err().code(), ErrorCode::Tok001);
}

// ── key rotation ──

#[tokio::test]
async fn a_token_signed_by_a_rotated_in_key_is_accepted_after_one_refresh() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    auth.verify_id_token(&idp.id_token(json!({}))).await.unwrap();
    assert_eq!(idp.requests_to("/jwks").len(), 1);

    let rotated = Signer::generate("key-2");
    idp.set_jwks(vec![idp.signer().jwk(), rotated.jwk()]);
    let claims = json!({ "iss": ISSUER, "sub": "u", "aud": CLIENT_ID, "iat": now(), "exp": now() + 300 });
    let token = rotated.sign(&claims, Some("key-2"), None, false);
    assert!(auth.verify_id_token(&token).await.is_ok());
    assert_eq!(idp.requests_to("/jwks").len(), 2);
}

#[tokio::test]
async fn unknown_key_ids_cannot_force_a_refetch_storm() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    auth.verify_id_token(&idp.id_token(json!({}))).await.unwrap();
    let stranger = Signer::generate("ghost");
    let claims = json!({ "iss": ISSUER, "sub": "u", "aud": CLIENT_ID, "iat": now(), "exp": now() + 300 });
    let token = stranger.sign(&claims, Some("ghost"), None, false);

    for _ in 0..5 {
        let err = auth.verify_id_token(&token).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::Tok001);
    }
    assert!(idp.requests_to("/jwks").len() <= 2, "one refetch for the first unknown kid, then the cooldown");
}

#[tokio::test]
async fn keys_that_do_not_fit_the_pinned_algorithm_are_ignored() {
    let idp = MockIdp::new();
    let rsa_like = json!({ "kty": "RSA", "n": "AQAB", "e": "AQAB", "kid": "key-1", "use": "sig" });
    let mut wrong_use = idp.signer().jwk();
    wrong_use["use"] = json!("enc");
    idp.set_jwks(vec![rsa_like, wrong_use]);
    let err = client(&idp).verify_id_token(&idp.id_token(json!({}))).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Tok001);
}

#[tokio::test]
async fn a_jwks_that_cannot_be_fetched_is_tok_001() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    idp.set_jwks(vec![]);
    let err = auth.verify_id_token(&idp.id_token(json!({}))).await.unwrap_err();
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
    assert_eq!(result.claims.name.as_deref(), Some("From Token"), "an ID token value is never replaced");
    assert_eq!(result.claims.roles.as_deref(), Some(&["editor".to_owned()][..]));
    assert_eq!(result.claims.sid.as_deref(), Some("sid-1"), "registered claims are never copied");
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
    let err = auth.handle_callback(&callback_url(&handshake, ""), &handshake).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Tok001);
}

#[tokio::test]
async fn userinfo_failures_are_oidc_003_and_never_carry_the_token() {
    for (status, body) in [(500, json!({})), (200, json!(["x"])), (200, json!({ "no_sub": 1 }))] {
        let idp = MockIdp::new();
        idp.on_userinfo(move |_| respond(status, &body));
        let auth = client(&idp);
        let handshake = auth.start_login(None, None).await.unwrap().handshake;
        respond_with_tokens(&idp, &handshake, &json!({}));
        let err = auth.handle_callback(&callback_url(&handshake, ""), &handshake).await.unwrap_err();
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
    let err = auth.handle_callback(&callback_url(&handshake, ""), &handshake).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Oidc003);
    assert!(idp.requests_to("/userinfo").is_empty(), "the access token must not travel over http");
}

#[tokio::test]
async fn a_provider_without_userinfo_signs_in_with_the_id_token_claims() {
    let idp = MockIdp::new();
    idp.update_metadata(&[("userinfo_endpoint", Value::Null)]);
    let auth = client(&idp);
    assert_eq!(sign_in(&idp, &auth, &json!({})).await.claims.sub, "user-1");
    assert_eq!(auth.fetch_userinfo("a").await.unwrap_err().code(), ErrorCode::Oidc004);
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
    let url = client(&idp).logout_url(Some("the-id-token"), Some("st")).await.unwrap();
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
    assert_eq!(auth.logout_url(None, None).await.unwrap_err().code(), ErrorCode::Oidc004);
    assert_eq!(auth.revoke("t", None).await.unwrap_err().code(), ErrorCode::Oidc004);
    assert_eq!(auth.introspect("t", None).await.unwrap_err().code(), ErrorCode::Oidc004);
}

#[tokio::test]
async fn revocation_posts_the_token_with_its_hint() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    auth.revoke("r-1", Some(TokenTypeHint::RefreshToken)).await.unwrap();
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
    let result = client(&idp).introspect("t", Some(TokenTypeHint::AccessToken)).await.unwrap();
    assert!(result.active);
    assert_eq!(result.scope.as_deref(), Some("a b"));
    assert_eq!(result.extra["custom"], 1);

    idp.set_introspection(json!({ "scope": "no active member" }));
    assert_eq!(client(&idp).introspect("t", None).await.unwrap_err().code(), ErrorCode::Oidc003);
}

#[tokio::test]
async fn verify_jwt_pins_the_type_when_asked() {
    let idp = MockIdp::new();
    let auth = client(&idp);
    let claims = json!({ "iss": ISSUER, "sub": "u", "aud": "https://api.test", "iat": now(), "exp": now() + 60 });
    let typed = idp.signer().sign(&claims, Some("key-1"), Some("at+jwt"), false);
    assert!(auth.verify_jwt(&typed, "https://api.test", Some("application/at+jwt")).await.is_ok());
    assert!(auth.verify_jwt(&typed, "https://api.test", Some("logout+jwt")).await.is_err());
    assert!(auth.verify_jwt(&typed, "https://api.test", None).await.is_ok());
    assert!(auth.verify_jwt(&typed, "https://other.test", None).await.is_err());
}

#[tokio::test]
async fn the_client_debug_output_hides_the_secret() {
    let idp = MockIdp::new();
    assert!(!format!("{:?}", client(&idp)).contains(CLIENT_SECRET));
}
