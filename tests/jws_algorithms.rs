#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The signature algorithms the SDK verifies, and the ones it refuses.

mod support;

use std::sync::Arc;

use auth_ai::{AuthAiError, ErrorCode};
use serde_json::{Value, json};
use support::*;

fn claims() -> Value {
    json!({ "iss": ISSUER, "sub": "u", "aud": CLIENT_ID, "iat": now(), "exp": now() + 300, "nonce": "n" })
}

async fn id_token_error(idp: &Arc<MockIdp>, token: String) -> AuthAiError {
    let auth = client(idp);
    let handshake = auth.start_login(None, None).await.unwrap().handshake;
    idp.on_token(move |_| token_response(&json!({ "id_token": token })));
    auth.handle_callback(&callback_url(&handshake, ""), &handshake)
        .await
        .unwrap_err()
}

#[tokio::test]
async fn every_supported_algorithm_signs_a_session_in() {
    for algorithm in TestAlgorithm::ALL {
        let idp = MockIdp::with_algorithm(algorithm);
        let auth = client(&idp);
        let result = sign_in(&idp, &auth, &json!({})).await;
        assert_eq!(result.claims.sub, "user-1", "{}", algorithm.name());
    }
}

#[tokio::test]
async fn a_token_whose_header_names_another_algorithm_than_the_pinned_one_is_refused() {
    for algorithm in TestAlgorithm::ALL {
        let idp = MockIdp::with_algorithm(algorithm);
        for other in [
            "ES256", "RS256", "PS256", "Ed25519", "EdDSA", "HS256", "none",
        ] {
            if other == algorithm.name() {
                continue;
            }
            let header = json!({ "alg": other, "kid": "key-1", "typ": "JWT" });
            let token = idp.signer().sign_with_header(&header, &claims());
            let err = id_token_error(&idp, token).await;
            assert_eq!(
                err.code(),
                ErrorCode::Tok001,
                "{} as {other}",
                algorithm.name()
            );
            assert_eq!(
                detail(&err, "reason"),
                Some("invalid_algorithm"),
                "{} as {other}",
                algorithm.name()
            );
        }
    }
}

#[tokio::test]
async fn a_jwk_that_declares_another_algorithm_than_the_pinned_one_is_not_a_candidate() {
    let idp = MockIdp::with_algorithm(TestAlgorithm::Es256);
    let mut jwk = idp.signer().jwk();
    jwk["alg"] = json!("ES384");
    idp.set_jwks(vec![jwk]);
    let err = id_token_error(&idp, idp.sign_jwt(&claims())).await;
    assert_eq!(err.code(), ErrorCode::Tok001);
}

#[tokio::test]
async fn a_signature_made_by_another_key_of_the_same_algorithm_is_refused() {
    for algorithm in TestAlgorithm::ALL {
        let idp = MockIdp::with_algorithm(algorithm);
        let foreign = Signer::generate_with("key-1", algorithm);
        let err = id_token_error(&idp, foreign.sign(&claims(), Some("key-1"), None, false)).await;
        assert_eq!(err.code(), ErrorCode::Tok001, "{}", algorithm.name());
        assert_eq!(
            detail(&err, "reason"),
            Some("invalid_signature"),
            "{}",
            algorithm.name()
        );
    }
}

#[tokio::test]
async fn a_provider_that_advertises_only_unsupported_algorithms_is_refused_at_discovery() {
    for algorithms in [
        json!(["Ed448"]),
        json!(["EdDSA", "Ed448"]),
        json!(["HS512"]),
    ] {
        let idp = MockIdp::new();
        idp.update_metadata(&[("id_token_signing_alg_values_supported", algorithms.clone())]);
        let err = client(&idp).start_login(None, None).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::Oidc001, "{algorithms}");
    }
}
