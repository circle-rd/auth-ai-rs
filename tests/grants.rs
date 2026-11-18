#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The grant manager: serialized refresh rotation and per-audience access tokens.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use auth_ai::{
    ErrorCode, GrantLock, GrantManager, GrantStore, LockGuard, MemoryGrantStore, SecretString,
};
use serde_json::json;
use support::{MockIdp, form_of, respond, test_auth};

struct Fixture {
    idp: Arc<MockIdp>,
    store: Arc<MemoryGrantStore>,
    grants: GrantManager,
    token_calls: Arc<AtomicU32>,
}

/// A provider that rotates: call `n` answers `access-n` and `refresh-(n+1)`.
fn fixture() -> Fixture {
    let idp = MockIdp::new();
    let token_calls = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&token_calls);
    idp.on_token(move |_| {
        let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
        respond(
            200,
            &json!({
                "access_token": format!("access-{n}"), "token_type": "Bearer", "expires_in": 3600,
                "refresh_token": format!("refresh-{}", n + 1), "id_token": format!("id-token-{n}")
            }),
        )
    });
    let store = Arc::new(MemoryGrantStore::new());
    let grants = GrantManager::new(test_auth(&idp), Arc::clone(&store));
    Fixture {
        idp,
        store,
        grants,
        token_calls,
    }
}

async fn saved(f: &Fixture, user: &str) {
    f.grants
        .save(user, &SecretString::new("refresh-1"))
        .await
        .unwrap();
}

async fn stored(f: &Fixture, user: &str) -> Option<String> {
    f.store
        .get(user)
        .await
        .unwrap()
        .map(|token| token.expose_secret().to_owned())
}

fn token(grant: &auth_ai::AccessToken) -> &str {
    grant.access_token.expose_secret()
}

#[tokio::test]
async fn access_tokens_are_minted_per_resource_and_cached() {
    let f = fixture();
    saved(&f, "u1").await;

    let first = f
        .grants
        .get_access_token("u1", Some("https://llm.test"))
        .await
        .unwrap();
    let again = f
        .grants
        .get_access_token("u1", Some("https://llm.test"))
        .await
        .unwrap();
    let other = f
        .grants
        .get_access_token("u1", Some("https://idp.test"))
        .await
        .unwrap();

    assert_eq!(token(&first), "access-1");
    assert_eq!(token(&again), "access-1");
    assert_eq!(token(&other), "access-2");
    assert_eq!(f.token_calls.load(Ordering::SeqCst), 2);
    let forms: Vec<_> = f.idp.requests_to("/token").iter().map(form_of).collect();
    assert_eq!(forms[0]["resource"], "https://llm.test");
    assert_eq!(forms[0]["refresh_token"], "refresh-1");
    assert_eq!(forms[1]["resource"], "https://idp.test");
    assert_eq!(
        forms[1]["refresh_token"], "refresh-2",
        "the rotated token replaces the presented one"
    );
    assert!(
        forms
            .iter()
            .all(|form| form["grant_type"] == "refresh_token" && !form.contains_key("scope"))
    );
}

#[tokio::test]
async fn the_rotated_refresh_token_is_stored() {
    let f = fixture();
    saved(&f, "u1").await;
    f.grants.get_access_token("u1", None).await.unwrap();
    assert_eq!(stored(&f, "u1").await.as_deref(), Some("refresh-2"));
}

#[tokio::test]
async fn a_provider_that_does_not_rotate_keeps_the_stored_token() {
    let f = fixture();
    f.idp.on_token(|_| {
        respond(
            200,
            &json!({ "access_token": "a", "token_type": "Bearer", "expires_in": 3600 }),
        )
    });
    saved(&f, "u1").await;
    f.grants.get_access_token("u1", None).await.unwrap();
    assert_eq!(stored(&f, "u1").await.as_deref(), Some("refresh-1"));
}

#[tokio::test]
async fn a_user_without_a_grant_gets_tok_002_and_no_request_is_sent() {
    let f = fixture();
    let err = f.grants.get_access_token("nobody", None).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Tok002);
    assert!(f.idp.requests().is_empty());
    assert!(!f.grants.has("nobody").await.unwrap());
}

#[tokio::test]
async fn a_rejected_grant_is_dropped_and_only_a_new_sign_in_restores_it() {
    let f = fixture();
    f.idp
        .on_token(|_| respond(400, &json!({ "error": "invalid_grant" })));
    saved(&f, "u1").await;
    assert!(f.grants.has("u1").await.unwrap());

    let err = f.grants.get_access_token("u1", None).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Tok002);
    assert!(
        std::error::Error::source(&err).is_some(),
        "the provider's refusal stays as the cause"
    );
    assert!(!f.grants.has("u1").await.unwrap());
    assert_eq!(
        f.grants
            .get_access_token("u1", None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Tok002
    );
    assert_eq!(
        f.idp.requests_to("/token").len(),
        1,
        "a dropped grant is not retried"
    );
}

#[tokio::test]
async fn other_provider_errors_keep_the_grant() {
    let f = fixture();
    saved(&f, "u1").await;
    f.idp.on_token(|_| respond(503, &json!({})));
    assert_eq!(
        f.grants
            .get_access_token("u1", None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Oidc003
    );
    f.idp
        .on_token(|_| respond(400, &json!({ "error": "invalid_scope" })));
    assert_eq!(
        f.grants
            .get_access_token("u1", None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Oidc003
    );
    assert!(f.grants.has("u1").await.unwrap());
}

#[tokio::test]
async fn a_token_about_to_expire_is_not_served_from_the_cache() {
    let f = fixture();
    f.idp.on_token(|_| {
        respond(
            200,
            &json!({ "access_token": "short", "token_type": "Bearer", "expires_in": 10 }),
        )
    });
    saved(&f, "u1").await;
    f.grants.get_access_token("u1", None).await.unwrap();
    f.grants.get_access_token("u1", None).await.unwrap();
    assert_eq!(
        f.idp.requests_to("/token").len(),
        2,
        "10 s is inside the 30 s renewal skew"
    );
}

#[tokio::test]
async fn the_expiry_skew_is_configurable() {
    let f = fixture();
    f.idp.on_token(|_| {
        respond(
            200,
            &json!({ "access_token": "short", "token_type": "Bearer", "expires_in": 10 }),
        )
    });
    let grants = GrantManager::builder(test_auth(&f.idp), Arc::clone(&f.store))
        .expiry_skew_seconds(0)
        .build();
    grants
        .save("u1", &SecretString::new("refresh-1"))
        .await
        .unwrap();
    grants.get_access_token("u1", None).await.unwrap();
    grants.get_access_token("u1", None).await.unwrap();
    assert_eq!(f.idp.requests_to("/token").len(), 1);
}

#[tokio::test]
async fn invalidate_drops_one_cached_token() {
    let f = fixture();
    saved(&f, "u1").await;
    f.grants
        .get_access_token("u1", Some("https://llm.test"))
        .await
        .unwrap();
    f.grants
        .get_access_token("u1", Some("https://idp.test"))
        .await
        .unwrap();
    f.grants.invalidate("u1", Some("https://llm.test"));

    let renewed = f
        .grants
        .get_access_token("u1", Some("https://llm.test"))
        .await
        .unwrap();
    assert_eq!(token(&renewed), "access-3");
    let untouched = f
        .grants
        .get_access_token("u1", Some("https://idp.test"))
        .await
        .unwrap();
    assert_eq!(token(&untouched), "access-2");
}

#[tokio::test]
async fn concurrent_callers_share_one_refresh() {
    let f = fixture();
    f.idp.set_token_delay(Duration::from_millis(60));
    saved(&f, "u1").await;

    let calls = (0..8).map(|_| {
        let grants = f.grants.clone();
        tokio::spawn(async move {
            grants
                .get_access_token("u1", Some("https://llm.test"))
                .await
                .unwrap()
        })
    });
    let tokens = futures_join(calls).await;

    assert_eq!(
        f.token_calls.load(Ordering::SeqCst),
        1,
        "a replayed refresh token would revoke the family"
    );
    assert!(tokens.iter().all(|t| token(t) == "access-1"));
}

#[tokio::test]
async fn concurrent_refreshes_of_different_resources_never_replay_a_token() {
    let f = fixture();
    f.idp.set_token_delay(Duration::from_millis(30));
    saved(&f, "u1").await;

    let calls = [
        "https://llm.test",
        "https://idp.test",
        "https://api.test",
        "https://app.test",
    ]
    .map(|resource| {
        let grants = f.grants.clone();
        tokio::spawn(async move { grants.get_access_token("u1", Some(resource)).await.unwrap() })
    });
    futures_join(calls).await;

    let presented: Vec<String> = f
        .idp
        .requests_to("/token")
        .iter()
        .map(|r| form_of(r)["refresh_token"].clone())
        .collect();
    assert_eq!(
        presented,
        ["refresh-1", "refresh-2", "refresh-3", "refresh-4"],
        "each refresh sees the previous rotation"
    );
}

#[tokio::test]
async fn a_caller_that_gives_up_does_not_abort_the_rotation() {
    let f = fixture();
    f.idp.set_token_delay(Duration::from_millis(80));
    saved(&f, "u1").await;

    let abandoned = tokio::time::timeout(
        Duration::from_millis(10),
        f.grants.get_access_token("u1", None),
    )
    .await;
    assert!(abandoned.is_err(), "the caller stopped waiting");

    let mut rotated = None;
    for _ in 0..100 {
        rotated = stored(&f, "u1").await.filter(|token| token == "refresh-2");
        if rotated.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        rotated.as_deref(),
        Some("refresh-2"),
        "the rotated token must reach the store"
    );
    let cached = f.grants.get_access_token("u1", None).await.unwrap();
    assert_eq!(token(&cached), "access-1");
    assert_eq!(f.token_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn refresh_tokens_returns_the_whole_set_for_claims_renewal() {
    let f = fixture();
    saved(&f, "u1").await;
    let tokens = f.grants.refresh_tokens("u1").await.unwrap();
    assert_eq!(
        tokens.id_token.as_ref().unwrap().expose_secret(),
        "id-token-1"
    );
    assert_eq!(stored(&f, "u1").await.as_deref(), Some("refresh-2"));
    assert!(!form_of(&f.idp.requests_to("/token")[0]).contains_key("resource"));
    assert_eq!(
        f.grants.refresh_tokens("nobody").await.unwrap_err().code(),
        ErrorCode::Tok002
    );
}

#[tokio::test]
async fn saving_a_new_chain_replaces_the_old_one_and_drops_cached_tokens() {
    let f = fixture();
    saved(&f, "u1").await;
    f.grants.get_access_token("u1", None).await.unwrap();
    f.grants
        .save("u1", &SecretString::new("fresh-chain"))
        .await
        .unwrap();

    assert_eq!(stored(&f, "u1").await.as_deref(), Some("fresh-chain"));
    let renewed = f.grants.get_access_token("u1", None).await.unwrap();
    assert_eq!(token(&renewed), "access-2");
    assert_eq!(
        form_of(&f.idp.requests_to("/token")[1])["refresh_token"],
        "fresh-chain"
    );
}

#[tokio::test]
async fn revoking_tells_the_provider_and_forgets_the_grant() {
    let f = fixture();
    saved(&f, "u1").await;
    f.grants.get_access_token("u1", None).await.unwrap();
    f.grants.revoke("u1").await.unwrap();

    let form = form_of(&f.idp.requests_to("/revoke")[0]);
    assert_eq!(form["token"], "refresh-2");
    assert_eq!(form["token_type_hint"], "refresh_token");
    assert!(!f.grants.has("u1").await.unwrap());
    assert_eq!(
        f.grants
            .get_access_token("u1", None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Tok002
    );
}

#[tokio::test]
async fn an_unreachable_provider_does_not_keep_the_user_signed_in_locally() {
    let f = fixture();
    saved(&f, "u1").await;
    f.idp.set_revocation_status(503);
    let err = f.grants.revoke("u1").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Oidc003);
    assert!(!f.grants.has("u1").await.unwrap());
}

#[tokio::test]
async fn revoking_a_user_without_a_grant_is_a_no_op() {
    let f = fixture();
    f.grants.revoke("nobody").await.unwrap();
    assert!(f.idp.requests().is_empty());
}

#[tokio::test]
async fn grants_of_different_users_do_not_mix() {
    let f = fixture();
    f.grants
        .save("u1", &SecretString::new("chain-a"))
        .await
        .unwrap();
    f.grants
        .save("u2", &SecretString::new("chain-b"))
        .await
        .unwrap();
    f.grants.get_access_token("u1", None).await.unwrap();
    assert_eq!(stored(&f, "u2").await.as_deref(), Some("chain-b"));
    assert_eq!(
        form_of(&f.idp.requests_to("/token")[0])["refresh_token"],
        "chain-a"
    );
}

/// Counts how often the lock is taken and for which grant.
struct SpyLock {
    held: std::sync::Mutex<Vec<String>>,
}

#[async_trait]
impl GrantLock for SpyLock {
    async fn hold(&self, grant_id: &str) -> auth_ai::Result<LockGuard> {
        self.held.lock().unwrap().push(grant_id.to_owned());
        Ok(LockGuard::new(()))
    }
}

#[tokio::test]
async fn a_distributed_lock_can_replace_the_in_process_one() {
    let f = fixture();
    let spy = Arc::new(SpyLock {
        held: std::sync::Mutex::new(Vec::new()),
    });
    let grants = GrantManager::builder(test_auth(&f.idp), Arc::clone(&f.store))
        .lock(Arc::clone(&spy))
        .build();
    grants
        .save("u1", &SecretString::new("refresh-1"))
        .await
        .unwrap();
    grants.get_access_token("u1", None).await.unwrap();
    grants.get_access_token("u1", None).await.unwrap();
    grants.revoke("u1").await.unwrap();

    assert_eq!(
        *spy.held.lock().unwrap(),
        ["u1", "u1", "u1"],
        "save, the one refresh (the cache hit takes no lock) and revoke"
    );
}

struct FailingStore;

#[async_trait]
impl GrantStore for FailingStore {
    async fn get(&self, _grant_id: &str) -> auth_ai::Result<Option<SecretString>> {
        Err(ErrorCode::Srv001.error())
    }

    async fn set(&self, _grant_id: &str, _refresh_token: &SecretString) -> auth_ai::Result<()> {
        Err(ErrorCode::Srv001.error())
    }

    async fn delete(&self, _grant_id: &str) -> auth_ai::Result<()> {
        Err(ErrorCode::Srv001.error())
    }
}

#[tokio::test]
async fn store_failures_surface_as_the_stores_own_error() {
    let idp = MockIdp::new();
    let grants = GrantManager::new(test_auth(&idp), FailingStore);
    assert_eq!(
        grants
            .get_access_token("u1", None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Srv001
    );
    assert_eq!(
        grants.has("u1").await.unwrap_err().code(),
        ErrorCode::Srv001
    );
    assert_eq!(
        grants
            .save("u1", &SecretString::new("r"))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Srv001
    );
    assert!(idp.requests().is_empty());
}

async fn futures_join<T: Send + 'static>(
    handles: impl IntoIterator<Item = tokio::task::JoinHandle<T>>,
) -> Vec<T> {
    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.unwrap());
    }
    results
}
