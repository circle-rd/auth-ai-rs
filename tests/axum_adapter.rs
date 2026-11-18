#![cfg(feature = "axum")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The axum adapter: routes, extractors and the public error envelope.

mod support;

use std::sync::Arc;

use auth_ai::axum::{AuthError, AuthSession, OptionalAuthSession, auth_router};
use auth_ai::server::MAX_BODY_BYTES;
use auth_ai::web::{AuthHandlers, MemorySessionStore, SessionStore};
use auth_ai::{AuthClient, AuthClientConfig, ErrorCode, GrantManager, MemoryGrantStore};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use axum::routing::get;
use serde_json::{Value, json};
use support::{CLIENT_ID, CLIENT_SECRET, ISSUER, MockIdp, query_of, respond};
use tower::ServiceExt;

const ORIGIN: &str = "https://app.test";

struct Harness {
    idp: Arc<MockIdp>,
    router: Router,
}

fn harness() -> Harness {
    let idp = MockIdp::new();
    let config = AuthClientConfig::builder(ISSUER, CLIENT_ID, format!("{ORIGIN}/auth/callback"))
        .client_secret(CLIENT_SECRET)
        .build()
        .unwrap();
    let auth = AuthClient::with_transport(config, Arc::clone(&idp) as Arc<dyn auth_ai::Transport>);
    let handlers = AuthHandlers::builder(
        auth.clone(),
        GrantManager::new(auth, MemoryGrantStore::new()),
        Arc::new(MemorySessionStore::new()) as Arc<dyn SessionStore>,
        "a-cookie-secret-of-at-least-32-chars",
    )
    .build()
    .unwrap();
    let router = Router::new()
        .merge(auth_router::<AuthHandlers>(handlers.clone()))
        .route(
            "/api/private",
            get(|AuthSession(session): AuthSession| async move { session.user_id }),
        )
        .route(
            "/api/maybe",
            get(
                |OptionalAuthSession(session): OptionalAuthSession| async move {
                    session.map_or_else(|| "anonymous".to_owned(), |session| session.user_id)
                },
            ),
        )
        .route(
            "/api/fails",
            get(|| async {
                Err::<String, AuthError>(AuthError(
                    ErrorCode::Gw001.error().with_message("internal detail"),
                ))
            }),
        )
        .with_state(handlers);
    Harness { idp, router }
}

async fn call(router: &Router, request: Request<Body>) -> Response<Body> {
    router.clone().oneshot(request).await.unwrap()
}

fn get_request(path: &str, cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .uri(path)
        .header(header::HOST, "evil.test");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Body::empty()).unwrap()
}

async fn text(response: Response<Body>) -> String {
    String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

fn cookie_pair(response: &Response<Body>, base: &str) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .find(|cookie| cookie.starts_with(&format!("__Host-{base}=")))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

async fn signed_in(h: &Harness) -> String {
    let login = call(&h.router, get_request("/auth/login?next=/dash", None)).await;
    assert_eq!(login.status(), StatusCode::FOUND);
    let params = query_of(login.headers()[header::LOCATION].to_str().unwrap());
    let id_token = h
        .idp
        .id_token(json!({ "nonce": params["nonce"][0], "sid": "sid-1" }));
    h.idp.on_token(move |_| {
        respond(
            200,
            &json!({ "access_token": "a", "token_type": "Bearer", "expires_in": 60, "refresh_token": "r", "id_token": id_token }),
        )
    });
    let callback_path = format!(
        "/auth/callback?code=abc&state={}&iss={ISSUER}",
        params["state"][0]
    );
    let callback = call(
        &h.router,
        get_request(&callback_path, Some(&cookie_pair(&login, "aai_login"))),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    assert_eq!(callback.headers()[header::LOCATION], "/dash");
    assert_eq!(
        callback
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        2,
        "Set-Cookie headers stay apart"
    );
    cookie_pair(&callback, "aai_session")
}

#[tokio::test]
async fn the_sign_in_routes_are_served_below_the_base_path() {
    let h = harness();
    let login = call(&h.router, get_request("/auth/login", None)).await;
    assert_eq!(login.status(), StatusCode::FOUND);
    assert!(
        login.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .starts_with(&format!("{ISSUER}/authorize?"))
    );
    assert_eq!(login.headers()[header::CACHE_CONTROL], "no-store");

    assert_eq!(
        call(&h.router, get_request("/auth/unknown", None))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&h.router, get_request("/nowhere", None))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    let wrong_method = call(
        &h.router,
        Request::builder()
            .method("POST")
            .uri("/auth/login")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(wrong_method.headers()[header::ALLOW], "GET");
}

#[tokio::test]
async fn a_whole_sign_in_through_axum_unlocks_the_extractors() {
    let h = harness();
    let cookie = signed_in(&h).await;

    let private = call(&h.router, get_request("/api/private", Some(&cookie))).await;
    assert_eq!(private.status(), StatusCode::OK);
    assert_eq!(text(private).await, "user-1");
    assert_eq!(
        text(call(&h.router, get_request("/api/maybe", Some(&cookie))).await).await,
        "user-1"
    );

    let me = call(&h.router, get_request("/auth/me", Some(&cookie))).await;
    let body: Value = serde_json::from_str(&text(me).await).unwrap();
    assert_eq!(body["user"]["sub"], "user-1");
}

#[tokio::test]
async fn the_callback_is_built_on_the_registered_origin_whatever_the_host_header_says() {
    let h = harness();
    signed_in(&h).await;
    let form = support::form_of(&h.idp.requests_to("/token")[0]);
    assert_eq!(form["redirect_uri"], format!("{ORIGIN}/auth/callback"));
}

#[tokio::test]
async fn a_signed_out_request_is_answered_401_with_the_public_envelope() {
    let h = harness();
    for cookie in [None, Some("__Host-aai_session=garbage")] {
        let response = call(&h.router, get_request("/api/private", cookie)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body: Value = serde_json::from_str(&text(response).await).unwrap();
        assert_eq!(
            body,
            json!({ "error": { "code": "SES_001", "message": "Not signed in" } })
        );
    }
    assert_eq!(
        text(call(&h.router, get_request("/api/maybe", None)).await).await,
        "anonymous"
    );
}

#[tokio::test]
async fn an_auth_error_leaks_neither_the_message_nor_the_details() {
    let h = harness();
    let response = call(&h.router, get_request("/api/fails", None)).await;
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    let raw = text(response).await;
    assert!(!raw.contains("internal detail"));
    let body: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(body["error"]["code"], "GW_001");
}

#[tokio::test]
async fn an_oversized_body_is_refused_before_it_is_buffered() {
    let h = harness();
    let request = Request::builder()
        .method("POST")
        .uri("/auth/backchannel-logout")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(vec![b'a'; MAX_BODY_BYTES + 1]))
        .unwrap();
    let response = call(&h.router, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_str(&text(response).await).unwrap();
    assert_eq!(body["error"]["code"], "REQ_001");
}

#[tokio::test]
async fn logout_through_axum_honours_the_cross_site_guard() {
    let h = harness();
    let cookie = signed_in(&h).await;
    let cross = Request::builder()
        .method("POST")
        .uri("/auth/logout")
        .header(header::ORIGIN, "https://evil.test")
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&h.router, cross).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        call(&h.router, get_request("/api/private", Some(&cookie)))
            .await
            .status(),
        StatusCode::OK
    );

    let same = Request::builder()
        .method("POST")
        .uri("/auth/logout")
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let response = call(&h.router, same).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        call(&h.router, get_request("/api/private", Some(&cookie)))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}
