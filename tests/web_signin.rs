#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The backend-for-frontend routes: configuration, sign-in and its failures.

mod support;

use std::sync::Arc;

use auth_ai::web::{AuthHandlers, MemorySessionStore, SessionStore};
use auth_ai::{
    AuthClient, AuthClientConfig, ErrorCode, GrantManager, MemoryGrantStore, WebRequest,
    WebResponse,
};
use serde_json::json;
use support::bff::*;
use support::*;

// ── configuration ──

#[tokio::test]
async fn the_base_path_and_the_redirect_uri_must_agree() {
    let idp = MockIdp::new();
    let build = |base: &str, redirect: &str, secret: &str| {
        let config = AuthClientConfig::builder(ISSUER, CLIENT_ID, redirect)
            .client_secret(CLIENT_SECRET)
            .build()
            .unwrap();
        let auth =
            AuthClient::with_transport(config, Arc::clone(&idp) as Arc<dyn auth_ai::Transport>);
        AuthHandlers::builder(
            auth.clone(),
            GrantManager::new(auth, MemoryGrantStore::new()),
            Arc::new(MemorySessionStore::new()),
            secret,
        )
        .base_path(base)
        .build()
    };
    assert!(build("/auth", "https://app.test/auth/callback", SECRET).is_ok());
    assert!(
        build(
            "/api/v1/auth",
            "https://app.test/api/v1/auth/callback",
            SECRET
        )
        .is_ok()
    );
    for (base, redirect) in [
        ("auth", "https://app.test/auth/callback"),
        ("/auth/", "https://app.test/auth/callback"),
        ("/au th", "https://app.test/au th/callback"),
        ("/auth", "https://app.test/callback"),
        ("/auth", "https://app.test/other/callback"),
    ] {
        assert_eq!(
            build(base, redirect, SECRET).unwrap_err().code(),
            ErrorCode::Cfg001,
            "{base} {redirect}"
        );
    }
    assert_eq!(
        build("/auth", "https://app.test/auth/callback", "short")
            .unwrap_err()
            .code(),
        ErrorCode::Cfg001
    );
}

#[tokio::test]
async fn only_known_routes_below_the_base_path_are_served() {
    let app = App::new(&Options::default());
    for path in [
        "/",
        "/other",
        "/auth",
        "/auth/",
        "/auth/unknown",
        "/authx/login",
        "/auth/wallet",
    ] {
        assert!(
            app.handlers
                .handle(&WebRequest::new("GET", format!("{ORIGIN}{path}")))
                .await
                .is_none(),
            "{path}"
        );
    }
    let wrong = app
        .send(WebRequest::new("POST", format!("{ORIGIN}/auth/login")))
        .await;
    assert_eq!(wrong.status, 405);
    assert_eq!(wrong.header("allow"), Some("GET"));
    assert_eq!(app.post("/auth/me", None).await.status, 405);
    assert_eq!(
        app.get("/auth/logout", None).await.header("allow"),
        Some("POST")
    );
    assert_eq!(app.handlers.origin(), ORIGIN);
    assert_eq!(app.handlers.base_path(), "/auth");
}

// ── sign-in ──

#[tokio::test]
async fn login_redirects_to_the_provider_with_a_sealed_one_shot_cookie() {
    let app = App::new(&Options::default());
    let response = app.get("/auth/login?next=/dash&prompt=consent", None).await;

    assert_eq!(response.status, 302);
    assert!(location(&response).starts_with(&format!("{ISSUER}/authorize?")));
    assert_eq!(query_of(location(&response))["prompt"], ["consent"]);
    assert_eq!(response.header("cache-control"), Some("no-store"));
    let cookie = set_cookie(&response, "aai_login");
    assert!(cookie.starts_with("__Host-aai_login="), "{cookie}");
    for attribute in [
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=600",
        "Secure",
    ] {
        assert!(
            cookie.contains(attribute),
            "{attribute} missing from {cookie}"
        );
    }
    for secret in ["state", "verifier"] {
        assert!(!cookie.to_lowercase().contains(secret));
    }
    let params = query_of(location(&response));
    assert!(
        !cookie.contains(&params["state"][0]),
        "the state is sealed, not stored in clear"
    );
}

#[tokio::test]
async fn an_unknown_prompt_is_not_forwarded() {
    let app = App::new(&Options::default());
    let response = app.get("/auth/login?prompt=bogus", None).await;
    assert!(!query_of(location(&response)).contains_key("prompt"));
}

#[tokio::test]
async fn the_whole_sign_in_ends_with_an_opaque_session_cookie_and_a_stored_grant() {
    let app = App::new(&Options::default());
    let login = app.get("/auth/login?next=/dash", None).await;
    let params = query_of(location(&login));
    *app.login_tokens.lock().unwrap() = json!({
        "access_token": "access-1", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "refresh-1",
        "id_token": app.idp.id_token(json!({ "nonce": params["nonce"][0], "sid": "sid-1", "roles": ["editor"], "name": "Ada" }))
    });

    let callback = app
        .get(
            &callback_path(&params["state"][0]),
            Some(&cookie_pair(&login, "aai_login")),
        )
        .await;

    assert_eq!(callback.status, 303);
    assert_eq!(location(&callback), "/dash");
    assert_eq!(callback.header("cache-control"), Some("no-store"));
    assert!(
        set_cookie(&callback, "aai_login").contains("Max-Age=0"),
        "the login cookie is one-shot"
    );
    let session = set_cookie(&callback, "aai_session");
    assert!(
        session.contains("HttpOnly")
            && session.contains("Secure")
            && session.contains("Max-Age=28800"),
        "{session}"
    );
    assert!(app.grants.has("user-1").await.unwrap());

    let value = cookie_pair(&callback, "aai_session")
        .split_once('=')
        .unwrap()
        .1
        .to_owned();
    assert!(
        app.sessions.get(&value).await.unwrap().is_none(),
        "the store never holds the cookie value itself"
    );
    assert_eq!(app.sessions_len().await, 1);

    let all_cookies = callback.header_values("set-cookie").join(";");
    for secret in ["access-1", "refresh-1"] {
        assert!(
            !all_cookies.contains(secret)
                && !String::from_utf8_lossy(&callback.body).contains(secret)
        );
    }
}

#[tokio::test]
async fn me_describes_the_user_without_any_token() {
    let app = App::new(&Options::default());
    let cookie = app
        .sign_in(&json!({ "name": "Ada", "email": "ada@x.y", "sid": "sid-9" }))
        .await;
    let response = app.get("/auth/me", Some(&cookie)).await;

    assert_eq!(response.status, 200);
    let body = response.json().unwrap();
    assert_eq!(
        body["user"],
        json!({
            "sub": "user-1", "name": "Ada", "email": "ada@x.y", "roles": ["editor"], "permissions": [], "features": {}
        })
    );
    assert!(body["expiresAt"].as_i64().unwrap() > now());
    let text = body.to_string();
    for leaked in ["sid-9", "access-1", "refresh-1", "id_token", "sid"] {
        assert!(!text.contains(leaked), "{leaked}");
    }
}

#[tokio::test]
async fn me_answers_401_ses_001_without_a_valid_session() {
    let app = App::new(&Options::default());
    for cookie in [
        None,
        Some("__Host-aai_session=garbage"),
        Some("__Host-aai_session="),
        Some("aai_session=anything"),
    ] {
        let response = app.get("/auth/me", cookie).await;
        assert_eq!(response.status, 401, "{cookie:?}");
        assert_eq!(error_code(&response), "SES_001");
    }
}

#[tokio::test]
async fn a_session_without_a_refresh_token_cannot_outlive_its_id_token() {
    let app = App::new(&Options {
        refresh_token: false,
        ..Options::default()
    });
    let cookie = app.sign_in(&json!({ "exp": now() + 120 })).await;
    let response = app.get("/auth/me", Some(&cookie)).await;
    let expires = response.json().unwrap()["expiresAt"].as_i64().unwrap();
    assert!((expires - (now() + 120)).abs() <= 2, "{expires}");
    assert!(
        !app.grants.has("user-1").await.unwrap(),
        "no grant without a refresh token"
    );
}

// ── sign-in failures ──

async fn failed_callback(app: &App, tamper: impl FnOnce(&WebRequest) -> WebRequest) -> WebResponse {
    let login = app.get("/auth/login", None).await;
    let params = query_of(location(&login));
    *app.login_tokens.lock().unwrap() = json!({
        "access_token": "a", "token_type": "Bearer", "expires_in": 60, "refresh_token": "r",
        "id_token": app.idp.id_token(json!({ "nonce": params["nonce"][0], "sid": "s" }))
    });
    let request = with_cookie(
        WebRequest::new(
            "GET",
            format!("{ORIGIN}{}", callback_path(&params["state"][0])),
        ),
        Some(&cookie_pair(&login, "aai_login")),
    );
    app.send(tamper(&request)).await
}

#[tokio::test]
async fn every_failed_callback_answers_the_same_generic_403_and_clears_the_cookie() {
    let app = App::new(&Options::default());
    type Tamper = Box<dyn FnOnce(&WebRequest) -> WebRequest>;
    let tampers: Vec<(&str, Tamper)> = vec![
        (
            "forged state",
            Box::new(|r| WebRequest {
                url: r.url.replace("state=", "state=forged"),
                ..r.clone()
            }),
        ),
        (
            "missing cookie",
            Box::new(|r| WebRequest {
                headers: vec![],
                ..r.clone()
            }),
        ),
        (
            "tampered cookie",
            Box::new(|r| {
                let mut copy = r.clone();
                let cookie = copy
                    .headers
                    .iter_mut()
                    .find(|(name, _)| name == "cookie")
                    .unwrap();
                cookie.1.push('x');
                copy
            }),
        ),
        (
            "provider error",
            Box::new(|r| WebRequest {
                url: r.url.replace("code=abc", "error=access_denied"),
                ..r.clone()
            }),
        ),
    ];
    for (label, tamper) in tampers {
        let response = failed_callback(&app, tamper).await;
        assert_eq!(response.status, 403, "{label}");
        assert_eq!(
            response.json().unwrap(),
            json!({ "error": { "code": "SES_005", "message": "Sign-in failed" } }),
            "{label}"
        );
        assert!(
            set_cookie(&response, "aai_login").contains("Max-Age=0"),
            "{label}"
        );
        assert!(
            response
                .header_values("set-cookie")
                .iter()
                .all(|c| !c.contains("aai_session")),
            "{label}"
        );
    }
    assert_eq!(app.reported().len(), 4, "every cause reaches on_error");
    assert!(!app.grants.has("user-1").await.unwrap());
}

#[tokio::test]
async fn a_token_endpoint_failure_hides_its_cause_from_the_browser() {
    let app = App::new(&Options::default());
    app.idp.on_token(|_| {
        respond(
            401,
            &json!({ "error": "invalid_client", "error_description": "bad secret" }),
        )
    });
    let login = app.get("/auth/login", None).await;
    let state = query_of(location(&login))["state"][0].clone();
    let response = app
        .get(
            &callback_path(&state),
            Some(&cookie_pair(&login, "aai_login")),
        )
        .await;
    assert_eq!(response.status, 403);
    assert!(!String::from_utf8_lossy(&response.body).contains("invalid_client"));
    assert_eq!(app.reported(), [ErrorCode::Oidc003]);
}

#[tokio::test]
async fn a_cookie_sealed_for_another_application_is_refused() {
    let app = App::new(&Options::default());
    let other = App::new(&Options {
        secret: "another-secret-of-at-least-32-characters",
        ..Options::default()
    });
    let login = other.get("/auth/login", None).await;
    let state = query_of(location(&login))["state"][0].clone();
    let response = app
        .get(
            &callback_path(&state),
            Some(&cookie_pair(&login, "aai_login")),
        )
        .await;
    assert_eq!(response.status, 403);
    assert_eq!(app.reported(), [ErrorCode::Ses002]);
}

#[tokio::test]
async fn a_replayed_callback_fails_because_the_cookie_is_one_shot() {
    let app = App::new(&Options::default());
    let login = app.get("/auth/login", None).await;
    let params = query_of(location(&login));
    *app.login_tokens.lock().unwrap() = json!({
        "access_token": "a", "token_type": "Bearer", "expires_in": 60, "refresh_token": "r",
        "id_token": app.idp.id_token(json!({ "nonce": params["nonce"][0], "sid": "s" }))
    });
    let path = callback_path(&params["state"][0]);
    assert_eq!(
        app.get(&path, Some(&cookie_pair(&login, "aai_login")))
            .await
            .status,
        303
    );
    assert_eq!(
        app.get(&path, None).await.status,
        403,
        "the browser dropped the cleared cookie"
    );
}

#[tokio::test]
async fn an_id_token_without_sid_is_refused_when_a_provider_session_is_required() {
    let strict = App::new(&Options::default());
    let login = strict.get("/auth/login", None).await;
    let params = query_of(location(&login));
    *strict.login_tokens.lock().unwrap() = json!({
        "access_token": "a", "token_type": "Bearer", "expires_in": 60, "refresh_token": "r",
        "id_token": strict.idp.id_token(json!({ "nonce": params["nonce"][0] }))
    });
    let response = strict
        .get(
            &callback_path(&params["state"][0]),
            Some(&cookie_pair(&login, "aai_login")),
        )
        .await;
    assert_eq!(response.status, 403);
    assert_eq!(strict.reported(), [ErrorCode::Ses003]);
    assert!(
        !strict.grants.has("user-1").await.unwrap(),
        "no grant is kept for a refused sign-in"
    );

    let lenient = App::new(&Options {
        require_sid: false,
        ..Options::default()
    });
    let login = lenient.get("/auth/login", None).await;
    let params = query_of(location(&login));
    *lenient.login_tokens.lock().unwrap() = json!({
        "access_token": "a", "token_type": "Bearer", "expires_in": 60, "refresh_token": "r",
        "id_token": lenient.idp.id_token(json!({ "nonce": params["nonce"][0] }))
    });
    let response = lenient
        .get(
            &callback_path(&params["state"][0]),
            Some(&cookie_pair(&login, "aai_login")),
        )
        .await;
    assert_eq!(response.status, 303);
}

#[tokio::test]
async fn a_failed_sign_in_can_redirect_to_an_error_page() {
    let app = App::new(&Options {
        error_redirect: Some("/login-failed"),
        ..Options::default()
    });
    let response = failed_callback(&app, |r| WebRequest {
        url: r.url.replace("state=", "state=x"),
        ..r.clone()
    })
    .await;
    assert_eq!(response.status, 303);
    assert_eq!(location(&response), "/login-failed?error=SES_005");
    assert!(set_cookie(&response, "aai_login").contains("Max-Age=0"));
}

#[tokio::test]
async fn the_callback_url_is_built_on_the_registered_origin_not_on_a_header() {
    let app = App::new(&Options::default());
    let login = app.get("/auth/login", None).await;
    let params = query_of(location(&login));
    *app.login_tokens.lock().unwrap() = json!({
        "access_token": "a", "token_type": "Bearer", "expires_in": 60, "refresh_token": "r",
        "id_token": app.idp.id_token(json!({ "nonce": params["nonce"][0], "sid": "s" }))
    });
    let request = WebRequest::new(
        "GET",
        format!("https://evil.test{}", callback_path(&params["state"][0])),
    )
    .with_header("host", "evil.test")
    .with_header("x-forwarded-host", "evil.test")
    .with_header("cookie", cookie_pair(&login, "aai_login"));
    assert_eq!(app.send(request).await.status, 303);
    assert_eq!(
        form_of(&app.idp.requests_to("/token")[0])["redirect_uri"],
        format!("{ORIGIN}/auth/callback")
    );
}

#[tokio::test]
async fn an_open_redirect_target_falls_back_to_the_default() {
    let app = App::new(&Options::default());
    for next in ["//evil.test", "https://evil.test", "/%5Cevil", "evil"] {
        let login = app.get(&format!("/auth/login?next={next}"), None).await;
        let params = query_of(location(&login));
        *app.login_tokens.lock().unwrap() = json!({
            "access_token": "a", "token_type": "Bearer", "expires_in": 60, "refresh_token": "r",
            "id_token": app.idp.id_token(json!({ "nonce": params["nonce"][0], "sid": "s" }))
        });
        let callback = app
            .get(
                &callback_path(&params["state"][0]),
                Some(&cookie_pair(&login, "aai_login")),
            )
            .await;
        let target = location(&callback);
        assert!(target == "/" || target == "/%5Cevil", "{next} -> {target}");
        assert!(!target.contains("evil.test"));
    }
}
