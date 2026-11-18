#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The backend-for-frontend routes: sign-out, back-channel logout, renewal and the wallet routes.

mod support;

use std::sync::Arc;
use std::time::Duration;

use auth_ai::web::SessionStore;
use auth_ai::{ErrorCode, WebRequest};
use serde_json::{Value, json};
use support::bff::*;
use support::*;

// ── sign-out ──

#[tokio::test]
async fn a_cross_site_logout_is_refused_and_keeps_the_session() {
    let app = App::new(&Options::default());
    let cookie = app.sign_in(&json!({})).await;
    for header in [
        ("origin", "https://evil.test"),
        ("origin", "null"),
        ("sec-fetch-site", "cross-site"),
    ] {
        let request = WebRequest::new("POST", format!("{ORIGIN}/auth/logout"))
            .with_header(header.0, header.1)
            .with_header("cookie", &cookie);
        let response = app.send(request).await;
        assert_eq!(response.status, 403, "{header:?}");
        assert_eq!(error_code(&response), "SES_004");
    }
    assert_eq!(app.get("/auth/me", Some(&cookie)).await.status, 200);
    assert!(app.idp.requests_to("/revoke").is_empty());
}

#[tokio::test]
async fn logout_ends_the_session_revokes_the_grant_and_sends_the_browser_to_the_provider() {
    let app = App::new(&Options::default());
    let cookie = app.sign_in(&json!({})).await;
    let request = WebRequest::new("POST", format!("{ORIGIN}/auth/logout?next=/bye"))
        .with_header("origin", ORIGIN)
        .with_header("cookie", &cookie);

    let response = app.send(request).await;

    assert_eq!(response.status, 303);
    let params = query_of(location(&response));
    assert!(location(&response).starts_with(&format!("{ISSUER}/end-session?")));
    assert_eq!(
        params["post_logout_redirect_uri"],
        [format!("{ORIGIN}/auth/logout/callback")]
    );
    assert!(!params["id_token_hint"][0].is_empty() && !params["state"][0].is_empty());
    assert!(set_cookie(&response, "aai_session").contains("Max-Age=0"));
    assert!(set_cookie(&response, "aai_logout").contains("Max-Age=600"));
    assert_eq!(app.get("/auth/me", Some(&cookie)).await.status, 401);
    assert!(!app.grants.has("user-1").await.unwrap());
    assert_eq!(
        form_of(&app.idp.requests_to("/revoke")[0])["token"],
        "refresh-1"
    );
    assert_eq!(*app.ended.lock().unwrap(), [1]);

    let back = app
        .get(
            "/auth/logout/callback",
            Some(&cookie_pair(&response, "aai_logout")),
        )
        .await;
    assert_eq!(back.status, 303);
    assert_eq!(location(&back), "/bye");
    assert!(set_cookie(&back, "aai_logout").contains("Max-Age=0"));
}

#[tokio::test]
async fn logout_can_answer_json_for_a_single_page_application() {
    let app = App::new(&Options::default());
    let cookie = app.sign_in(&json!({})).await;
    let request = WebRequest::new("POST", format!("{ORIGIN}/auth/logout"))
        .with_header("accept", "application/json")
        .with_header("sec-fetch-site", "same-origin")
        .with_header("cookie", &cookie);
    let response = app.send(request).await;
    assert_eq!(response.status, 200);
    assert!(
        response.json().unwrap()["logoutUrl"]
            .as_str()
            .unwrap()
            .starts_with(ISSUER)
    );
}

#[tokio::test]
async fn the_grant_survives_while_the_user_has_another_session() {
    let app = App::new(&Options::default());
    let first = app.sign_in(&json!({})).await;
    let second = app.sign_in(&json!({})).await;
    app.post("/auth/logout", Some(&first)).await;
    assert!(
        app.grants.has("user-1").await.unwrap(),
        "another browser is still signed in"
    );
    assert_eq!(app.get("/auth/me", Some(&second)).await.status, 200);
    app.post("/auth/logout", Some(&second)).await;
    assert!(!app.grants.has("user-1").await.unwrap());
}

#[tokio::test]
async fn logout_without_a_session_still_ends_the_provider_session() {
    let app = App::new(&Options::default());
    let response = app.post("/auth/logout", None).await;
    assert_eq!(response.status, 303);
    assert!(location(&response).starts_with(&format!("{ISSUER}/end-session")));
    assert!(!location(&response).contains("id_token_hint"));
}

#[tokio::test]
async fn a_provider_without_end_session_still_lets_the_local_session_end() {
    let app = App::new(&Options::default());
    app.idp
        .update_metadata(&[("end_session_endpoint", Value::Null)]);
    let cookie = app.sign_in(&json!({})).await;
    let response = app.post("/auth/logout?next=/bye", Some(&cookie)).await;
    assert_eq!(location(&response), "/bye");
    assert_eq!(app.get("/auth/me", Some(&cookie)).await.status, 401);
    assert_eq!(app.reported(), [ErrorCode::Oidc004]);
}

#[tokio::test]
async fn the_post_logout_redirect_never_strands_or_bounces_the_user() {
    let app = App::new(&Options::default());
    for cookie in [None, Some("__Host-aai_logout=garbage")] {
        let response = app.get("/auth/logout/callback", cookie).await;
        assert_eq!(
            (response.status, location(&response)),
            (303, "/"),
            "{cookie:?}"
        );
    }
    let hostile = app.post("/auth/logout?next=//evil.test", None).await;
    let back = app
        .get(
            "/auth/logout/callback",
            Some(&cookie_pair(&hostile, "aai_logout")),
        )
        .await;
    assert_eq!(location(&back), "/");
}

// ── back-channel logout ──

#[tokio::test]
async fn a_back_channel_logout_ends_every_session_of_the_provider_session() {
    let app = App::new(&Options::default());
    let cookie = app.sign_in(&json!({ "sid": "sid-77" })).await;
    let token = app.idp.signer().sign(
        &json!({
            "iss": ISSUER, "aud": CLIENT_ID, "sub": "user-1", "sid": "sid-77", "jti": "j-1", "iat": now(), "exp": now() + 60,
            "events": { "http://schemas.openid.net/event/backchannel-logout": {} }
        }),
        Some("key-1"),
        Some("logout+jwt"),
        false,
    );
    let request = WebRequest::new("POST", format!("{ORIGIN}/auth/backchannel-logout"))
        .with_header("content-type", "application/x-www-form-urlencoded")
        .with_body(format!("logout_token={token}"));

    assert_eq!(app.send(request.clone()).await.status, 200);
    assert_eq!(app.get("/auth/me", Some(&cookie)).await.status, 401);
    assert!(!app.grants.has("user-1").await.unwrap());
    assert_eq!(*app.ended.lock().unwrap(), [1]);
    assert_eq!(
        app.send(request).await.status,
        400,
        "a replayed token is refused"
    );
}

// ── claims renewal ──

#[tokio::test]
async fn claims_are_renewed_when_due_and_the_session_keeps_its_id() {
    let app = App::new(&Options {
        renew_seconds: 0,
        ..Options::default()
    });
    let cookie = app.sign_in(&json!({})).await;
    *app.renewal_claims.lock().unwrap() = json!({ "roles": ["admin"], "plan": "pro" });

    let response = app.get("/auth/me", Some(&cookie)).await;

    let user = &response.json().unwrap()["user"];
    assert_eq!(
        (&user["roles"], &user["plan"]),
        (&json!(["admin"]), &json!("pro"))
    );
    let refresh = app
        .idp
        .requests_to("/token")
        .into_iter()
        .map(|r| form_of(&r))
        .find(|f| f["grant_type"] == "refresh_token")
        .unwrap();
    assert_eq!(refresh["refresh_token"], "refresh-1");
    assert!(!refresh.contains_key("resource"));
    assert_eq!(
        app.get("/auth/me", Some(&cookie)).await.status,
        200,
        "the same cookie still works"
    );
}

#[tokio::test]
async fn claims_are_not_renewed_before_they_are_due() {
    let app = App::new(&Options::default());
    let cookie = app.sign_in(&json!({})).await;
    app.get("/auth/me", Some(&cookie)).await;
    app.get("/auth/me", Some(&cookie)).await;
    assert!(
        app.idp
            .requests_to("/token")
            .iter()
            .all(|r| form_of(r)["grant_type"] != "refresh_token")
    );
}

#[tokio::test]
async fn simultaneous_requests_of_one_session_share_a_single_renewal() {
    let app = Arc::new(App::new(&Options::default()));
    let cookie = app.sign_in(&json!({})).await;
    let request =
        WebRequest::new("GET", format!("{ORIGIN}/api/thing")).with_header("cookie", &cookie);
    let mut due = app.handlers.get_session(&request).await.unwrap().unwrap();
    due.renew_at = now() - 1;
    app.sessions.update(&due).await.unwrap();
    app.idp.set_token_delay(Duration::from_millis(60));

    let calls = (0..6).map(|_| {
        let (app, cookie) = (Arc::clone(&app), cookie.clone());
        tokio::spawn(async move { app.get("/auth/me", Some(&cookie)).await.status })
    });
    for call in calls {
        assert_eq!(call.await.unwrap(), 200);
    }
    let refreshes = app
        .idp
        .requests_to("/token")
        .iter()
        .filter(|r| form_of(r)["grant_type"] == "refresh_token")
        .count();
    assert_eq!(
        refreshes, 1,
        "a replayed refresh token would revoke the family"
    );
}

#[tokio::test]
async fn a_revoked_grant_signs_the_user_out_at_the_next_renewal() {
    let app = App::new(&Options {
        renew_seconds: 0,
        ..Options::default()
    });
    let cookie = app.sign_in(&json!({})).await;
    app.idp
        .on_token(|_| respond(400, &json!({ "error": "invalid_grant" })));
    assert_eq!(app.get("/auth/me", Some(&cookie)).await.status, 401);
    assert_eq!(app.get("/auth/me", Some(&cookie)).await.status, 401);
    assert_eq!(*app.ended.lock().unwrap(), [1]);
}

#[tokio::test]
async fn a_renewal_that_yields_another_user_ends_the_session() {
    let app = App::new(&Options {
        renew_seconds: 0,
        ..Options::default()
    });
    let cookie = app.sign_in(&json!({})).await;
    *app.renewal_claims.lock().unwrap() = json!({ "sub": "someone-else" });
    let response = app.get("/auth/me", Some(&cookie)).await;
    assert_eq!(
        (response.status, error_code(&response).as_str()),
        (401, "TOK_001")
    );
    *app.renewal_claims.lock().unwrap() = json!({});
    assert_eq!(
        app.get("/auth/me", Some(&cookie)).await.status,
        401,
        "the session is gone"
    );
}

#[tokio::test]
async fn a_userinfo_outage_does_not_fail_a_renewal() {
    let app = App::new(&Options {
        renew_seconds: 0,
        ..Options::default()
    });
    let cookie = app.sign_in(&json!({})).await;
    app.idp.on_userinfo(|_| respond(503, &json!({})));
    *app.renewal_claims.lock().unwrap() = json!({ "roles": ["viewer"] });
    let response = app.get("/auth/me", Some(&cookie)).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.json().unwrap()["user"]["roles"], json!(["viewer"]));
    assert!(app.reported().contains(&ErrorCode::Oidc003));
}

#[tokio::test]
async fn a_provider_outage_during_renewal_is_a_502_that_keeps_the_session() {
    let app = App::new(&Options {
        renew_seconds: 0,
        ..Options::default()
    });
    let cookie = app.sign_in(&json!({})).await;
    app.idp.on_token(|_| respond(503, &json!({})));
    let response = app.get("/auth/me", Some(&cookie)).await;
    assert_eq!(
        (response.status, error_code(&response).as_str()),
        (502, "OIDC_003")
    );
    app.idp.on_token(|_| token_response(&json!({})));
    assert_eq!(
        app.sessions_len().await,
        1,
        "a transient failure must not sign the user out"
    );
}

#[tokio::test]
async fn get_session_and_require_session_read_the_cookie() {
    let app = App::new(&Options::default());
    let cookie = app.sign_in(&json!({})).await;
    let request =
        WebRequest::new("GET", format!("{ORIGIN}/api/thing")).with_header("cookie", &cookie);
    assert_eq!(
        app.handlers
            .get_session(&request)
            .await
            .unwrap()
            .unwrap()
            .user_id,
        "user-1"
    );
    assert_eq!(
        app.handlers
            .require_session(&request)
            .await
            .unwrap()
            .claims
            .sub,
        "user-1"
    );
    let anonymous = WebRequest::new("GET", format!("{ORIGIN}/api/thing"));
    assert!(
        app.handlers
            .get_session(&anonymous)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        app.handlers
            .require_session(&anonymous)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Ses001
    );
}

// ── wallet and models for the frontend ──

fn user_api(app: &App) {
    app.idp.on_api(|request| match path_of(request).as_str() {
        "/api/user/wallet" => respond(200, &json!({ "balance": "7000000", "isUnlimited": false, "canSpend": true, "currency": "eur" })),
        _ => respond(
            200,
            &json!({ "days": 7, "total": "0", "notBilled": "0", "calls": 0, "series": [], "byApplication": [], "byKind": [], "byModel": [], "daily": [] }),
        ),
    });
    app.idp
        .on_gateway(|_| respond(200, &json!({ "data": [{ "id": "gpt" }] })));
}

#[tokio::test]
async fn the_frontend_reads_the_wallet_and_the_models_without_holding_a_token() {
    let app = App::new(&Options {
        ai: true,
        ..Options::default()
    });
    user_api(&app);
    let cookie = app.sign_in(&json!({})).await;

    let wallet = app.get("/auth/wallet", Some(&cookie)).await;
    assert_eq!(wallet.status, 200);
    assert_eq!(
        wallet.json().unwrap(),
        json!({
            "balance": "7000000", "isUnlimited": false, "canSpend": true, "currency": "eur", "topupUrl": "https://idp.test/profile"
        })
    );
    let stats = app.get("/auth/wallet/stats?days=7", Some(&cookie)).await;
    assert_eq!(stats.json().unwrap()["days"], 7);
    assert!(
        app.idp.requests_to("/api/user/wallet/stats")[0]
            .url
            .ends_with("?days=7")
    );
    let models = app.get("/auth/models", Some(&cookie)).await;
    assert_eq!(
        models.json().unwrap(),
        json!({ "models": [{ "id": "gpt" }] })
    );
}

#[tokio::test]
async fn the_wallet_routes_need_a_session_and_a_sane_query() {
    let app = App::new(&Options {
        ai: true,
        ..Options::default()
    });
    user_api(&app);
    let cookie = app.sign_in(&json!({})).await;
    for path in ["/auth/wallet", "/auth/wallet/stats", "/auth/models"] {
        assert_eq!(app.get(path, None).await.status, 401, "{path}");
    }
    for days in ["0", "91", "abc", "-1", "1.5"] {
        let response = app
            .get(&format!("/auth/wallet/stats?days={days}"), Some(&cookie))
            .await;
        assert_eq!(
            (response.status, error_code(&response).as_str()),
            (400, "REQ_001"),
            "{days}"
        );
    }
    assert_eq!(
        app.get("/auth/wallet/stats", Some(&cookie)).await.status,
        200
    );
}

#[tokio::test]
async fn a_gateway_refusal_reaches_the_frontend_as_the_public_envelope() {
    let app = App::new(&Options {
        ai: true,
        ..Options::default()
    });
    app.idp.on_gateway(|_| {
        respond(
            402,
            &json!({ "error": { "message": "internal budget detail" } }),
        )
    });
    let cookie = app.sign_in(&json!({})).await;
    let response = app.get("/auth/models", Some(&cookie)).await;
    assert_eq!(response.status, 402);
    assert_eq!(
        response.json().unwrap(),
        json!({
            "error": { "code": "GW_001", "message": "Insufficient credit: the wallet cannot pay for this call" }
        })
    );
}
