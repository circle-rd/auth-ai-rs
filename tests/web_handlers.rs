#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

//! The backend-for-frontend routes end to end against a scripted identity provider.

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use auth_ai::web::{AuthHandlers, MemorySessionStore, Session, SessionStore};
use auth_ai::{
    AiClient, AuthAiError, AuthClient, AuthClientConfig, ErrorCallback, ErrorCode, GrantManager, MemoryGrantStore,
    WebRequest, WebResponse,
};
use serde_json::{Value, json};
use support::{
    CLIENT_ID, CLIENT_SECRET, GATEWAY_URL, ISSUER, MockIdp, form_of, merge, now, path_of, query_of, respond,
    token_response,
};

const ORIGIN: &str = "https://app.test";
const SECRET: &str = "a-cookie-secret-of-at-least-32-chars";

struct Options {
    renew_seconds: i64,
    require_sid: bool,
    error_redirect: Option<&'static str>,
    ai: bool,
    refresh_token: bool,
    secret: &'static str,
}

impl Default for Options {
    fn default() -> Self {
        Self { renew_seconds: 900, require_sid: true, error_redirect: None, ai: false, refresh_token: true, secret: SECRET }
    }
}

struct App {
    idp: Arc<MockIdp>,
    handlers: AuthHandlers,
    sessions: Arc<MemorySessionStore>,
    grants: GrantManager,
    errors: Arc<Mutex<Vec<AuthAiError>>>,
    ended: Arc<Mutex<Vec<usize>>>,
    login_tokens: Arc<Mutex<Value>>,
    renewal_claims: Arc<Mutex<Value>>,
}

fn auth_client(idp: &Arc<MockIdp>) -> AuthClient {
    let config = AuthClientConfig::builder(ISSUER, CLIENT_ID, format!("{ORIGIN}/auth/callback"))
        .client_secret(CLIENT_SECRET)
        .gateway_url(GATEWAY_URL)
        .post_logout_redirect_uri(format!("{ORIGIN}/auth/logout/callback"))
        .build()
        .unwrap();
    AuthClient::with_transport(config, Arc::clone(idp) as Arc<dyn auth_ai::Transport>)
}

impl App {
    fn new(options: &Options) -> Self {
        let idp = MockIdp::new();
        let auth = auth_client(&idp);
        let grants = GrantManager::new(auth.clone(), MemoryGrantStore::new());
        let sessions = Arc::new(MemorySessionStore::new());
        let errors = Arc::new(Mutex::new(Vec::new()));
        let ended = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&errors);
        let ended_sink = Arc::clone(&ended);
        let on_error: ErrorCallback = Arc::new(move |err: &AuthAiError| {
            sink.lock().unwrap().push(AuthAiError::new(err.code()).with_message(err.message().to_owned()));
        });
        let mut builder = AuthHandlers::builder(
            auth.clone(),
            grants.clone(),
            Arc::clone(&sessions) as Arc<dyn SessionStore>,
            options.secret,
        )
        .claims_renew_seconds(options.renew_seconds)
        .require_provider_session(options.require_sid)
        .on_error(on_error)
        .on_sessions_ended(Arc::new(move |sessions: Vec<Session>| {
            let ended_sink = Arc::clone(&ended_sink);
            Box::pin(async move {
                ended_sink.lock().unwrap().push(sessions.len());
                Ok(())
            })
        }));
        if let Some(target) = options.error_redirect {
            builder = builder.error_redirect(target);
        }
        if options.ai {
            builder = builder.ai(AiClient::new(auth, grants.clone()));
        }
        let login_tokens = Arc::new(Mutex::new(Value::Null));
        let renewal_claims = Arc::new(Mutex::new(json!({})));
        let (login, renewal, signer) = (Arc::clone(&login_tokens), Arc::clone(&renewal_claims), Arc::clone(&idp));
        let with_refresh = options.refresh_token;
        idp.on_token(move |request| match form_of(request)["grant_type"].as_str() {
            "authorization_code" => {
                let mut body = login.lock().unwrap().clone();
                if !with_refresh {
                    body.as_object_mut().unwrap().remove("refresh_token");
                }
                respond(200, &body)
            }
            _ => {
                let mut claims = json!({ "sid": "sid-1" });
                merge(&mut claims, &renewal.lock().unwrap());
                token_response(&json!({
                    "access_token": "renewed", "refresh_token": "refresh-2", "id_token": signer.id_token(claims)
                }))
            }
        });
        Self { idp, handlers: builder.build().unwrap(), sessions, grants, errors, ended, login_tokens, renewal_claims }
    }

    async fn send(&self, request: WebRequest) -> WebResponse {
        self.handlers.handle(&request).await.expect("a route of the handlers")
    }

    async fn get(&self, path: &str, cookie: Option<&str>) -> WebResponse {
        self.send(with_cookie(WebRequest::new("GET", format!("{ORIGIN}{path}")), cookie)).await
    }

    async fn post(&self, path: &str, cookie: Option<&str>) -> WebResponse {
        self.send(with_cookie(WebRequest::new("POST", format!("{ORIGIN}{path}")), cookie)).await
    }

    /// Signs in and returns the `name=value` pair of the session cookie.
    async fn sign_in(&self, id_claims: &Value) -> String {
        let login = self.get("/auth/login?next=/dash", None).await;
        let (login_cookie, params) = (cookie_pair(&login, "aai_login"), query_of(location(&login)));
        let nonce = params["nonce"][0].clone();
        let mut claims = json!({ "nonce": nonce, "sid": "sid-1", "roles": ["editor"] });
        merge(&mut claims, id_claims);
        *self.login_tokens.lock().unwrap() = json!({
            "access_token": "access-1", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "refresh-1",
            "id_token": self.idp.id_token(claims)
        });
        let callback = self.get(&callback_path(&params["state"][0]), Some(&login_cookie)).await;
        assert_eq!(callback.status, 303, "{:?}", callback.json());
        cookie_pair(&callback, "aai_session")
    }

    fn reported(&self) -> Vec<ErrorCode> {
        self.errors.lock().unwrap().iter().map(AuthAiError::code).collect()
    }
}

fn callback_path(state: &str) -> String {
    format!("/auth/callback?code=abc&state={state}&iss={ISSUER}")
}

fn with_cookie(request: WebRequest, cookie: Option<&str>) -> WebRequest {
    cookie.map_or(request.clone(), |cookie| request.with_header("cookie", cookie))
}

fn location(response: &WebResponse) -> &str {
    response.header("location").unwrap()
}

/// `name=value` of a cookie the response sets, whatever the `__Host-` prefix.
fn cookie_pair(response: &WebResponse, base: &str) -> String {
    set_cookie(response, base).split(';').next().unwrap().to_owned()
}

fn set_cookie<'a>(response: &'a WebResponse, base: &str) -> &'a str {
    response
        .header_values("set-cookie")
        .into_iter()
        .find(|cookie| cookie.starts_with(&format!("__Host-{base}=")) || cookie.starts_with(&format!("{base}=")))
        .unwrap_or_else(|| panic!("no {base} cookie in {:?}", response.headers))
}

fn error_code(response: &WebResponse) -> String {
    response.json().unwrap()["error"]["code"].as_str().unwrap().to_owned()
}

impl App {
    async fn sessions_len(&self) -> usize {
        self.sessions.count_by_user("user-1").await.unwrap()
    }
}

// ── configuration ──

#[tokio::test]
async fn the_base_path_and_the_redirect_uri_must_agree() {
    let idp = MockIdp::new();
    let build = |base: &str, redirect: &str, secret: &str| {
        let config = AuthClientConfig::builder(ISSUER, CLIENT_ID, redirect).client_secret(CLIENT_SECRET).build().unwrap();
        let auth = AuthClient::with_transport(config, Arc::clone(&idp) as Arc<dyn auth_ai::Transport>);
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
    assert!(build("/api/v1/auth", "https://app.test/api/v1/auth/callback", SECRET).is_ok());
    for (base, redirect) in [
        ("auth", "https://app.test/auth/callback"),
        ("/auth/", "https://app.test/auth/callback"),
        ("/au th", "https://app.test/au th/callback"),
        ("/auth", "https://app.test/callback"),
        ("/auth", "https://app.test/other/callback"),
    ] {
        assert_eq!(build(base, redirect, SECRET).unwrap_err().code(), ErrorCode::Cfg001, "{base} {redirect}");
    }
    assert_eq!(build("/auth", "https://app.test/auth/callback", "short").unwrap_err().code(), ErrorCode::Cfg001);
}

#[tokio::test]
async fn only_known_routes_below_the_base_path_are_served() {
    let app = App::new(&Options::default());
    for path in ["/", "/other", "/auth", "/auth/", "/auth/unknown", "/authx/login", "/auth/wallet"] {
        assert!(app.handlers.handle(&WebRequest::new("GET", format!("{ORIGIN}{path}"))).await.is_none(), "{path}");
    }
    let wrong = app.send(WebRequest::new("POST", format!("{ORIGIN}/auth/login"))).await;
    assert_eq!(wrong.status, 405);
    assert_eq!(wrong.header("allow"), Some("GET"));
    assert_eq!(app.post("/auth/me", None).await.status, 405);
    assert_eq!(app.get("/auth/logout", None).await.header("allow"), Some("POST"));
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
    for attribute in ["Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=600", "Secure"] {
        assert!(cookie.contains(attribute), "{attribute} missing from {cookie}");
    }
    for secret in ["state", "verifier"] {
        assert!(!cookie.to_lowercase().contains(secret));
    }
    let params = query_of(location(&response));
    assert!(!cookie.contains(&params["state"][0]), "the state is sealed, not stored in clear");
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

    let callback = app.get(&callback_path(&params["state"][0]), Some(&cookie_pair(&login, "aai_login"))).await;

    assert_eq!(callback.status, 303);
    assert_eq!(location(&callback), "/dash");
    assert_eq!(callback.header("cache-control"), Some("no-store"));
    assert!(set_cookie(&callback, "aai_login").contains("Max-Age=0"), "the login cookie is one-shot");
    let session = set_cookie(&callback, "aai_session");
    assert!(session.contains("HttpOnly") && session.contains("Secure") && session.contains("Max-Age=28800"), "{session}");
    assert!(app.grants.has("user-1").await.unwrap());

    let value = cookie_pair(&callback, "aai_session").split_once('=').unwrap().1.to_owned();
    assert!(app.sessions.get(&value).await.unwrap().is_none(), "the store never holds the cookie value itself");
    assert_eq!(app.sessions_len().await, 1);

    let all_cookies = callback.header_values("set-cookie").join(";");
    for secret in ["access-1", "refresh-1"] {
        assert!(!all_cookies.contains(secret) && !String::from_utf8_lossy(&callback.body).contains(secret));
    }
}

#[tokio::test]
async fn me_describes_the_user_without_any_token() {
    let app = App::new(&Options::default());
    let cookie = app.sign_in(&json!({ "name": "Ada", "email": "ada@x.y", "sid": "sid-9" })).await;
    let response = app.get("/auth/me", Some(&cookie)).await;

    assert_eq!(response.status, 200);
    let body = response.json().unwrap();
    assert_eq!(body["user"], json!({
        "sub": "user-1", "name": "Ada", "email": "ada@x.y", "roles": ["editor"], "permissions": [], "features": {}
    }));
    assert!(body["expiresAt"].as_i64().unwrap() > now());
    let text = body.to_string();
    for leaked in ["sid-9", "access-1", "refresh-1", "id_token", "sid"] {
        assert!(!text.contains(leaked), "{leaked}");
    }
}

#[tokio::test]
async fn me_answers_401_ses_001_without_a_valid_session() {
    let app = App::new(&Options::default());
    for cookie in [None, Some("__Host-aai_session=garbage"), Some("__Host-aai_session="), Some("aai_session=anything")] {
        let response = app.get("/auth/me", cookie).await;
        assert_eq!(response.status, 401, "{cookie:?}");
        assert_eq!(error_code(&response), "SES_001");
    }
}

#[tokio::test]
async fn a_session_without_a_refresh_token_cannot_outlive_its_id_token() {
    let app = App::new(&Options { refresh_token: false, ..Options::default() });
    let cookie = app.sign_in(&json!({ "exp": now() + 120 })).await;
    let response = app.get("/auth/me", Some(&cookie)).await;
    let expires = response.json().unwrap()["expiresAt"].as_i64().unwrap();
    assert!((expires - (now() + 120)).abs() <= 2, "{expires}");
    assert!(!app.grants.has("user-1").await.unwrap(), "no grant without a refresh token");
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
        WebRequest::new("GET", format!("{ORIGIN}{}", callback_path(&params["state"][0]))),
        Some(&cookie_pair(&login, "aai_login")),
    );
    app.send(tamper(&request)).await
}

#[tokio::test]
async fn every_failed_callback_answers_the_same_generic_403_and_clears_the_cookie() {
    let app = App::new(&Options::default());
    type Tamper = Box<dyn FnOnce(&WebRequest) -> WebRequest>;
    let tampers: Vec<(&str, Tamper)> = vec![
        ("forged state", Box::new(|r| WebRequest { url: r.url.replace("state=", "state=forged"), ..r.clone() })),
        ("missing cookie", Box::new(|r| WebRequest { headers: vec![], ..r.clone() })),
        (
            "tampered cookie",
            Box::new(|r| {
                let mut copy = r.clone();
                let cookie = copy.headers.iter_mut().find(|(name, _)| name == "cookie").unwrap();
                cookie.1.push('x');
                copy
            }),
        ),
        ("provider error", Box::new(|r| WebRequest { url: r.url.replace("code=abc", "error=access_denied"), ..r.clone() })),
    ];
    for (label, tamper) in tampers {
        let response = failed_callback(&app, tamper).await;
        assert_eq!(response.status, 403, "{label}");
        assert_eq!(response.json().unwrap(), json!({ "error": { "code": "SES_005", "message": "Sign-in failed" } }), "{label}");
        assert!(set_cookie(&response, "aai_login").contains("Max-Age=0"), "{label}");
        assert!(response.header_values("set-cookie").iter().all(|c| !c.contains("aai_session")), "{label}");
    }
    assert_eq!(app.reported().len(), 4, "every cause reaches on_error");
    assert!(!app.grants.has("user-1").await.unwrap());
}

#[tokio::test]
async fn a_token_endpoint_failure_hides_its_cause_from_the_browser() {
    let app = App::new(&Options::default());
    app.idp.on_token(|_| respond(401, &json!({ "error": "invalid_client", "error_description": "bad secret" })));
    let login = app.get("/auth/login", None).await;
    let state = query_of(location(&login))["state"][0].clone();
    let response = app.get(&callback_path(&state), Some(&cookie_pair(&login, "aai_login"))).await;
    assert_eq!(response.status, 403);
    assert!(!String::from_utf8_lossy(&response.body).contains("invalid_client"));
    assert_eq!(app.reported(), [ErrorCode::Oidc003]);
}

#[tokio::test]
async fn a_cookie_sealed_for_another_application_is_refused() {
    let app = App::new(&Options::default());
    let other = App::new(&Options { secret: "another-secret-of-at-least-32-characters", ..Options::default() });
    let login = other.get("/auth/login", None).await;
    let state = query_of(location(&login))["state"][0].clone();
    let response = app.get(&callback_path(&state), Some(&cookie_pair(&login, "aai_login"))).await;
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
    assert_eq!(app.get(&path, Some(&cookie_pair(&login, "aai_login"))).await.status, 303);
    assert_eq!(app.get(&path, None).await.status, 403, "the browser dropped the cleared cookie");
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
    let response = strict.get(&callback_path(&params["state"][0]), Some(&cookie_pair(&login, "aai_login"))).await;
    assert_eq!(response.status, 403);
    assert_eq!(strict.reported(), [ErrorCode::Ses003]);
    assert!(!strict.grants.has("user-1").await.unwrap(), "no grant is kept for a refused sign-in");

    let lenient = App::new(&Options { require_sid: false, ..Options::default() });
    let login = lenient.get("/auth/login", None).await;
    let params = query_of(location(&login));
    *lenient.login_tokens.lock().unwrap() = json!({
        "access_token": "a", "token_type": "Bearer", "expires_in": 60, "refresh_token": "r",
        "id_token": lenient.idp.id_token(json!({ "nonce": params["nonce"][0] }))
    });
    let response = lenient.get(&callback_path(&params["state"][0]), Some(&cookie_pair(&login, "aai_login"))).await;
    assert_eq!(response.status, 303);
}

#[tokio::test]
async fn a_failed_sign_in_can_redirect_to_an_error_page() {
    let app = App::new(&Options { error_redirect: Some("/login-failed"), ..Options::default() });
    let response = failed_callback(&app, |r| WebRequest { url: r.url.replace("state=", "state=x"), ..r.clone() }).await;
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
    let request = WebRequest::new("GET", format!("https://evil.test{}", callback_path(&params["state"][0])))
        .with_header("host", "evil.test")
        .with_header("x-forwarded-host", "evil.test")
        .with_header("cookie", cookie_pair(&login, "aai_login"));
    assert_eq!(app.send(request).await.status, 303);
    assert_eq!(form_of(&app.idp.requests_to("/token")[0])["redirect_uri"], format!("{ORIGIN}/auth/callback"));
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
        let callback = app.get(&callback_path(&params["state"][0]), Some(&cookie_pair(&login, "aai_login"))).await;
        let target = location(&callback);
        assert!(target == "/" || target == "/%5Cevil", "{next} -> {target}");
        assert!(!target.contains("evil.test"));
    }
}

// ── sign-out ──

#[tokio::test]
async fn a_cross_site_logout_is_refused_and_keeps_the_session() {
    let app = App::new(&Options::default());
    let cookie = app.sign_in(&json!({})).await;
    for header in [("origin", "https://evil.test"), ("origin", "null"), ("sec-fetch-site", "cross-site")] {
        let request = WebRequest::new("POST", format!("{ORIGIN}/auth/logout")).with_header(header.0, header.1).with_header("cookie", &cookie);
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
    assert_eq!(params["post_logout_redirect_uri"], [format!("{ORIGIN}/auth/logout/callback")]);
    assert!(!params["id_token_hint"][0].is_empty() && !params["state"][0].is_empty());
    assert!(set_cookie(&response, "aai_session").contains("Max-Age=0"));
    assert!(set_cookie(&response, "aai_logout").contains("Max-Age=600"));
    assert_eq!(app.get("/auth/me", Some(&cookie)).await.status, 401);
    assert!(!app.grants.has("user-1").await.unwrap());
    assert_eq!(form_of(&app.idp.requests_to("/revoke")[0])["token"], "refresh-1");
    assert_eq!(*app.ended.lock().unwrap(), [1]);

    let back = app.get("/auth/logout/callback", Some(&cookie_pair(&response, "aai_logout"))).await;
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
    assert!(response.json().unwrap()["logoutUrl"].as_str().unwrap().starts_with(ISSUER));
}

#[tokio::test]
async fn the_grant_survives_while_the_user_has_another_session() {
    let app = App::new(&Options::default());
    let first = app.sign_in(&json!({})).await;
    let second = app.sign_in(&json!({})).await;
    app.post("/auth/logout", Some(&first)).await;
    assert!(app.grants.has("user-1").await.unwrap(), "another browser is still signed in");
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
    app.idp.update_metadata(&[("end_session_endpoint", Value::Null)]);
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
        assert_eq!((response.status, location(&response)), (303, "/"), "{cookie:?}");
    }
    let hostile = app.post("/auth/logout?next=//evil.test", None).await;
    let back = app.get("/auth/logout/callback", Some(&cookie_pair(&hostile, "aai_logout"))).await;
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
    assert_eq!(app.send(request).await.status, 400, "a replayed token is refused");
}

// ── claims renewal ──

#[tokio::test]
async fn claims_are_renewed_when_due_and_the_session_keeps_its_id() {
    let app = App::new(&Options { renew_seconds: 0, ..Options::default() });
    let cookie = app.sign_in(&json!({})).await;
    *app.renewal_claims.lock().unwrap() = json!({ "roles": ["admin"], "plan": "pro" });

    let response = app.get("/auth/me", Some(&cookie)).await;

    let user = &response.json().unwrap()["user"];
    assert_eq!((&user["roles"], &user["plan"]), (&json!(["admin"]), &json!("pro")));
    let refresh = app.idp.requests_to("/token").into_iter().map(|r| form_of(&r)).find(|f| f["grant_type"] == "refresh_token").unwrap();
    assert_eq!(refresh["refresh_token"], "refresh-1");
    assert!(!refresh.contains_key("resource"));
    assert_eq!(app.get("/auth/me", Some(&cookie)).await.status, 200, "the same cookie still works");
}

#[tokio::test]
async fn claims_are_not_renewed_before_they_are_due() {
    let app = App::new(&Options::default());
    let cookie = app.sign_in(&json!({})).await;
    app.get("/auth/me", Some(&cookie)).await;
    app.get("/auth/me", Some(&cookie)).await;
    assert!(app.idp.requests_to("/token").iter().all(|r| form_of(r)["grant_type"] != "refresh_token"));
}

#[tokio::test]
async fn simultaneous_requests_of_one_session_share_a_single_renewal() {
    let app = Arc::new(App::new(&Options::default()));
    let cookie = app.sign_in(&json!({})).await;
    let request = WebRequest::new("GET", format!("{ORIGIN}/api/thing")).with_header("cookie", &cookie);
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
    let refreshes = app.idp.requests_to("/token").iter().filter(|r| form_of(r)["grant_type"] == "refresh_token").count();
    assert_eq!(refreshes, 1, "a replayed refresh token would revoke the family");
}

#[tokio::test]
async fn a_revoked_grant_signs_the_user_out_at_the_next_renewal() {
    let app = App::new(&Options { renew_seconds: 0, ..Options::default() });
    let cookie = app.sign_in(&json!({})).await;
    app.idp.on_token(|_| respond(400, &json!({ "error": "invalid_grant" })));
    assert_eq!(app.get("/auth/me", Some(&cookie)).await.status, 401);
    assert_eq!(app.get("/auth/me", Some(&cookie)).await.status, 401);
    assert_eq!(*app.ended.lock().unwrap(), [1]);
}

#[tokio::test]
async fn a_renewal_that_yields_another_user_ends_the_session() {
    let app = App::new(&Options { renew_seconds: 0, ..Options::default() });
    let cookie = app.sign_in(&json!({})).await;
    *app.renewal_claims.lock().unwrap() = json!({ "sub": "someone-else" });
    let response = app.get("/auth/me", Some(&cookie)).await;
    assert_eq!((response.status, error_code(&response).as_str()), (401, "TOK_001"));
    *app.renewal_claims.lock().unwrap() = json!({});
    assert_eq!(app.get("/auth/me", Some(&cookie)).await.status, 401, "the session is gone");
}

#[tokio::test]
async fn a_userinfo_outage_does_not_fail_a_renewal() {
    let app = App::new(&Options { renew_seconds: 0, ..Options::default() });
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
    let app = App::new(&Options { renew_seconds: 0, ..Options::default() });
    let cookie = app.sign_in(&json!({})).await;
    app.idp.on_token(|_| respond(503, &json!({})));
    let response = app.get("/auth/me", Some(&cookie)).await;
    assert_eq!((response.status, error_code(&response).as_str()), (502, "OIDC_003"));
    app.idp.on_token(|_| token_response(&json!({})));
    assert_eq!(app.sessions_len().await, 1, "a transient failure must not sign the user out");
}

#[tokio::test]
async fn get_session_and_require_session_read_the_cookie() {
    let app = App::new(&Options::default());
    let cookie = app.sign_in(&json!({})).await;
    let request = WebRequest::new("GET", format!("{ORIGIN}/api/thing")).with_header("cookie", &cookie);
    assert_eq!(app.handlers.get_session(&request).await.unwrap().unwrap().user_id, "user-1");
    assert_eq!(app.handlers.require_session(&request).await.unwrap().claims.sub, "user-1");
    let anonymous = WebRequest::new("GET", format!("{ORIGIN}/api/thing"));
    assert!(app.handlers.get_session(&anonymous).await.unwrap().is_none());
    assert_eq!(app.handlers.require_session(&anonymous).await.unwrap_err().code(), ErrorCode::Ses001);
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
    app.idp.on_gateway(|_| respond(200, &json!({ "data": [{ "id": "gpt" }] })));
}

#[tokio::test]
async fn the_frontend_reads_the_wallet_and_the_models_without_holding_a_token() {
    let app = App::new(&Options { ai: true, ..Options::default() });
    user_api(&app);
    let cookie = app.sign_in(&json!({})).await;

    let wallet = app.get("/auth/wallet", Some(&cookie)).await;
    assert_eq!(wallet.status, 200);
    assert_eq!(wallet.json().unwrap(), json!({
        "balance": "7000000", "isUnlimited": false, "canSpend": true, "currency": "eur", "topupUrl": "https://idp.test/profile"
    }));
    let stats = app.get("/auth/wallet/stats?days=7", Some(&cookie)).await;
    assert_eq!(stats.json().unwrap()["days"], 7);
    assert!(app.idp.requests_to("/api/user/wallet/stats")[0].url.ends_with("?days=7"));
    let models = app.get("/auth/models", Some(&cookie)).await;
    assert_eq!(models.json().unwrap(), json!({ "models": [{ "id": "gpt" }] }));
}

#[tokio::test]
async fn the_wallet_routes_need_a_session_and_a_sane_query() {
    let app = App::new(&Options { ai: true, ..Options::default() });
    user_api(&app);
    let cookie = app.sign_in(&json!({})).await;
    for path in ["/auth/wallet", "/auth/wallet/stats", "/auth/models"] {
        assert_eq!(app.get(path, None).await.status, 401, "{path}");
    }
    for days in ["0", "91", "abc", "-1", "1.5"] {
        let response = app.get(&format!("/auth/wallet/stats?days={days}"), Some(&cookie)).await;
        assert_eq!((response.status, error_code(&response).as_str()), (400, "REQ_001"), "{days}");
    }
    assert_eq!(app.get("/auth/wallet/stats", Some(&cookie)).await.status, 200);
}

#[tokio::test]
async fn a_gateway_refusal_reaches_the_frontend_as_the_public_envelope() {
    let app = App::new(&Options { ai: true, ..Options::default() });
    app.idp.on_gateway(|_| respond(402, &json!({ "error": { "message": "internal budget detail" } })));
    let cookie = app.sign_in(&json!({})).await;
    let response = app.get("/auth/models", Some(&cookie)).await;
    assert_eq!(response.status, 402);
    assert_eq!(response.json().unwrap(), json!({
        "error": { "code": "GW_001", "message": "Insufficient credit: the wallet cannot pay for this call" }
    }));
}
