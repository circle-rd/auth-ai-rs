#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The backend-for-frontend harness: handlers wired to a scripted identity provider.

use std::sync::{Arc, Mutex};

use auth_ai::web::{AuthHandlers, MemorySessionStore, Session, SessionStore};
use auth_ai::{
    AiClient, AuthAiError, AuthClient, AuthClientConfig, ErrorCallback, ErrorCode, GrantManager,
    MemoryGrantStore, WebRequest, WebResponse,
};
use serde_json::{Value, json};

use super::*;

pub const ORIGIN: &str = "https://app.test";
pub const SECRET: &str = "a-cookie-secret-of-at-least-32-chars";

pub struct Options {
    pub renew_seconds: i64,
    pub require_sid: bool,
    pub error_redirect: Option<&'static str>,
    pub ai: bool,
    pub refresh_token: bool,
    pub secret: &'static str,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            renew_seconds: 900,
            require_sid: true,
            error_redirect: None,
            ai: false,
            refresh_token: true,
            secret: SECRET,
        }
    }
}

pub struct App {
    pub idp: Arc<MockIdp>,
    pub handlers: AuthHandlers,
    pub sessions: Arc<MemorySessionStore>,
    pub grants: GrantManager,
    pub errors: Arc<Mutex<Vec<AuthAiError>>>,
    pub ended: Arc<Mutex<Vec<usize>>>,
    pub login_tokens: Arc<Mutex<Value>>,
    pub renewal_claims: Arc<Mutex<Value>>,
}

pub fn auth_client(idp: &Arc<MockIdp>) -> AuthClient {
    let config = AuthClientConfig::builder(ISSUER, CLIENT_ID, format!("{ORIGIN}/auth/callback"))
        .client_secret(CLIENT_SECRET)
        .gateway_url(GATEWAY_URL)
        .post_logout_redirect_uri(format!("{ORIGIN}/auth/logout/callback"))
        .build()
        .unwrap();
    AuthClient::with_transport(config, Arc::clone(idp) as Arc<dyn auth_ai::Transport>)
}

impl App {
    pub fn new(options: &Options) -> Self {
        let idp = MockIdp::new();
        let auth = auth_client(&idp);
        let grants = GrantManager::new(auth.clone(), MemoryGrantStore::new());
        let sessions = Arc::new(MemorySessionStore::new());
        let errors = Arc::new(Mutex::new(Vec::new()));
        let ended = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&errors);
        let ended_sink = Arc::clone(&ended);
        let on_error: ErrorCallback = Arc::new(move |err: &AuthAiError| {
            sink.lock()
                .unwrap()
                .push(AuthAiError::new(err.code()).with_message(err.message().to_owned()));
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
        let (login, renewal, signer) = (
            Arc::clone(&login_tokens),
            Arc::clone(&renewal_claims),
            Arc::clone(&idp),
        );
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
        Self {
            idp,
            handlers: builder.build().unwrap(),
            sessions,
            grants,
            errors,
            ended,
            login_tokens,
            renewal_claims,
        }
    }

    pub async fn send(&self, request: WebRequest) -> WebResponse {
        self.handlers
            .handle(&request)
            .await
            .expect("a route of the handlers")
    }

    pub async fn get(&self, path: &str, cookie: Option<&str>) -> WebResponse {
        self.send(with_cookie(
            WebRequest::new("GET", format!("{ORIGIN}{path}")),
            cookie,
        ))
        .await
    }

    pub async fn post(&self, path: &str, cookie: Option<&str>) -> WebResponse {
        self.send(with_cookie(
            WebRequest::new("POST", format!("{ORIGIN}{path}")),
            cookie,
        ))
        .await
    }

    /// Signs in and returns the `name=value` pair of the session cookie.
    pub async fn sign_in(&self, id_claims: &Value) -> String {
        let login = self.get("/auth/login?next=/dash", None).await;
        let (login_cookie, params) = (cookie_pair(&login, "aai_login"), query_of(location(&login)));
        let nonce = params["nonce"][0].clone();
        let mut claims = json!({ "nonce": nonce, "sid": "sid-1", "roles": ["editor"] });
        merge(&mut claims, id_claims);
        *self.login_tokens.lock().unwrap() = json!({
            "access_token": "access-1", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "refresh-1",
            "id_token": self.idp.id_token(claims)
        });
        let callback = self
            .get(&callback_path(&params["state"][0]), Some(&login_cookie))
            .await;
        assert_eq!(callback.status, 303, "{:?}", callback.json());
        cookie_pair(&callback, "aai_session")
    }

    pub fn reported(&self) -> Vec<ErrorCode> {
        self.errors
            .lock()
            .unwrap()
            .iter()
            .map(AuthAiError::code)
            .collect()
    }
}

pub fn callback_path(state: &str) -> String {
    format!("/auth/callback?code=abc&state={state}&iss={ISSUER}")
}

pub fn with_cookie(request: WebRequest, cookie: Option<&str>) -> WebRequest {
    cookie.map_or(request.clone(), |cookie| {
        request.with_header("cookie", cookie)
    })
}

pub fn location(response: &WebResponse) -> &str {
    response.header("location").unwrap()
}

/// `name=value` of a cookie the response sets, whatever the `__Host-` prefix.
pub fn cookie_pair(response: &WebResponse, base: &str) -> String {
    set_cookie(response, base)
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

pub fn set_cookie<'a>(response: &'a WebResponse, base: &str) -> &'a str {
    response
        .header_values("set-cookie")
        .into_iter()
        .find(|cookie| {
            cookie.starts_with(&format!("__Host-{base}="))
                || cookie.starts_with(&format!("{base}="))
        })
        .unwrap_or_else(|| panic!("no {base} cookie in {:?}", response.headers))
}

pub fn error_code(response: &WebResponse) -> String {
    response.json().unwrap()["error"]["code"]
        .as_str()
        .unwrap()
        .to_owned()
}

impl App {
    pub async fn sessions_len(&self) -> usize {
        self.sessions.count_by_user("user-1").await.unwrap()
    }
}
