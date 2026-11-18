// Each test crate compiles this module and uses a different subset of it.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! A scripted identity provider and gateway behind the SDK's `Transport` seam.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

pub mod bff;

use async_trait::async_trait;
use auth_ai::{
    AuthAiError, AuthClient, AuthClientConfig, AuthClientConfigBuilder, HttpRequest, HttpResponse,
    LoginHandshake, Transport, TransportError,
};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use url::Url;

pub const ISSUER: &str = "https://idp.test";
pub const CLIENT_ID: &str = "test-app";
pub const CLIENT_SECRET: &str = "test-secret";
pub const REDIRECT_URI: &str = "https://app.test/callback";
pub const GATEWAY_URL: &str = "https://llm.test";

pub type Handler = Box<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync>;

pub fn respond(status: u16, body: &Value) -> HttpResponse {
    HttpResponse::json(status, body)
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// An ES256 signing key and the JWK that publishes it.
pub struct Signer {
    der: Vec<u8>,
    jwk: Value,
}

impl Signer {
    pub fn generate(kid: &str) -> Self {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        let point = pair.public_key().as_ref().to_vec();
        let jwk = json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid,
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
        });
        Self {
            der: pkcs8.as_ref().to_vec(),
            jwk,
        }
    }

    pub fn jwk(&self) -> Value {
        self.jwk.clone()
    }

    pub fn sign(
        &self,
        claims: &Value,
        kid: Option<&str>,
        typ: Option<&str>,
        omit_typ: bool,
    ) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = kid.map(str::to_owned);
        header.typ = if omit_typ {
            None
        } else {
            Some(typ.unwrap_or("JWT").to_owned())
        };
        jsonwebtoken::encode(&header, claims, &EncodingKey::from_ec_der(&self.der)).unwrap()
    }
}

/// A token signed with a shared secret, for the algorithm-confusion tests.
pub fn hs256_token(claims: &Value, secret: &[u8]) -> String {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("key-1".to_owned());
    jsonwebtoken::encode(&header, claims, &EncodingKey::from_secret(secret).unwrap()).unwrap()
}

pub struct MockIdp {
    signer: Signer,
    pub metadata: Mutex<Value>,
    requests: Mutex<Vec<HttpRequest>>,
    gateway_requests: Mutex<Vec<HttpRequest>>,
    token_handler: Mutex<Handler>,
    userinfo_handler: Mutex<Handler>,
    api_handler: Mutex<Handler>,
    gateway_handler: Mutex<Handler>,
    revocation_status: Mutex<u16>,
    introspection: Mutex<Value>,
    discovery_failures: Mutex<u32>,
    jwks_override: Mutex<Option<Value>>,
    token_delay: Mutex<Duration>,
    offline: Mutex<bool>,
}

impl std::fmt::Debug for MockIdp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MockIdp")
    }
}

impl MockIdp {
    pub fn new() -> Arc<Self> {
        let metadata = json!({
            "issuer": ISSUER,
            "authorization_endpoint": format!("{ISSUER}/authorize"),
            "token_endpoint": format!("{ISSUER}/token"),
            "userinfo_endpoint": format!("{ISSUER}/userinfo"),
            "jwks_uri": format!("{ISSUER}/jwks"),
            "introspection_endpoint": format!("{ISSUER}/introspect"),
            "revocation_endpoint": format!("{ISSUER}/revoke"),
            "end_session_endpoint": format!("{ISSUER}/end-session"),
            "id_token_signing_alg_values_supported": ["ES256"],
            "authorization_response_iss_parameter_supported": true,
        });
        Arc::new(Self {
            signer: Signer::generate("key-1"),
            metadata: Mutex::new(metadata),
            requests: Mutex::new(Vec::new()),
            gateway_requests: Mutex::new(Vec::new()),
            token_handler: Mutex::new(Box::new(|_| {
                respond(500, &json!({ "error": "server_error" }))
            })),
            userinfo_handler: Mutex::new(Box::new(|_| respond(200, &json!({ "sub": "user-1" })))),
            api_handler: Mutex::new(Box::new(|_| {
                respond(
                    404,
                    &json!({ "error": { "code": "APP_002", "message": "unhandled" } }),
                )
            })),
            gateway_handler: Mutex::new(Box::new(|_| {
                respond(404, &json!({ "error": { "message": "unhandled" } }))
            })),
            revocation_status: Mutex::new(200),
            introspection: Mutex::new(json!({ "active": false })),
            discovery_failures: Mutex::new(0),
            jwks_override: Mutex::new(None),
            token_delay: Mutex::new(Duration::ZERO),
            offline: Mutex::new(false),
        })
    }

    pub fn on_token(&self, handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static) {
        *locked(&self.token_handler) = Box::new(handler);
    }

    pub fn on_userinfo(
        &self,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) {
        *locked(&self.userinfo_handler) = Box::new(handler);
    }

    pub fn on_api(&self, handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static) {
        *locked(&self.api_handler) = Box::new(handler);
    }

    pub fn on_gateway(
        &self,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) {
        *locked(&self.gateway_handler) = Box::new(handler);
    }

    pub fn set_revocation_status(&self, status: u16) {
        *locked(&self.revocation_status) = status;
    }

    pub fn set_introspection(&self, body: Value) {
        *locked(&self.introspection) = body;
    }

    pub fn fail_discovery(&self, times: u32) {
        *locked(&self.discovery_failures) = times;
    }

    pub fn set_jwks(&self, keys: Vec<Value>) {
        *locked(&self.jwks_override) = Some(json!({ "keys": keys }));
    }

    pub fn set_token_delay(&self, delay: Duration) {
        *locked(&self.token_delay) = delay;
    }

    pub fn go_offline(&self) {
        *locked(&self.offline) = true;
    }

    pub fn update_metadata(&self, entries: &[(&str, Value)]) {
        let mut metadata = locked(&self.metadata);
        for (name, value) in entries {
            metadata[*name] = value.clone();
        }
    }

    pub fn signer(&self) -> &Signer {
        &self.signer
    }

    pub fn sign_jwt(&self, claims: &Value) -> String {
        self.signer.sign(claims, Some("key-1"), None, false)
    }

    pub fn id_token(&self, extra: Value) -> String {
        let issued = now();
        let mut claims = json!({
            "iss": ISSUER, "sub": "user-1", "aud": CLIENT_ID, "iat": issued, "exp": issued + 300
        });
        merge(&mut claims, &extra);
        self.sign_jwt(&claims)
    }

    pub fn requests(&self) -> Vec<HttpRequest> {
        locked(&self.requests).clone()
    }

    pub fn requests_to(&self, path: &str) -> Vec<HttpRequest> {
        self.requests()
            .into_iter()
            .filter(|request| path_of(request) == path)
            .collect()
    }

    pub fn gateway_requests(&self) -> Vec<HttpRequest> {
        locked(&self.gateway_requests).clone()
    }

    fn jwks(&self) -> Value {
        locked(&self.jwks_override)
            .clone()
            .unwrap_or_else(|| json!({ "keys": [self.signer.jwk()] }))
    }
}

pub fn merge(target: &mut Value, extra: &Value) {
    if let (Some(target), Some(extra)) = (target.as_object_mut(), extra.as_object()) {
        for (name, value) in extra {
            target.insert(name.clone(), value.clone());
        }
    }
}

pub fn path_of(request: &HttpRequest) -> String {
    Url::parse(&request.url).unwrap().path().to_owned()
}

pub fn query_of(url: &str) -> HashMap<String, Vec<String>> {
    let mut query: HashMap<String, Vec<String>> = HashMap::new();
    for (name, value) in Url::parse(url).unwrap().query_pairs() {
        query
            .entry(name.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    query
}

pub fn form_of(request: &HttpRequest) -> HashMap<String, String> {
    url::form_urlencoded::parse(request.body.as_deref().unwrap_or_default())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

pub fn json_of(request: &HttpRequest) -> Value {
    serde_json::from_slice(request.body.as_deref().unwrap()).unwrap()
}

#[async_trait]
impl Transport for MockIdp {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        if *locked(&self.offline) {
            return Err(TransportError::new("The HTTP exchange could not connect"));
        }
        let url = Url::parse(&request.url).unwrap();
        if url.host_str() == Some("llm.test") {
            locked(&self.gateway_requests).push(request.clone());
            return Ok((locked(&self.gateway_handler))(&request));
        }
        locked(&self.requests).push(request.clone());
        let path = url.path();
        if path.ends_with("/.well-known/openid-configuration") {
            let mut failures = locked(&self.discovery_failures);
            if *failures > 0 {
                *failures -= 1;
                return Ok(HttpResponse {
                    status: 503,
                    headers: vec![],
                    body: b"unavailable".to_vec(),
                });
            }
            return Ok(respond(200, &locked(&self.metadata)));
        }
        Ok(match path {
            "/jwks" => respond(200, &self.jwks()),
            "/token" => {
                let delay = *locked(&self.token_delay);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                (locked(&self.token_handler))(&request)
            }
            "/userinfo" => (locked(&self.userinfo_handler))(&request),
            "/revoke" => HttpResponse {
                status: *locked(&self.revocation_status),
                headers: vec![],
                body: vec![],
            },
            "/introspect" => respond(200, &locked(&self.introspection)),
            _ if path.starts_with("/api/") => (locked(&self.api_handler))(&request),
            _ => HttpResponse {
                status: 404,
                headers: vec![],
                body: b"not found".to_vec(),
            },
        })
    }
}

pub fn config() -> AuthClientConfigBuilder {
    AuthClientConfig::builder(ISSUER, CLIENT_ID, REDIRECT_URI).client_secret(CLIENT_SECRET)
}

pub fn auth_with(idp: &Arc<MockIdp>, config: AuthClientConfigBuilder) -> AuthClient {
    AuthClient::with_transport(
        config.build().unwrap(),
        Arc::clone(idp) as Arc<dyn Transport>,
    )
}

pub fn test_auth(idp: &Arc<MockIdp>) -> AuthClient {
    auth_with(idp, config())
}

/// A token response with the given extra members.
pub fn token_response(extra: &Value) -> HttpResponse {
    let mut body = json!({ "access_token": "a", "token_type": "Bearer", "expires_in": 60 });
    merge(&mut body, extra);
    respond(200, &body)
}

// ── OIDC flow helpers shared by the client suites ──

pub const RESOURCES: [&str; 2] = ["https://app.test", "https://llm.test"];

pub fn client(idp: &Arc<MockIdp>) -> AuthClient {
    auth_with(
        idp,
        config()
            .post_logout_redirect_uri("https://app.test/")
            .resources(RESOURCES),
    )
}

pub fn callback_url(handshake: &LoginHandshake, extra: &str) -> String {
    format!(
        "{REDIRECT_URI}?code=abc&state={}&iss={ISSUER}{extra}",
        handshake.state.expose_secret()
    )
}

pub fn respond_with_tokens(idp: &Arc<MockIdp>, handshake: &LoginHandshake, claims: &Value) {
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

pub fn detail<'a>(err: &'a AuthAiError, key: &str) -> Option<&'a str> {
    err.detail(key).and_then(auth_ai::DetailValue::as_str)
}

pub async fn sign_in(
    idp: &Arc<MockIdp>,
    auth: &AuthClient,
    claims: &Value,
) -> auth_ai::LoginResult {
    let handshake = auth.start_login(None, None).await.unwrap().handshake;
    respond_with_tokens(idp, &handshake, claims);
    auth.handle_callback(&callback_url(&handshake, ""), &handshake)
        .await
        .unwrap()
}
