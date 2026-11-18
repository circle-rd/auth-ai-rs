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
use aws_lc_rs::hmac;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeySize, PublicKeyComponents};
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING,
    ECDSA_P521_SHA512_FIXED_SIGNING, EcdsaKeyPair, EcdsaSigningAlgorithm, Ed25519KeyPair, KeyPair,
    RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384,
    RSA_PSS_SHA512, RsaKeyPair, RsaSignatureEncoding,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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

/// A signature algorithm of the SDK, as a provider would advertise it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestAlgorithm {
    Es256,
    Es384,
    Es512,
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Ed25519,
}

impl TestAlgorithm {
    pub const ALL: [Self; 10] = [
        Self::Es256,
        Self::Es384,
        Self::Es512,
        Self::Rs256,
        Self::Rs384,
        Self::Rs512,
        Self::Ps256,
        Self::Ps384,
        Self::Ps512,
        Self::Ed25519,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Ed25519 => "Ed25519",
        }
    }
}

enum Key {
    Ec(EcdsaKeyPair),
    Rsa(RsaKeyPair, &'static RsaSignatureEncoding),
    Ed25519(Ed25519KeyPair),
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A signing key of any supported algorithm and the JWK that publishes it.
pub struct Signer {
    algorithm: TestAlgorithm,
    key: Key,
    jwk: Value,
}

impl Signer {
    /// An ES256 key, which is what auth-service signs with.
    pub fn generate(kid: &str) -> Self {
        Self::generate_with(kid, TestAlgorithm::Es256)
    }

    pub fn generate_with(kid: &str, algorithm: TestAlgorithm) -> Self {
        let rng = SystemRandom::new();
        let mut jwk = json!({ "use": "sig", "kid": kid, "alg": algorithm.name() });
        let curve = |parameters: &'static EcdsaSigningAlgorithm,
                     crv: &str,
                     length: usize,
                     jwk: &mut Value| {
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(parameters, &rng).unwrap();
            let pair = EcdsaKeyPair::from_pkcs8(parameters, pkcs8.as_ref()).unwrap();
            let point = pair.public_key().as_ref().to_vec();
            merge_into(
                jwk,
                json!({
                    "kty": "EC", "crv": crv,
                    "x": b64(&point[1..=length]), "y": b64(&point[1 + length..1 + 2 * length]),
                }),
            );
            Key::Ec(pair)
        };
        let rsa = |padding: &'static RsaSignatureEncoding, jwk: &mut Value| {
            let pair = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
            let components = PublicKeyComponents::<Vec<u8>>::from(pair.public_key());
            merge_into(
                jwk,
                json!({ "kty": "RSA", "n": b64(&components.n), "e": b64(&components.e) }),
            );
            Key::Rsa(pair, padding)
        };
        let key = match algorithm {
            TestAlgorithm::Es256 => curve(&ECDSA_P256_SHA256_FIXED_SIGNING, "P-256", 32, &mut jwk),
            TestAlgorithm::Es384 => curve(&ECDSA_P384_SHA384_FIXED_SIGNING, "P-384", 48, &mut jwk),
            TestAlgorithm::Es512 => curve(&ECDSA_P521_SHA512_FIXED_SIGNING, "P-521", 66, &mut jwk),
            TestAlgorithm::Rs256 => rsa(&RSA_PKCS1_SHA256, &mut jwk),
            TestAlgorithm::Rs384 => rsa(&RSA_PKCS1_SHA384, &mut jwk),
            TestAlgorithm::Rs512 => rsa(&RSA_PKCS1_SHA512, &mut jwk),
            TestAlgorithm::Ps256 => rsa(&RSA_PSS_SHA256, &mut jwk),
            TestAlgorithm::Ps384 => rsa(&RSA_PSS_SHA384, &mut jwk),
            TestAlgorithm::Ps512 => rsa(&RSA_PSS_SHA512, &mut jwk),
            TestAlgorithm::Ed25519 => {
                let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
                let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
                merge_into(
                    &mut jwk,
                    json!({ "kty": "OKP", "crv": "Ed25519", "x": b64(pair.public_key().as_ref()) }),
                );
                Key::Ed25519(pair)
            }
        };
        Self {
            algorithm,
            key,
            jwk,
        }
    }

    pub fn algorithm(&self) -> TestAlgorithm {
        self.algorithm
    }

    pub fn jwk(&self) -> Value {
        self.jwk.clone()
    }

    pub fn raw_sign(&self, message: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        match &self.key {
            Key::Ec(pair) => pair.sign(&rng, message).unwrap().as_ref().to_vec(),
            Key::Ed25519(pair) => pair.sign(message).as_ref().to_vec(),
            Key::Rsa(pair, padding) => {
                let mut signature = vec![0_u8; pair.public_modulus_len()];
                pair.sign(*padding, &rng, message, &mut signature).unwrap();
                signature
            }
        }
    }

    /// A compact JWS with exactly this header.
    pub fn sign_with_header(&self, header: &Value, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        format!("{input}.{}", b64(&self.raw_sign(input.as_bytes())))
    }

    pub fn sign(
        &self,
        claims: &Value,
        kid: Option<&str>,
        typ: Option<&str>,
        omit_typ: bool,
    ) -> String {
        let mut header = json!({ "alg": self.algorithm.name() });
        if let Some(kid) = kid {
            header["kid"] = json!(kid);
        }
        if !omit_typ {
            header["typ"] = json!(typ.unwrap_or("JWT"));
        }
        self.sign_with_header(&header, claims)
    }
}

fn merge_into(target: &mut Value, extra: Value) {
    merge(target, &extra);
}

/// A token signed with a shared secret, for the algorithm-confusion tests.
pub fn hs256_token(claims: &Value, secret: &[u8]) -> String {
    let header = json!({ "alg": "HS256", "kid": "key-1", "typ": "JWT" });
    let input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret), input.as_bytes());
    format!("{input}.{}", b64(tag.as_ref()))
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
        Self::with_algorithm(TestAlgorithm::Es256)
    }

    pub fn with_algorithm(algorithm: TestAlgorithm) -> Arc<Self> {
        let metadata = json!({
            "issuer": ISSUER,
            "authorization_endpoint": format!("{ISSUER}/authorize"),
            "token_endpoint": format!("{ISSUER}/token"),
            "userinfo_endpoint": format!("{ISSUER}/userinfo"),
            "jwks_uri": format!("{ISSUER}/jwks"),
            "introspection_endpoint": format!("{ISSUER}/introspect"),
            "revocation_endpoint": format!("{ISSUER}/revoke"),
            "end_session_endpoint": format!("{ISSUER}/end-session"),
            "id_token_signing_alg_values_supported": [algorithm.name()],
            "authorization_response_iss_parameter_supported": true,
        });
        Arc::new(Self {
            signer: Signer::generate_with("key-1", algorithm),
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

/// A machine API whose tokens read `machine-<n>-<scope>`, and the count of tokens minted.
pub fn machine() -> (
    Arc<MockIdp>,
    auth_ai::server::MachineApi,
    Arc<std::sync::atomic::AtomicU32>,
) {
    use std::sync::atomic::{AtomicU32, Ordering};
    let idp = MockIdp::new();
    let minted = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&minted);
    idp.on_token(move |request| {
        let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
        let scope = form_of(request).get("scope").cloned().unwrap_or_default();
        token_response(&json!({ "access_token": format!("machine-{n}-{scope}") }))
    });
    let api = auth_ai::server::MachineApi::new(&test_auth(&idp)).unwrap();
    (idp, api, minted)
}

pub fn bearer(request: &HttpRequest) -> String {
    request.header("authorization").unwrap().to_owned()
}
