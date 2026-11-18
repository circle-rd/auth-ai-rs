//! Verification of the JWTs the provider signs, against its published keys.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value};
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::error::{AuthAiError, ErrorCode, Result};
use crate::jws::{self, Algorithm, PublicKey};
use crate::transport::{HttpRequest, Method, Transport};
use crate::util::now_unix_f64;

/// An unknown `kid` (key rotation) refreshes the keys at most once per second.
pub(crate) const JWKS_UNKNOWN_KID_COOLDOWN: Duration = Duration::from_secs(1);
/// Keys are re-fetched at least this often.
pub(crate) const JWKS_COOLDOWN: Duration = Duration::from_secs(30);
/// Keys older than this are never served.
pub(crate) const JWKS_MAX_AGE: Duration = Duration::from_secs(3600);

struct KeyEntry {
    kid: Option<String>,
    key: Arc<PublicKey>,
}

#[derive(Default)]
struct JwksState {
    keys: Vec<KeyEntry>,
    loaded_at: Option<Instant>,
    last_unknown_kid_refresh: Option<Instant>,
}

impl JwksState {
    fn has(&self, kid: &str) -> bool {
        self.keys
            .iter()
            .any(|entry| entry.kid.as_deref() == Some(kid))
    }
}

/// A JWKS fetched over HTTP and cached: unknown `kid` values refresh it, rate-limited.
pub(crate) struct RemoteJwks {
    uri: String,
    transport: Arc<dyn Transport>,
    timeout: Duration,
    algorithm: Algorithm,
    state: Mutex<JwksState>,
}

impl RemoteJwks {
    pub(crate) fn new(
        uri: String,
        transport: Arc<dyn Transport>,
        timeout: Duration,
        algorithm: Algorithm,
    ) -> Self {
        Self {
            uri,
            transport,
            timeout,
            algorithm,
            state: Mutex::new(JwksState::default()),
        }
    }

    /// The keys that may have signed a token with this `kid`.
    async fn candidates(&self, kid: Option<&str>) -> Result<Vec<Arc<PublicKey>>> {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        let age = state.loaded_at.map(|loaded| now.duration_since(loaded));
        let fresh = age.is_some_and(|age| age < JWKS_MAX_AGE);
        if !(fresh && kid.is_some_and(|kid| state.has(kid))) {
            let stale = !fresh;
            let unknown_kid = kid.is_none_or(|kid| age.is_some() && !state.has(kid));
            let cooled_down = state
                .last_unknown_kid_refresh
                .is_none_or(|last| now.duration_since(last) >= JWKS_UNKNOWN_KID_COOLDOWN);
            let refresh_unknown = unknown_kid && cooled_down;
            if stale || refresh_unknown || age.is_some_and(|age| age >= JWKS_COOLDOWN) {
                let keys = self.fetch().await?;
                state.keys = keys;
                state.loaded_at = Some(Instant::now());
                if refresh_unknown {
                    state.last_unknown_kid_refresh = Some(Instant::now());
                }
            }
        }
        let selected: Vec<_> = state
            .keys
            .iter()
            .filter(|entry| kid.is_none_or(|kid| entry.kid.as_deref() == Some(kid)))
            .map(|entry| Arc::clone(&entry.key))
            .collect();
        if selected.is_empty() {
            return Err(AuthAiError::new(ErrorCode::Tok001)
                .with_message("No published key matches the token")
                .with_detail("reason", "unknown_key"));
        }
        Ok(selected)
    }

    async fn fetch(&self) -> Result<Vec<KeyEntry>> {
        let failure =
            |message: &str| AuthAiError::new(ErrorCode::Tok001).with_message(message.to_owned());
        let request = HttpRequest::new(Method::Get, &self.uri, self.timeout)
            .with_header("accept", "application/json");
        let response = self
            .transport
            .send(request)
            .await
            .map_err(|err| failure("Fetching the provider's keys failed").with_source(err))?;
        if !response.is_success() {
            return Err(failure("Fetching the provider's keys failed")
                .with_detail("status", response.status));
        }
        let document: Value = response
            .parse_json()
            .map_err(|err| failure("The provider's keys are not JSON").with_source(err))?;
        let listed = document
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| failure("The provider's key set has no keys"))?;
        // A key that cannot verify the pinned algorithm is not a candidate.
        Ok(listed
            .iter()
            .filter_map(|jwk| {
                Some(KeyEntry {
                    kid: jwk.get("kid").and_then(Value::as_str).map(str::to_owned),
                    key: Arc::new(PublicKey::from_jwk(jwk, self.algorithm)?),
                })
            })
            .collect())
    }
}

fn normalise_typ(value: Option<&str>) -> String {
    let lowered = value.unwrap_or_default().to_ascii_lowercase();
    lowered
        .strip_prefix("application/")
        .map_or_else(|| lowered.clone(), str::to_owned)
}

fn rejection(reason: &'static str) -> AuthAiError {
    AuthAiError::new(ErrorCode::Tok001)
        .with_message(format!("Token verification failed: {reason}"))
        .with_detail("reason", reason)
}

/// Verifies the signature, issuer, audience and expiry of a JWT of the provider.
///
/// The accepted algorithm is pinned to the one the provider declares.
pub(crate) struct JwtVerifier {
    issuer: String,
    jwks: RemoteJwks,
    algorithm: Algorithm,
    leeway: u64,
}

impl JwtVerifier {
    pub(crate) const fn new(
        issuer: String,
        jwks: RemoteJwks,
        algorithm: Algorithm,
        leeway: u64,
    ) -> Self {
        Self {
            issuer,
            jwks,
            algorithm,
            leeway,
        }
    }

    /// The claims of a token whose signature, issuer, audience and expiry were checked.
    pub(crate) async fn verify(
        &self,
        token: &str,
        audience: &str,
        typ: Option<&str>,
    ) -> Result<Map<String, Value>> {
        let parsed = jws::parse(token).map_err(rejection)?;
        if parsed.algorithm != self.algorithm.name() {
            return Err(rejection("invalid_algorithm"));
        }
        let signed_by_a_published_key = self
            .jwks
            .candidates(parsed.key_id.as_deref())
            .await?
            .iter()
            .any(|key| parsed.verify(self.algorithm, key));
        if !signed_by_a_published_key {
            return Err(rejection("invalid_signature"));
        }
        let claims = parsed
            .claims(&self.issuer, audience, self.leeway, now_unix_f64())
            .map_err(rejection)?;
        if let Some(expected) = typ
            && normalise_typ(parsed.typ.as_deref()) != normalise_typ(Some(expected))
        {
            return Err(AuthAiError::new(ErrorCode::Tok001).with_message("Unexpected token type"));
        }
        Ok(claims)
    }
}
