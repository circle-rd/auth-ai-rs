//! Verification of the JWTs the provider signs, against its published keys.

use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::{Map, Value};
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::error::{AuthAiError, ErrorCode, Result};
use crate::transport::{HttpRequest, Method, Transport};

/// An unknown `kid` (key rotation) refreshes the keys at most once per second.
pub(crate) const JWKS_UNKNOWN_KID_COOLDOWN: Duration = Duration::from_secs(1);
/// Keys are re-fetched at least this often.
pub(crate) const JWKS_COOLDOWN: Duration = Duration::from_secs(30);
/// Keys older than this are never served.
pub(crate) const JWKS_MAX_AGE: Duration = Duration::from_secs(3600);

/// The signing algorithms this SDK verifies. HMAC and `none` never qualify, and
/// neither does the deprecated `EdDSA` name (RFC 9864).
#[must_use]
pub(crate) fn supported_algorithm(name: &str) -> Option<Algorithm> {
    match name {
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "PS256" => Some(Algorithm::PS256),
        "PS384" => Some(Algorithm::PS384),
        "PS512" => Some(Algorithm::PS512),
        _ => None,
    }
}

struct KeyEntry {
    kid: Option<String>,
    key: Arc<DecodingKey>,
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
    async fn candidates(&self, kid: Option<&str>) -> Result<Vec<Arc<DecodingKey>>> {
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

    fn supports(&self, key: &Value) -> bool {
        let text = |name: &str| key.get(name).and_then(Value::as_str);
        if !matches!(text("use"), None | Some("sig")) {
            return false;
        }
        if text("alg").is_some_and(|alg| supported_algorithm(alg) != Some(self.algorithm)) {
            return false;
        }
        match self.algorithm {
            Algorithm::ES256 => text("kty") == Some("EC") && text("crv") == Some("P-256"),
            Algorithm::ES384 => text("kty") == Some("EC") && text("crv") == Some("P-384"),
            _ => text("kty") == Some("RSA"),
        }
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
        let mut entries = Vec::new();
        for key in listed.iter().filter(|key| self.supports(key)) {
            let jwk: Jwk = serde_json::from_value(key.clone())
                .map_err(|err| failure("A published key is malformed").with_source(err))?;
            let decoding = DecodingKey::from_jwk(&jwk)
                .map_err(|err| failure("A published key is unusable").with_source(err))?;
            entries.push(KeyEntry {
                kid: key.get("kid").and_then(Value::as_str).map(str::to_owned),
                key: Arc::new(decoding),
            });
        }
        Ok(entries)
    }
}

fn normalise_typ(value: Option<&str>) -> String {
    let lowered = value.unwrap_or_default().to_ascii_lowercase();
    lowered
        .strip_prefix("application/")
        .map_or_else(|| lowered.clone(), str::to_owned)
}

fn failure_reason(kind: &ErrorKind) -> &'static str {
    match kind {
        ErrorKind::ExpiredSignature => "expired_token",
        ErrorKind::ImmatureSignature => "token_not_yet_valid",
        ErrorKind::InvalidSignature => "invalid_signature",
        ErrorKind::InvalidIssuer => "invalid_issuer",
        ErrorKind::InvalidAudience => "invalid_audience",
        ErrorKind::MissingRequiredClaim(_) | ErrorKind::InvalidClaimFormat(_) => "invalid_claim",
        ErrorKind::InvalidAlgorithm | ErrorKind::UnsupportedAlgorithm => "invalid_algorithm",
        _ => "invalid_token",
    }
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
        let header = decode_header(token).map_err(|err| rejection(failure_reason(err.kind())))?;
        if header.alg != self.algorithm {
            return Err(rejection("invalid_algorithm"));
        }
        let mut validation = Validation::new(self.algorithm);
        validation.leeway = self.leeway;
        validation.validate_nbf = true;
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);

        let mut last = rejection("invalid_signature");
        for key in self.jwks.candidates(header.kid.as_deref()).await? {
            match decode::<Map<String, Value>>(token, &key, &validation) {
                Ok(data) => {
                    if let Some(expected) = typ
                        && normalise_typ(data.header.typ.as_deref())
                            != normalise_typ(Some(expected))
                    {
                        return Err(AuthAiError::new(ErrorCode::Tok001)
                            .with_message("Unexpected token type"));
                    }
                    return Ok(data.claims);
                }
                Err(err) => last = rejection(failure_reason(err.kind())),
            }
        }
        Err(last)
    }
}
