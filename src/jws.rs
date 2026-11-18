//! Compact JWS verification: the signature against a published key, then the registered claims.
//!
//! The algorithm names are the fully specified ones of RFC 9864 (`Ed25519`, not the deprecated
//! `EdDSA`), which the JOSE crates do not parse yet. HMAC and `none` never qualify: the caller
//! pins one asymmetric algorithm and a token naming another is refused.

use aws_lc_rs::rsa::PublicKeyComponents;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED, ECDSA_P521_SHA512_FIXED, ED25519,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
    RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512,
    UnparsedPublicKey,
};
use serde_json::{Map, Value};

use crate::util::b64url_decode;

/// A signature algorithm the SDK verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Algorithm {
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

impl Algorithm {
    /// `None` for `none`, HMAC, the deprecated `EdDSA` and `Ed448`.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "ES256" => Self::Es256,
            "ES384" => Self::Es384,
            "ES512" => Self::Es512,
            "RS256" => Self::Rs256,
            "RS384" => Self::Rs384,
            "RS512" => Self::Rs512,
            "PS256" => Self::Ps256,
            "PS384" => Self::Ps384,
            "PS512" => Self::Ps512,
            "Ed25519" => Self::Ed25519,
            _ => return None,
        })
    }

    pub(crate) const fn name(self) -> &'static str {
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

    /// The JWK `crv` and coordinate length of an elliptic or Edwards algorithm.
    const fn curve(self) -> Option<(&'static str, usize)> {
        match self {
            Self::Es256 => Some(("P-256", 32)),
            Self::Es384 => Some(("P-384", 48)),
            Self::Es512 => Some(("P-521", 66)),
            Self::Ed25519 => Some(("Ed25519", 32)),
            _ => None,
        }
    }
}

/// The public part of a published key, in the form the verifier consumes.
#[derive(Debug)]
pub(crate) enum PublicKey {
    /// Uncompressed SEC1 point.
    Ec(Vec<u8>),
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    Ed25519(Vec<u8>),
}

impl PublicKey {
    /// The key of a JWK, `None` unless it can verify `algorithm` and is meant for signatures.
    pub(crate) fn from_jwk(jwk: &Value, algorithm: Algorithm) -> Option<Self> {
        let text = |name: &str| jwk.get(name).and_then(Value::as_str);
        let bytes = |name: &str| text(name).and_then(b64url_decode);
        if !matches!(text("use"), None | Some("sig")) {
            return None;
        }
        if text("alg").is_some_and(|alg| alg != algorithm.name()) {
            return None;
        }
        match (algorithm, algorithm.curve()) {
            (Algorithm::Ed25519, Some((curve, length))) => {
                let x = bytes("x").filter(|x| x.len() == length)?;
                (text("kty") == Some("OKP") && text("crv") == Some(curve))
                    .then_some(Self::Ed25519(x))
            }
            (_, Some((curve, length))) => {
                let (x, y) = (bytes("x")?, bytes("y")?);
                if text("kty") != Some("EC")
                    || text("crv") != Some(curve)
                    || x.len() != length
                    || y.len() != length
                {
                    return None;
                }
                let mut point = Vec::with_capacity(1 + 2 * length);
                point.push(0x04);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                Some(Self::Ec(point))
            }
            (_, None) => {
                let (n, e) = (bytes("n")?, bytes("e")?);
                (text("kty") == Some("RSA") && !n.is_empty() && !e.is_empty())
                    .then_some(Self::Rsa { n, e })
            }
        }
    }
}

/// A compact JWS split into its parts, signature not yet checked.
pub(crate) struct Parsed<'a> {
    pub(crate) algorithm: String,
    pub(crate) key_id: Option<String>,
    pub(crate) typ: Option<String>,
    signing_input: &'a str,
    signature: Vec<u8>,
    payload: Vec<u8>,
}

/// The token is not a well-formed compact JWS with a usable protected header.
pub(crate) fn parse(token: &str) -> Result<Parsed<'_>, &'static str> {
    let malformed = "invalid_token";
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(malformed);
    };
    let header: Map<String, Value> =
        serde_json::from_slice(&b64url_decode(header).ok_or(malformed)?).map_err(|_| malformed)?;
    // Extensions this verifier does not implement must not be ignored.
    if header.contains_key("crit") || header.get("b64") == Some(&Value::Bool(false)) {
        return Err(malformed);
    }
    let optional = |name: &str| match header.get(name) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(malformed),
    };
    Ok(Parsed {
        algorithm: optional("alg")?.ok_or(malformed)?,
        key_id: optional("kid")?,
        typ: optional("typ")?,
        signing_input: token
            .rsplit_once('.')
            .map(|(input, _)| input)
            .ok_or(malformed)?,
        signature: b64url_decode(signature).ok_or(malformed)?,
        payload: b64url_decode(payload).ok_or(malformed)?,
    })
}

impl Parsed<'_> {
    /// Whether `key` signed this token with `algorithm`.
    pub(crate) fn verify(&self, algorithm: Algorithm, key: &PublicKey) -> bool {
        let message = self.signing_input.as_bytes();
        let signature = self.signature.as_slice();
        let ec = |parameters, point: &[u8]| {
            UnparsedPublicKey::new(parameters, point)
                .verify(message, signature)
                .is_ok()
        };
        let rsa = |parameters, n: &[u8], e: &[u8]| {
            PublicKeyComponents { n, e }
                .verify(parameters, message, signature)
                .is_ok()
        };
        match (algorithm, key) {
            (Algorithm::Es256, PublicKey::Ec(point)) => ec(&ECDSA_P256_SHA256_FIXED, point),
            (Algorithm::Es384, PublicKey::Ec(point)) => ec(&ECDSA_P384_SHA384_FIXED, point),
            (Algorithm::Es512, PublicKey::Ec(point)) => ec(&ECDSA_P521_SHA512_FIXED, point),
            (Algorithm::Ed25519, PublicKey::Ed25519(point)) => ec(&ED25519, point),
            (Algorithm::Rs256, PublicKey::Rsa { n, e }) => rsa(&RSA_PKCS1_2048_8192_SHA256, n, e),
            (Algorithm::Rs384, PublicKey::Rsa { n, e }) => rsa(&RSA_PKCS1_2048_8192_SHA384, n, e),
            (Algorithm::Rs512, PublicKey::Rsa { n, e }) => rsa(&RSA_PKCS1_2048_8192_SHA512, n, e),
            (Algorithm::Ps256, PublicKey::Rsa { n, e }) => rsa(&RSA_PSS_2048_8192_SHA256, n, e),
            (Algorithm::Ps384, PublicKey::Rsa { n, e }) => rsa(&RSA_PSS_2048_8192_SHA384, n, e),
            (Algorithm::Ps512, PublicKey::Rsa { n, e }) => rsa(&RSA_PSS_2048_8192_SHA512, n, e),
            _ => false,
        }
    }

    /// The claims, once the signature is known good: issuer, audience, subject and times.
    pub(crate) fn claims(
        &self,
        issuer: &str,
        audience: &str,
        leeway_seconds: u64,
        now: f64,
    ) -> Result<Map<String, Value>, &'static str> {
        let claims: Map<String, Value> =
            serde_json::from_slice(&self.payload).map_err(|_| "invalid_token")?;
        validate_claims(&claims, issuer, audience, leeway_seconds, now)?;
        Ok(claims)
    }
}

fn validate_claims(
    claims: &Map<String, Value>,
    issuer: &str,
    audience: &str,
    leeway_seconds: u64,
    now: f64,
) -> Result<(), &'static str> {
    let missing = "invalid_claim";
    let leeway = leeway_seconds as f64;
    let number = |name: &str| {
        claims
            .get(name)
            .map(|value| value.as_f64().ok_or(missing))
            .transpose()
    };

    if claims.get("sub").and_then(Value::as_str).is_none() {
        return Err(missing);
    }
    let expires_at = number("exp")?.ok_or(missing)?;
    if expires_at + leeway < now {
        return Err("expired_token");
    }
    if number("nbf")?.is_some_and(|not_before| not_before - leeway > now) {
        return Err("token_not_yet_valid");
    }
    match claims.get("iss").and_then(Value::as_str) {
        None => return Err(missing),
        Some(found) if found != issuer => return Err("invalid_issuer"),
        Some(_) => {}
    }
    let audience_matches = match claims.get("aud") {
        Some(Value::String(found)) => found == audience,
        Some(Value::Array(found)) => found.iter().any(|item| item.as_str() == Some(audience)),
        _ => return Err(missing),
    };
    if audience_matches {
        Ok(())
    } else {
        Err("invalid_audience")
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::util::b64url;

    fn token(header: &Value, payload: &Value) -> String {
        format!(
            "{}.{}.{}",
            b64url(header.to_string().as_bytes()),
            b64url(payload.to_string().as_bytes()),
            b64url(b"sig")
        )
    }

    fn claims() -> Map<String, Value> {
        json!({ "iss": "https://i", "sub": "u", "aud": "app", "exp": 1000, "nbf": 100 })
            .as_object()
            .cloned()
            .unwrap_or_default()
    }

    #[test]
    fn only_fully_specified_asymmetric_names_are_known() {
        for name in [
            "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
            "Ed25519",
        ] {
            assert_eq!(Algorithm::from_name(name).map(Algorithm::name), Some(name));
        }
        for name in [
            "EdDSA", "Ed448", "none", "HS256", "HS512", "es256", "", "RS1",
        ] {
            assert!(Algorithm::from_name(name).is_none(), "{name}");
        }
    }

    #[test]
    fn a_token_must_have_exactly_three_parts_and_a_usable_header() {
        let header = json!({ "alg": "ES256", "kid": "k", "typ": "JWT" });
        let built = token(&header, &json!({}));
        let parsed = parse(&built).unwrap();
        assert_eq!(
            (
                parsed.algorithm.as_str(),
                parsed.key_id.as_deref(),
                parsed.typ.as_deref()
            ),
            ("ES256", Some("k"), Some("JWT"))
        );

        let good = token(&header, &json!({}));
        for bad in [
            String::new(),
            "a.b".to_owned(),
            format!("{good}.extra"),
            "!!.!!.!!".to_owned(),
            token(&json!({ "kid": "k" }), &json!({})),
            token(&json!({ "alg": 5 }), &json!({})),
            token(&json!({ "alg": "ES256", "kid": 5 }), &json!({})),
            token(&json!({ "alg": "ES256", "crit": ["exp"] }), &json!({})),
            token(&json!({ "alg": "ES256", "b64": false }), &json!({})),
            format!("{}.{}.{}", b64url(b"[]"), b64url(b"{}"), b64url(b"s")),
        ] {
            assert_eq!(parse(&bad).err(), Some("invalid_token"), "{bad}");
        }
    }

    #[test]
    fn claims_are_checked_with_the_leeway() {
        assert!(validate_claims(&claims(), "https://i", "app", 0, 500.0).is_ok());
        assert_eq!(
            validate_claims(&claims(), "https://i", "app", 0, 1001.0),
            Err("expired_token")
        );
        assert!(validate_claims(&claims(), "https://i", "app", 5, 1004.0).is_ok());
        assert_eq!(
            validate_claims(&claims(), "https://i", "app", 5, 1006.0),
            Err("expired_token")
        );
        assert_eq!(
            validate_claims(&claims(), "https://i", "app", 0, 99.0),
            Err("token_not_yet_valid")
        );
        assert!(validate_claims(&claims(), "https://i", "app", 5, 96.0).is_ok());
    }

    #[test]
    fn issuer_audience_and_subject_are_exact() {
        assert_eq!(
            validate_claims(&claims(), "https://other", "app", 0, 500.0),
            Err("invalid_issuer")
        );
        assert_eq!(
            validate_claims(&claims(), "https://i", "App", 0, 500.0),
            Err("invalid_audience")
        );
        let mut listed = claims();
        listed.insert("aud".into(), json!(["x", "app"]));
        assert!(validate_claims(&listed, "https://i", "app", 0, 500.0).is_ok());
        listed.insert("aud".into(), json!(["x", 5]));
        assert_eq!(
            validate_claims(&listed, "https://i", "app", 0, 500.0),
            Err("invalid_audience")
        );
    }

    #[test]
    fn required_claims_must_be_present_and_well_typed() {
        for name in ["sub", "exp", "iss", "aud"] {
            let mut incomplete = claims();
            incomplete.remove(name);
            assert_eq!(
                validate_claims(&incomplete, "https://i", "app", 0, 500.0),
                Err("invalid_claim"),
                "{name}"
            );
        }
        for (name, value) in [
            ("sub", json!(5)),
            ("exp", json!("1000")),
            ("nbf", json!("1")),
            ("iss", json!(1)),
            ("aud", json!(7)),
        ] {
            let mut wrong = claims();
            wrong.insert(name.into(), value);
            assert_eq!(
                validate_claims(&wrong, "https://i", "app", 0, 500.0),
                Err("invalid_claim"),
                "{name}"
            );
        }
    }

    #[test]
    fn a_jwk_must_fit_the_algorithm_and_be_meant_for_signatures() {
        let x = b64url(&[7_u8; 32]);
        let ed = json!({ "kty": "OKP", "crv": "Ed25519", "x": x });
        assert!(PublicKey::from_jwk(&ed, Algorithm::Ed25519).is_some());
        assert!(
            PublicKey::from_jwk(&ed, Algorithm::Es256).is_none(),
            "an OKP key cannot verify ES256"
        );
        let labelled =
            json!({ "kty": "OKP", "crv": "Ed25519", "x": b64url(&[7_u8; 32]), "alg": "EdDSA" });
        assert!(
            PublicKey::from_jwk(&labelled, Algorithm::Ed25519).is_none(),
            "the deprecated label is refused"
        );
        let encryption =
            json!({ "kty": "OKP", "crv": "Ed25519", "x": b64url(&[7_u8; 32]), "use": "enc" });
        assert!(PublicKey::from_jwk(&encryption, Algorithm::Ed25519).is_none());
        let short = json!({ "kty": "OKP", "crv": "Ed25519", "x": b64url(&[7_u8; 31]) });
        assert!(PublicKey::from_jwk(&short, Algorithm::Ed25519).is_none());

        let p256 = json!({ "kty": "EC", "crv": "P-256", "x": b64url(&[1_u8; 32]), "y": b64url(&[2_u8; 32]) });
        assert!(PublicKey::from_jwk(&p256, Algorithm::Es256).is_some());
        assert!(
            PublicKey::from_jwk(&p256, Algorithm::Es384).is_none(),
            "the curve must match"
        );
        assert!(PublicKey::from_jwk(&p256, Algorithm::Rs256).is_none());
        let rsa = json!({ "kty": "RSA", "n": b64url(&[1_u8; 256]), "e": b64url(&[1, 0, 1]) });
        assert!(PublicKey::from_jwk(&rsa, Algorithm::Rs256).is_some());
        assert!(PublicKey::from_jwk(&rsa, Algorithm::Ps512).is_some());
        assert!(PublicKey::from_jwk(&rsa, Algorithm::Es256).is_none());
        assert!(
            PublicKey::from_jwk(
                &json!({ "kty": "RSA", "n": "", "e": "AQAB" }),
                Algorithm::Rs256
            )
            .is_none()
        );
    }
}
