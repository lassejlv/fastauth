//! Verifying fastauth JWTs against a JWKS, for resource servers that don't run fastauth.
//!
//! Fetch `{base_url}{base_path}/jwks` (`http://localhost:3000/api/auth/jwks`), build a
//! [`JwksVerifier`] from it, and check each request's token with it. When
//! [`VerifyError::UnknownKey`] comes back, the auth server has rotated to a key you haven't
//! seen: fetch the JWKS again and retry once.

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;

/// Checks a token's signature against a JWKS, then its `exp`, `nbf`, `iss` and `aud`.
/// Tokens need `exp`, `sub`, `iss` and `aud`, which every token fastauth signs has.
///
/// ```
/// use fastauth_plugin_jwt::verify::JwksVerifier;
///
/// # let jwks = r#"{"keys":[]}"#;
/// // `jwks` is the body of GET /api/auth/jwks.
/// let verifier = JwksVerifier::from_json(jwks, "https://acme.dk", "https://acme.dk")?;
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct JwksVerifier {
    jwks: JwkSet,
    issuer: String,
    audience: String,
    leeway: u64,
}

/// Why a token didn't verify.
#[derive(Debug)]
pub enum VerifyError {
    /// The token's `kid` isn't in the JWKS (or it has none). If the kid is new, the server
    /// rotated keys: fetch the JWKS again.
    UnknownKey(Option<String>),
    /// A bad signature, an expired token, the wrong issuer or audience, or not a JWT.
    Invalid(jsonwebtoken::errors::Error),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::UnknownKey(Some(kid)) => write!(f, "no key with kid {kid} in the JWKS"),
            VerifyError::UnknownKey(None) => f.write_str("the token has no kid"),
            VerifyError::Invalid(err) => write!(f, "invalid token: {err}"),
        }
    }
}

impl std::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VerifyError::Invalid(err) => Some(err),
            VerifyError::UnknownKey(_) => None,
        }
    }
}

impl JwksVerifier {
    /// `issuer` and `audience` are what the auth server signs with: its base URL
    /// (`https://acme.dk`) unless `Jwt::issuer` or `Jwt::audience` set something else.
    pub fn new(jwks: JwkSet, issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            jwks,
            issuer: issuer.into(),
            audience: audience.into(),
            leeway: 0,
        }
    }

    /// From the JSON body of `/jwks`.
    pub fn from_json(
        jwks: &str,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self::new(serde_json::from_str(jwks)?, issuer, audience))
    }

    /// Seconds of clock skew allowed on `exp` and `nbf` (default 0, like Better Auth).
    pub fn leeway(mut self, seconds: u64) -> Self {
        self.leeway = seconds;
        self
    }

    pub fn jwks(&self) -> &JwkSet {
        &self.jwks
    }

    /// The token's claims, once everything checks out. `T` can be
    /// `serde_json::Map<String, serde_json::Value>` or your own claims struct.
    pub fn verify<T: DeserializeOwned>(&self, token: &str) -> Result<T, VerifyError> {
        let header = jsonwebtoken::decode_header(token).map_err(VerifyError::Invalid)?;
        let jwk = header
            .kid
            .as_deref()
            .and_then(|kid| self.jwks.find(kid))
            .ok_or_else(|| VerifyError::UnknownKey(header.kid.clone()))?;
        let alg = algorithm(jwk)
            .ok_or_else(|| VerifyError::Invalid(ErrorKind::InvalidAlgorithm.into()))?;
        let key = DecodingKey::from_jwk(jwk).map_err(VerifyError::Invalid)?;
        let mut validation = Validation::new(alg);
        validation.leeway = self.leeway;
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"]);
        jsonwebtoken::decode::<T>(token, &key, &validation)
            .map(|data| data.claims)
            .map_err(VerifyError::Invalid)
    }
}

/// The algorithm a key signs with: its `alg`, else the one its key type implies.
fn algorithm(jwk: &Jwk) -> Option<Algorithm> {
    match (jwk.common.key_algorithm, &jwk.algorithm) {
        (Some(KeyAlgorithm::EdDSA), AlgorithmParameters::OctetKeyPair(_)) => Some(Algorithm::EdDSA),
        (Some(KeyAlgorithm::ES256), AlgorithmParameters::EllipticCurve(_)) => {
            Some(Algorithm::ES256)
        }
        (Some(KeyAlgorithm::RS256), AlgorithmParameters::RSA(_)) => Some(Algorithm::RS256),
        (Some(_), _) => None,
        (None, AlgorithmParameters::OctetKeyPair(p)) if p.curve == EllipticCurve::Ed25519 => {
            Some(Algorithm::EdDSA)
        }
        (None, AlgorithmParameters::EllipticCurve(p)) if p.curve == EllipticCurve::P256 => {
            Some(Algorithm::ES256)
        }
        (None, AlgorithmParameters::RSA(_)) => Some(Algorithm::RS256),
        (None, _) => None,
    }
}
