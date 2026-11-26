//! Key generation, storage and signing.

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair};
use fastauth_core::crypto::{base64url, base64url_decode};
use fastauth_core::plugin_prelude::*;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{EncodingKey, Header};
use serde_json::{Map, Value};

use crate::model::JsonWebKey;
use crate::{Jwt, JwtAlgorithm};

impl JwtAlgorithm {
    fn crv(self) -> Option<&'static str> {
        match self {
            JwtAlgorithm::EdDSA => Some("Ed25519"),
            JwtAlgorithm::ES256 => Some("P-256"),
            JwtAlgorithm::RS256 => None,
        }
    }

    fn parse(name: &str) -> Option<Self> {
        [
            JwtAlgorithm::EdDSA,
            JwtAlgorithm::ES256,
            JwtAlgorithm::RS256,
        ]
        .into_iter()
        .find(|alg| alg.name() == name)
    }

    pub(crate) fn jsonwebtoken(self) -> jsonwebtoken::Algorithm {
        match self {
            JwtAlgorithm::EdDSA => jsonwebtoken::Algorithm::EdDSA,
            JwtAlgorithm::ES256 => jsonwebtoken::Algorithm::ES256,
            JwtAlgorithm::RS256 => jsonwebtoken::Algorithm::RS256,
        }
    }

    /// A new private key as PKCS#8 PEM.
    fn generate(self) -> Result<String, AuthError> {
        let failed = |_| AuthError::internal("generating a JWT signing key failed");
        let rng = SystemRandom::new();
        let der = match self {
            JwtAlgorithm::EdDSA => Ed25519KeyPair::generate_pkcs8v1(&rng)
                .map_err(failed)?
                .as_ref()
                .to_vec(),
            JwtAlgorithm::ES256 => {
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                    .map_err(failed)?
                    .as_ref()
                    .to_vec()
            }
            JwtAlgorithm::RS256 => RsaKeyPair::generate(KeySize::Rsa2048)
                .map_err(failed)?
                .as_der()
                .map_err(failed)?
                .as_ref()
                .to_vec(),
        };
        Ok(pem::encode(&pem::Pem::new("PRIVATE KEY", der)))
    }

    fn encoding_key(self, pem: &[u8]) -> Result<EncodingKey, AuthError> {
        match self {
            JwtAlgorithm::EdDSA => EncodingKey::from_ed_pem(pem),
            JwtAlgorithm::ES256 => EncodingKey::from_ec_pem(pem),
            JwtAlgorithm::RS256 => EncodingKey::from_rsa_pem(pem),
        }
        .map_err(AuthError::internal)
    }
}

/// A key ready to sign with.
pub(crate) struct SigningKey {
    pub kid: Id,
    pub alg: JwtAlgorithm,
    pub key: EncodingKey,
}

fn is_live(key: &JsonWebKey, now: OffsetDateTime) -> bool {
    key.expires_at.is_none_or(|at| at > now)
}

fn alg_of(key: &JsonWebKey, jwt: &Jwt) -> Option<JwtAlgorithm> {
    key.alg
        .as_deref()
        .map_or(Some(jwt.alg), JwtAlgorithm::parse)
}

/// Every stored key, newest first.
pub(crate) async fn all<D: Adapter, A>(ctx: &Ctx<D, A>) -> Result<Vec<JsonWebKey>, AuthError> {
    let mut keys = ctx.db().find::<JsonWebKey>(Where::all()).all().await?;
    keys.sort_by(|a, b| (b.created_at, &b.id).cmp(&(a.created_at, &a.id)));
    Ok(keys)
}

/// Generates, encrypts and stores a key pair of the configured algorithm.
pub(crate) async fn create<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    jwt: &Jwt,
) -> Result<JsonWebKey, AuthError> {
    let pem = jwt.alg.generate()?;
    let encoding = jwt.alg.encoding_key(pem.as_bytes())?;
    let public =
        Jwk::from_encoding_key(&encoding, jwt.alg.jsonwebtoken()).map_err(AuthError::internal)?;
    let now = ctx.now();
    let key = JsonWebKey {
        id: ctx.new_id()?,
        public_key: serde_json::to_string(&public.algorithm).map_err(AuthError::internal)?,
        private_key: base64url(&ctx.keys().encrypt(pem.as_bytes())),
        created_at: now,
        expires_at: jwt.rotation_interval.map(|interval| now + interval),
        alg: Some(jwt.alg.name().to_owned()),
        crv: jwt.alg.crv().map(str::to_owned),
    };
    Ok(ctx.db().insert(&key).await?)
}

/// The newest live key of the configured algorithm, minting one when there is none (the
/// first call, or the last one expired under `rotation_interval`).
pub(crate) async fn current<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    jwt: &Jwt,
) -> Result<JsonWebKey, AuthError> {
    let now = ctx.now();
    let live = all(ctx)
        .await?
        .into_iter()
        .find(|key| is_live(key, now) && alg_of(key, jwt) == Some(jwt.alg));
    match live {
        Some(key) => Ok(key),
        None => create(ctx, jwt).await,
    }
}

fn decrypt(ctx_keys: &fastauth_core::crypto::Keys, key: &JsonWebKey) -> Option<Vec<u8>> {
    ctx_keys.decrypt(&base64url_decode(&key.private_key)?)
}

pub(crate) async fn signing_key<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    jwt: &Jwt,
) -> Result<SigningKey, AuthError> {
    let key = current(ctx, jwt).await?;
    let pem = decrypt(ctx.keys(), &key).ok_or_else(|| {
        AuthError::internal(format!(
            "JWKS key {} doesn't decrypt with the configured secrets; it was encrypted with \
             another secret. Add that secret to `.secrets(..)` or delete the jwks rows",
            key.id
        ))
    })?;
    Ok(SigningKey {
        kid: key.id,
        alg: jwt.alg,
        key: jwt.alg.encoding_key(&pem)?,
    })
}

/// Marks every live key as expiring now and mints a new one. Tokens the old keys signed keep
/// verifying for the grace period.
pub(crate) async fn rotate<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    jwt: &Jwt,
) -> Result<JsonWebKey, AuthError> {
    let now = ctx.now();
    for key in all(ctx).await?.into_iter().filter(|k| is_live(k, now)) {
        ctx.db()
            .update::<JsonWebKey>(JsonWebKey::ID.eq(&key.id))
            .set(JsonWebKey::EXPIRES_AT, Some(now))
            .exec()
            .await?;
    }
    create(ctx, jwt).await
}

/// The public keys a verifier may need: live ones, and expired ones for the grace period.
/// Each is the stored JWK plus `alg`, `crv` and `kid`, as Better Auth lists them.
pub(crate) fn public_jwk(key: &JsonWebKey, jwt: &Jwt) -> Result<Map<String, Value>, AuthError> {
    let mut out = Map::new();
    out.insert(
        "alg".into(),
        key.alg
            .clone()
            .unwrap_or_else(|| jwt.alg.name().into())
            .into(),
    );
    if let Some(crv) = key.crv.clone().or_else(|| jwt.alg.crv().map(str::to_owned)) {
        out.insert("crv".into(), crv.into());
    }
    let public: Map<String, Value> =
        serde_json::from_str(&key.public_key).map_err(AuthError::internal)?;
    out.extend(public);
    out.insert("kid".into(), key.id.as_str().into());
    Ok(out)
}

pub(crate) fn published<'k>(
    keys: &'k [JsonWebKey],
    jwt: &Jwt,
    now: OffsetDateTime,
) -> Vec<&'k JsonWebKey> {
    keys.iter()
        .filter(|key| key.expires_at.is_none_or(|at| at + jwt.grace_period > now))
        .collect()
}

/// Signs `claims` like Better Auth's `signJWT`: `exp`, `iss` and `aud` default to
/// `iat` (or now) plus the expiration time, the configured issuer and the configured
/// audience (both the base URL unless set).
pub(crate) async fn sign<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    jwt: &Jwt,
    mut claims: Map<String, Value>,
) -> Result<String, AuthError> {
    let base_url = ctx
        .config()
        .base_url
        .as_str()
        .trim_end_matches('/')
        .to_owned();
    let issued = claims
        .get("iat")
        .and_then(Value::as_i64)
        .unwrap_or_else(|| ctx.now().unix_timestamp());
    claims
        .entry("exp")
        .or_insert_with(|| (issued + jwt.expiration_time.whole_seconds()).into());
    claims.entry("iss").or_insert_with(|| {
        jwt.issuer
            .clone()
            .unwrap_or_else(|| base_url.clone())
            .into()
    });
    claims
        .entry("aud")
        .or_insert_with(|| jwt.audience.clone().unwrap_or(base_url).into());
    let key = signing_key(ctx, jwt).await?;
    let mut header = Header::new(key.alg.jsonwebtoken());
    header.typ = None;
    header.kid = Some(key.kid.to_string());
    jsonwebtoken::encode(&header, &claims, &key.key).map_err(AuthError::internal)
}

/// The token `/token` answers with and `set-auth-jwt` carries: the user (or what
/// `define_payload` returns), `iat`, and the user id as `sub`.
pub(crate) async fn session_token<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    jwt: &Jwt,
    session: &SessionView,
) -> Result<String, AuthError> {
    let payload = match &jwt.define_payload {
        Some(define) => define(session.clone()).await?,
        None => session.user.to_json(),
    };
    let mut claims = Map::new();
    claims.insert("iat".into(), ctx.now().unix_timestamp().into());
    claims.extend(payload);
    claims.insert("sub".into(), session.user.id.as_str().into());
    sign(ctx, jwt, claims).await
}
