//! The JWT endpoints.

use fastauth_core::plugin_prelude::*;
use jsonwebtoken::jwk::JwkSet;
use serde_json::{Map, Value};

use crate::verify::JwksVerifier;
use crate::{Jwt, keys};

/// The body of `/jwks`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Map<String, Value>>,
}

/// `GET /jwks`: the public keys, as Better Auth lists them. Creates the first key on first
/// use.
#[derive(Clone, Copy, Debug, Default)]
pub struct GetJwks;

impl<D: Adapter> Endpoint<D> for GetJwks {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/jwks";
    type Access = Public;
    type Input = Map<String, Value>;
    type Output = Jwks;

    async fn call(&self, ctx: Ctx<D>, _: Map<String, Value>) -> Result<Jwks, AuthError> {
        let jwt = ctx.plugin::<Jwt>();
        keys::current(&ctx, jwt).await?;
        let all = keys::all(&ctx).await?;
        let keys = keys::published(&all, jwt, ctx.now())
            .into_iter()
            .map(|key| keys::public_jwk(key, jwt))
            .collect::<Result<_, _>>()?;
        Ok(Jwks { keys })
    }
}

/// A signed token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenOutput {
    pub token: String,
}

/// `GET /token`: a JWT for the request's session.
#[derive(Clone, Copy, Debug, Default)]
pub struct GetToken;

impl<D: Adapter> Endpoint<D> for GetToken {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/token";
    type Access = Authenticated;
    type Input = Map<String, Value>;
    type Output = TokenOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        _: Map<String, Value>,
    ) -> Result<TokenOutput, AuthError> {
        let token = keys::session_token(&ctx, ctx.plugin::<Jwt>(), ctx.session()).await?;
        Ok(TokenOutput { token })
    }
}

/// The input of [`SignJwt`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SignJwtInput {
    pub payload: Map<String, Value>,
}

/// Server-only, like Better Auth's `signJWT`: signs any claims with the current key.
#[derive(Clone, Copy, Debug, Default)]
pub struct SignJwt;

impl<D: Adapter> Endpoint<D> for SignJwt {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/sign-jwt";
    type Access = Public;
    type Input = SignJwtInput;
    type Output = TokenOutput;

    async fn call(&self, ctx: Ctx<D>, input: SignJwtInput) -> Result<TokenOutput, AuthError> {
        let token = keys::sign(&ctx, ctx.plugin::<Jwt>(), input.payload).await?;
        Ok(TokenOutput { token })
    }
}

/// The input of [`VerifyJwt`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VerifyJwtInput {
    pub token: String,
    /// Expected `iss`, instead of the configured issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

/// What [`VerifyJwt`] answers: the claims, or `None` when the token doesn't verify.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VerifyJwtOutput {
    pub payload: Option<Map<String, Value>>,
}

/// Server-only, like Better Auth's `verifyJWT`: checks a token against the keys `/jwks`
/// publishes, so a retired key stops verifying once its grace period ends.
#[derive(Clone, Copy, Debug, Default)]
pub struct VerifyJwt;

impl<D: Adapter> Endpoint<D> for VerifyJwt {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/verify-jwt";
    type Access = Public;
    type Input = VerifyJwtInput;
    type Output = VerifyJwtOutput;

    async fn call(&self, ctx: Ctx<D>, input: VerifyJwtInput) -> Result<VerifyJwtOutput, AuthError> {
        let jwt = ctx.plugin::<Jwt>();
        let all = keys::all(&ctx).await?;
        let keys = keys::published(&all, jwt, ctx.now())
            .into_iter()
            .map(|key| keys::public_jwk(key, jwt))
            .collect::<Result<Vec<_>, _>>()?;
        let jwks: JwkSet = serde_json::from_value(serde_json::json!({ "keys": keys }))
            .map_err(AuthError::internal)?;
        let base_url = ctx
            .config()
            .base_url
            .as_str()
            .trim_end_matches('/')
            .to_owned();
        let issuer = input
            .issuer
            .or_else(|| jwt.issuer.clone())
            .unwrap_or_else(|| base_url.clone());
        let audience = jwt.audience.clone().unwrap_or(base_url);
        let payload = JwksVerifier::new(jwks, issuer, audience)
            .verify(&input.token)
            .ok();
        Ok(VerifyJwtOutput { payload })
    }
}

/// The key [`RotateKeys`] created.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotatedKey {
    pub kid: Id,
}

/// Server-only: retires every live key (they keep verifying for the grace period) and
/// creates a new one that signs from now on.
#[derive(Clone, Copy, Debug, Default)]
pub struct RotateKeys;

impl<D: Adapter> Endpoint<D> for RotateKeys {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/jwks/rotate";
    type Access = Public;
    type Input = Empty;
    type Output = RotatedKey;

    async fn call(&self, ctx: Ctx<D>, _: Empty) -> Result<RotatedKey, AuthError> {
        let key = keys::rotate(&ctx, ctx.plugin::<Jwt>()).await?;
        Ok(RotatedKey { kid: key.id })
    }
}
