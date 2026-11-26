//! JWTs for [fastauth](https://github.com/lassejlv/fastauth), like Better Auth's `jwt` plugin:
//! services that can't share the session store check a signed token against a public key set
//! instead of calling back to the auth server.
//!
//! - `GET /token` answers `{ "token": "<jwt>" }` for the request's session.
//! - `GET /jwks` lists the public keys as a JWKS. The first key is created on first use.
//! - `/get-session` also answers with the token in a `set-auth-jwt` header, listed in
//!   `Access-Control-Expose-Headers`.
//!
//! Tokens are EdDSA (Ed25519) by default; [`JwtAlgorithm::ES256`] and
//! [`JwtAlgorithm::RS256`] are options. They carry the user, `sub` (the user id), `iat`,
//! `exp` (15 minutes), and `iss` and `aud` (the base URL unless configured). Private keys
//! are stored encrypted with the app secret. With [`Jwt::rotation_interval`], keys expire
//! and a new one is created on the next signing; retired keys stay in the JWKS for
//! [`Jwt::grace_period`] (30 days) so tokens they signed keep verifying.
//!
//! ```
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_jwt::{Jwt, JwtExt};
//!
//! # tokio_test(async {
//! let auth: Auth<MemoryAdapter, (), plugins![Jwt]> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("https://acme.dk")
//!     .database(MemoryAdapter::new())
//!     .plugin(Jwt::new().expiration_time(Duration::minutes(5)))
//!     .build()?;
//!
//! let token = auth
//!     .jwt()
//!     .sign(serde_json::json!({ "sub": "user_1" }).as_object().unwrap().clone())
//!     .await?;
//! let claims = auth.jwt().verify(&token).await?.expect("valid");
//! assert_eq!(claims["sub"], "user_1");
//! assert_eq!(claims["iss"], "https://acme.dk");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # });
//! # fn tokio_test<F: std::future::Future>(f: F) -> F::Output {
//! #     tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
//! # }
//! ```
//!
//! Resource servers verify tokens with [`verify::JwksVerifier`], built from the JWKS.

mod endpoints;
mod keys;
mod model;
pub mod verify;

use std::future::Future;
use std::pin::Pin;

use fastauth_core::plugin_prelude::*;
use fastauth_core::routes::GetSession;
use http::header::ACCESS_CONTROL_EXPOSE_HEADERS;
use http::{HeaderName, HeaderValue};
use serde_json::{Map, Value};

pub use endpoints::{
    GetJwks, GetToken, Jwks, RotateKeys, RotatedKey, SignJwt, SignJwtInput, TokenOutput, VerifyJwt,
    VerifyJwtInput, VerifyJwtOutput,
};
pub use jsonwebtoken;
pub use model::JsonWebKey;
pub use verify::{JwksVerifier, VerifyError};

/// The response header `/get-session` carries the session's JWT in.
pub const SET_AUTH_JWT: &str = "set-auth-jwt";

/// The algorithm new keys use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum JwtAlgorithm {
    /// Ed25519, Better Auth's default.
    #[default]
    EdDSA,
    /// ECDSA on P-256 with SHA-256.
    ES256,
    /// RSA PKCS#1 v1.5 with SHA-256, 2048-bit keys.
    RS256,
}

impl JwtAlgorithm {
    /// The JOSE name: `EdDSA`, `ES256`, `RS256`.
    pub fn name(self) -> &'static str {
        match self {
            JwtAlgorithm::EdDSA => "EdDSA",
            JwtAlgorithm::ES256 => "ES256",
            JwtAlgorithm::RS256 => "RS256",
        }
    }
}

type Claims = Map<String, Value>;
type DefinePayload = Arc<
    dyn Fn(SessionView) -> Pin<Box<dyn Future<Output = Result<Claims, AuthError>> + Send>>
        + Send
        + Sync,
>;

/// The JWT plugin: `.plugin(Jwt::new())`.
#[derive(Clone)]
pub struct Jwt {
    alg: JwtAlgorithm,
    issuer: Option<String>,
    audience: Option<String>,
    expiration_time: Duration,
    rotation_interval: Option<Duration>,
    grace_period: Duration,
    set_jwt_header: bool,
    define_payload: Option<DefinePayload>,
}

impl std::fmt::Debug for Jwt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jwt")
            .field("alg", &self.alg)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("expiration_time", &self.expiration_time)
            .field("rotation_interval", &self.rotation_interval)
            .field("grace_period", &self.grace_period)
            .finish_non_exhaustive()
    }
}

impl Default for Jwt {
    fn default() -> Self {
        Self {
            alg: JwtAlgorithm::EdDSA,
            issuer: None,
            audience: None,
            expiration_time: Duration::minutes(15),
            rotation_interval: None,
            grace_period: Duration::days(30),
            set_jwt_header: true,
            define_payload: None,
        }
    }
}

impl Jwt {
    pub fn new() -> Self {
        Self::default()
    }

    /// The algorithm of new keys (default EdDSA). Switching mints a key of the new algorithm
    /// on the next signing; tokens signed by the old keys keep verifying.
    pub fn algorithm(mut self, alg: JwtAlgorithm) -> Self {
        self.alg = alg;
        self
    }

    /// The `iss` of every token (default: the base URL).
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// The `aud` of every token (default: the base URL).
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// How long tokens are valid (default 15 minutes).
    pub fn expiration_time(mut self, ttl: Duration) -> Self {
        self.expiration_time = ttl;
        self
    }

    /// Keys expire this long after they're created, and the next signing creates a new one
    /// (default: keys never expire). Better Auth's `jwks.rotationInterval`.
    pub fn rotation_interval(mut self, interval: Duration) -> Self {
        self.rotation_interval = Some(interval);
        self
    }

    /// How long an expired key stays in the JWKS (default 30 days). Keep it longer than
    /// `expiration_time`. Better Auth's `jwks.gracePeriod`.
    pub fn grace_period(mut self, grace: Duration) -> Self {
        self.grace_period = grace;
        self
    }

    /// Stops `/get-session` from signing a token into `set-auth-jwt` on every call. Better
    /// Auth's `disableSettingJwtHeader`.
    pub fn disable_jwt_header(mut self) -> Self {
        self.set_jwt_header = false;
        self
    }

    /// The claims a session's token carries instead of the user. `sub` is always the user id
    /// and `iat`, `exp`, `iss` and `aud` are added unless the claims set them. Better
    /// Auth's `jwt.definePayload`.
    ///
    /// ```
    /// # use fastauth_plugin_jwt::Jwt;
    /// let jwt = Jwt::new().define_payload(|session| async move {
    ///     let mut claims = serde_json::Map::new();
    ///     claims.insert("email".into(), session.user.email.clone().into());
    ///     claims.insert("role".into(), "member".into());
    ///     Ok(claims)
    /// });
    /// ```
    pub fn define_payload<F, Fut>(mut self, define: F) -> Self
    where
        F: Fn(SessionView) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Map<String, Value>, AuthError>> + Send + 'static,
    {
        self.define_payload = Some(Arc::new(move |session| Box::pin(define(session))));
        self
    }
}

impl Plugin for Jwt {
    const ID: &'static str = "jwt";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn schema(&self, schema: &mut SchemaBuilder) {
        schema.model::<JsonWebKey>();
    }

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.endpoint(GetJwks)
            .endpoint(GetToken)
            .server_endpoint::<SignJwt>()
            .server_endpoint::<VerifyJwt>()
            .server_endpoint::<RotateKeys>();
        if self.set_jwt_header {
            app.hook::<GetSession>().after(set_jwt_header);
        }
    }
}

async fn set_jwt_header<D: Adapter>(
    ctx: HookCtx<D>,
    output: Option<Value>,
) -> Result<After<Option<Value>>, AuthError> {
    if let Some(session) = ctx.session() {
        let token = keys::session_token(&ctx, ctx.plugin::<Jwt>(), session).await?;
        let value = HeaderValue::from_str(&token).map_err(AuthError::internal)?;
        ctx.set_header(HeaderName::from_static(SET_AUTH_JWT), value);
        ctx.set_header(
            ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static(SET_AUTH_JWT),
        );
    }
    Ok(After::Continue(output))
}

/// `auth.jwt()`: the server API. Only compiles on an `Auth` with `Jwt` registered.
pub trait JwtExt: AuthInstance + Sized {
    fn jwt<I>(&self) -> JwtApi<'_, Self>
    where
        Self: HasPlugin<Jwt, I>,
    {
        JwtApi {
            auth: self,
            headers: HeaderMap::new(),
        }
    }
}

impl<A: AuthInstance> JwtExt for A {}

/// Signs, verifies and rotates without HTTP.
pub struct JwtApi<'a, A> {
    auth: &'a A,
    headers: HeaderMap,
}

impl<A> std::fmt::Debug for JwtApi<'_, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JwtApi")
    }
}

impl<A: AuthInstance> JwtApi<'_, A> {
    /// Acts for the session in these request headers (for [`token`](Self::token)).
    pub fn headers(mut self, headers: &HeaderMap) -> Self {
        self.headers = headers.clone();
        self
    }

    async fn call<E: Endpoint<A::Db>>(
        &self,
        endpoint: &E,
        input: E::Input,
    ) -> Result<E::Output, AuthError> {
        Ok(self
            .auth
            .api()
            .headers(&self.headers)
            .call(endpoint, input)
            .await?
            .data)
    }

    /// The session's token, as `/token` answers it. Needs [`headers`](Self::headers) with
    /// a session; `UNAUTHORIZED` without one.
    pub async fn token(&self) -> Result<String, AuthError> {
        Ok(self.call(&GetToken, Map::new()).await?.token)
    }

    /// Signs any claims with the current key. `exp`, `iss` and `aud` are added unless set.
    pub async fn sign(&self, claims: Map<String, Value>) -> Result<String, AuthError> {
        Ok(self
            .call(&SignJwt, SignJwtInput { payload: claims })
            .await?
            .token)
    }

    /// The claims of a token signed by any stored key, with a valid `exp`, `iss` and
    /// `aud`; `None` when it doesn't verify.
    pub async fn verify(&self, token: &str) -> Result<Option<Map<String, Value>>, AuthError> {
        let input = VerifyJwtInput {
            token: token.to_owned(),
            issuer: None,
        };
        Ok(self.call(&VerifyJwt, input).await?.payload)
    }

    /// The JWKS, as `/jwks` answers it.
    pub async fn jwks(&self) -> Result<Jwks, AuthError> {
        self.call(&GetJwks, Map::new()).await
    }

    /// Retires every live key and creates a new one, returning its `kid`. Tokens signed by
    /// the retired keys verify until the grace period ends.
    pub async fn rotate(&self) -> Result<Id, AuthError> {
        Ok(self.call(&RotateKeys, Empty {}).await?.kid)
    }
}
