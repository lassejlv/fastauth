//! Bearer tokens for [fastauth](https://github.com/lassejlv/fastauth), like Better Auth's
//! `bearer` plugin: clients that can't keep cookies (mobile apps, CLIs, other servers) send
//! `Authorization: Bearer <token>` and get the same session a cookie would give them, on
//! every auth route, in server API calls with request headers, and in the axum `Session`
//! extractors and session layer.
//!
//! Every auth response that sets the session cookie (sign-up, sign-in, a refreshed session)
//! also carries the cookie's value in a `set-auth-token` header, listed in
//! `Access-Control-Expose-Headers` so browsers let scripts read it. That value is the
//! signed form of the token; send it back as the bearer token.
//!
//! ```
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_bearer::Bearer;
//!
//! let auth: Auth<MemoryAdapter, (), plugins![Bearer]> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .email_password(EmailPassword::default())
//!     .plugin(Bearer::new())
//!     .build()?;
//! # Ok::<(), BuildError>(())
//! ```
//!
//! A bearer token is either signed (`token.signature`, what `set-auth-token` carries) or the
//! raw session token a sign-in answers with. A signed token with a bad signature is ignored.
//! Raw tokens are accepted unless [`Bearer::require_signature`] is set. When a request
//! carries both a session cookie and a bearer token, the cookie wins.

use fastauth_core::crypto::SignPurpose;
use fastauth_core::endpoint::Response;
use fastauth_core::plugin_prelude::*;
use http::HeaderValue;
use http::header::{ACCESS_CONTROL_EXPOSE_HEADERS, AUTHORIZATION, SET_COOKIE};

/// The response header that carries the signed session token.
pub const SET_AUTH_TOKEN: &str = "set-auth-token";

/// The bearer plugin: `.plugin(Bearer::new())`.
#[derive(Clone, Debug, Default)]
pub struct Bearer {
    require_signature: bool,
}

impl Bearer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accepts only signed tokens (what `set-auth-token` carries), not the raw session
    /// token. Better Auth's `requireSignature`; off by default.
    pub fn require_signature(mut self, required: bool) -> Self {
        self.require_signature = required;
        self
    }

    /// The session token in an `Authorization: Bearer` value, or `None` when the value isn't
    /// a bearer token this plugin accepts.
    fn token<D: Adapter>(&self, ctx: &Ctx<D>, authorization: &str) -> Option<String> {
        let scheme = authorization.get(..7)?;
        if !scheme.eq_ignore_ascii_case("bearer ") {
            return None;
        }
        let token = authorization[7..].trim();
        if token.is_empty() {
            return None;
        }
        if !token.contains('.') {
            return (!self.require_signature).then(|| token.to_owned());
        }
        let decoded = percent_encoding::percent_decode_str(token)
            .decode_utf8()
            .ok()?;
        ctx.keys()
            .verify(SignPurpose::Cookie, &decoded)
            .map(str::to_owned)
    }
}

impl Plugin for Bearer {
    const ID: &'static str = "bearer";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.session_resolver(BearerResolver(self.clone()))
            .on_response(expose_token);
    }
}

struct BearerResolver(Arc<Bearer>);

impl<D: Adapter> SessionResolver<D> for BearerResolver {
    async fn resolve(
        &self,
        ctx: &Ctx<D>,
        headers: &HeaderMap,
    ) -> Result<Option<Resolved>, AuthError> {
        Ok(headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| self.0.token(ctx, v))
            .map(Resolved::Token))
    }
}

/// Copies a session cookie the response sets into `set-auth-token`, unless the cookie is
/// being cleared.
fn expose_token<D: Adapter>(ctx: &Ctx<D>, response: &mut Response) {
    let name = ctx.config().cookie_name("session_token");
    let token = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|cookie| {
            let (pair, attributes) = cookie.split_once(';').unwrap_or((cookie, ""));
            let value = pair.trim().strip_prefix(&name)?.strip_prefix('=')?;
            let cleared = attributes
                .split(';')
                .any(|a| a.trim().eq_ignore_ascii_case("max-age=0"));
            (!value.is_empty() && !cleared).then(|| value.to_owned())
        });
    let Some(value) = token.and_then(|t| HeaderValue::from_str(&t).ok()) else {
        return;
    };
    let headers = response.headers_mut();
    let mut exposed: Vec<String> = headers
        .get_all(ACCESS_CONTROL_EXPOSE_HEADERS)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .collect();
    if !exposed
        .iter()
        .any(|h| h.eq_ignore_ascii_case(SET_AUTH_TOKEN))
    {
        exposed.push(SET_AUTH_TOKEN.to_owned());
    }
    headers.insert(SET_AUTH_TOKEN, value);
    if let Ok(list) = HeaderValue::from_str(&exposed.join(", ")) {
        headers.insert(ACCESS_CONTROL_EXPOSE_HEADERS, list);
    }
}
