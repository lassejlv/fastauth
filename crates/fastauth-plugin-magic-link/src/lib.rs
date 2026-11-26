//! Magic link sign-in for [fastauth](https://github.com/lassejlv/fastauth). The routes and
//! JSON match Better Auth's `magicLink` plugin, so its `magicLinkClient` works unchanged.
//!
//! `POST /sign-in/magic-link` emails a single-use link through the configured
//! [`Mailer`](fastauth_core::mail::Mailer) as `AuthEmail::Plugin` with `kind: "magic-link"`.
//! `GET /magic-link/verify` signs the user in, creating them on first use unless
//! [`disable_sign_up`](MagicLink::disable_sign_up) is set. Only the token's SHA-256 is stored,
//! in the `verification` table; the token is never logged or returned.
//!
//! ```
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_magic_link::{MagicLink, MagicLinkExt};
//!
//! let auth: Auth<MemoryAdapter, (), plugins![MagicLink]> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .mailer(LogMailer)
//!     .plugin(MagicLink::new().expires_in(Duration::minutes(10)))
//!     .build()?;
//! let _magic_link = auth.magic_link();
//! # Ok::<(), BuildError>(())
//! ```
//!
//! Without the plugin registered, `auth.magic_link()` doesn't compile:
//!
//! ```compile_fail
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_magic_link::MagicLinkExt;
//!
//! let auth: Auth<MemoryAdapter> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .build()
//!     .unwrap();
//! let _magic_link = auth.magic_link();
//! ```

mod endpoints;
mod error;

use fastauth_core::plugin_prelude::*;
use fastauth_core::{ApiResponse, routes::Status};

pub use endpoints::{
    SignInMagicLink, SignInMagicLinkInput, VerifyMagicLink, VerifyMagicLinkInput,
    VerifyMagicLinkOutput,
};
pub use error::MagicLinkError;

/// The magic link plugin: `.plugin(MagicLink::new())`. Needs a mailer.
#[derive(Clone, Debug)]
pub struct MagicLink {
    expires_in: Duration,
    disable_sign_up: bool,
    rate_limit: Limit,
}

impl Default for MagicLink {
    fn default() -> Self {
        Self {
            expires_in: Duration::seconds(300),
            disable_sign_up: false,
            rate_limit: Limit::per(Duration::minutes(1), 5),
        }
    }
}

impl MagicLink {
    pub fn new() -> Self {
        Self::default()
    }

    /// How long a link works (default 5 minutes, Better Auth's `expiresIn: 300`).
    pub fn expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_in = expires_in;
        self
    }

    /// Only existing users can sign in; a link for an unknown email redirects with
    /// `error=new_user_signup_disabled`.
    pub fn disable_sign_up(mut self, disable: bool) -> Self {
        self.disable_sign_up = disable;
        self
    }

    /// Requests per client to each of the two routes (default 5 a minute). App rules win.
    pub fn rate_limit(mut self, limit: Limit) -> Self {
        self.rate_limit = limit;
        self
    }
}

impl Plugin for MagicLink {
    const ID: &'static str = "magic-link";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.endpoint(SignInMagicLink(self.clone()))
            .endpoint(VerifyMagicLink(self.clone()))
            .rate_limit("/sign-in/magic-link", self.rate_limit)
            .rate_limit("/magic-link/verify", self.rate_limit)
            .errors::<MagicLinkError>();
    }
}

/// `auth.magic_link()`: the server API. Only compiles on an `Auth` with `MagicLink` registered.
pub trait MagicLinkExt: AuthInstance + Sized {
    fn magic_link<I>(&self) -> MagicLinkApi<'_, Self>
    where
        Self: HasPlugin<MagicLink, I>,
    {
        MagicLinkApi {
            auth: self,
            plugin: self.plugin_arc().clone(),
        }
    }
}

impl<A: AuthInstance> MagicLinkExt for A {}

/// Calls the magic link endpoints without HTTP.
pub struct MagicLinkApi<'a, A> {
    auth: &'a A,
    plugin: Arc<MagicLink>,
}

impl<A: AuthInstance> MagicLinkApi<'_, A> {
    /// `POST /sign-in/magic-link`: emails a link.
    pub async fn sign_in(
        &self,
        input: SignInMagicLinkInput,
    ) -> Result<ApiResponse<Status>, AuthError> {
        self.auth
            .api()
            .call(&SignInMagicLink(self.plugin.clone()), input)
            .await
    }

    /// `GET /magic-link/verify`. The response's cookies carry the new session.
    pub async fn verify(
        &self,
        headers: &HeaderMap,
        input: VerifyMagicLinkInput,
    ) -> Result<ApiResponse<VerifyMagicLinkOutput>, AuthError> {
        self.auth
            .api()
            .headers(headers)
            .call(&VerifyMagicLink(self.plugin.clone()), input)
            .await
    }
}
