//! Passkeys for [fastauth](https://github.com/lassejlv/fastauth): WebAuthn registration and
//! sign-in, built on [webauthn-rs](https://docs.rs/webauthn-rs). The routes and JSON match
//! Better Auth's passkey plugin, so its `passkeyClient` works unchanged.
//!
//! ```
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_passkey::{Passkey, PasskeyExt};
//!
//! let auth: Auth<MemoryAdapter, (), plugins![Passkey]> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("https://acme.dk")
//!     .database(MemoryAdapter::new())
//!     .email_password(EmailPassword::default())
//!     .plugin(Passkey::new().rp_name("Acme"))
//!     .build()?;
//! let _passkeys = auth.passkey();
//! # Ok::<(), BuildError>(())
//! ```
//!
//! Without the plugin registered, `auth.passkey()` doesn't compile:
//!
//! ```compile_fail
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_passkey::PasskeyExt;
//!
//! let auth: Auth<MemoryAdapter> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("https://acme.dk")
//!     .database(MemoryAdapter::new())
//!     .build()
//!     .unwrap();
//! let _passkeys = auth.passkey();
//! ```
//!
//! A signed-in user adds a passkey with `generate-register-options` then
//! `verify-registration`; anyone signs in with `generate-authenticate-options` then
//! `verify-authentication`. Each `generate-*` call stores its challenge server-side for five
//! minutes, in the `verification` table, and names it in a signed `{prefix}.passkey` cookie;
//! the matching `verify-*` call consumes it, so each challenge works once. Signing in runs the
//! other plugins' sign-in gates with method `"passkey"`, and checks and advances the
//! credential's signature counter.

mod ceremony;
mod endpoints;
mod error;
mod model;

use fastauth_core::config::CoreConfig;
use fastauth_core::plugin_prelude::*;
use fastauth_core::{ApiResponse, routes::Status};

pub use endpoints::{
    DeletePasskey, DeletePasskeyInput, GenerateAuthenticateOptions, GenerateRegisterOptions,
    GenerateRegisterOptionsInput, ListUserPasskeys, PasskeyView, RegisterOutput, SignInOutput,
    UpdatePasskey, UpdatePasskeyInput, UpdatePasskeyOutput, VerifyAuthentication,
    VerifyAuthenticationInput, VerifyRegistration, VerifyRegistrationInput,
};
pub use error::PasskeyError;
pub use model::PasskeyRow;
pub use webauthn_rs;

/// The passkey plugin: `.plugin(Passkey::new())`.
///
/// The relying party defaults to the app: its ID is `base_url`'s host, its name the app name,
/// and ceremonies may come from `base_url`'s origin or any exact (wildcard-free) trusted
/// origin. Passkeys always require user verification (a PIN or biometric), as webauthn-rs
/// does for passkeys.
#[derive(Clone, Debug, Default)]
pub struct Passkey {
    rp_id: Option<String>,
    rp_name: Option<String>,
    origins: Vec<String>,
}

impl Passkey {
    pub fn new() -> Self {
        Self::default()
    }

    /// The relying party ID passkeys are bound to: a domain, e.g. `acme.dk` to share
    /// passkeys between `acme.dk` and `app.acme.dk`. Default: `base_url`'s host.
    pub fn rp_id(mut self, rp_id: impl Into<String>) -> Self {
        self.rp_id = Some(rp_id.into());
        self
    }

    /// The name authenticators show for the site. Default: the app name.
    pub fn rp_name(mut self, rp_name: impl Into<String>) -> Self {
        self.rp_name = Some(rp_name.into());
        self
    }

    /// An origin ceremonies may come from, e.g. `https://app.acme.dk`. Call it once per
    /// origin. Setting any replaces the default (`base_url` plus exact trusted origins).
    pub fn origin(mut self, origin: impl Into<String>) -> Self {
        self.origins.push(origin.into());
        self
    }

    /// The relying party for this app's configuration.
    fn relying_party(&self, config: &CoreConfig) -> Result<webauthn_rs::Webauthn, AuthError> {
        ceremony::relying_party(
            self.rp_id.as_deref(),
            self.rp_name.as_deref(),
            &self.origins,
            config,
        )
    }
}

impl Plugin for Passkey {
    const ID: &'static str = "passkey";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn schema(&self, schema: &mut SchemaBuilder) {
        schema.model::<PasskeyRow>();
    }

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.endpoint(GenerateRegisterOptions(self.clone()))
            .endpoint(VerifyRegistration(self.clone()))
            .endpoint(GenerateAuthenticateOptions(self.clone()))
            .endpoint(VerifyAuthentication(self.clone()))
            .endpoint(ListUserPasskeys)
            .endpoint(DeletePasskey)
            .endpoint(UpdatePasskey)
            .errors::<PasskeyError>();
    }
}

/// Emitted when a user registers a passkey.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyAdded {
    pub user_id: Id,
    pub passkey_id: Id,
}

/// Emitted when a user deletes one of their passkeys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyDeleted {
    pub user_id: Id,
    pub passkey_id: Id,
}

impl Event for PasskeyAdded {}
impl Event for PasskeyDeleted {}

/// `auth.passkey()`: the server API. Only compiles on an `Auth` with `Passkey` registered.
pub trait PasskeyExt: AuthInstance + Sized {
    fn passkey<I>(&self) -> PasskeyApi<'_, Self>
    where
        Self: HasPlugin<Passkey, I>,
    {
        PasskeyApi { auth: self }
    }
}

impl<A: AuthInstance> PasskeyExt for A {}

/// Manages a user's passkeys without HTTP. `headers` are the request's: their cookies carry
/// the session. Registering and signing in need a browser, so they go over HTTP.
pub struct PasskeyApi<'a, A> {
    auth: &'a A,
}

impl<A: AuthInstance> PasskeyApi<'_, A> {
    /// `GET /passkey/list-user-passkeys`.
    pub async fn list(&self, headers: &HeaderMap) -> Result<Vec<PasskeyView>, AuthError> {
        Ok(self
            .auth
            .api()
            .headers(headers)
            .call(&ListUserPasskeys, Empty {})
            .await?
            .data)
    }

    /// `POST /passkey/update-passkey`: renames one of the user's passkeys.
    pub async fn update(
        &self,
        headers: &HeaderMap,
        input: UpdatePasskeyInput,
    ) -> Result<ApiResponse<UpdatePasskeyOutput>, AuthError> {
        self.auth
            .api()
            .headers(headers)
            .call(&UpdatePasskey, input)
            .await
    }

    /// `POST /passkey/delete-passkey`.
    pub async fn delete(
        &self,
        headers: &HeaderMap,
        input: DeletePasskeyInput,
    ) -> Result<ApiResponse<Status>, AuthError> {
        self.auth
            .api()
            .headers(headers)
            .call(&DeletePasskey, input)
            .await
    }
}
