//! Two-factor authentication for [fastauth](https://github.com/lassejlv/fastauth): TOTP
//! authenticator apps, one-time codes by email, backup codes and trusted devices. The routes
//! and JSON match Better Auth's two-factor plugin, so its `twoFactorClient` works unchanged.
//!
//! ```
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_two_factor::{TwoFactor, TwoFactorExt};
//!
//! let auth: Auth<MemoryAdapter, (), plugins![TwoFactor]> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .email_password(EmailPassword::default())
//!     .plugin(TwoFactor::new().issuer("Acme"))
//!     .build()?;
//! let _two_factor = auth.two_factor();
//! # Ok::<(), BuildError>(())
//! ```
//!
//! Without the plugin registered, `auth.two_factor()` doesn't compile:
//!
//! ```compile_fail
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_two_factor::TwoFactorExt;
//!
//! let auth: Auth<MemoryAdapter> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .email_password(EmailPassword::default())
//!     .build()
//!     .unwrap();
//! let _two_factor = auth.two_factor();
//! ```
//!
//! Signing in as a user with two-factor on answers
//! `{ "twoFactorRedirect": true, "twoFactorMethods": ["totp", "otp"] }` (`"otp"` only with a
//! mailer) and sets a
//! signed `{prefix}.two_factor` cookie naming the pending user. One of `verify-totp`,
//! `verify-otp` (after `send-otp`) or `verify-backup-code` then finishes the sign-in: the
//! other plugins' sign-in gates still run, so one that denies (a ban) or challenges answers
//! instead of a session.

mod endpoints;
mod error;
mod model;
pub mod totp;

use fastauth_core::plugin_prelude::*;
use fastauth_core::{ApiResponse, routes::Status};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

pub use endpoints::{
    BackupCodesOutput, Disable, Enable, EnableInput, EnableOutput, GenerateBackupCodes, GetTotpUri,
    PasswordInput, SendOtp, TotpUriOutput, VerifyBackupCode, VerifyInput, VerifyOtp, VerifyOutput,
    VerifyTotp,
};
pub use error::TwoFactorError;
pub use model::{TwoFactorRow, TwoFactorUser};

const URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// The two-factor plugin: `.plugin(TwoFactor::new().issuer("Acme"))`.
#[derive(Clone, Debug)]
pub struct TwoFactor {
    issuer: Option<String>,
    digits: u32,
    period: u32,
    backup_codes: usize,
    skip_verification_on_enable: bool,
    trust_device_for: Duration,
    two_factor_cookie_max_age: Duration,
}

impl Default for TwoFactor {
    fn default() -> Self {
        Self {
            issuer: None,
            digits: 6,
            period: 30,
            backup_codes: 10,
            skip_verification_on_enable: false,
            trust_device_for: Duration::days(30),
            two_factor_cookie_max_age: Duration::minutes(10),
        }
    }
}

impl TwoFactor {
    pub fn new() -> Self {
        Self::default()
    }

    /// The name authenticator apps show next to the account. Default: the app name.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Digits per TOTP code, 6 (the default) to 8.
    pub fn digits(mut self, digits: u32) -> Self {
        assert!((6..=8).contains(&digits), "TOTP codes have 6 to 8 digits");
        self.digits = digits;
        self
    }

    /// Seconds per TOTP code (default 30). Codes one period early or late are accepted.
    pub fn period(mut self, seconds: u32) -> Self {
        assert!(seconds > 0, "a TOTP period is at least one second");
        self.period = seconds;
        self
    }

    /// How many backup codes enabling or regenerating hands out (default 10).
    pub fn backup_codes(mut self, count: usize) -> Self {
        self.backup_codes = count;
        self
    }

    /// Turn two-factor on at `/two-factor/enable` instead of after the first verified code.
    pub fn skip_verification_on_enable(mut self, skip: bool) -> Self {
        self.skip_verification_on_enable = skip;
        self
    }

    /// How long `trustDevice: true` skips the challenge on that device (default 30 days).
    pub fn trust_device_for(mut self, duration: Duration) -> Self {
        self.trust_device_for = duration;
        self
    }

    /// How long a challenged sign-in may take to verify (default 10 minutes).
    pub fn two_factor_cookie_max_age(mut self, max_age: Duration) -> Self {
        self.two_factor_cookie_max_age = max_age;
        self
    }

    fn totp_uri(
        &self,
        app_name: &str,
        issuer: Option<&str>,
        account: &str,
        secret: &[u8],
    ) -> String {
        let issuer = issuer.or(self.issuer.as_deref()).unwrap_or(app_name);
        let issuer = utf8_percent_encode(issuer, URI_COMPONENT);
        format!(
            "otpauth://totp/{issuer}:{}?secret={}&issuer={issuer}&digits={}&period={}",
            utf8_percent_encode(account, URI_COMPONENT),
            totp::base32(secret),
            self.digits,
            self.period
        )
    }
}

impl Plugin for TwoFactor {
    const ID: &'static str = "two-factor";
    type Requires = ();
    type UserFields = TwoFactorUser;
    type SessionFields = ();

    fn schema(&self, schema: &mut SchemaBuilder) {
        schema.model::<TwoFactorRow>();
    }

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.endpoint(Enable(self.clone()))
            .endpoint(Disable)
            .endpoint(GetTotpUri(self.clone()))
            .endpoint(VerifyTotp(self.clone()))
            .endpoint(SendOtp)
            .endpoint(VerifyOtp(self.clone()))
            .endpoint(GenerateBackupCodes(self.clone()))
            .endpoint(VerifyBackupCode(self.clone()))
            .rate_limit("/two-factor/verify-*", Limit::per(Duration::minutes(1), 5))
            .errors::<TwoFactorError>();
        let plugin = self.clone();
        app.sign_in_gate(move |ctx, attempt| {
            let plugin = plugin.clone();
            async move { endpoints::gate(&plugin, ctx, attempt).await }
        });
    }
}

/// Emitted when a user's two-factor turns on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoFactorEnabled {
    pub user_id: Id,
}

/// Emitted when a user turns two-factor off.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoFactorDisabled {
    pub user_id: Id,
}

impl Event for TwoFactorEnabled {}
impl Event for TwoFactorDisabled {}

/// `auth.two_factor()`: the server API. Only compiles on an `Auth` with `TwoFactor` registered.
pub trait TwoFactorExt: AuthInstance + Sized {
    fn two_factor<I>(&self) -> TwoFactorApi<'_, Self>
    where
        Self: HasPlugin<TwoFactor, I>,
    {
        TwoFactorApi {
            auth: self,
            plugin: self.plugin_arc().clone(),
        }
    }
}

impl<A: AuthInstance> TwoFactorExt for A {}

/// Calls the two-factor endpoints without HTTP. `headers` are the request's: their cookies
/// carry the session, or the pending sign-in for `verify_totp`.
pub struct TwoFactorApi<'a, A> {
    auth: &'a A,
    plugin: Arc<TwoFactor>,
}

impl<A: AuthInstance> TwoFactorApi<'_, A> {
    /// `POST /two-factor/enable`.
    pub async fn enable(
        &self,
        headers: &HeaderMap,
        input: EnableInput,
    ) -> Result<ApiResponse<EnableOutput>, AuthError> {
        self.auth
            .api()
            .headers(headers)
            .call(&Enable(self.plugin.clone()), input)
            .await
    }

    /// `POST /two-factor/disable`.
    pub async fn disable(
        &self,
        headers: &HeaderMap,
        input: PasswordInput,
    ) -> Result<ApiResponse<Status>, AuthError> {
        self.auth.api().headers(headers).call(&Disable, input).await
    }

    /// `POST /two-factor/verify-totp`. The response's cookies carry a new session when this
    /// finishes a sign-in.
    pub async fn verify_totp(
        &self,
        headers: &HeaderMap,
        input: VerifyInput,
    ) -> Result<ApiResponse<VerifyOutput>, AuthError> {
        self.auth
            .api()
            .headers(headers)
            .call(&VerifyTotp(self.plugin.clone()), input)
            .await
    }
}
