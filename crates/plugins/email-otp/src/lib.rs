//! Email one-time codes for [fastauth](https://github.com/lassejlv/fastauth): sign in, verify
//! an email and reset a password with a code sent by email. The routes and JSON match Better
//! Auth's `emailOTP` plugin, so its `emailOTPClient` works unchanged.
//!
//! `POST /email-otp/send-verification-otp` with a `type` of `sign-in`, `email-verification` or
//! `forget-password` emails a code through the configured
//! [`Mailer`](fastauth_core::mail::Mailer) as `AuthEmail::Plugin` with `code: Some(..)` and
//! `kind` `"email-otp-sign-in"`, `"email-otp-email-verification"` or
//! `"email-otp-forget-password"`. With [`change_email`](EmailOtp::change_email) on, a signed-in
//! user changes their email with a code sent to the new address
//! (`/email-otp/request-email-change`, then `/email-otp/change-email`). Codes are stored as an HMAC in the `verification` table,
//! compared in constant time, burnt after [`allowed_attempts`](EmailOtp::allowed_attempts)
//! wrong guesses, and never logged or returned.
//!
//! ```
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_email_otp::{EmailOtp, EmailOtpExt};
//!
//! let auth: Auth<MemoryAdapter, (), plugins![EmailOtp]> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .mailer(LogMailer)
//!     .plugin(EmailOtp::new().otp_length(8).allowed_attempts(5))
//!     .build()?;
//! let _email_otp = auth.email_otp();
//! # Ok::<(), BuildError>(())
//! ```
//!
//! Without the plugin registered, `auth.email_otp()` doesn't compile:
//!
//! ```compile_fail
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_email_otp::EmailOtpExt;
//!
//! let auth: Auth<MemoryAdapter> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .build()
//!     .unwrap();
//! let _email_otp = auth.email_otp();
//! ```

mod endpoints;
mod error;
mod otp;

use fastauth_core::ApiResponse;
use fastauth_core::plugin_prelude::*;

pub use endpoints::{
    ChangeEmailOtp, ChangeEmailOtpInput, CheckOtpInput, CheckVerificationOtp, EmailInput,
    ForgetPasswordOtp, RequestEmailChangeOtp, RequestEmailChangeOtpInput, RequestPasswordResetOtp,
    ResetPasswordOtp, ResetPasswordOtpInput, SendOtpInput, SendVerificationOtp, SignInEmailOtp,
    SignInEmailOtpInput, SignInEmailOtpOutput, Success, VerifyEmailOtp, VerifyEmailOtpInput,
    VerifyEmailOtpOutput,
};
pub use error::EmailOtpError;

/// What a code is for: the `type` field of the routes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OtpType {
    SignIn,
    EmailVerification,
    ForgetPassword,
    /// A code sent to a new address by `/email-otp/request-email-change`.
    /// `send-verification-otp` answers `INVALID_OTP_TYPE` for it, as Better Auth does.
    ChangeEmail,
}

impl OtpType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SignIn => "sign-in",
            Self::EmailVerification => "email-verification",
            Self::ForgetPassword => "forget-password",
            Self::ChangeEmail => "change-email",
        }
    }

    /// The `PluginEmail::kind` of the email carrying this code.
    pub const fn email_kind(self) -> &'static str {
        match self {
            Self::SignIn => "email-otp-sign-in",
            Self::EmailVerification => "email-otp-email-verification",
            Self::ForgetPassword => "email-otp-forget-password",
            Self::ChangeEmail => "email-otp-change-email",
        }
    }
}

/// The email OTP plugin: `.plugin(EmailOtp::new())`. Needs a mailer.
#[derive(Clone, Debug)]
pub struct EmailOtp {
    otp_length: usize,
    expires_in: Duration,
    allowed_attempts: u32,
    disable_sign_up: bool,
    change_email: bool,
    verify_current_email: bool,
    rate_limit: Limit,
}

impl Default for EmailOtp {
    fn default() -> Self {
        Self {
            otp_length: 6,
            expires_in: Duration::seconds(300),
            allowed_attempts: 3,
            disable_sign_up: false,
            change_email: false,
            verify_current_email: false,
            rate_limit: Limit::per(Duration::minutes(1), 3),
        }
    }
}

impl EmailOtp {
    pub fn new() -> Self {
        Self::default()
    }

    /// Digits per code (default 6). At least 4.
    pub fn otp_length(mut self, digits: usize) -> Self {
        assert!(digits >= 4, "an email OTP has at least 4 digits");
        self.otp_length = digits;
        self
    }

    /// How long a code works (default 5 minutes, Better Auth's `expiresIn: 300`).
    pub fn expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_in = expires_in;
        self
    }

    /// Wrong guesses a code survives (default 3). The next guess answers
    /// `TOO_MANY_ATTEMPTS` and burns the code.
    pub fn allowed_attempts(mut self, attempts: u32) -> Self {
        assert!(attempts > 0, "a code allows at least one attempt");
        self.allowed_attempts = attempts;
        self
    }

    /// Only existing users can sign in with a code: `sign-in` codes go only to known emails,
    /// and `/sign-in/email-otp` never creates a user.
    pub fn disable_sign_up(mut self, disable: bool) -> Self {
        self.disable_sign_up = disable;
        self
    }

    /// The change-email flow (off by default, Better Auth's `changeEmail.enabled`): a
    /// signed-in user asks `/email-otp/request-email-change` for a code sent to the new
    /// address, then `/email-otp/change-email` with it makes that address theirs, verified.
    /// Off, both routes answer `400 CHANGE_EMAIL_WITH_OTP_IS_DISABLED`.
    pub fn change_email(mut self, enabled: bool) -> Self {
        self.change_email = enabled;
        self
    }

    /// Also require a code sent to the current address to request a change (Better Auth's
    /// `changeEmail.verifyCurrentEmail`, default off): an `email-verification` code from
    /// `send-verification-otp`, passed as `otp` to `request-email-change`.
    pub fn verify_current_email(mut self, verify: bool) -> Self {
        self.verify_current_email = verify;
        self
    }

    /// Requests per client to each route (default 3 a minute, as in Better Auth). App rules
    /// win.
    pub fn rate_limit(mut self, limit: Limit) -> Self {
        self.rate_limit = limit;
        self
    }
}

impl Plugin for EmailOtp {
    const ID: &'static str = "email-otp";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.endpoint(SendVerificationOtp(self.clone()))
            .endpoint(CheckVerificationOtp(self.clone()))
            .endpoint(VerifyEmailOtp(self.clone()))
            .endpoint(SignInEmailOtp(self.clone()))
            .endpoint(RequestPasswordResetOtp(self.clone()))
            .endpoint(ForgetPasswordOtp(self.clone()))
            .endpoint(ResetPasswordOtp(self.clone()))
            .endpoint(RequestEmailChangeOtp(self.clone()))
            .endpoint(ChangeEmailOtp(self.clone()))
            .errors::<EmailOtpError>();
        for path in [
            "/email-otp/send-verification-otp",
            "/email-otp/check-verification-otp",
            "/email-otp/verify-email",
            "/sign-in/email-otp",
            "/email-otp/request-password-reset",
            "/forget-password/email-otp",
            "/email-otp/reset-password",
            "/email-otp/request-email-change",
            "/email-otp/change-email",
        ] {
            app.rate_limit(path, self.rate_limit);
        }
    }
}

/// `auth.email_otp()`: the server API. Only compiles on an `Auth` with `EmailOtp` registered.
pub trait EmailOtpExt: AuthInstance + Sized {
    fn email_otp<I>(&self) -> EmailOtpApi<'_, Self>
    where
        Self: HasPlugin<EmailOtp, I>,
    {
        EmailOtpApi {
            auth: self,
            plugin: self.plugin_arc().clone(),
        }
    }
}

impl<A: AuthInstance> EmailOtpExt for A {}

/// Calls the email OTP endpoints without HTTP. `headers` are the request's, for the
/// session cookies a sign-in sets against.
pub struct EmailOtpApi<'a, A> {
    auth: &'a A,
    plugin: Arc<EmailOtp>,
}

impl<A: AuthInstance> EmailOtpApi<'_, A> {
    /// `POST /email-otp/send-verification-otp`: emails a code.
    pub async fn send_verification_otp(
        &self,
        input: SendOtpInput,
    ) -> Result<ApiResponse<Success>, AuthError> {
        self.auth
            .api()
            .call(&SendVerificationOtp(self.plugin.clone()), input)
            .await
    }

    /// `POST /email-otp/check-verification-otp`: checks a code without using it up.
    pub async fn check_verification_otp(
        &self,
        input: CheckOtpInput,
    ) -> Result<ApiResponse<Success>, AuthError> {
        self.auth
            .api()
            .call(&CheckVerificationOtp(self.plugin.clone()), input)
            .await
    }

    /// `POST /email-otp/verify-email`: marks the email verified.
    pub async fn verify_email(
        &self,
        headers: &HeaderMap,
        input: VerifyEmailOtpInput,
    ) -> Result<ApiResponse<VerifyEmailOtpOutput>, AuthError> {
        self.auth
            .api()
            .headers(headers)
            .call(&VerifyEmailOtp(self.plugin.clone()), input)
            .await
    }

    /// `POST /sign-in/email-otp`. The response's cookies carry the new session.
    pub async fn sign_in(
        &self,
        headers: &HeaderMap,
        input: SignInEmailOtpInput,
    ) -> Result<ApiResponse<SignInEmailOtpOutput>, AuthError> {
        self.auth
            .api()
            .headers(headers)
            .call(&SignInEmailOtp(self.plugin.clone()), input)
            .await
    }

    /// `POST /email-otp/request-password-reset`: emails a `forget-password` code.
    pub async fn request_password_reset(
        &self,
        input: EmailInput,
    ) -> Result<ApiResponse<Success>, AuthError> {
        self.auth
            .api()
            .call(&RequestPasswordResetOtp(self.plugin.clone()), input)
            .await
    }

    /// `POST /email-otp/reset-password`: sets a new password with a `forget-password` code.
    pub async fn reset_password(
        &self,
        input: ResetPasswordOtpInput,
    ) -> Result<ApiResponse<Success>, AuthError> {
        self.auth
            .api()
            .call(&ResetPasswordOtp(self.plugin.clone()), input)
            .await
    }

    /// `POST /email-otp/request-email-change`: emails a `change-email` code to the new
    /// address of the user `headers` sign in.
    pub async fn request_email_change(
        &self,
        headers: &HeaderMap,
        input: RequestEmailChangeOtpInput,
    ) -> Result<ApiResponse<Success>, AuthError> {
        self.auth
            .api()
            .headers(headers)
            .call(&RequestEmailChangeOtp(self.plugin.clone()), input)
            .await
    }

    /// `POST /email-otp/change-email`: makes the new address the user's, verified.
    pub async fn change_email(
        &self,
        headers: &HeaderMap,
        input: ChangeEmailOtpInput,
    ) -> Result<ApiResponse<Success>, AuthError> {
        self.auth
            .api()
            .headers(headers)
            .call(&ChangeEmailOtp(self.plugin.clone()), input)
            .await
    }
}
