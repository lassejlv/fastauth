//! The email OTP routes.

use fastauth_core::events::{EmailVerified, PasswordChanged};
use fastauth_core::mail::{AuthEmail, PluginEmail};
use fastauth_core::plugin_prelude::*;
use fastauth_core::routes::{normalize_email, user_input_fields};
use serde_json::{Map, Value as Json};

use crate::otp::{self, OnMatch};
use crate::{EmailOtp, EmailOtpError, OtpType};

/// `{"success": true}`
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Success {
    pub success: bool,
}

const SUCCESS: Success = Success { success: true };

fn user_not_found() -> AuthError {
    AuthError::new(
        StatusCode::BAD_REQUEST,
        codes::USER_NOT_FOUND,
        "User not found",
    )
}

/// Issues a code and emails it, unless the email has no user and the code couldn't sign one
/// up. Either way the caller answers success, so the route doesn't reveal who has an account.
async fn send_code<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    plugin: &EmailOtp,
    email: &str,
    kind: OtpType,
) -> Result<(), AuthError> {
    let identifier = otp::identifier(kind, email);
    let code = otp::issue(ctx, plugin, &identifier).await?;
    let internal = ctx.internal();
    let user = internal.find_user_by_email(email).await?;
    let signs_up = kind == OtpType::SignIn && !plugin.disable_sign_up;
    if user.is_none() && !signs_up {
        return otp::discard(ctx, &identifier).await;
    }
    let app_name = &ctx.config().app_name;
    let subject = match kind {
        OtpType::SignIn => format!("Your {app_name} sign-in code"),
        OtpType::EmailVerification => format!("Verify your email for {app_name}"),
        OtpType::ForgetPassword => format!("Reset your {app_name} password"),
        OtpType::ChangeEmail => format!("Confirm your new {app_name} email"),
    };
    let minutes = plugin.expires_in.whole_minutes().max(1);
    internal
        .send_email_in_background(AuthEmail::Plugin(PluginEmail {
            kind: kind.email_kind(),
            to: user.map_or_else(|| email.to_owned(), |u| u.email.clone()),
            subject,
            text: format!(
                "Your code is {code}. It expires in {minutes} minutes. Ignore this email if \
                 you didn't ask for it.\n"
            ),
            url: None,
            code: Some(code),
        }))
        .await
}

// ---------------------------------------------------------------------------- send

/// `POST /email-otp/send-verification-otp`: emails a code of the given `type`.
pub struct SendVerificationOtp(pub(crate) Arc<EmailOtp>);

#[derive(Debug, Deserialize)]
pub struct SendOtpInput {
    pub email: String,
    #[serde(rename = "type")]
    pub kind: OtpType,
}

impl<D: Adapter> Endpoint<D> for SendVerificationOtp {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/email-otp/send-verification-otp";
    type Access = Public;
    type Input = SendOtpInput;
    type Output = Success;

    async fn call(&self, ctx: Ctx<D, Public>, input: SendOtpInput) -> Result<Success, AuthError> {
        let email = normalize_email(&input.email)?;
        if input.kind == OtpType::ChangeEmail {
            return Err(EmailOtpError::InvalidOtpType.into());
        }
        send_code(&ctx, &self.0, &email, input.kind).await?;
        Ok(SUCCESS)
    }
}

/// `POST /email-otp/request-password-reset`: emails a `forget-password` code.
pub struct RequestPasswordResetOtp(pub(crate) Arc<EmailOtp>);

/// The older Better Auth name for `/email-otp/request-password-reset`.
pub struct ForgetPasswordOtp(pub(crate) Arc<EmailOtp>);

#[derive(Debug, Deserialize)]
pub struct EmailInput {
    pub email: String,
}

impl<D: Adapter> Endpoint<D> for RequestPasswordResetOtp {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/email-otp/request-password-reset";
    type Access = Public;
    type Input = EmailInput;
    type Output = Success;

    async fn call(&self, ctx: Ctx<D, Public>, input: EmailInput) -> Result<Success, AuthError> {
        let email = normalize_email(&input.email)?;
        send_code(&ctx, &self.0, &email, OtpType::ForgetPassword).await?;
        Ok(SUCCESS)
    }
}

impl<D: Adapter> Endpoint<D> for ForgetPasswordOtp {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/forget-password/email-otp";
    type Access = Public;
    type Input = EmailInput;
    type Output = Success;

    async fn call(&self, ctx: Ctx<D, Public>, input: EmailInput) -> Result<Success, AuthError> {
        let email = normalize_email(&input.email)?;
        send_code(&ctx, &self.0, &email, OtpType::ForgetPassword).await?;
        Ok(SUCCESS)
    }
}

// ---------------------------------------------------------------------------- check

/// `POST /email-otp/check-verification-otp`: whether a code is right, without using it up,
/// so a later `reset-password` or `sign-in` can. A wrong code still counts as an attempt.
pub struct CheckVerificationOtp(pub(crate) Arc<EmailOtp>);

#[derive(Debug, Deserialize)]
pub struct CheckOtpInput {
    pub email: String,
    #[serde(rename = "type")]
    pub kind: OtpType,
    pub otp: String,
}

impl<D: Adapter> Endpoint<D> for CheckVerificationOtp {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/email-otp/check-verification-otp";
    type Access = Public;
    type Input = CheckOtpInput;
    type Output = Success;

    async fn call(&self, ctx: Ctx<D, Public>, input: CheckOtpInput) -> Result<Success, AuthError> {
        let email = normalize_email(&input.email)?;
        let identifier = otp::identifier(input.kind, &email);
        otp::verify(&ctx, &self.0, &identifier, &input.otp, OnMatch::Keep).await?;
        if ctx.internal().find_user_by_email(&email).await?.is_none() {
            return Err(user_not_found());
        }
        Ok(SUCCESS)
    }
}

// ---------------------------------------------------------------------------- verify email

/// `POST /email-otp/verify-email`: marks the email verified with an `email-verification`
/// code. Signs the user in when `EmailVerification::auto_sign_in_after_verification` is on.
pub struct VerifyEmailOtp(pub(crate) Arc<EmailOtp>);

#[derive(Debug, Deserialize)]
pub struct VerifyEmailOtpInput {
    pub email: String,
    pub otp: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum VerifyEmailOtpOutput {
    /// `{ status: true, token, user }`; `token` is `null` unless the call signed in.
    Verified {
        status: bool,
        token: Option<String>,
        user: Map<String, Json>,
    },
    /// A sign-in gate's answer, e.g. `{"twoFactorRedirect": true}`.
    Challenge(Json),
}

impl<D: Adapter> Endpoint<D> for VerifyEmailOtp {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/email-otp/verify-email";
    type Access = Public;
    type Input = VerifyEmailOtpInput;
    type Output = VerifyEmailOtpOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: VerifyEmailOtpInput,
    ) -> Result<VerifyEmailOtpOutput, AuthError> {
        let email = normalize_email(&input.email)?;
        let identifier = otp::identifier(OtpType::EmailVerification, &email);
        otp::verify(&ctx, &self.0, &identifier, &input.otp, OnMatch::Consume).await?;
        let internal = ctx.internal();
        let user = internal
            .find_user_by_email(&email)
            .await?
            .ok_or_else(user_not_found)?;
        ctx.db()
            .update::<User>(User::ID.eq(&user.id))
            .set(User::EMAIL_VERIFIED, true)
            .exec()
            .await?;
        ctx.emit(EmailVerified {
            user_id: user.id.clone(),
        });
        let user = internal
            .find_user_by_id(&user.id)
            .await?
            .ok_or_else(|| AuthError::internal("user deleted while verifying its email"))?;
        let json = user.to_json();
        if !ctx
            .config()
            .email_verification
            .auto_signs_in_after_verification()
        {
            return Ok(VerifyEmailOtpOutput::Verified {
                status: true,
                token: None,
                user: json,
            });
        }
        Ok(match internal.sign_in(user, EmailOtp::ID, true).await? {
            SignInResult::SignedIn(session) => VerifyEmailOtpOutput::Verified {
                status: true,
                token: session.token.clone(),
                user: json,
            },
            SignInResult::Challenge(body) => VerifyEmailOtpOutput::Challenge(body),
        })
    }
}

// ---------------------------------------------------------------------------- sign in

/// `POST /sign-in/email-otp`: signs in with a `sign-in` code, creating the user on first use
/// unless sign-up is disabled. A code proves the email, so an unverified user it lands on is
/// claimed first: accounts and sessions from before the proof are deleted.
pub struct SignInEmailOtp(pub(crate) Arc<EmailOtp>);

#[derive(Debug, Deserialize)]
pub struct SignInEmailOtpInput {
    pub email: String,
    pub otp: String,
    /// The new user's name, when the code signs them up.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub image: Option<String>,
    /// App and plugin `input` columns for a new user, by camelCase name, as on sign-up.
    #[serde(flatten)]
    pub extra: Map<String, Json>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum SignInEmailOtpOutput {
    /// Better Auth's `{ token, user }`.
    SignedIn {
        token: String,
        user: Map<String, Json>,
    },
    /// A sign-in gate's answer, e.g. `{"twoFactorRedirect": true}`.
    Challenge(Json),
}

impl<D: Adapter> Endpoint<D> for SignInEmailOtp {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/sign-in/email-otp";
    type Access = Public;
    type Input = SignInEmailOtpInput;
    type Output = SignInEmailOtpOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: SignInEmailOtpInput,
    ) -> Result<SignInEmailOtpOutput, AuthError> {
        let email = normalize_email(&input.email)?;
        let identifier = otp::identifier(OtpType::SignIn, &email);
        otp::verify(&ctx, &self.0, &identifier, &input.otp, OnMatch::Consume).await?;
        let internal = ctx.internal();
        let user = match internal.find_user_by_email(&email).await? {
            Some(user) => internal.claim_unverified_user(user).await?,
            None if self.0.disable_sign_up => return Err(EmailOtpError::InvalidOtp.into()),
            None => {
                let new_user = NewUser {
                    email,
                    name: input.name.unwrap_or_default(),
                    image: input.image,
                    email_verified: true,
                    extra: user_input_fields(&ctx, &input.extra, true)?,
                };
                internal.create_user(new_user, None).await?
            }
        };
        Ok(match internal.sign_in(user, EmailOtp::ID, true).await? {
            SignInResult::SignedIn(session) => SignInEmailOtpOutput::SignedIn {
                token: session.token.clone().unwrap_or_default(),
                user: session.user.to_json(),
            },
            SignInResult::Challenge(body) => SignInEmailOtpOutput::Challenge(body),
        })
    }
}

// ---------------------------------------------------------------------------- reset password

/// `POST /email-otp/reset-password`: sets a new password with a `forget-password` code.
/// The code proves the email, so the user is claimed first when it isn't verified.
pub struct ResetPasswordOtp(pub(crate) Arc<EmailOtp>);

#[derive(Debug, Deserialize)]
pub struct ResetPasswordOtpInput {
    pub email: String,
    pub otp: String,
    pub password: String,
}

impl<D: Adapter> Endpoint<D> for ResetPasswordOtp {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/email-otp/reset-password";
    type Access = Public;
    type Input = ResetPasswordOtpInput;
    type Output = Success;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: ResetPasswordOtpInput,
    ) -> Result<Success, AuthError> {
        let email = normalize_email(&input.email)?;
        let internal = ctx.internal();
        internal.validate_new_password(&input.password)?;
        let identifier = otp::identifier(OtpType::ForgetPassword, &email);
        otp::verify(&ctx, &self.0, &identifier, &input.otp, OnMatch::Consume).await?;
        let user = internal
            .find_user_by_email(&email)
            .await?
            .ok_or_else(user_not_found)?;
        let user = internal.claim_unverified_user(user).await?;
        internal.set_password(&user.id, &input.password).await?;
        if ctx
            .config()
            .email_password
            .as_ref()
            .is_some_and(|config| config.revokes_sessions_on_password_reset())
        {
            internal.revoke_user_sessions(&user.id, None).await?;
        }
        ctx.emit(PasswordChanged {
            user_id: user.id.clone(),
        });
        Ok(SUCCESS)
    }
}
