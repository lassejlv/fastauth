# Email OTP (feature `email-otp`)

```rust
use fastauth::mail::{AuthEmail, Mailer};
use fastauth::plugins::email_otp::{EmailOtp, EmailOtpExt, OtpType, SendOtpInput};
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![EmailOtp]>;

pub fn build(pool: PgPool, mailer: impl Mailer) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .mailer(mailer)
        .plugin(EmailOtp::new().otp_length(6).allowed_attempts(3))
        .build()
}

// In your Mailer: kind is "email-otp-sign-in", "email-otp-email-verification",
// "email-otp-forget-password" or "email-otp-change-email", and the code is in code.
pub fn otp_code(email: &AuthEmail) -> Option<&str> {
    match email {
        AuthEmail::Plugin(e) if e.kind.starts_with("email-otp-") => e.code.as_deref(),
        _ => None,
    }
}

pub async fn send_sign_in_code(auth: &AppAuth, email: &str) -> Result<(), AuthError> {
    auth.email_otp()
        .send_verification_otp(SendOtpInput { email: email.into(), kind: OtpType::SignIn })
        .await?;
    Ok(())
}
```

Full page: `docs/plugins/sign-in/02-email-otp.md`.

## Setup

- `fastauth = { version = "0.7", features = ["email-otp"] }`; path `fastauth::plugins::email_otp`.
- Needs a mailer. No tables or columns: codes live in `verification` as an HMAC keyed from
  the secret, under the identifier `{type}-otp-{email}`.
- Options: `otp_length` (6, at least 4), `expires_in` (5 minutes), `allowed_attempts` (3),
  `disable_sign_up(true)`, `change_email(true)`, `verify_current_email(true)`, `rate_limit`
  (3 per minute per route).
- `email_password` isn't required; reset-password uses its length limits and
  `revoke_sessions_on_password_reset` when it's on.

## Routes (under `/api/auth`)

- `POST /email-otp/send-verification-otp` `{ email, type }`, `type` is `sign-in`,
  `email-verification` or `forget-password`. Always answers `{ "success": true }`; a code is
  only sent when the user exists, or for `sign-in` with sign-up on.
- `POST /sign-in/email-otp` `{ email, otp, name?, image?, ..input fields }` answers `{ token, user }`,
  creates unknown users (verified), and runs the sign-in gates with method `"email-otp"`.
- `POST /email-otp/verify-email` `{ email, otp }`, `POST /email-otp/check-verification-otp`
  `{ email, type, otp }` (doesn't use the code up), `POST /email-otp/request-password-reset`
  `{ email }` (old name `/forget-password/email-otp`), `POST /email-otp/reset-password`
  `{ email, otp, password }`.
- With `change_email(true)`: `POST /email-otp/request-email-change` `{ newEmail, otp? }` (session;
  emails a `change-email` code, kind `"email-otp-change-email"`, to the new address unless it's
  taken; `otp` is an `email-verification` code for the current address when
  `verify_current_email` is on), then `POST /email-otp/change-email` `{ newEmail, otp }` sets
  the new email, verified. Both read the session from the database (no API keys,
  no impersonation).
- Errors: 400 `INVALID_OTP`, 400 `OTP_EXPIRED`, 403 `TOO_MANY_ATTEMPTS` (the code is burnt),
  400 `INVALID_OTP_TYPE` for `change-email` on `send-verification-otp`, 400
  `CHANGE_EMAIL_WITH_OTP_IS_DISABLED`, `EMAIL_IS_THE_SAME`, `OTP_IS_REQUIRED_TO_VERIFY_CURRENT_EMAIL`,
  `EMAIL_ALREADY_IN_USE`.
- A sign-in or reset code for an unverified user's email deletes that user's earlier accounts
  and sessions and marks the email verified.

## Server API and gaps

- `auth.email_otp()`: `send_verification_otp`, `check_verification_otp`,
  `verify_email(&headers, ..)`, `sign_in(&headers, ..)`, `request_password_reset`,
  `reset_password`, `request_email_change(&headers, ..)`, `change_email(&headers, ..)`.
- Not built: `sendVerificationOnSignUp`,
  `overrideDefaultEmailVerification`, `storeOTP`, `resendStrategy`, `getVerificationOTP`.
- Client: `emailOTPClient()` from `better-auth/client/plugins`.
