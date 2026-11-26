# Email OTP

The `EmailOtp` plugin sends one-time codes by email to sign in, verify an email address or
reset a password. It matches Better Auth's `emailOTP` plugin, including its routes, JSON and
error codes, so `emailOTPClient` works unchanged. A sign-in code for an unknown email
creates the user, unless you turn sign-up off.

## Setup

Turn on the facade's `email-otp` feature:

```toml
[dependencies]
fastauth = { version = "0.3", features = ["email-otp"] }
```

The plugin lives at `fastauth::plugins::email_otp` (crate `fastauth-plugin-email-otp`).
It sends codes through the app's mailer:

```rust
use fastauth::plugins::email_otp::EmailOtp;
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![EmailOtp]>;

pub fn build(pool: PgPool, mailer: impl Mailer) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .mailer(mailer)
        .plugin(EmailOtp::new())
        .build()
}
```

The plugin adds no tables or columns; codes live in core's `verification` table. Without a
mailer, sending a code answers `500 INTERNAL_SERVER_ERROR` and logs that no mailer is
configured. `email_password` isn't required, but `/email-otp/reset-password` uses its
password length limits and `revoke_sessions_on_password_reset` (on by default).

Codes are emailed in the background, so `send-verification-otp` and `request-password-reset`
answer in the same time whether or not the email has an account (and so sent anything).
A failed send is logged with `tracing::error!` instead of failing the request.

### The email

Your mailer gets `AuthEmail::Plugin` with the code in `code` and a `kind` per purpose:

| `type` | `kind` |
|---|---|
| `sign-in` | `email-otp-sign-in` |
| `email-verification` | `email-otp-email-verification` |
| `forget-password` | `email-otp-forget-password` |

`subject` and `text` are plain-text defaults you can replace with a template:

```rust
match email {
    AuthEmail::Plugin(e) if e.kind.starts_with("email-otp-") => {
        let code = e.code.expect("email OTP emails carry the code");
        self.send_template(e.kind, &e.to, &code).await
    }
    other => { /* .. */ }
}
```

## Configuration

| Method | Default | What it does |
|---|---|---|
| `.otp_length(usize)` | 6 | Digits per code, at least 4 |
| `.expires_in(Duration)` | 5 minutes | How long a code works (Better Auth's `expiresIn: 300`) |
| `.allowed_attempts(u32)` | 3 | Wrong guesses a code survives; the next guess answers `403 TOO_MANY_ATTEMPTS` and burns it |
| `.disable_sign_up(bool)` | `false` | Sign-in codes go only to existing users, and `/sign-in/email-otp` never creates one |
| `.rate_limit(Limit)` | 3 per minute | Requests per client to each route, as in Better Auth. App rules win |

Core settings apply too: `EmailVerification::auto_sign_in_after_verification` makes
`/email-otp/verify-email` sign the user in.

## Endpoints

Under your `base_path` (`/api/auth` by default):

| Method | Path | Better Auth client | Notes |
|---|---|---|---|
| `POST` | `/email-otp/send-verification-otp` | `authClient.emailOtp.sendVerificationOtp` | `email`, `type`. Answers `{ "success": true }` |
| `POST` | `/sign-in/email-otp` | `authClient.signIn.emailOtp` | `email`, `otp`, plus `name`, `image` and your `input` user fields for a new user. Answers `{ token, user }` |
| `POST` | `/email-otp/verify-email` | `authClient.emailOtp.verifyEmail` | `email`, `otp`. Answers `{ status: true, token, user }` |
| `POST` | `/email-otp/check-verification-otp` | `authClient.emailOtp.checkVerificationOtp` | `email`, `type`, `otp`. Checks a code without using it up |
| `POST` | `/email-otp/request-password-reset` | `authClient.emailOtp.requestPasswordReset` | `email`. Sends a `forget-password` code |
| `POST` | `/forget-password/email-otp` | `authClient.forgetPassword.emailOtp` | The older name of the route above |
| `POST` | `/email-otp/reset-password` | `authClient.emailOtp.resetPassword` | `email`, `otp`, `password`. Answers `{ "success": true }` |

**Sending.** `type` is `sign-in`, `email-verification` or `forget-password`; `change-email`
answers `400 INVALID_OTP_TYPE`, as Better Auth does on this route. A new code replaces the
previous one for the same email and type. Every valid request answers success, but a code
is only emailed (and kept) when the email has a user, or when it's a `sign-in` code and
sign-up is on. So the routes don't reveal who has an account.

**Signing in.** A right `sign-in` code signs the user in through every plugin's sign-in
gate with method `"email-otp"`; a gate that challenges answers its JSON
(`{ "twoFactorRedirect": true, .. }`) instead of `{ token, user }`. An unknown email creates
a user with `emailVerified: true`. Extra body keys are user fields, checked like
[sign-up](../../get-started/03-configuration.md#user-fields): an unknown or non-`input` field answers `400 INVALID_FIELD`.

**Claiming unverified users.** A code proves who owns the email. When a sign-in or
password-reset code lands on a user whose email isn't verified, every account (password
and OAuth links) and session that user had is deleted first and the email is marked
verified, so whoever registered the address first keeps no access. Better Auth does the
same for sign-in. Password reset then creates a fresh password.

**Verifying an email.** `/email-otp/verify-email` sets `emailVerified` and emits
`EmailVerified`. `token` is `null` unless `auto_sign_in_after_verification` is on.

**Resetting a password.** `check-verification-otp` lets a form check the code before asking
for the new password; it keeps the code. `reset-password` uses it up, sets the password,
revokes every session of the user unless `revoke_sessions_on_password_reset(false)` is set,
and emits `PasswordChanged`.

## Server API

`auth.email_otp()` (trait `EmailOtpExt`) calls the endpoints without HTTP:
`send_verification_otp`, `check_verification_otp`, `verify_email`, `sign_in`,
`request_password_reset` and `reset_password`.

```rust
use fastauth::plugins::email_otp::{EmailOtpExt, OtpType, SendOtpInput};

auth.email_otp()
    .send_verification_otp(SendOtpInput { email: "ada@acme.dk".into(), kind: OtpType::SignIn })
    .await?;
```

Every endpoint type (`SendVerificationOtp`, `SignInEmailOtp`, `VerifyEmailOtp`,
`CheckVerificationOtp`, `RequestPasswordResetOtp`, `ForgetPasswordOtp`,
`ResetPasswordOtp`) is hookable ([Hooks](../../reference/01-plugin-authoring.md#hooks)).

## How codes are stored

- **One row per purpose and email**, in `verification` under Better Auth's identifier
  `{type}-otp-{email}` (`sign-in-otp-ada@acme.dk`).
- **Only a keyed hash.** `value_hash` is an HMAC-SHA256 of the identifier and the code,
  under a key derived from your secret for this plugin. A short code hashed without a key
  could be brute-forced from a database dump; this one can't without the secret. The code
  appears only in the email, never in a response or a log.
- **Constant-time comparison** of the stored and computed hashes.
- **Attempts are counted atomically.** `data` holds the number of guesses. Each guess first
  claims an attempt with a conditional update that only applies if the count is still the
  one it read, and only then compares the code. Concurrent guesses that lose that race
  answer `INVALID_OTP` without being compared, so parallel requests can't try more than
  `allowed_attempts` codes. A guess past the limit deletes the code and answers
  `TOO_MANY_ATTEMPTS`. A right code is deleted when used; `check-verification-otp` gives its
  attempt back instead.
- An expired code is deleted when tried and answers `OTP_EXPIRED`.

## Error codes

| Code | Status | When |
|---|---|---|
| `INVALID_OTP` | 400 | The code is wrong, used, replaced, or was never sent; also sign-in for an unknown email with sign-up off |
| `OTP_EXPIRED` | 400 | The code is past `expires_in` |
| `TOO_MANY_ATTEMPTS` | 403 | The code already took `allowed_attempts` wrong guesses |
| `INVALID_OTP_TYPE` | 400 | `send-verification-otp` with `type: "change-email"` |

Core's codes appear too: `400 INVALID_EMAIL`, `400 USER_NOT_FOUND` (a right code for an
email whose user was deleted), `400 INVALID_FIELD`, `400 PASSWORD_TOO_SHORT` and
`PASSWORD_TOO_LONG`, and `400 INVALID_REQUEST_BODY` for an unknown `type`.

## Better Auth's client

```ts
import { createAuthClient } from "better-auth/client";
import { emailOTPClient } from "better-auth/client/plugins";

export const authClient = createAuthClient({
  baseURL: "http://localhost:3000",
  plugins: [emailOTPClient()],
});

await authClient.emailOtp.sendVerificationOtp({ email: "ada@acme.dk", type: "sign-in" });
const { data } = await authClient.signIn.emailOtp({ email: "ada@acme.dk", otp: "123456" });
```

`compat/better-auth/run-email-otp.sh` builds the plugin's `email_otp_server` example, which
writes emails to an outbox file, and runs `email-otp.ts` against it with Better Auth
1.7.28. It checks sign-up by code (a verified user, `getSession`), a used code, three wrong
codes then `403 TOO_MANY_ATTEMPTS`, `verifyEmail` after a password sign-up,
`requestPasswordReset`, `checkVerificationOtp` and `resetPassword` followed by a password
sign-in, the deprecated `forgetPassword.emailOtp`, and invalid input.

## Not built

- The change-email flow (`changeEmail`, `/email-otp/request-email-change`,
  `/email-otp/change-email`).
- `sendVerificationOnSignUp` and `overrideDefaultEmailVerification`; core's link-based
  verification email still goes out on sign-up unless you turn it off with
  `EmailVerification::send_on_sign_up(false)`.
- `storeOTP` options and `resendStrategy: "reuse"` (codes are always stored as a keyed hash,
  so they can't be resent), and the server-only `getVerificationOTP` and
  `createVerificationOTP`.
- `generateOTP` and `sendVerificationOTP` as callbacks; the app's mailer sends the code.
