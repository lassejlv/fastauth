# First-party plugins

```rust
use axum::http::HeaderMap;
use fastauth::plugins::two_factor::{EnableInput, TwoFactor, TwoFactorExt, TwoFactorUser};
use fastauth::prelude::*;
use fastauth::social::{AccountLinking, Github, Google, Social};

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![Social, TwoFactor]>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .app_name("Acme")
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .mailer(LogMailer)
        .plugin(
            Social::new()
                .provider(Github::from_env()?)
                .provider(Google::new("client-id", "client-secret"))
                .account_linking(AccountLinking::ByVerifiedEmail),
        )
        .plugin(
            TwoFactor::new()
                .issuer("Acme")
                .backup_codes(8)
                .trust_device_for(Duration::days(14)),
        )
        .build()
}

pub fn two_factor_on(session: &Session<AppAuth>) -> bool {
    let tfa: &TwoFactorUser = session.user.plugin::<TwoFactor, _>();
    tfa.two_factor_enabled
}

pub async fn start_totp_setup(
    auth: &AppAuth,
    headers: &HeaderMap,
    password: String,
) -> Result<String, AuthError> {
    let setup = auth
        .two_factor()
        .enable(headers, EnableInput { password, issuer: None })
        .await?;
    Ok(setup.data.totp_uri)
}
```

## Social (feature `oauth`)

- `Github::from_env()?` reads `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`;
  `Google::from_env()?` reads `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`. A missing
  variable is a `BuildError`. `.scopes([..])` replaces the default scopes.
- Register the provider's redirect URL as `{base_url}{base_path}/callback/{id}`, for example
  `https://acme.dk/api/auth/callback/github`; the ids are `github` and `google`.
- Routes: `POST /sign-in/social` with `{ "provider": "github", "callbackURL": "/dashboard" }`
  answers `{ url, redirect: true }`; the browser goes to `url`, the provider returns to
  `/callback/{id}`, and that redirects to `callbackURL` with the session cookie set, or to
  `errorCallbackURL?error=..` on failure. `/link-social`, `/list-accounts` and
  `/unlink-account` manage linked accounts for a signed-in user.
- `AccountLinking::ByVerifiedEmail` (the default) attaches a social sign-in to an existing
  user with the same email only when the provider says the email is verified;
  `AccountLinking::Off` never links by email.
- Social sign-up creates the user with no app columns, so required app columns need a
  `default` ([database.md](database.md#app-columns-on-user)).

## TwoFactor (feature `two-factor`)

Adds `user.two_factor_enabled` (read it as `session.user.plugin::<TwoFactor, _>()`, a
`&TwoFactorUser`) and a `two_factor` table, so run migrations after adding it.

The flow, with Better Auth's routes and JSON:

1. A signed-in user calls `POST /two-factor/enable` `{ "password" }` and gets
   `{ "totpURI", "backupCodes" }`. Show the URI as a QR code and the backup codes once.
2. The first `POST /two-factor/verify-totp` `{ "code" }` turns it on
   (`.skip_verification_on_enable(true)` turns it on at step 1).
3. From then on, `/sign-in/email` answers `{ "twoFactorRedirect": true }` instead of a
   session, plus a short-lived signed cookie naming the pending user. Social sign-in
   redirects to `callbackURL?twoFactorRedirect=true` instead.
4. The client finishes with `/two-factor/verify-totp`, `/two-factor/send-otp` then
   `/two-factor/verify-otp`, or `/two-factor/verify-backup-code`; that creates the session.
   `"trustDevice": true` skips step 3 on that device for `trust_device_for` (30 days by
   default).

Email OTP sends through the mailer, so set `.mailer(..)`; without one `send-otp` fails with
a 500. The verify routes allow 5 attempts a minute. From Rust, `auth.two_factor()` (trait
`TwoFactorExt`) has `enable`, `disable` and `verify_totp`, each taking the request's
headers, which carry the session or the pending sign-in.

## Plugin data on the user

`session.user.plugin::<P, _>()` returns `&P::UserFields` and only compiles when `P` is in
the alias. `session.session_plugin::<P, _>()` does the same for session columns. The `_` is
the plugin's position in the list; never write it out.
