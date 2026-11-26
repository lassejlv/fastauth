# Magic links (feature `magic-link`)

```rust
use fastauth::mail::{AuthEmail, Mailer};
use fastauth::plugins::magic_link::{MagicLink, MagicLinkExt, SignInMagicLinkInput};
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![MagicLink]>;

pub fn build(pool: PgPool, mailer: impl Mailer) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .mailer(mailer)
        .plugin(MagicLink::new().expires_in(Duration::minutes(10)))
        .build()
}

// In your Mailer: the link arrives as AuthEmail::Plugin with kind "magic-link".
pub fn magic_link_url(email: &AuthEmail) -> Option<&str> {
    match email {
        AuthEmail::Plugin(e) if e.kind == "magic-link" => e.url.as_deref(),
        _ => None,
    }
}

pub async fn email_link(auth: &AppAuth, email: &str) -> Result<(), AuthError> {
    auth.magic_link()
        .sign_in(SignInMagicLinkInput {
            email: email.into(),
            callback_url: Some("/dashboard".into()),
            ..Default::default()
        })
        .await?;
    Ok(())
}
```

Full page: `docs/plugins/sign-in/01-magic-link.md`.

## Setup

- `fastauth = { version = "0.5", features = ["magic-link"] }`; path `fastauth::plugins::magic_link`.
- Needs a mailer (`.mailer(..)`); without one, `/sign-in/magic-link` answers 500.
- No tables or columns: links live in core's `verification` table, as a SHA-256 of the token.
- Options: `expires_in` (5 minutes), `disable_sign_up(true)` (unknown emails get
  `error=new_user_signup_disabled`), `rate_limit` (5 per minute per route).

## Routes (under `/api/auth`)

- `POST /sign-in/magic-link` `{ email, name?, callbackURL?, newUserCallbackURL?, errorCallbackURL?, metadata? }`
  answers `{ "status": true }` for every valid email, so it doesn't reveal accounts.
- `GET /magic-link/verify?token=..&callbackURL=..` is the link. It works once, creates the user
  on first use (`emailVerified: true`), runs every sign-in gate with method `"magic-link"`, sets
  the session cookies and redirects to `callbackURL` (`newUserCallbackURL` for a new user), or
  answers `{ token, user, session }` without a callback.
- Failures redirect to `errorCallbackURL` with `?error=INVALID_TOKEN` and similar. Untrusted
  callback URLs answer 403 as JSON: `INVALID_CALLBACK_URL`, `INVALID_ERROR_CALLBACK_URL`,
  `INVALID_NEW_USER_CALLBACK_URL`.
- A link for an unverified user's email deletes that user's earlier accounts and sessions and
  marks the email verified.
- With two-factor on, verify answers the challenge instead of a session.

## Server API and gaps

- `auth.magic_link()`: `sign_in(input)`, `verify(&headers, input)` (answers `SignedIn`,
  `Challenge` or `Redirect`). Only compiles with `MagicLink` in the alias.
- `metadata` doesn't reach the mailer; read it in `hook::<SignInMagicLink>().before(..)`.
- Not built: `generateToken`, `storeToken`, `sendMagicLink` as a callback.
- Client: `magicLinkClient()` from `better-auth/client/plugins`, then
  `authClient.signIn.magicLink({ email, callbackURL })`.
