# Magic links

The `MagicLink` plugin signs users in with a link sent by email. It matches Better Auth's
`magicLink` plugin, including its routes, JSON, redirects and error codes, so
`magicLinkClient` works unchanged. The first link for an unknown email creates the user,
unless you turn sign-up off.

## Setup

Turn on the facade's `magic-link` feature:

```toml
[dependencies]
fastauth = { version = "0.8", features = ["magic-link"] }
```

The plugin lives at `fastauth::plugins::magic_link` (crate `fastauth-plugin-magic-link`).
It sends links through the app's mailer, so configure one
([Email](../../get-started/03-configuration.md)):

```rust
use fastauth::plugins::magic_link::MagicLink;
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![MagicLink]>;

pub fn build(pool: PgPool, mailer: impl Mailer) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .mailer(mailer)
        .plugin(MagicLink::new())
        .build()
}
```

The plugin adds no tables or columns. Pending links live in core's `verification` table, so
there's nothing new to migrate. Without a mailer, `/sign-in/magic-link` answers
`500 INTERNAL_SERVER_ERROR` and logs that no mailer is configured.

### The email

Your mailer gets `AuthEmail::Plugin` with `kind: "magic-link"`, the link in `url` and a
plain-text `subject` and `text` you can use as they are or replace with a template:

```rust
use fastauth::mail::{AuthEmail, MailError, Mailer};

impl Mailer for MyMailer {
    async fn send(&self, email: AuthEmail) -> Result<(), MailError> {
        match email {
            AuthEmail::Plugin(e) if e.kind == "magic-link" => {
                let url = e.url.expect("magic-link emails carry the link");
                self.send_template("magic-link", &e.to, &url).await
            }
            other => {
                let (subject, body) = other.default_text("Acme");
                self.send_plain(other.to(), &subject, &body).await
            }
        }
    }
}
```

## Configuration

| Method | Default | What it does |
|---|---|---|
| `.expires_in(Duration)` | 5 minutes | How long a link works (Better Auth's `expiresIn: 300`) |
| `.disable_sign_up(bool)` | `false` | Only existing users can sign in; a link for an unknown email redirects with `error=new_user_signup_disabled` |
| `.rate_limit(Limit)` | 5 per minute | Requests per client to each route. App rules win |

## Endpoints

Under your `base_path` (`/api/auth` by default):

| Method | Path | Better Auth client | Notes |
|---|---|---|---|
| `POST` | `/sign-in/magic-link` | `authClient.signIn.magicLink` | `email`, `name`, `callbackURL`, `newUserCallbackURL`, `errorCallbackURL`, `metadata`. Answers `{ "status": true }` |
| `GET` | `/magic-link/verify` | `authClient.magicLink.verify` | `token` plus the three callback URLs. The link in the email |

`/sign-in/magic-link` answers the same for every valid email, so it doesn't reveal who has
an account. The link it emails is
`{base_url}{base_path}/magic-link/verify?token=..&callbackURL=..`, with `callbackURL`
defaulting to `/` and the other two callbacks included when you passed them.

`/magic-link/verify` consumes the token, then:

1. **Finds or creates the user.** An unknown email creates a user with `emailVerified: true`
   and the `name` from the sign-in request (or `""`).
2. **Claims an unverified user.** If the email belongs to a user whose email isn't
   verified, the link is the first proof of who owns it. Core
   [claims the user](../../concepts/03-security.md#claiming-an-email) in one transaction:
   every account (password and OAuth links), session, [passkey](03-passkey.md#claimed-users),
   API key and two-factor enrollment that user had is deleted, and the email is marked
   verified, so whoever registered the address first keeps no access. Better Auth does the
   same, except for passkeys, API keys and two-factor.
3. **Signs in** through every plugin's sign-in gate, with method `"magic-link"`.
4. **Answers.** With `callbackURL` in the query, a `302` to it, or to `newUserCallbackURL`
   when step 1 created the user. Without one, Better Auth's `{ token, user, session }` JSON.
   Either way the session cookies are set.

Relative callbacks resolve against `base_url`, as in Better Auth, so `/dashboard` redirects
to `https://acme.dk/dashboard`.

Failures after the URL check redirect to `errorCallbackURL` (or `callbackURL`, or `/`) with
an `error` query parameter:

| `error` | When |
|---|---|
| `INVALID_TOKEN` | The token is unknown, expired, already used, or isn't a magic link token |
| `new_user_signup_disabled` | No user has the email and sign-up is off |
| any other code, plus `error_description` | Creating the user failed, or a sign-in gate denied (`BANNED_USER` from the admin plugin) |

When a gate challenges instead, for example two-factor, no session is created and the
challenge cookie is set. Without `callbackURL` the answer is the gate's JSON
(`{ "twoFactorRedirect": true, .. }`). With one, it redirects to the callback with the
challenge's fields as query parameters (`?twoFactorMethods=totp%2Cotp&twoFactorRedirect=true`),
so the page can show the second step. Better Auth doesn't run two-factor for magic links.

## Server API

`auth.magic_link()` (trait `MagicLinkExt`) calls the endpoints without HTTP:

```rust
use fastauth::plugins::magic_link::{MagicLinkExt, SignInMagicLinkInput, VerifyMagicLinkInput};

auth.magic_link()
    .sign_in(SignInMagicLinkInput {
        email: "ada@acme.dk".into(),
        callback_url: Some("/dashboard".into()),
        ..Default::default()
    })
    .await?;

let verified = auth
    .magic_link()
    .verify(&headers, VerifyMagicLinkInput { token, ..Default::default() })
    .await?;
// verified.set_cookies carries the session cookies.
```

`verify` answers `VerifyMagicLinkOutput::SignedIn { token, user, session }`,
`Challenge(json)`, or `Redirect { url, .. }` when it would have redirected over HTTP.

Both endpoint types (`SignInMagicLink` and `VerifyMagicLink`) are hookable. `metadata` from
the sign-in request doesn't reach the mailer; read it in a
`hook::<SignInMagicLink>().before(..)` ([Hooks](../../reference/01-plugin-authoring.md#hooks)).

## How tokens are stored

- A token is 32 random bytes as base64url (43 characters). Only its SHA-256 is stored, in
  `verification.value_hash` under the identifier `magic-link`; the email and name sit in
  `data`. The token appears only in the email, never in a response or a log.
- A token works once: verifying deletes the row before signing in, and a second click
  redirects with `INVALID_TOKEN`. Expired rows can't be used.
- Tokens from other flows (email verification, password reset) share the table but fail
  the identifier check, and checking them doesn't consume them.

## Error codes

These answer as JSON, before any redirect:

| Code | Status | When |
|---|---|---|
| `INVALID_EMAIL` | 400 | `email` isn't an email address |
| `INVALID_CALLBACK_URL` | 403 | `callbackURL` isn't a relative path or on a trusted origin |
| `INVALID_ERROR_CALLBACK_URL` | 403 | The same for `errorCallbackURL` |
| `INVALID_NEW_USER_CALLBACK_URL` | 403 | The same for `newUserCallbackURL` |

`INVALID_CALLBACK_URL` is core's; the other two are the plugin's (`MagicLinkError`).

## Better Auth's client

```ts
import { createAuthClient } from "better-auth/client";
import { magicLinkClient } from "better-auth/client/plugins";

export const authClient = createAuthClient({
  baseURL: "http://localhost:3000",
  plugins: [magicLinkClient()],
});

await authClient.signIn.magicLink({ email: "ada@acme.dk", callbackURL: "/dashboard" });
```

`tests/compat/better-auth/run-magic-link.sh` builds the plugin's `magic_link_server` example,
which writes emails to an outbox file, and runs `magic-link.ts` against it with Better Auth
1.7.28. It checks sending a link, signing up through it (`302` to `newUserCallbackURL`, a
verified user), reusing it (`INVALID_TOKEN`), an existing user (`302` to `callbackURL`),
`magicLink.verify` without a callback (`token`, `user`, `session`), an unknown token, the
three untrusted-callback codes, and an invalid email.

## Not built

- `generateToken` and `storeToken` (fastauth always stores a SHA-256 of a random token).
- `sendMagicLink` as a callback; the app's mailer sends the email instead, without
  `metadata`.
- `allowedAttempts` (Better Auth 1.7 ignores it too: links work once).
