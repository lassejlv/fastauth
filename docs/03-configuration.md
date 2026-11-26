# Configuration

Everything is set on `FastAuth::builder()`. Only `secret`, `base_url` and `database`
are required, and the builder enforces that in its type: `.build()` does not exist until
all three are set, so a missing database is a compile error, not a startup panic.

```rust
FastAuth::builder()
    .app_name("Acme")
    .secret(Secret::from_env("FASTAUTH_SECRET")?)
    .base_url("https://acme.dk")
    .base_path("/api/auth")                     // default
    .trusted_origins(["https://app.acme.dk"])   // base_url's origin is always trusted
    .database(Sqlx::new(pool))
    .mailer(LogMailer)                          // needed for verification, reset, two-factor codes
    .email_password(EmailPassword::default())
    .email_verification(EmailVerification::default())
    .session(SessionConfig::default())
    .cookies(CookieConfig::default())
    .rate_limit(RateLimit::default())
    .client_ip(ClientIp::Socket)                // default
    .ids(IdStrategy::Ulid)                      // default
    .user_fields::<Profile>()
    .on(|event: UserCreated, ctx| async move { /* ... */ Ok(()) })
    .plugin(Social::new().provider(Github::from_env()?).provider(Google::from_env()?))
    .plugin(TwoFactor::new())
    .build()
```

`.build()` returns `Result<Auth<..>, BuildError>`. It fails on configuration that types
can't express: a secret shorter than 32 bytes, a `base_url` that isn't an http(s) URL,
`require_email_verification` without a mailer, two plugins defining the same column, route
or error code, and a hook on an endpoint nothing registered. Every problem is collected and
reported at once.

## Secrets

```rust
.secret(Secret::from_env("FASTAUTH_SECRET")?)
// Rotation: the first secret signs and encrypts; all of them verify and decrypt.
.secrets([Secret::from_env("FASTAUTH_SECRET")?, Secret::from_env("FASTAUTH_SECRET_OLD")?])
```

`Secret::from_env` reads base64url (what `fastauth secret` prints) or, failing that, the
raw string, and fails with a `BuildError` when the variable isn't set. `Secret` zeroizes on
drop and is never printed.

## Email and password

```rust
.email_password(
    EmailPassword::default()
        .min_password_length(10)                   // default 8
        .max_password_length(256)                  // default 128; bounds the hashing work
        .require_email_verification(true)          // sign-in fails until verified; needs a mailer
        .auto_sign_in(true)                        // sign-up returns a session (default)
        .revoke_sessions_on_password_reset(false)  // default true: a reset signs out everywhere
        .reset_password_ttl(Duration::minutes(30)) // default 1 hour
        .password_policy(|pw: &str| pw.chars().any(|c| !c.is_alphanumeric()))
        .hasher(Argon2id::owasp())                 // default; see Security
)
.email_verification(
    EmailVerification::default()
        .send_on_sign_up(true)                     // default
        .auto_sign_in_after_verification(false)    // default
        .ttl(Duration::hours(1))                   // default
);
```

Without `.email_password(..)` there is no `/sign-up/email` or `/sign-in/email`.

Mail templates come from the mailer. Each auth email is an `AuthEmail` value
(`VerifyEmail { to, name, url, token }`, `ResetPassword { .. }`, and `Plugin(..)` for plugin
emails such as two-factor codes and invitations), and a mailer turns it into a message.
`LogMailer` logs emails (development), `MemoryMailer` keeps them (tests), and anything else
implements `Mailer`. Emails whose sending depends on whether an account exists (password
reset, email verification, email OTP codes) are sent in the background, so the response
doesn't wait for your mailer and takes as long for unknown emails as for known ones (see
[Security](09-security.md#account-enumeration)). A background send that fails is logged with
`tracing::error!`; the client already got its answer. `LogMailer` and `MemoryMailer` do no
I/O, so they send before the response, and tests can read `MemoryMailer` right away.

```rust
pub struct AcmeMailer;

impl Mailer for AcmeMailer {
    async fn send(&self, email: AuthEmail) -> Result<(), MailError> {
        let to = email.to().to_owned();
        let (subject, html) = match &email {
            AuthEmail::VerifyEmail(e) => ("Confirm your email".to_owned(), verify_template(&e.url)),
            AuthEmail::ResetPassword(e) => ("Reset your password".to_owned(), reset_template(&e.url)),
            other => other.default_text("Acme"),
        };
        deliver(&to, &subject, html).await
    }
}
```

`AuthEmail` is `#[non_exhaustive]`, so new email kinds don't break mailers that fall
through to `default_text`, which gives a plain subject and body for any email.

## Social providers

Social sign-in is a plugin, `Social` from `fastauth-oauth` (feature `oauth`), so it is
registered with `.plugin(..)` and listed in the alias like any other plugin:

```rust
use fastauth::social::{AccountLinking, Github, Google, OAuthProfile, OAuthProviderExt, Social};

pub type AppAuth = Auth<Sqlx<Postgres>, Profile, plugins![Social, TwoFactor]>;

.plugin(
    Social::new()
        .provider(Github::new(client_id, client_secret).scopes(["read:user", "user:email"]))
        .provider(Google::from_env()?)                        // GOOGLE_CLIENT_ID / _SECRET
        .account_linking(AccountLinking::ByVerifiedEmail),    // default
);
```

It serves Better Auth's routes: `POST /sign-in/social`, `GET /callback/{provider_id}`,
`POST /link-social`, `GET /list-accounts` and `POST /unlink-account` (which refuses to remove
a user's last account). `/link-social` reads the caller's session from the database and
refuses API-key sessions (401) and impersonation sessions (403), like the other endpoints
that add a credential. The redirect URI to register with the provider is
`{base_url}{base_path}/callback/{provider_id}`. A successful callback redirects to
`callbackURL` (or `newUserCallbackURL` for a new user); a failed one redirects to
`errorCallbackURL` with `?error=` set to Better Auth's error string (`state_mismatch`,
`account_not_linked`, ...). When a sign-in gate challenges, the callback redirects to
`callbackURL` with the challenge as query parameters (`?twoFactorRedirect=true`).

Built in: GitHub and Google. A provider is the `OAuthProvider` trait (an authorization URL,
a code exchange, and a profile mapping), and `fastauth_oauth::provider` has the standard
OAuth 2.0 steps, so adding one takes about 60 lines.

Accounts link by verified email by default: a social sign-in whose email matches an
existing user is attached to that user only when the provider reports the email as
verified. If that user never verified their email, their password and sessions are removed
first ([Security](09-security.md#oauth)). `AccountLinking::Off` never links by email;
signed-in users can still link with `/link-social`.

A social sign-up fills `email`, `name`, `image` and `email_verified` from the provider's
profile. Every other user column needs a default or a value from `map_profile`, which runs
when a social sign-in creates a user (never for existing ones) and returns extra columns:

```rust
Social::new()
    .provider(Github::from_env()?.map_profile(|_, _| Ok(vec![Profile::PLAN.value("developer")])))
    .provider(Google::from_env()?.disable_sign_up(true))
    .map_profile(|profile: &OAuthProfile, _provider: &str| {
        Ok(vec![Profile::PLAN.value(if profile.email_verified { "free" } else { "trial" })])
    })
```

A provider's own `map_profile` (from `OAuthProviderExt`, for built-in and custom providers)
wins over `Social::map_profile` for that provider; the two are not merged. `Col::value`
builds a typed `(column, Value)` pair, so a wrong type is a compile error; a raw
`("plan", Value::Text(..))` works too. The returned columns are checked like sign-up input
fields: each must be an app or plugin column on `user`, set once, with the column's type.
Unlike sign-up input, server-only columns are allowed, because the server wrote the
mapping. An unknown or core column, a wrong type, or a required column left unset is a bug
in the app, so the callback answers 500 and logs the reason, for example that `user.plan`
is required and has no default but social sign-up through `github` doesn't set it. An
`AuthError` the mapping returns is passed on, so a 4xx such as `AuthError::forbidden()`
turns the sign-up away with `?error=FORBIDDEN` on the error callback URL.

`disable_sign_up(true)` (Better Auth's `disableSignUp`) stops a provider from creating
users: someone new gets `?error=signup_disabled`, while existing users still sign in
through it, including ones it links by verified email.

## Sessions

```rust
.session(
    SessionConfig::default()
        .expires_in(Duration::days(7))        // default
        .update_age(Duration::days(1))        // extend expiry at most once a day (default)
        .fresh_age(Duration::days(1))         // "fresh" endpoints need a session this young (default)
        .cookie_cache(Duration::minutes(5))   // signed cache cookie; off by default
)
```

The cookie cache trades revocation latency for speed: a revoked session keeps working on
other devices until the cache cookie expires. Endpoints that create or change a credential
(API keys, passkeys, linked accounts, two-factor) skip the cache and read the session from
the database, so a revoked session can't mint one ([Security](09-security.md#sessions-that-arent-a-sign-in)).
A session is extended only when it was created with the full `expires_in`: one created
shorter (an impersonation session) keeps its expiry. Raising `expires_in` therefore stops
existing sessions from sliding; they expire on their old date and the user signs in again. [Internals](08-internals.md#the-session-hot-path)
shows the cost of each tier. Sessions live in the database; secondary storage such as Redis
is [planned](01-overview.md#planned), not built.

## Cookies

```rust
.cookies(
    CookieConfig::default()
        .prefix("acme")                   // acme.session_token; default "fastauth"
        .same_site(SameSite::Lax)         // default
        .domain(".acme.dk")               // share across subdomains
        .secure(Secure::Auto)             // __Secure- prefix when base_url is https (default)
)
```

## Rate limits

```rust
.rate_limit(
    RateLimit::default()                        // 100 requests / 10 s per IP and path
        .default_limit(Limit::per(Duration::seconds(10), 200))
        .rule("/sign-in/*", Limit::per(Duration::seconds(10), 5))
        .rule("/two-factor/verify-*", Limit::per(Duration::minutes(1), 3))
)
.client_ip(ClientIp::Header("fly-client-ip".into()))   // default: ClientIp::Socket
```

A rule's pattern is an exact path or a prefix ending in `*`, relative to the base path.
Rules are checked in order and the first match wins: yours, then the plugins' (two-factor
allows 5 a minute on `/two-factor/verify-*` and 3 per 10 seconds on the routes that check the
password: `/two-factor/enable`, `/disable`, `/get-totp-uri` and `/generate-backup-codes`),
then core's 3 per 10 seconds on `/sign-in/*`, `/sign-up/*`, `/request-password-reset`,
`/forget-password`, `/send-verification-email` and `/change-password`.
`RateLimit::disabled()` turns limiting off, which is useful in tests. The counters live in
memory, per process.

Limits are kept per client IP, which `.client_ip(..)` says where to find:

| Source | Use it when |
|---|---|
| `ClientIp::Socket` (default) | Clients connect to the app directly. The integration passes the socket address along; in axum, serve with `into_make_service_with_connect_info::<SocketAddr>()`. |
| `ClientIp::Header(name)` | A proxy you trust sets a header holding exactly one address and overwrites whatever the client sent: `fly-client-ip`, `cf-connecting-ip`, `x-real-ip` from your own nginx. |
| `ClientIp::TrustedProxies { header, proxies }` | Proxies append to the header, like `x-forwarded-for`. `proxies` is how many you run in front of the app; the client is the `proxies`-th address from the right. |

Never use `ClientIp::Header("x-forwarded-for")`: each proxy appends to that header, so its
first values are whatever the client sent, and a client could pick its own IP and dodge
every limit. With `TrustedProxies`, count only proxies that append: with one nginx in front,
`proxies: 1`; with a CDN in front of that nginx, `proxies: 2`. A value that isn't a valid IP
counts as no IP.

A request without a client IP (no socket address, a missing header, or too few hops) is
logged once with `tracing::warn!`. Such requests are limited per account when the JSON body
names one (`email` or `username`), so guessing one account's password stays limited without
letting one client lock everybody out of sign-in, and otherwise share one bucket.

## Ids

```rust
.ids(IdStrategy::UuidV7)
```

`IdStrategy::Ulid` (the default), `UuidV7`, `UuidV4` or `IdStrategy::custom(|| ..)` decides
the ids of every row fastauth and its plugins create, and how id columns are stored. Pick
it before the first migration: [Databases](06-database.md#ids) covers storage per strategy
and what happens when you switch.

## User fields

```rust
#[derive(Fields, Serialize, Deserialize, Clone, Debug)]
pub struct Profile {
    #[field(default = "free", input)]     // sign-up and update-user bodies may set it
    pub plan: String,
    pub stripe_customer_id: Option<String>, // no `input`: only server code sets it
    #[field(returned = false)]            // never serialized to the client
    pub internal_notes: Option<String>,
}

.user_fields::<Profile>()
```

Columns are server-only unless marked `#[field(input)]`. That is stricter than Better Auth,
whose `additionalFields` default to `input: true`, so a forgotten attribute never lets a
client set a column. Sign-up and `/update-user` accept `input` fields in their JSON body in
camelCase (`"plan": "pro"`), validated by the types; a body that sets any other column gets
`400 INVALID_FIELD`. They show up typed as `session.user.fields`. The other field
attributes are `default = ..` (a bool, integer or string literal, or `now`, checked against
the type at compile time), `unique`, `index` and `rename = "column_name"`. Apps can't add
columns to `session`; plugins can ([Plugins](05-plugins.md#columns-on-user-and-session-derivefields)).

## Events

Events fire after the endpoint that emitted them succeeds, for every caller: HTTP, the
server API, and plugins. Server API calls that share the app's transaction (`.in_tx(&tx)`)
fire their events after `tx.commit()` ([Sharing a transaction](04-sessions.md#sharing-a-transaction)).
Use them for side effects such as a welcome email or a billing customer.

```rust
.on(|e: UserCreated, ctx| async move {
    let customer_id = format!("cus_{}", e.user_id); // call your billing provider here
    ctx.db()
        .update::<User>(User::ID.eq(e.user_id))
        .set(Profile::STRIPE_CUSTOMER_ID, Some(customer_id))
        .exec()
        .await?;
    Ok(())
})
```

A handler's error is logged and doesn't fail the request. Core events, all in the prelude:
`UserCreated { user_id, email }`, `UserUpdated`, `UserDeleted { user_id, email }`, `SessionCreated`,
`SessionRevoked`, `PasswordChanged`, `EmailVerified`, `AccountLinked`. Plugins publish their own
(`TwoFactorEnabled`, and the events on the [organization](12-organization.md#events),
[admin](13-admin.md#events) and [API key](14-api-keys.md#events) pages). To change or block
an operation before it happens, use a hook ([Plugins](05-plugins.md#hooks)); an app
registers hooks with `.configure(|app| ..)`.
