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
    .secondary_storage(Redis::new(redis_pool))  // optional
    .mailer(Resend::from_env()?)                // needed for verification, reset, magic link
    .email_password(EmailPassword::default())
    .social(Github::from_env()?)
    .social(Google::from_env()?)
    .session(SessionConfig::default())
    .cookies(CookieConfig::default())
    .rate_limit(RateLimit::default())
    .user_fields::<Profile>()
    .on(|event: &UserCreated, ctx| async move { /* ... */ Ok(()) })
    .plugin(TwoFactor::new())
    .build()?
```

`.build()` returns `Result<Auth<..>, BuildError>`. It fails on configuration that types
can't express: two plugins defining the same column or route, `require_email_verification`
without a mailer, a `base_url` that isn't a URL, a secret shorter than 32 bytes. Every
problem is collected and reported at once.

## Secrets

```rust
.secret(Secret::from_env("FASTAUTH_SECRET")?)
// Rotation: the first secret signs and encrypts; all of them verify and decrypt.
.secrets([Secret::from_env("FASTAUTH_SECRET")?, Secret::from_env("FASTAUTH_SECRET_OLD")?])
```

`Secret` zeroizes on drop and has no `Debug` output beyond `Secret(..)`.

## Email and password

```rust
.email_password(
    EmailPassword::default()
        .min_password_length(10)                   // default 8
        .max_password_length(256)                  // default 128; argon2 input cap
        .require_email_verification(true)          // sign-in fails until verified
        .auto_sign_in(true)                        // sign-up returns a session (default)
        .revoke_sessions_on_password_reset(true)
        .password_policy(|pw: &str| zxcvbn(pw, &[]).score() >= Score::Three)
        .hasher(Argon2id::owasp())                 // default; see Security
)
```

Mail templates come from the mailer. Each auth email is a typed value
(`VerifyEmail { user, url, token }`, `ResetPassword { .. }`, `MagicLink { .. }`), and a
mailer turns it into a message:

```rust
struct AcmeMailer { resend: Resend }

impl Mailer for AcmeMailer {
    async fn send(&self, email: AuthEmail<'_>) -> Result<(), MailError> {
        let (subject, html) = match email {
            AuthEmail::VerifyEmail(e) => ("Confirm your email", templates::verify(e.url)),
            AuthEmail::ResetPassword(e) => ("Reset your password", templates::reset(e.url)),
            other => return self.resend.send_default(other).await,
        };
        self.resend.send(email.to(), subject, html).await
    }
}
```

`AuthEmail` is `#[non_exhaustive]`, so plugins can add email kinds without breaking
mailers that already fall through to a default.

## Social providers

```rust
.social(Github::new(client_id, client_secret).scopes(["read:user", "user:email"]))
.social(Google::from_env()?)                                  // GOOGLE_CLIENT_ID / _SECRET
.social(Oidc::discover("keycloak", "https://sso.acme.dk/realms/main", id, secret).await?)
```

Built in: GitHub, Google, Apple, Discord, Microsoft, GitLab, Twitch, Spotify, and a
generic OIDC provider with discovery. A provider is the `OAuthProvider` trait (an
authorize URL, a token exchange, and a profile mapping), so adding one takes about 60
lines. The redirect URI is `{base_url}{base_path}/callback/{provider_id}`.

Accounts link by verified email by default. `.account_linking(AccountLinking::Off)`
turns that off, and `::TrustedProviders([..])` limits it to providers you trust to verify
email addresses.

## Sessions

```rust
.session(
    SessionConfig::default()
        .expires_in(Duration::days(7))        // default
        .update_age(Duration::days(1))        // extend expiry at most once a day (default)
        .fresh_age(Duration::days(1))         // "fresh" endpoints need a session this young
        .cookie_cache(Duration::minutes(5))   // signed cache cookie; off by default
        .store(SessionStore::Database)        // or ::Secondary, or ::Both (default with secondary storage)
)
```

The cookie cache trades revocation latency for speed: a revoked session keeps working on
other devices until the cache cookie expires. [Internals](08-internals.md#the-session-hot-path)
shows the cost of each tier.

## Cookies

```rust
.cookies(
    CookieConfig::default()
        .prefix("acme")                   // acme.session_token; default "fastauth"
        .same_site(SameSite::Lax)         // default
        .domain(".acme.dk")               // share across subdomains
        .secure(Secure::Auto)             // __Secure- prefix when base_url is https
)
```

## Rate limits

```rust
.rate_limit(
    RateLimit::default()                        // 100 requests / 10 s per IP and path
        .rule("/sign-in/*", Limit::per(Duration::seconds(10), 3))
        .rule("/two-factor/verify-*", Limit::per(Duration::minutes(1), 5))
        .client_ip(ClientIp::Header("fly-client-ip"))  // default: the socket address
        .store(RateLimitStore::Secondary)       // default: in memory
)
```

Plugins add their own rules; yours override theirs for the same path. Set
`ClientIp::Header` only behind a proxy that overwrites that header, or clients can pick
their own IP.

## User fields

```rust
#[derive(Fields, Serialize, Deserialize, Clone)]
pub struct Profile {
    #[field(default = "free")]
    pub plan: String,
    #[field(input = false)]               // sign-up and update-user bodies can't set it
    pub stripe_customer_id: Option<String>,
    #[field(returned = false)]            // never serialized to the client
    pub internal_notes: Option<String>,
}

.user_fields::<Profile>()
```

Sign-up and `/update-user` accept `input` fields in their JSON body, validated by the
types. They show up typed as `session.user.fields`. The same works for sessions with
`.session_fields::<T>()`.

## Events

Events fire after the change is committed, for every caller: HTTP, the server API, and
plugins. Use them for side effects such as a welcome email or a Stripe customer.

```rust
.on(|e: &UserCreated, ctx: &EventCtx<_>| async move {
    let customer = stripe::create_customer(&e.user.email).await?;
    ctx.db().update::<User>(User::ID.eq(&e.user.id))
        .set(Profile::STRIPE_CUSTOMER_ID, Some(customer.id))
        .exec()
        .await?;
    Ok(())
})
```

Core events: `UserCreated`, `UserUpdated`, `UserDeleted`, `SessionCreated`,
`SessionRevoked`, `PasswordChanged`, `EmailVerified`, `AccountLinked`. Plugins publish
their own (`MemberAdded`, `TwoFactorEnabled`). To change or block an operation before it
happens, use a hook ([Plugins](05-plugins.md#hooks)); an app can register hooks too, with
`.hook(..)`.
