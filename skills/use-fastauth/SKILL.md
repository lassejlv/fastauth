---
name: use-fastauth
description: Use fastauth, Better Auth for Rust, in an app. Use in any Rust project that depends on `fastauth` or a `fastauth-*` crate, or when asked to add authentication, login, sessions, OAuth, 2FA, passkeys, magic links, JWTs, usernames, guest users or account switching to a Rust or axum app.
---

# Using fastauth in an app

fastauth gives a Rust web app email and password sign-in, sessions, social login,
two-factor, organizations, admin tools, API keys, magic links, email codes, bearer tokens,
JWTs, passkeys, usernames, anonymous users and multiple sessions per browser, with Better
Auth's routes and JSON. The whole configuration is one value,
`Auth<D, U, P>`: the database adapter, the app's own user columns and the plugin list. The
compiler checks it, so most mistakes are compile errors; [Common mistakes](#common-mistakes)
lists the real ones.

This skill matches fastauth 0.3 on crates.io and the code on `main`, and so does the repo's
`docs/`. Use only what this skill, `docs/` or `crates/*/src` shows. Not built yet: other
plugins, organization teams, `TestAuth`,
`#[endpoint]`, secondary storage (Redis), actix-web and MySQL
(`docs/01-overview.md#planned`).

Ids are opaque strings, ULIDs by default (`.ids(IdStrategy::UuidV7)` and others on the
builder). Never parse them or assume a format.

## Setup

### Dependencies

```toml
[dependencies]
fastauth = { version = "0.3", features = ["oauth", "two-factor"] }
axum = { version = "0.8", features = ["macros"] }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
```

| Feature | Default | Adds |
|---|---|---|
| `axum` | yes | `auth.router()`, `auth.session_layer()`, the `Session` extractors |
| `postgres` | yes | `Sqlx<Postgres>`, `PgPool` in the prelude |
| `sqlite` | no | `Sqlx<Sqlite>`, `SqlitePool` in the prelude |
| `macros` | yes | `#[derive(Fields, Model, AuthError)]` |
| `oauth` | no | `fastauth::social`: `Social`, `Github`, `Google` |
| `two-factor` | no | `fastauth::plugins::two_factor`: `TwoFactor` |
| `organization` | no | `fastauth::plugins::organization`: `Organization`, its extractors with `axum` |
| `admin` | no | `fastauth::plugins::admin`: `Admin`, `RequireRole` with `axum` |
| `api-key` | no | `fastauth::plugins::api_key`: `ApiKeys` |
| `magic-link` | no | `fastauth::plugins::magic_link`: `MagicLink` |
| `email-otp` | no | `fastauth::plugins::email_otp`: `EmailOtp` |
| `bearer` | no | `fastauth::plugins::bearer`: `Bearer` |
| `jwt` | no | `fastauth::plugins::jwt`: `Jwt` |
| `passkey` | no | `fastauth::plugins::passkey`: `Passkey` |
| `username` | no | `fastauth::plugins::username`: `Username` |
| `anonymous` | no | `fastauth::plugins::anonymous`: `Anonymous` |
| `multi-session` | no | `fastauth::plugins::multi_session`: `MultiSession` |
| `cli` | no | `fastauth::cli::run` for a `fastauth` binary: `schema`, `status`, `generate`, `migrate` |

For SQLite only, set `default-features = false, features = ["axum", "sqlite", "macros"]`.
axum's `macros` feature is only needed for `#[derive(FromRef)]`. fastauth is built on
sqlx 0.9: take `PgPool` and `SqlitePool` from `fastauth::prelude`, or depend on sqlx 0.9
yourself so the pool types match.

### The secret

`Secret::from_env("FASTAUTH_SECRET")` reads at least 32 bytes: base64url, or else the raw
string. `openssl rand -hex 32` makes one. It signs cookies and derives every other key, so
losing it signs everyone out. Rotate with `.secrets([new, old])`: the first signs, all verify.

### The auth instance and the server

Keep the auth instance in its own module. `src/auth.rs`:

```rust
use fastauth::plugins::two_factor::TwoFactor;
use fastauth::prelude::*;
use fastauth::social::{Github, Social};

#[derive(Fields, Clone, Debug)]
pub struct Profile {
    #[field(default = "free", input)]
    pub plan: String,
}

pub type AppAuth = Auth<Sqlx<Postgres>, Profile, plugins![Social, TwoFactor]>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .app_name("Acme")
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("http://localhost:3000")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .user_fields::<Profile>()
        .plugin(Social::new().provider(Github::from_env()?))
        .plugin(TwoFactor::new().issuer("Acme"))
        .build()
}
```

`src/main.rs`:

```rust
mod auth;

use std::net::SocketAddr;

use auth::{AppAuth, build};
use axum::routing::get;
use axum::{Json, Router};
use fastauth::plugins::two_factor::TwoFactor;
use fastauth::prelude::*;
use serde::Serialize;

#[derive(Serialize)]
struct Me {
    email: String,
    plan: String,
    two_factor: bool,
}

async fn me(session: Session<AppAuth>) -> Json<Me> {
    Json(Me {
        email: session.user.email.clone(),
        plan: session.user.fields.plan.clone(),
        two_factor: session.user.plugin::<TwoFactor, _>().two_factor_enabled,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    let auth = build(pool)?;
    auth.migrator().run().await?;

    let app = Router::new()
        .route("/me", get(me))
        .merge(auth.router())
        .layer(auth.session_layer())
        .with_state(auth);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
```

The rules these samples follow:

- **The alias is the plugin list in registration order.** `plugins![Social, TwoFactor]`
  must match the `.plugin(..)` calls one for one. Every handler names the alias.
- `Auth<D, U = (), P = Nil>`: with no user fields and no plugins it is `Auth<Sqlx<Postgres>>`.
- `.build()` only exists once `secret`, `base_url` and `database` are set. It returns
  `Err(BuildError)` listing every problem at once: a short secret, a bad URL, two plugins
  claiming a route or column, a hook on an endpoint nothing registered.
- `.email_password(EmailPassword::default())` turns on `/sign-up/email` and
  `/sign-in/email`. Without it there is no password sign-in.
- `auth.migrator().run()` creates or extends the tables and is safe on every start.
- `.layer(auth.session_layer())` makes refreshed session cookies reach the browser on your
  own routes. `into_make_service_with_connect_info::<SocketAddr>()` gives rate limiting the
  client IP; without it every client shares one bucket.
- `Auth` is two `Arc`s: clone it freely, keep it in router state.

All auth routes live under `/api/auth` (`.base_path(..)` changes it). A route that needs a
signed-in user takes `Session<AppAuth>`, which answers `401` without one.

## Where to go next

Read the reference for the task in front of you:

| Task | Reference |
|---|---|
| Handlers, extractors, `FromRef` state, CORS and CSRF, errors in handlers | [references/axum.md](references/axum.md) |
| Postgres or SQLite, migrations or generated SQL, app columns on `user` | [references/database.md](references/database.md) |
| GitHub and Google sign-in, two-factor, plugin data on the user | [references/plugins.md](references/plugins.md) |
| Organizations, members, invitations, org roles and extractors | [references/organization.md](references/organization.md) |
| Admin routes, user roles, bans, impersonation, `RequireRole` | [references/admin.md](references/admin.md) |
| API keys, sessions from `x-api-key` | [references/api-keys.md](references/api-keys.md) |
| Sign-in links by email | [references/magic-link.md](references/magic-link.md) |
| One-time codes by email: sign-in, email verification, password reset | [references/email-otp.md](references/email-otp.md) |
| Sessions for mobile, CLI or server clients via `Authorization: Bearer` | [references/bearer.md](references/bearer.md) |
| JWTs and a JWKS for other services, verifying tokens elsewhere | [references/jwt.md](references/jwt.md) |
| Passkeys (WebAuthn) | [references/passkey.md](references/passkey.md) |
| Usernames, sign-in by username | [references/username.md](references/username.md) |
| Guest users who sign up later | [references/anonymous.md](references/anonymous.md) |
| Several accounts per browser, account switching | [references/multi-session.md](references/multi-session.md) |
| Calling sign-up, sign-in or any endpoint from Rust; app-level hooks and events | [references/server-api.md](references/server-api.md) |
| A custom plugin: tables, endpoints, hooks, gates, resolvers, events | [references/custom-plugins.md](references/custom-plugins.md) |
| Tests with `MemoryAdapter` and `MemoryMailer` | [references/testing.md](references/testing.md) |
| A frontend using Better Auth's client against fastauth | [references/client.md](references/client.md) |

## Common mistakes

Real compiler output against `main`, trimmed to the lines that matter.

**A plugin used but not registered.** `session.user.plugin::<P, _>()`, `auth.two_factor()`
and other plugin APIs only compile when `P` is in the alias. Add `.plugin(..)` to the
builder and `P` to `plugins![..]`:

```text
error[E0277]: plugin `TwoFactor` is not registered on this auth instance
  |     session.user.plugin::<TwoFactor, _>().two_factor_enabled.to_string()
  |                  ^^^^^^ `TwoFactor` is not in this plugin list
  = help: the trait `Has<TwoFactor, _>` is not implemented for `fastauth::Nil`
  = note: register it with `.plugin(...)` on the builder, before any plugin that requires it, and list it in your `plugins![..]` alias
```

**The alias in a different order than the `.plugin(..)` calls.** Reorder the alias to
match registration:

```text
error[E0308]: mismatched types
 7 |   pub fn build() -> Result<AppAuth, BuildError> {
   |                     --------------------------- expected `Result<Auth<MemoryAdapter, (), Cons<TwoFactor, Cons<Social, Nil>>>, _>` because of return type
...
14 | |         .build()
   | |________________^ expected `TwoFactor`, found `Social`
```

**A plugin registered before a plugin it `Requires`.** The error names the missing
dependency at the `.plugin(..)` call; register the dependency first:

```text
error[E0277]: plugin `AccessTokens` is not registered on this auth instance
  |         .plugin(TokenAudit)
  |          ------ ^^^^^^^^^^ `AccessTokens` is not in this plugin list
  = help: the trait `Has<AccessTokens, _>` is not implemented for `fastauth::Nil`
  = note: register it with `.plugin(...)` on the builder, before any plugin that requires it, and list it in your `plugins![..]` alias
```

**`router` or `session_layer` not found.** They come from the `AuthRouter` trait, which
`use fastauth::prelude::*` brings in. Import the prelude or `fastauth::axum::AuthRouter`:

```text
error[E0599]: no method named `router` found for struct `Auth<D, U, P>` in the current scope
  |         .merge(auth.router())
  |                     ^^^^^^ method not found in `Auth<MemoryAdapter>`
  = help: items from traits can only be used if the trait is in scope
```

**No `build` method.** A required option is missing. The builder's last two type
parameters are the secret and the base URL (`Missing` or `Present`); a database that was
never set shows as `NoDatabase`:

```text
error[E0599]: no method named `build` found for struct `fastauth::Builder<fastauth::prelude::MemoryAdapter, (), fastauth::Nil, Missing, Present>` in the current scope
  = note: the method was found for `fastauth::Builder<D, U, P, Present, Present>`
```

**Router state that isn't the auth instance.** `Session<AppAuth>` needs `AppAuth: FromRef<S>`.
Put `#[derive(Clone, FromRef)]` on the state struct ([axum.md](references/axum.md#state)):

```text
error[E0308]: mismatched types
  |     Router::new().route("/me", get(me)).with_state(state)
  |                                         ---------- ^^^^^ expected `Auth<MemoryAdapter>`, found `AppState`
```

At runtime:

- `BuildError`: `` `app` hooks endpoint `fastauth_core::routes::SignUpEmail`, which no plugin registers ``.
  Hooks on `SignUpEmail` or `SignInEmail` need `.email_password(..)`.
- `403 INVALID_ORIGIN`: a non-GET request carried cookies without a trusted `Origin` or
  `Referer`. Browsers send it; add `-H 'origin: http://localhost:3000'` to curl, and list
  other frontends in `.trusted_origins([..])`.
- `400 INVALID_FIELD` (`field \`stripeCustomerId\` can't be set`): a client sent an app
  column without `#[field(input)]` ([database.md](references/database.md#app-columns-on-user)).
