# fastauth

Authentication for Rust web apps, modelled on [Better Auth](https://www.better-auth.com):
one builder call gives you email and password sign-in, social login, sessions, and a
plugin system for two-factor, organizations, admin tools, API keys, magic links, email codes,
bearer tokens, JWTs, passkeys, usernames, anonymous users, multiple sessions and your own plugins.
It runs on sqlx and axum out of the box, and the plugin API is checked by the compiler.

[![crates.io](https://img.shields.io/crates/v/fastauth.svg)](https://crates.io/crates/fastauth)
[![docs.rs](https://docs.rs/fastauth/badge.svg)](https://docs.rs/fastauth)

**Status:** 0.4.0 is on crates.io. It fixes two high-severity security issues that affect every
earlier version, adds the username, anonymous and multi-session plugins, and changes a few
defaults; read [upgrading from 0.3](CHANGELOG.md#upgrading-from-03) before you bump. The docs in
`docs/` describe 0.4.

## Install

```bash
cargo add fastauth --features oauth,two-factor
cargo install fastauth-cli   # `fastauth secret` for FASTAUTH_SECRET
```

Default features are `axum`, `postgres` and `macros`. Use `sqlite` instead of (or as well as)
`postgres`, and add `oauth` for GitHub and Google sign-in, `two-factor` for TOTP, email codes and
backup codes, `organization`, `admin`, `api-key`, `magic-link`, `email-otp`, `bearer`, `jwt`,
`passkey`, `username`, `anonymous` and `multi-session` for those plugins, and `cli` for the migration commands. Requires Rust 1.94 or newer.

## Example

```rust
use std::net::SocketAddr;

use axum::routing::get;
use axum::{Json, Router};
use fastauth::plugins::two_factor::TwoFactor;
use fastauth::prelude::*;
use fastauth::social::{Github, Social};
use serde::Serialize;

pub type AppAuth = Auth<Sqlx<Postgres>, Profile, plugins![Social, TwoFactor]>;

#[derive(Fields, Clone, Debug, Serialize)]
pub struct Profile {
    #[field(default = "free")]
    pub plan: String,
}

pub fn auth(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("http://localhost:3000")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .user_fields::<Profile>()
        .plugin(Social::new().provider(Github::from_env()?))
        .plugin(TwoFactor::new().issuer("Acme"))
        .build()
}

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
    let auth = auth(pool)?;
    auth.migrator().run().await?;

    let app = Router::new()
        .route("/me", get(me))
        .merge(auth.router()) // serves /api/auth/*
        .layer(auth.session_layer())
        .with_state(auth);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    // Rate limits are per client IP, read from the socket address passed along here.
    // Behind a proxy, also set `.client_ip(..)`: see docs/get-started/03-configuration.md#rate-limits.
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
```

If you remove `TwoFactor` from the builder, `session.user.plugin::<TwoFactor, _>()`
stops compiling and tells you which plugin is missing. `crates/fastauth/examples/` has runnable
apps on SQLite and in memory.

## Crates

| Crate | What |
|---|---|
| [`fastauth`](https://crates.io/crates/fastauth) | The crate apps depend on: re-exports everything below behind features |
| [`fastauth-core`](https://crates.io/crates/fastauth-core) | Builder, compile-checked plugin list, sessions, crypto, routing, email and password, verification, reset |
| [`fastauth-axum`](https://crates.io/crates/fastauth-axum) | `auth.router()`, `Session` / `FreshSession` extractors, the session layer |
| [`fastauth-sqlx`](https://crates.io/crates/fastauth-sqlx) | Postgres and SQLite adapter, migrations, shared transactions (`.in_tx`) |
| [`fastauth-macros`](https://crates.io/crates/fastauth-macros) | `#[derive(Fields, Model, AuthError)]` |
| [`fastauth-oauth`](https://crates.io/crates/fastauth-oauth) | The `Social` plugin: GitHub and Google |
| [`fastauth-plugin-two-factor`](https://crates.io/crates/fastauth-plugin-two-factor) | TOTP, email codes, backup codes, trusted devices |
| [`fastauth-plugin-organization`](https://crates.io/crates/fastauth-plugin-organization) | Organizations, members, invitations, roles and permissions, axum extractors (0.2) |
| [`fastauth-plugin-admin`](https://crates.io/crates/fastauth-plugin-admin) | User management, roles and permissions, bans, impersonation, `RequireRole` (0.2) |
| [`fastauth-plugin-api-key`](https://crates.io/crates/fastauth-plugin-api-key) | Hashed API keys with expiry, usage and rate limits, permissions, optional sessions from keys (0.2) |
| [`fastauth-plugin-magic-link`](https://crates.io/crates/fastauth-plugin-magic-link) | Sign-in links by email, with sign-up on first use (0.3) |
| [`fastauth-plugin-email-otp`](https://crates.io/crates/fastauth-plugin-email-otp) | One-time codes by email for sign-in, email verification and password reset (0.3) |
| [`fastauth-plugin-bearer`](https://crates.io/crates/fastauth-plugin-bearer) | Sessions from `Authorization: Bearer`, and the `set-auth-token` header (0.3) |
| [`fastauth-plugin-jwt`](https://crates.io/crates/fastauth-plugin-jwt) | JWTs for signed-in users, a JWKS with rotating keys, `JwksVerifier` for other services (0.3) |
| [`fastauth-plugin-passkey`](https://crates.io/crates/fastauth-plugin-passkey) | Passkeys (WebAuthn) on webauthn-rs: registration, sign-in, management (0.3) |
| [`fastauth-plugin-username`](https://crates.io/crates/fastauth-plugin-username) | Usernames next to emails, sign-in by username, availability checks (0.4) |
| [`fastauth-plugin-anonymous`](https://crates.io/crates/fastauth-plugin-anonymous) | Anonymous users, linked to the real account they sign up or in with (0.4) |
| [`fastauth-plugin-multi-session`](https://crates.io/crates/fastauth-plugin-multi-session) | Several signed-in accounts per browser, switching between them (0.4) |
| [`fastauth-cli`](https://crates.io/crates/fastauth-cli) | `fastauth secret`; schema and migration commands run from your app via `fastauth::cli::run` |

The HTTP API is compatible with Better Auth's TypeScript client (tested against
`better-auth` 1.7.28, see [Better Auth client](docs/integrations/02-better-auth-client.md)), so its React, Vue and
Svelte clients work against a fastauth server.

Not built yet: other plugins, teams in organizations,
actix-web, Redis and MySQL. [Overview](docs/get-started/01-overview.md#planned) lists what's planned.

## Docs

The docs live in `docs/`, one folder per group, in the same order as the
[docs site](https://fastauth.lassejlv.dev/docs/overview/).

### Get started

| Page | What it covers |
|---|---|
| [Overview](docs/get-started/01-overview.md) | Goals, non-goals, crate layout, feature flags, the main design decisions, what's planned |
| [Quickstart](docs/get-started/02-quickstart.md) | From `cargo new` to sign-up, sign-in and a protected route |
| [Configuration](docs/get-started/03-configuration.md) | Every builder option: secrets, email and password, social providers, sessions, cookies, rate limits, ids, user fields, events |

### Core concepts

| Page | What it covers |
|---|---|
| [Sessions and the server API](docs/concepts/01-sessions.md) | Extractors, typed user fields, calling auth from your own code, shared transactions |
| [Databases](docs/concepts/02-database.md) | sqlx, the schema, ids, migrations, typed queries, writing an adapter |
| [Security](docs/concepts/03-security.md) | Tokens, cookies, password hashing, CSRF, OAuth, rate limiting, secret rotation |

### Integrations

| Page | What it covers |
|---|---|
| [HTTP and axum](docs/integrations/01-http.md) | axum, `tower`, the outgoing HTTP client, writing an integration |
| [Better Auth client](docs/integrations/02-better-auth-client.md) | Using `better-auth/client` with fastauth, the tested versions, known gaps |

### Plugins

| Page | What it covers |
|---|---|
| [All plugins](docs/plugins/README.md) | Every first-party plugin with its crate and feature, and how to register plugins |
| [Magic links](docs/plugins/sign-in/01-magic-link.md) | Sign-in links by email, redirects, sign-up on first use |
| [Email OTP](docs/plugins/sign-in/02-email-otp.md) | One-time codes by email for sign-in, email verification and password reset |
| [Passkeys](docs/plugins/sign-in/03-passkey.md) | WebAuthn registration and sign-in, the `passkey` table, managing passkeys |
| [Usernames](docs/plugins/sign-in/04-username.md) | Usernames on sign-up and update-user, sign-in by username, validation and normalization |
| [Anonymous users](docs/plugins/sign-in/05-anonymous.md) | Guest sign-in, linking to the real account, deleting anonymous users |
| [Bearer tokens](docs/plugins/tokens/01-bearer.md) | Sessions from `Authorization: Bearer` for clients without cookies |
| [JWT](docs/plugins/tokens/02-jwt.md) | Tokens and a JWKS for other services, key rotation, verifying tokens elsewhere |
| [API keys](docs/plugins/tokens/03-api-keys.md) | Hashed API keys, limits, permissions, sessions from keys |
| [Organizations](docs/plugins/access/01-organization.md) | Organizations, members, invitations, roles and permissions, extractors |
| [Admin](docs/plugins/access/02-admin.md) | User management, roles and permissions, bans, impersonation, `RequireRole` |
| [Multiple sessions](docs/plugins/access/03-multi-session.md) | Several accounts per browser, device-session cookies, switching and revoking |

### Reference

| Page | What it covers |
|---|---|
| [Plugin authoring](docs/reference/01-plugin-authoring.md) | Writing a plugin: schema, endpoints, resolvers, hooks, gates, events, errors, dependencies, tests |
| [Internals](docs/reference/02-internals.md) | How it works: the type-level plugin list, the build step, the request path, the session hot path |
| [Decisions](docs/reference/03-decisions.md) | The design decisions, including the ones made since 0.1 |

## Agent skill

[`skills/use-fastauth`](skills/use-fastauth/SKILL.md) teaches coding agents to use fastauth
in their own apps: setup, axum, migrations, user fields, the first-party plugins, the server
API, custom plugins and tests, plus the compiler errors they'll meet. Every code sample in it
compiles against `main` (0.4). Copy the folder into your agent's skills directory (for Claude Code,
`.claude/skills/use-fastauth/`).

## License

Licensed under the [MIT license](LICENSE).
