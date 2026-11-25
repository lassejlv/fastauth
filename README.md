# fastauth

Authentication for Rust web apps, modelled on [Better Auth](https://www.better-auth.com):
one builder call gives you email and password sign-in, social login, sessions, and a
plugin system for two-factor, organizations, passkeys, API keys and the rest. It
runs on sqlx and axum out of the box, and the plugin API is checked by the compiler.

[![crates.io](https://img.shields.io/crates/v/fastauth.svg)](https://crates.io/crates/fastauth)
[![docs.rs](https://docs.rs/fastauth/badge.svg)](https://docs.rs/fastauth)

## Install

```bash
cargo add fastauth --features oauth,two-factor
cargo install fastauth-cli   # `fastauth secret` for FASTAUTH_SECRET
```

Default features are `axum`, `postgres` and `macros`. Use `sqlite` instead of (or as well as)
`postgres`, and add `oauth` for GitHub and Google sign-in, `two-factor` for TOTP, email codes and
backup codes, and `cli` for the migration commands. Requires Rust 1.94 or newer.

## Example

```rust
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
    axum::serve(listener, app).await?;
    Ok(())
}
```

If you remove `TwoFactor` from the builder, `session.user.plugin::<TwoFactor, _>()`
stops compiling and tells you which plugin is missing. `crates/fastauth/examples/` has runnable
apps on SQLite and in memory.

## What's in 0.1

| Crate | What |
|---|---|
| [`fastauth`](https://crates.io/crates/fastauth) | The crate apps depend on: re-exports everything below behind features |
| [`fastauth-core`](https://crates.io/crates/fastauth-core) | Builder, compile-checked plugin list, sessions, crypto, routing, email and password, verification, reset |
| [`fastauth-axum`](https://crates.io/crates/fastauth-axum) | `auth.router()`, `Session` / `FreshSession` extractors, the session layer |
| [`fastauth-sqlx`](https://crates.io/crates/fastauth-sqlx) | Postgres and SQLite adapter, migrations, shared transactions (`.in_tx`) |
| [`fastauth-macros`](https://crates.io/crates/fastauth-macros) | `#[derive(Fields, Model, AuthError)]` |
| [`fastauth-oauth`](https://crates.io/crates/fastauth-oauth) | The `Social` plugin: GitHub and Google |
| [`fastauth-plugin-two-factor`](https://crates.io/crates/fastauth-plugin-two-factor) | TOTP, email codes, backup codes, trusted devices |
| [`fastauth-cli`](https://crates.io/crates/fastauth-cli) | `fastauth secret`; schema and migration commands run from your app via `fastauth::cli::run` |

The HTTP API is compatible with Better Auth's TypeScript client (tested against
`better-auth` 1.7.28, see [docs/11](docs/11-better-auth-client.md)), so its React, Vue and
Svelte clients work against a fastauth server.

Not built yet, though some `docs/` pages describe them: the organization, admin, passkey,
magic link, API key and JWT plugins, actix-web, Redis and MySQL.

## Docs

| Page | What it covers |
|---|---|
| [Overview](docs/01-overview.md) | Goals, non-goals, crate layout, feature flags, the main design decisions |
| [Quickstart](docs/02-quickstart.md) | From `cargo new` to sign-up, sign-in and a protected route |
| [Configuration](docs/03-configuration.md) | Every builder option: secrets, email and password, social providers, sessions, cookies, rate limits |
| [Sessions and the server API](docs/04-sessions.md) | Extractors, typed user fields, calling auth from your own code |
| [Plugins](docs/05-plugins.md) | Using plugins, and writing one: schema, endpoints, hooks, events, errors, dependencies |
| [Databases](docs/06-database.md) | The adapter trait, typed models, sqlx, migrations, writing an adapter |
| [HTTP integrations](docs/07-http.md) | axum, actix-web, raw `tower`, the outgoing HTTP client, writing an integration |
| [Internals](docs/08-internals.md) | How it works: the type-level plugin list, the build step, the request path, the session hot path |
| [Security](docs/09-security.md) | Tokens, cookies, password hashing, CSRF, OAuth, rate limiting, secret rotation |
| [Open questions](docs/10-open-questions.md) | Design decisions, what was decided, and what's planned next |
| [Better Auth's client](docs/11-better-auth-client.md) | Using `better-auth/client` with fastauth, the tested version, known gaps |

## Agent skill

[`skills/use-fastauth`](skills/use-fastauth/SKILL.md) teaches coding agents to use fastauth
in their own apps: setup, axum, migrations, user fields, the first-party plugins, the server
API, custom plugins and tests, plus the compiler errors they'll meet. Every code sample in it
compiles against fastauth 0.1. Copy the folder into your agent's skills directory (for Claude Code,
`.claude/skills/use-fastauth/`).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.
