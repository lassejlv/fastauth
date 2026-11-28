# fastauth

Authentication for Rust web apps, modelled on [Better Auth](https://www.better-auth.com). One
builder call gives you email and password sign-in, social login, sessions and plugins, the
compiler checks that every plugin you use is registered, and Better Auth's TypeScript client
works against it unchanged.

[![crates.io](https://img.shields.io/crates/v/fastauth.svg)](https://crates.io/crates/fastauth)
[![docs.rs](https://docs.rs/fastauth/badge.svg)](https://docs.rs/fastauth)

## Install

```bash
cargo add fastauth --features oauth,two-factor
cargo install fastauth-cli   # `fastauth secret` for FASTAUTH_SECRET
```

Default features are `axum`, `postgres` and `macros`. Use `sqlite` or `mysql` instead of (or
as well as) `postgres`. Requires Rust 1.94 or newer.

## Example

```rust
use std::net::SocketAddr;

use axum::{Router, routing::get};
use fastauth::plugins::two_factor::TwoFactor;
use fastauth::prelude::*;
use fastauth::social::{Github, Social};

type AppAuth = Auth<Sqlx<Postgres>, (), plugins![Social, TwoFactor]>;

async fn me(session: Session<AppAuth>) -> String {
    let two_factor = session.user.plugin::<TwoFactor, _>().two_factor_enabled;
    format!("{} (two-factor: {two_factor})", session.user.email)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    let auth: AppAuth = FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("http://localhost:3000")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .plugin(Social::new().provider(Github::from_env()?))
        .plugin(TwoFactor::new().issuer("Acme"))
        .build()?;
    auth.migrator().run().await?;

    let app = Router::new()
        .route("/me", get(me))
        .merge(auth.router()) // serves /api/auth/*
        .layer(auth.session_layer())
        .with_state(auth);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
```

Remove `TwoFactor` from the builder and `session.user.plugin::<TwoFactor, _>()` stops
compiling. [`examples/fullstack`](examples/fullstack) is a complete axum and React app.

## Plugins

Each plugin is a feature of `fastauth` with the same name ([all plugins](docs/plugins/README.md)):

- **Sign-in:** `oauth` (GitHub, Google), `magic-link`, `email-otp`, `passkey`, `username`, `anonymous`, `two-factor`
- **Tokens:** `bearer`, `jwt`, `api-key`
- **Access:** `organization`, `admin`, `multi-session`

The `actix` feature adds actix-web, and `redis` adds Redis or Valkey for state shared by several instances.

## Docs

The guides are at [fastauth.lassejlv.dev](https://fastauth.lassejlv.dev/docs/overview/), and the
same pages are in [`docs/`](docs/README.md), including [every crate](docs/reference/05-crates.md).
[CHANGELOG.md](CHANGELOG.md) covers each release, and [CONTRIBUTING.md](CONTRIBUTING.md) the
local checks.

[`skills/use-fastauth`](skills/use-fastauth/SKILL.md) is an agent skill for building with
fastauth: copy it into your agent's skills directory (for Claude Code, `.claude/skills/`).

## License

[MIT](LICENSE).
