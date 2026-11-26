# Quickstart

This builds an axum app on Postgres with email and password sign-in, a session cookie,
and one protected route. The defaults cover everything not shown.

## 1. Dependencies

```toml
[dependencies]
fastauth = { version = "0.3", features = ["cli"] }
axum = "0.8"
sqlx = { version = "0.9", features = ["runtime-tokio", "postgres"] }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
anyhow = "1"
```

## 2. A secret and a database

```bash
cargo install fastauth-cli
fastauth secret >> .env          # FASTAUTH_SECRET=<64 random bytes, base64url>; --raw prints only the value
echo 'DATABASE_URL=postgres://localhost/acme' >> .env
```

The secret signs cookies and derives every other key fastauth uses. Losing it signs
everyone out; leaking it lets an attacker forge cookies. [Security](09-security.md#secrets)
covers rotation.

## 3. The auth instance

Keep it in its own module. The type alias is the one place you list your plugins, and
every handler names it.

```rust
// src/auth.rs
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url(std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:3000".into()))
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .build()
}
```

`Auth<D, U = (), P = Nil>` has defaults for the user fields and plugin list, so an app
with neither writes `Auth<Sqlx<Postgres>>`.

## 4. Tables

fastauth knows its own schema, so it can create it. In development, run migrations at
startup:

```rust
auth.migrator().run().await?;
```

For production, generate a sqlx migration file instead and review it like any other
migration. Add a three-line binary to your project:

```rust
// src/bin/fastauth.rs
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fastauth::cli::run(acme::auth::build).await
}
```

`run` loads `.env`, connects to `DATABASE_URL` (or `--database-url`), and passes the pool
to `build`. The function's argument type picks the database: `build` takes a `PgPool`, so
the CLI opens one; a `SqlitePool` works the same way. A closure works too.

```bash
cargo run --bin fastauth -- generate --out migrations   # writes migrations/<ts>_fastauth.sql
sqlx migrate run
```

`generate` compares the schema your config needs with the live database and writes only
the difference, so adding a plugin later produces a migration with only that plugin's tables
and columns. [Databases](06-database.md#migrations) has the details.

## 5. The server

```rust
// src/main.rs
use acme::auth::{self, AppAuth};
use axum::{Json, Router, routing::get};
use fastauth::axum::{AuthRouter, Session};
use serde::Serialize;

#[derive(Serialize)]
struct Me {
    id: String,
    email: String,
}

async fn me(session: Session<AppAuth>) -> Json<Me> {
    Json(Me { id: session.user.id.to_string(), email: session.user.email.clone() })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    let auth = auth::build(pool)?;
    auth.migrator().run().await?;

    let app = Router::new()
        .route("/me", get(me))
        .merge(auth.router())
        .with_state(auth);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

`Session<AppAuth>` rejects the request with `401` and a JSON error body when there is
no valid session. Use `Option<Session<AppAuth>>` for routes that work signed in or out.
Ids are opaque strings, [ULIDs](06-database.md#ids) unless you pick another strategy, so
`to_string()` is all `Me.id` needs.

## 6. Try it

```bash
curl -i -c jar -X POST localhost:3000/api/auth/sign-up/email \
  -H 'content-type: application/json' -H 'origin: http://localhost:3000' \
  -d '{"email":"lasse@acme.dk","password":"correct horse battery","name":"Lasse"}'

curl -b jar localhost:3000/me
# {"id":"01M8AH3K9Q2W7X5R1N0PJCV4TB","email":"lasse@acme.dk"}

curl -b jar localhost:3000/api/auth/get-session
curl -b jar -c jar -X POST localhost:3000/api/auth/sign-out -H 'origin: http://localhost:3000'
```

The `origin` header is there because state-changing requests that carry cookies must come
from a trusted origin ([Security](09-security.md#csrf)). Browsers send it automatically.

## 7. Add a plugin

```rust
use fastauth::plugins::two_factor::TwoFactor;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![TwoFactor]>;

FastAuth::builder()
    // ...
    .plugin(TwoFactor::new().issuer("Acme"))
    .build()
```

Run `cargo run --bin fastauth -- generate` again to get the `two_factor` table and the
`user.two_factor_enabled` column. The plugin's routes (`/api/auth/two-factor/*`) are now
mounted, `session.user.plugin::<TwoFactor, _>()` compiles, and sign-in returns
`{"twoFactorRedirect": true, "twoFactorMethods": ["totp", "otp"]}` for users who turned it on
(`"otp"` only when a mailer is configured).

Next: [Configuration](03-configuration.md) for everything the builder takes, or
[Plugins](05-plugins.md) to write your own.
