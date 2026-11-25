# fastauth

Authentication for Rust web apps, modelled on [Better Auth](https://www.better-auth.com):
one builder call gives you email and password sign-in, social login, sessions, and a
plugin system for two-factor, organizations, passkeys, API keys and the rest. It
runs on sqlx and axum out of the box, and the plugin API is checked by the compiler.

> **Status: v0.1, unreleased.** Core, axum, sqlx (Postgres and SQLite), the derive macros,
> GitHub and Google sign-in, two-factor and the CLI are on `main` and tested, including
> against Better Auth's own client. Not on crates.io yet. Some pages in `docs/` still describe
> planned features (organization, passkey, admin, actix, Redis); docs/01 lists what ships.

```rust
use fastauth::prelude::*;
use fastauth::plugins::{organization::Organization, two_factor::TwoFactor};
use fastauth::social::{Github, Social};

pub type AppAuth = Auth<Sqlx<Postgres>, Profile, plugins![Social, TwoFactor, Organization]>;

#[derive(Fields, Serialize, Clone)]
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
        .plugin(Organization::default())
        .build()
}

async fn me(session: Session<AppAuth>) -> Json<Value> {
    let tfa = session.user.plugin::<TwoFactor, _>();
    Json(json!({
        "email": session.user.email,
        "plan": session.user.fields.plan,
        "twoFactor": tfa.two_factor_enabled,
    }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    let auth = auth(pool)?;
    auth.migrator().run().await?;

    let app = Router::new()
        .route("/me", get(me))
        .merge(auth.router()) // serves /api/auth/*
        .with_state(auth);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

If you remove `TwoFactor` from the builder, `session.user.plugin::<TwoFactor, _>()`
stops compiling and tells you which plugin is missing.

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
| [Open questions](docs/10-open-questions.md) | Decisions that need an owner before v0.1 |
| [Better Auth's client](docs/11-better-auth-client.md) | Using `better-auth/client` with fastauth, the tested version, known gaps |

## Agent skill

[`skills/use-fastauth`](skills/use-fastauth/SKILL.md) teaches coding agents to use fastauth
in their own apps: setup, axum, migrations, user fields, the first-party plugins, the server
API, custom plugins and tests, plus the compiler errors they'll meet. Every code sample in it
compiles against `main`. Copy the folder into your agent's skills directory (for Claude Code,
`.claude/skills/use-fastauth/`).
