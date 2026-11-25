//! An app's `fastauth` binary: the config from `axum_sqlite`, with the schema and migration
//! commands instead of a server.
//!
//! ```bash
//! export DATABASE_URL='sqlite://fastauth-example.db?mode=rwc'
//! cargo run -p fastauth --example cli_sqlite --features cli,sqlite,two-factor -- schema
//! cargo run -p fastauth --example cli_sqlite --features cli,sqlite,two-factor -- status
//! cargo run -p fastauth --example cli_sqlite --features cli,sqlite,two-factor -- generate --out migrations
//! cargo run -p fastauth --example cli_sqlite --features cli,sqlite,two-factor -- migrate
//! ```

use fastauth::plugins::two_factor::TwoFactor;
use fastauth::prelude::*;

#[derive(Fields, Clone, Debug)]
pub struct Profile {
    #[field(default = "free", input)]
    pub plan: String,
}

pub type AppAuth = Auth<Sqlx<Sqlite>, Profile, plugins![TwoFactor]>;

fn build(pool: SqlitePool) -> Result<AppAuth, BuildError> {
    let secret = Secret::from_env("FASTAUTH_SECRET")
        .unwrap_or_else(|_| Secret::from_base64(&Secret::generate()));
    FastAuth::builder()
        .secret(secret)
        .base_url("http://localhost:3000")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .user_fields::<Profile>()
        .plugin(TwoFactor::new().issuer("Acme"))
        .build()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fastauth::cli::run(build).await
}
