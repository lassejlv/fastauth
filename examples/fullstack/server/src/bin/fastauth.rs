//! The app's `fastauth` binary: `schema`, `status`, `generate` and `migrate` for the
//! auth tables, built from the same config as the server.
//!
//! ```bash
//! cargo run --bin fastauth -- status
//! cargo run --bin fastauth -- generate --out migrations
//! ```

use fastauth::prelude::PgPool;
use fastauth_example_fullstack::{auth, config::Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fastauth::cli::run(|pool: PgPool| -> anyhow::Result<auth::AppAuth> {
        Ok(auth::build(&Config::from_env()?, pool, None)?)
    })
    .await
}
