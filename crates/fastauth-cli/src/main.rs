//! The `fastauth` command. `cargo install fastauth-cli`, then `fastauth secret >> .env`.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use fastauth_core::crypto::Secret;

const APP_COMMANDS: [&str; 4] = ["schema", "status", "generate", "migrate"];

const APP_BINARY: &str = "\
The schema, status, generate and migrate commands live in your app's own binary, not in
this one. fastauth computes the schema at runtime from your config (the plugins and user
fields you register decide which tables and columns exist), so only a binary compiled
from your code can know it. With the `cli` feature on your fastauth dependency, it is
three lines:

    // src/bin/fastauth.rs
    #[tokio::main]
    async fn main() -> anyhow::Result<()> {
        fastauth::cli::run(async |pool| my_app::auth::build(pool)).await
    }

Then:

    cargo run --bin fastauth -- schema
    cargo run --bin fastauth -- status
    cargo run --bin fastauth -- generate --out migrations
    cargo run --bin fastauth -- migrate";

/// fastauth's command line.
#[derive(Parser)]
#[command(name = "fastauth", version, about, after_help = APP_BINARY)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Prints a new secret, 64 random bytes as base64url, as a FASTAUTH_SECRET= line.
    Secret {
        /// Print only the value.
        #[arg(long)]
        raw: bool,
    },
    #[command(external_subcommand)]
    Other(Vec<String>),
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Secret { raw: true } => println!("{}", Secret::generate()),
        Command::Secret { raw: false } => println!("FASTAUTH_SECRET={}", Secret::generate()),
        Command::Other(args) => {
            let name = &args[0];
            if APP_COMMANDS.contains(&name.as_str()) {
                eprintln!("error: `fastauth {name}` runs from your app's binary.\n\n{APP_BINARY}");
            } else {
                eprintln!("error: unknown command `{name}`; see `fastauth --help`");
            }
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}
