//! The commands behind your app's `fastauth` binary: `schema`, `status`, `generate` and
//! `migrate`. See `docs/06-database.md`.
//!
//! ```ignore
//! // src/bin/fastauth.rs
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     fastauth::cli::run(async |pool| acme::auth::build(pool)).await
//! }
//! ```
//!
//! The binary is yours because the schema comes from your config: only your code knows
//! which plugins and user fields it registers. `crates/fastauth/examples/cli_sqlite.rs`
//! is a complete one.

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};
use fastauth_core::adapter::Adapter;
use fastauth_core::migrate::MigrationPlan;
use fastauth_core::model::Fields;
use fastauth_core::schema::{ColumnDef, ColumnType, DefaultValue, OnDelete, Schema};
use fastauth_core::{Auth, PluginSet};
use fastauth_sqlx::sqlx::{Database, Pool};
use time::OffsetDateTime;
use time::macros::format_description;

/// A database handle the CLI can open from `DATABASE_URL`: any sqlx pool. The closure
/// passed to [`run`] names the concrete type, so `PgPool` and `SqlitePool` both work.
pub trait Connect: Sized {
    fn connect(url: &str) -> impl Future<Output = anyhow::Result<Self>>;
}

impl<DB: Database> Connect for Pool<DB> {
    async fn connect(url: &str) -> anyhow::Result<Self> {
        Ok(Pool::connect(url).await?)
    }
}

/// Runs the command line of your app's `fastauth` binary.
///
/// Loads `.env` if there is one, parses the arguments, connects to `DATABASE_URL`
/// (or `--database-url`), passes the pool to `build` and runs the command on the
/// `Auth` it returns. `status` returns an error when migrations are pending, so the
/// binary exits with 1.
pub async fn run<C, D, U, P, E, F, Fut>(build: F) -> anyhow::Result<()>
where
    C: Connect,
    D: Adapter,
    U: Fields,
    P: PluginSet,
    E: Into<anyhow::Error>,
    F: FnOnce(C) -> Fut,
    Fut: Future<Output = Result<Auth<D, U, P>, E>>,
{
    let _ = dotenvy::dotenv();
    Cli::parse().run(build).await
}

/// The parsed command line. [`run`] is `Cli::parse().run(build)`; use this to pass your
/// own arguments instead of the process's.
#[derive(Debug, Parser)]
#[command(
    name = "fastauth",
    about = "fastauth's schema and migrations for this app"
)]
pub struct Cli {
    /// The database to inspect and migrate.
    #[arg(long, env = "DATABASE_URL", hide_env_values = true, global = true)]
    database_url: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Prints the merged schema for this config, with the owner of each column.
    Schema,
    /// Prints the steps `generate` would write; fails when there are any (for CI).
    Status,
    /// Writes the pending steps to <OUT>/<UTC timestamp>_fastauth.sql for `sqlx migrate`.
    Generate {
        /// The migrations directory.
        #[arg(long, default_value = "migrations")]
        out: PathBuf,
    },
    /// Applies the pending steps to the database.
    Migrate,
}

impl Cli {
    /// Connects, builds the `Auth` and runs the command, printing to stdout.
    pub async fn run<C, D, U, P, E, F, Fut>(self, build: F) -> anyhow::Result<()>
    where
        C: Connect,
        D: Adapter,
        U: Fields,
        P: PluginSet,
        E: Into<anyhow::Error>,
        F: FnOnce(C) -> Fut,
        Fut: Future<Output = Result<Auth<D, U, P>, E>>,
    {
        let Some(url) = self.database_url else {
            bail!("DATABASE_URL is not set; set it, put it in .env, or pass --database-url");
        };
        let pool = C::connect(&url)
            .await
            .context("connecting to DATABASE_URL")?;
        let auth = build(pool).await.map_err(Into::into)?;
        self.command
            .execute(&auth, &mut std::io::stdout().lock())
            .await
    }
}

impl Command {
    async fn execute<D: Adapter, U: Fields, P: PluginSet>(
        &self,
        auth: &Auth<D, U, P>,
        out: &mut impl Write,
    ) -> anyhow::Result<()> {
        match self {
            Command::Schema => out.write_all(render_schema(auth.schema()).as_bytes())?,
            Command::Status => {
                let plan = auth.migrator().plan().await?;
                print_plan(&plan, out)?;
                if !plan.is_empty() {
                    bail!("{} migration steps pending", plan.steps.len());
                }
            }
            Command::Generate { out: dir } => {
                let plan = auth.migrator().plan().await?;
                if plan.is_empty() {
                    print_plan(&plan, out)?;
                    return Ok(());
                }
                let sql = auth.adapter().render_sql(&plan)?;
                let path = write_migration(dir, &plan, &sql, OffsetDateTime::now_utc())?;
                writeln!(out, "wrote {} ({} steps)", path.display(), plan.steps.len())?;
                print_warnings(&plan, out)?;
            }
            Command::Migrate => {
                let plan = auth.migrator().plan().await?;
                auth.migrator().apply(&plan).await?;
                if plan.is_empty() {
                    print_plan(&plan, out)?;
                    return Ok(());
                }
                writeln!(out, "applied {} steps:", plan.steps.len())?;
                for step in &plan.steps {
                    writeln!(out, "  {step}")?;
                }
                print_warnings(&plan, out)?;
            }
        }
        Ok(())
    }
}

fn print_plan(plan: &MigrationPlan, out: &mut impl Write) -> std::io::Result<()> {
    if plan.is_empty() {
        writeln!(out, "up to date: no pending migration steps")?;
    } else {
        writeln!(out, "{} pending steps:", plan.steps.len())?;
        for step in &plan.steps {
            writeln!(out, "  {step}")?;
        }
    }
    print_warnings(plan, out)
}

fn print_warnings(plan: &MigrationPlan, out: &mut impl Write) -> std::io::Result<()> {
    for warning in &plan.warnings {
        writeln!(out, "warning: {warning}")?;
    }
    Ok(())
}

/// Writes a migration in sqlx-cli's format: `<YYYYMMDDHHMMSS>_fastauth.sql`. Never
/// overwrites a file.
fn write_migration(
    dir: &Path,
    plan: &MigrationPlan,
    sql: &str,
    now: OffsetDateTime,
) -> anyhow::Result<PathBuf> {
    let timestamp = now.format(format_description!(
        "[year][month][day][hour][minute][second]"
    ))?;
    let path = dir.join(format!("{timestamp}_fastauth.sql"));
    let mut contents =
        String::from("-- Generated by `fastauth generate`. Review it before applying.\n");
    for warning in &plan.warnings {
        writeln!(contents, "-- warning: {warning}")?;
    }
    contents.push('\n');
    contents.push_str(sql);
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut file| file.write_all(contents.as_bytes()))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// The schema as `docs/06-database.md` shows it: per table, each column's name, type,
/// owner and attributes, aligned.
fn render_schema(schema: &Schema) -> String {
    let columns = || schema.tables().iter().flat_map(|t| &t.columns);
    let name_width = columns().map(|c| c.name.len()).max().unwrap_or(0) + 2;
    let type_width = columns().map(|c| type_name(c.ty).len()).max().unwrap_or(0) + 2;
    let owner_width = columns().map(|c| c.owner.len()).max().unwrap_or(0) + 1;
    let mut out = String::new();
    for table in schema.tables() {
        out.push_str(table.name);
        out.push('\n');
        for column in &table.columns {
            let line = format!(
                "  {:name_width$}{:type_width$}{:owner_width$}{}",
                column.name,
                type_name(column.ty),
                column.owner,
                attributes(column).join(", "),
            );
            out.push_str(line.trim_end());
            out.push('\n');
        }
    }
    out
}

fn type_name(ty: ColumnType) -> &'static str {
    match ty {
        ColumnType::Id => "id",
        ColumnType::Text => "text",
        ColumnType::Bool => "bool",
        ColumnType::Int => "int",
        ColumnType::Timestamp => "timestamp",
        ColumnType::Json => "json",
        ColumnType::Bytes => "bytes",
    }
}

fn attributes(column: &ColumnDef) -> Vec<String> {
    let mut attributes = Vec::new();
    if column.primary_key {
        attributes.push("primary key".to_owned());
    }
    if let Some(r) = column.references {
        let on_delete = match r.on_delete {
            OnDelete::Cascade => "cascade",
            OnDelete::SetNull => "set null",
            OnDelete::Restrict => "restrict",
        };
        attributes.push(format!("-> {}.{} on delete {on_delete}", r.table, r.column));
    }
    if column.unique {
        attributes.push("unique".to_owned());
    }
    if column.index {
        attributes.push("index".to_owned());
    }
    if column.nullable {
        attributes.push("nullable".to_owned());
    }
    match column.default {
        Some(DefaultValue::Bool(value)) => attributes.push(format!("default {value}")),
        Some(DefaultValue::Int(value)) => attributes.push(format!("default {value}")),
        Some(DefaultValue::Text(value)) => {
            attributes.push(format!("default '{}'", value.replace('\'', "''")))
        }
        Some(DefaultValue::Now) => attributes.push("default now".to_owned()),
        None => {}
    }
    attributes
}

#[cfg(test)]
mod tests {
    use fastauth_core::prelude::*;
    use time::macros::datetime;

    use super::*;

    fn auth() -> Auth<MemoryAdapter> {
        FastAuth::builder()
            .secret(Secret::from_base64(&Secret::generate()))
            .base_url("http://localhost:3000")
            .database(MemoryAdapter::new())
            .build()
            .unwrap()
    }

    async fn execute(command: Command, auth: &Auth<MemoryAdapter>) -> (anyhow::Result<()>, String) {
        let mut out = Vec::new();
        let result = command.execute(auth, &mut out).await;
        (result, String::from_utf8(out).unwrap())
    }

    #[tokio::test]
    async fn schema_lists_columns_with_owner_and_attributes() {
        let (result, out) = execute(Command::Schema, &auth()).await;
        result.unwrap();
        let session: Vec<&str> = out
            .lines()
            .skip_while(|l| *l != "session")
            .take(4)
            .collect();
        assert_eq!(
            session,
            [
                "session",
                "  id                        id         core primary key",
                "  token_hash                bytes      core unique",
                "  user_id                   id         core -> user.id on delete cascade, index",
            ]
        );
        assert!(
            out.contains("\n  image                     text       core nullable\n"),
            "{out}"
        );
        assert!(out.lines().all(|l| l == l.trim_end()));
    }

    #[test]
    fn attributes_cover_every_default() {
        let column = ColumnDef::new("bio", ColumnType::Text)
            .nullable()
            .default(DefaultValue::Text("it's"));
        assert_eq!(attributes(&column), ["nullable", "default 'it''s'"]);
        let column = ColumnDef::new("n", ColumnType::Int).default(DefaultValue::Int(3));
        assert_eq!(attributes(&column), ["default 3"]);
        let column = ColumnDef::new("org_id", ColumnType::Id)
            .nullable()
            .references("org", "id", OnDelete::SetNull);
        assert_eq!(
            attributes(&column),
            ["-> org.id on delete set null", "nullable"]
        );
    }

    #[tokio::test]
    async fn status_fails_until_migrate_applies_the_plan() {
        let auth = auth();
        let (result, out) = execute(Command::Status, &auth).await;
        assert_eq!(result.unwrap_err().to_string(), "8 migration steps pending");
        assert!(
            out.starts_with("8 pending steps:\n  create table user (7 columns, owner core)\n"),
            "{out}"
        );

        let (result, out) = execute(Command::Migrate, &auth).await;
        result.unwrap();
        assert!(out.starts_with("applied 8 steps:\n"), "{out}");

        let (result, out) = execute(Command::Status, &auth).await;
        result.unwrap();
        assert_eq!(out, "up to date: no pending migration steps\n");
        let (result, out) = execute(Command::Migrate, &auth).await;
        result.unwrap();
        assert_eq!(out, "up to date: no pending migration steps\n");
    }

    #[tokio::test]
    async fn generate_needs_an_adapter_that_renders_sql() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("migrations");
        let (result, _) = execute(Command::Generate { out: out.clone() }, &auth()).await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "the adapter does not support SQL rendering"
        );
        assert!(!out.exists());
    }

    #[tokio::test]
    async fn generate_writes_nothing_for_an_empty_plan() {
        let auth = auth();
        auth.migrator().run().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("migrations");
        let (result, printed) = execute(Command::Generate { out: out.clone() }, &auth).await;
        result.unwrap();
        assert_eq!(printed, "up to date: no pending migration steps\n");
        assert!(!out.exists());
    }

    #[test]
    fn migration_files_use_sqlx_names_and_never_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let plan = MigrationPlan {
            steps: Vec::new(),
            warnings: vec!["user.nickname exists in the database but not in the config".into()],
        };
        let now = datetime!(2026-11-25 09:05:03 UTC);
        let path = write_migration(dir.path(), &plan, "SELECT 1;\n", now).unwrap();
        assert_eq!(path, dir.path().join("20261125090503_fastauth.sql"));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "-- Generated by `fastauth generate`. Review it before applying.\n\
             -- warning: user.nickname exists in the database but not in the config\n\
             \n\
             SELECT 1;\n"
        );
        assert!(write_migration(dir.path(), &plan, "SELECT 2;\n", now).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().lines().last(),
            Some("SELECT 1;")
        );
    }
}
