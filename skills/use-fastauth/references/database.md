# Database

## Adapters

`Sqlx::new(pool)` takes a `PgPool` (feature `postgres`) or a `SqlitePool` (feature
`sqlite`); the adapter type follows the pool: `Sqlx<Postgres>`, `Sqlx<Sqlite>`. Options:
`.table_prefix("fa_")`, `.rename("user", "accounts")` and, on Postgres, `.schema("auth")`.
SQLite needs `?mode=rwc` in the URL to create the file:
`SqlitePool::connect("sqlite://app.db?mode=rwc")`.

`MemoryAdapter::new()` keeps everything in memory, needs no migrations, and is for tests
([testing.md](testing.md)).

Core tables are `user`, `session`, `account` (passwords live here, provider `credential`)
and `verification`. Plugins and your user fields add tables and columns. `docs/06-database.md`
has the full schema.

## Ids

Every row's id comes from the builder's `.ids(..)`: `IdStrategy::Ulid` (default, stored as
`text`), `UuidV7` or `UuidV4` (Postgres `uuid`), or `IdStrategy::custom(|| ..)` (`text`, at
most 255 bytes). Pick it before the first migration; the migrator never changes a column
type and only warns. A Postgres database created with fastauth 0.1 has `uuid` columns: keep
it on `.ids(IdStrategy::UuidV7)`. Treat `Id` as an opaque string.

## Migrations

fastauth derives the schema from the config (plugins decide it) and diffs it against the
live database. The diff only adds tables, columns and indexes; a dropped plugin's table or a
changed type becomes a warning for you to handle.

- Development or a small deployment: `auth.migrator().run().await?` at startup. It is a
  no-op when nothing changed.
- To look before applying, or to write a migration file for `sqlx migrate` and review it:

```rust
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Sqlite>>;

pub async fn migrate(auth: &AppAuth) -> Result<(), Box<dyn std::error::Error>> {
    let plan = auth.migrator().plan().await?;
    for step in &plan.steps {
        println!("{step}");
    }
    for warning in &plan.warnings {
        eprintln!("warning: {warning}");
    }
    auth.migrator().apply(&plan).await?;
    Ok(())
}

pub async fn migration_sql(auth: &AppAuth) -> Result<String, Box<dyn std::error::Error>> {
    Ok(auth.migrator().sql().await?)
}
```

`plan.steps` print as `create table user (7 columns, owner core)`, `create index on
session.user_id`, `add column user.plan (Text, owner app)`. `sql()` renders the same plan as
`CREATE TABLE`, `ALTER TABLE` and `CREATE INDEX` statements for the pool's database (adding
`Profile` below gives `ALTER TABLE "user" ADD COLUMN "plan" text NOT NULL DEFAULT 'free';`),
and an empty string once the database is up to date, so generate it after each config change,
against a database that has every earlier migration applied. For files, add
`src/bin/fastauth.rs` with `fastauth::cli::run(my_app::auth::build).await` (facade feature
`cli`) and run `cargo run --bin fastauth -- generate` (also `schema`, `status`, `migrate`);
`docs/02-quickstart.md#4-tables` has the three lines.

## App columns on `user`

```rust
#[derive(Fields, Clone, Debug)]
pub struct Profile {
    #[field(default = "free", input)]
    pub plan: String,
    pub stripe_customer_id: Option<String>,
}
```

Register it with `.user_fields::<Profile>()` and put it second in the alias:
`Auth<Sqlx<Postgres>, Profile, plugins![..]>`. Handlers read `session.user.fields.plan`.

- **`input` defaults to false.** A column without `#[field(input)]` is server-only: a
  sign-up or `/update-user` body that sets it gets `400 INVALID_FIELD`
  (`field \`stripeCustomerId\` can't be set`). This is stricter than Better Auth's
  `additionalFields`. Clients send input columns in camelCase (`"plan": "pro"`) next to
  `email` and `password`.
- `Option<T>` is a nullable column. A non-`Option` column needs a `default` unless every
  sign-up sends it; social sign-up can't send app columns, so give required columns a
  default when `Social` is registered.
- Other attributes: `default = ..` (bool, integer or string literal, or `now`; checked
  against the type at compile time), `returned = false` (never sent to clients), `unique`,
  `index`, `rename = "column"`.
- The derive adds a typed column constant per field (`Profile::STRIPE_CUSTOMER_ID`) for
  queries.

Server code sets server-only columns with the typed query builder. Inside event handlers,
hooks and endpoints, use `ctx.db()`; anywhere else, build one from the instance:

```rust
use fastauth::models::User;
use fastauth::query::Db;

pub async fn ban_user(auth: &BanAuth, user_id: &Id) -> Result<(), AuthError> {
    Db::new(auth.adapter(), auth.schema())
        .update::<User>(User::ID.eq(user_id))
        .set(BanFields::BANNED, true)
        .exec()
        .await?;
    Ok(())
}
```

(`BanFields` is a plugin's `Fields` struct from [custom-plugins.md](custom-plugins.md); app
fields work the same way.) `find::<M>(filter).one()/.all()`, `insert(&model)`,
`delete::<M>(filter)` and `count::<M>(filter)` complete the builder.
