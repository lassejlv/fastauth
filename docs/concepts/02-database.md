# Databases

fastauth talks to the database through one trait, `Adapter`. `fastauth-sqlx` implements
it for Postgres and SQLite; `MemoryAdapter` implements it for tests. Plugins never see SQL,
so every plugin works on every adapter.

## Using sqlx

```rust
use fastauth::prelude::*;   // re-exports Sqlx, Postgres, Sqlite, PgPool, SqlitePool

let pool = PgPool::connect(&url).await?;
FastAuth::builder().database(Sqlx::new(pool));  // Sqlx<Postgres>, inferred from the pool

let pool = SqlitePool::connect("sqlite://acme.db?mode=rwc").await?;
FastAuth::builder().database(Sqlx::new(pool));  // Sqlx<Sqlite>
```

The facade's `postgres` (default) and `sqlite` features pick the drivers. Options:

```rust
Sqlx::new(pool)
    .schema("auth")              // Postgres only; default: the search_path. The migrator creates it.
    .table_prefix("fa_")         // fa_user, fa_session, ...
    .rename("user", "accounts")  // keep an existing users table name (the prefix doesn't apply)
```

`fastauth-sqlx` is built on sqlx 0.9, which needs Rust 1.94, the MSRV of the whole
workspace. Take `PgPool` and `SqlitePool` from `fastauth::prelude`, or depend on sqlx 0.9
yourself so the pool types match. What it does with the database:

- **Bind parameters only.** Values never appear in SQL text. The text for each query shape
  (operation, table, filter shape, columns) is rendered once and cached, so sqlx's prepared
  statement cache hits on every repeat.
- **Constraint names are fixed:** `<table>_pkey`, `<table>_<column>_key` for unique columns
  and `idx_<table>_<column>` for indexes, using the stored (prefixed) table name. The
  adapter maps a unique violation back to `DbError::UniqueViolation { table, column }`
  through these names on Postgres and through the error message on SQLite.
- **SQLite `ADD COLUMN`** can't add a UNIQUE constraint or a non-constant default, so the
  migrator adds a unique column plus a unique index named `<table>_<column>_key`, and a
  `DefaultValue::Now` column gets the migration time as its default for existing rows.
- **Text search is case-sensitive.** `contains`, `starts_with` and `ends_with` match their
  string literally (`%` and `_` are not wildcards): Postgres uses `LIKE .. ESCAPE`, SQLite
  uses `GLOB` with escapes, because SQLite's `LIKE` ignores case.
- **In-memory SQLite** (`sqlite::memory:`) is one shared-cache database per pool. A query on
  the pool waits while another connection's transaction holds uncommitted writes to the same
  table, so code that holds a transaction must run every query through it (`ctx.db_on(&tx)`)
  or it waits on itself. Server API calls made with `.in_tx(&tx)` do this for you: the
  adapter they run on is bound to the app's transaction
  ([Sharing a transaction](01-sessions.md#sharing-a-transaction)).

## The schema

Core tables (column names in snake_case; JSON uses camelCase):

| Table | Columns |
|---|---|
| `user` | `id`, `email` (unique), `email_verified`, `name`, `image`, `created_at`, `updated_at` |
| `session` | `id`, `token_hash` (unique), `user_id` → user, `expires_at`, `ip_address`, `user_agent`, `created_at`, `updated_at` |
| `account` | `id`, `user_id` → user, `provider_id`, `account_id`, `password_hash`, `access_token` (encrypted), `refresh_token` (encrypted), `id_token`, `access_token_expires_at`, `refresh_token_expires_at`, `scope`, `created_at`, `updated_at` |
| `verification` | `id`, `identifier`, `value_hash`, `data`, `expires_at`, `created_at`, `updated_at` |

Passwords live on `account` (provider `credential`), like Better Auth, so a user can have a
password and a GitHub login at once. Plugins and `user_fields` add tables and columns to
this: two-factor adds `two_factor` and `user.two_factor_enabled`; the
[organization](../plugins/access/01-organization.md#setup), [admin](../plugins/access/02-admin.md#setup) and
[API key](../plugins/tokens/03-api-keys.md#setup) pages list theirs.

`cargo run --bin fastauth -- schema` ([Migrations](#migrations) has the binary) prints the
merged schema for your config, with the owner of each column. With a `plan` user field and
`TwoFactor`:

```
user
  id                        id         core       primary key
  email                     text       core       unique
  ...
  plan                      text       app        default 'free'
  two_factor_enabled        bool       two-factor default false
...
two_factor
  id                        id         two-factor primary key
  user_id                   id         two-factor -> user.id on delete cascade, index
  secret                    bytes      two-factor
  backup_codes              bytes      two-factor
  last_used_step            int        two-factor nullable
```

The types are the schema's column types (`id`, `text`, `bool`, `int`, `timestamp`, `json`,
`bytes`). Encrypted and hashed values are `bytes`; the schema doesn't record which.

### Column types

| Schema type | Rust type | Postgres | SQLite |
|---|---|---|---|
| `id` | `Id` | `text`, or `uuid` under a UUID [id strategy](#ids) | `text` |
| `text` | `String` | `text` | `text` |
| `bool` | `bool` | `boolean` | `integer` |
| `int` | `i64` | `bigint` | `integer` |
| `timestamp` | `OffsetDateTime` | `timestamptz` | `integer` (Unix milliseconds) |
| `json` | `Json<T>` | `jsonb` | `text` |
| `bytes` | `Hash`, `Vec<u8>` | `bytea` | `blob` |

## Ids

`Id` is an opaque string. The id strategy, set with `.ids(..)` on the builder, decides the
ids of every row fastauth creates, the ones plugins create with `ctx.new_id()?`, and how id
columns are stored:

```rust
.ids(IdStrategy::Ulid)                                     // default: 01M8AH3K9Q2W7X5R1N0PJCV4TB
.ids(IdStrategy::UuidV7)                                   // 019ac3f1-6c2e-7a41-9d0b-3f5e2a7c8b14
.ids(IdStrategy::UuidV4)                                   // random UUIDs
.ids(IdStrategy::custom(|| format!("usr_{}", random_token())))  // anything up to 255 bytes
```

| Strategy | Ids | Postgres columns | SQLite columns |
|---|---|---|---|
| `Ulid` (default) | 26 characters of Crockford base32, sortable by creation time | `text` | `text` |
| `UuidV7` | hyphenated UUIDv7, sortable by creation time | `uuid` | `text` |
| `UuidV4` | hyphenated random UUIDv4 | `uuid` | `text` |
| `custom(f)` | whatever `f` returns | `text` | `text` |

ULIDs and UUIDv7s are time-ordered, so inserts land at the end of the primary key index
instead of splitting pages at random. A custom generator's ids are checked as they're made:
an empty id, or one longer than 255 bytes, fails the request with a 500 and a log line.
Custom ids must be unique; fastauth doesn't retry on a collision.

**Switching strategies on an existing database.** The migrator never changes a column's
type. On Postgres, when the configured strategy stores ids differently from the live
columns, the migration plan carries a warning naming the columns ("id columns ... are uuid
in the database, but the config uses an id strategy that stores ids as text"), and inserts
fail. Two cases matter:

- **A Postgres database created with fastauth 0.1** has `uuid` id columns, because 0.1
  generated UUIDv7s. Keep it working with `.ids(IdStrategy::UuidV7)`, or convert the columns
  to `text` yourself before moving to ULIDs.
- **Between strategies that store the same way** (ULID and custom on any database; anything
  on SQLite), new rows simply get the new kind of id, and old ids stay valid. Code that
  parses ids, sorts by them, or assumes their length breaks, which is why `Id` is opaque.

## Migrations

fastauth computes the schema from your config at runtime (plugins decide it), so it can
diff that against the live database. The diff only ever **adds**: tables, columns, indexes,
foreign keys. Anything it would have to drop or alter (a removed plugin's table, a type
change, a column that's NOT NULL without a default on a table with rows) is reported as a
warning and left for you.

Three ways to apply it:

```rust
// 1. At startup. Fine for development and small deployments.
auth.migrator().run().await?;

// 2. Inspect first.
let migrator = auth.migrator();
let plan = migrator.plan().await?;
for step in &plan.steps { println!("{step}"); }
for warning in &plan.warnings { eprintln!("{warning}"); }
migrator.apply(&plan).await?;

// 3. As SQL, for sqlx migrate / your own tooling.
let sql: String = auth.migrator().sql().await?;
```

Option 3 is what `cargo run --bin fastauth -- generate` does: it writes
`migrations/<UTC timestamp>_fastauth.sql` (`20261125090503_fastauth.sql`) in sqlx-cli's
format, with the plan's warnings as comments at the top, and writes nothing when the plan
is empty. The binary is yours (three lines with the facade's `cli` feature, see
[Quickstart](../get-started/02-quickstart.md#4-tables)) because only your code knows your config. That's
the Rust version of Better Auth's CLI loading `auth.ts`. The `fastauth` command from
`cargo install fastauth-cli` only generates secrets, and its `--help` says why.

```
cargo run --bin fastauth -- schema            # print the merged schema
cargo run --bin fastauth -- status            # what generate would write; exit 1 if non-empty (CI)
cargo run --bin fastauth -- generate --out migrations   # --out defaults to migrations
cargo run --bin fastauth -- migrate           # apply directly
```

Every command reads `DATABASE_URL` from the environment or `.env`, or takes
`--database-url`. `status` in CI catches a forgotten migration after adding a plugin; it
also exits 1 when it can't reach the database.

## Typed queries

Inside plugins, hooks and event handlers, `ctx.db()` gives a typed query builder over
models. (Outside them, `auth.api().db()` does the same.) With the `AccessToken` model from
[Plugins](../reference/01-plugin-authoring.md#tables-derivemodel):

```rust
let token = ctx.db().find::<AccessToken>(AccessToken::TOKEN_HASH.eq(hash)).one().await?;  // Option<AccessToken>

let tokens = ctx.db()
    .find::<AccessToken>(AccessToken::USER_ID.eq(&user_id).and(AccessToken::EXPIRES_AT.gt(ctx.now())))
    .order_by(AccessToken::CREATED_AT.desc())
    .limit(50)
    .all()
    .await?;                                                                     // Vec<AccessToken>

ctx.db().update::<User>(User::ID.eq(&user_id))
    .set(TwoFactorUser::TWO_FACTOR_ENABLED, true)
    .exec()
    .await?;                                                                     // u64

ctx.db().delete::<AccessToken>(AccessToken::ID.eq(&id)).await?;
ctx.db().count::<Session>(Session::USER_ID.eq(&user_id)).await?;
ctx.db().find::<User>(User::NAME.contains("Lasse")).all().await?;              // case-sensitive
```

`Col<M, T>` carries the model and the Rust type, so comparing `EXPIRES_AT` with a string,
or filtering `find::<AccessToken>` on a `Session` column, is a compile error. Filters
support `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `in_`, `is_null`, `is_not_null`, and on text
columns `starts_with`, `contains` and `ends_with`, combined with `and` and `or`
(`Where::all()` matches every row). `find` also takes `.offset(n)`, and `.one_row()` /
`.all_rows()` return raw rows, including columns plugins added. That is enough for auth and
keeps every adapter small.

Transactions go through the adapter:

```rust
let tx = ctx.adapter().begin().await?;
ctx.db_on(&tx).delete::<AccessToken>(AccessToken::USER_ID.eq(&user_id)).await?;
ctx.db_on(&tx).update::<User>(User::ID.eq(&user_id)).set(TwoFactorUser::TWO_FACTOR_ENABLED, false).exec().await?;
tx.commit().await?;   // dropping without commit rolls back
```

`commit` needs `fastauth::adapter::Transaction` in scope.

## The `Adapter` trait

This is what a new database implements. It's dynamic on purpose: rows are `Row`s of
`Value`s, and table and column names come from the schema, because the adapter can't
know at compile time which plugins an app uses.

```rust
pub trait Queries: Send + Sync {
    fn insert(&self, q: Insert<'_>) -> impl Future<Output = DbResult<Row>> + Send;
    fn find_one(&self, q: Select<'_>) -> impl Future<Output = DbResult<Option<Row>>> + Send;
    fn find_many(&self, q: Select<'_>) -> impl Future<Output = DbResult<Vec<Row>>> + Send;
    fn update(&self, q: Update<'_>) -> impl Future<Output = DbResult<u64>> + Send;
    fn delete(&self, q: Delete<'_>) -> impl Future<Output = DbResult<u64>> + Send;
    fn count(&self, q: Select<'_>) -> impl Future<Output = DbResult<u64>> + Send;
}

pub trait Transaction: Queries + 'static {
    fn commit(self) -> impl Future<Output = DbResult<()>> + Send;
    fn rollback(self) -> impl Future<Output = DbResult<()>> + Send;
}

pub trait Adapter: Queries + 'static {
    type Tx: Transaction;
    fn begin(&self) -> impl Future<Output = DbResult<Self::Tx>> + Send;
    /// Reads the live schema for the migrator. Adapters without DDL return `Unsupported`.
    fn introspect(&self) -> impl Future<Output = DbResult<LiveSchema>> + Send;
    /// Applies a migration plan computed by the migrator.
    fn apply(&self, plan: &MigrationPlan) -> impl Future<Output = DbResult<()>> + Send;
    /// Renders a plan as SQL for `fastauth generate`. Non-SQL adapters return `Unsupported`.
    fn render_sql(&self, plan: &MigrationPlan) -> DbResult<String> {
```

(From `fastauth_core::adapter`; `render_sql` and `session_with_user` have defaults, and
SQL adapters override `session_with_user` with one JOIN.) `Select` holds the table
definition, a `Filter` tree, an order, a limit and an offset. `Filter` is
`#[non_exhaustive]`: answer a variant you don't know with `DbError::Unsupported`. A row is
positional, in the table's column order, which the schema fixed at build time. A unique
violation must map to `DbError::UniqueViolation`, so sign-up can answer "email taken".
`TableDef::id_storage()` says whether id columns are `uuid` or `text`.

### Conformance tests

`fastauth-core` ships the adapter test suite as a function behind its `testing` feature.
A new adapter is done when this passes:

```rust
// [dev-dependencies] fastauth-core = { version = "0.4", features = ["testing"] }
#[tokio::test]
async fn conformance() {
    fastauth_core::testing::run_adapter_conformance(async || fastauth::prelude::MemoryAdapter::new()).await;
}
```

Each case gets a fresh adapter from the closure, so it must return an empty database. The
suite runs every case twice, with text ids and with UUID ids, and covers every `Filter`
variant (the text matches with `%`, `_` and mixed case), ordering, limit and offset, updates
and deletes, unique violations, transaction commit, rollback and drop,
`session_with_user`, and the migrator round trip (create, then an empty plan, then added
columns on a table with rows). `MemoryAdapter` and both `fastauth-sqlx` databases run it.

Secondary storage (Redis), MySQL and other adapters are [planned](../get-started/01-overview.md#planned).
