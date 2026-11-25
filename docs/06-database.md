# Databases

fastauth talks to the database through one trait, `Adapter`. `fastauth-sqlx` implements
it for Postgres and SQLite (MySQL is planned, not built); `MemoryAdapter` implements it for
tests. Plugins never see SQL, so every plugin works on every adapter.

## Using sqlx

```rust
use fastauth::prelude::*;   // re-exports Sqlx, Postgres, Sqlite, MySql, PgPool, ...

let pool = PgPool::connect(&url).await?;
FastAuth::builder().database(Sqlx::new(pool))  // Sqlx<Postgres>, inferred from the pool

let pool = SqlitePool::connect("sqlite://acme.db?mode=rwc").await?;
FastAuth::builder().database(Sqlx::new(pool))  // Sqlx<Sqlite>
```

Options:

```rust
Sqlx::new(pool)
    .schema("auth")              // Postgres only; default: the search_path. The migrator creates it.
    .table_prefix("fa_")         // fa_user, fa_session, ...
    .rename("user", "accounts")  // keep an existing users table name (the prefix doesn't apply)
```

`fastauth-sqlx` is built on sqlx 0.9, with the `postgres` and `sqlite` features (both on by
default). sqlx 0.9 needs Rust 1.94, so this crate's MSRV is 1.94 while core stays at 1.88.
What it does with the database:

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
- **In-memory SQLite** (`sqlite::memory:`) is one shared-cache database per pool. A query on
  the pool waits while another connection's transaction holds uncommitted writes to the same
  table, so code that holds a transaction must run every query through it (`ctx.db_on(&tx)`)
  or it waits on itself.

## The schema

Core tables (column names in snake_case; JSON uses camelCase):

| Table | Columns |
|---|---|
| `user` | `id`, `email` (unique), `email_verified`, `name`, `image`, `created_at`, `updated_at` |
| `session` | `id`, `token_hash` (unique), `user_id` → user, `expires_at`, `ip_address`, `user_agent`, `created_at`, `updated_at` |
| `account` | `id`, `user_id` → user, `provider_id`, `account_id`, `password_hash`, `access_token` (encrypted), `refresh_token` (encrypted), `id_token`, `access_token_expires_at`, `scope`, `created_at`, `updated_at` |
| `verification` | `id`, `identifier`, `value_hash`, `expires_at`, `created_at` |

Passwords live on `account` (provider `credential`), like Better Auth, so a user can have a
password, a GitHub login and a passkey at once. Plugins and `user_fields` add tables and
columns to this.

`fastauth schema` prints the merged schema for your config, with the owner of each column:

```
user
  id                  id          core
  email               text        core       unique
  ...
  plan                text        app        default 'free'
  two_factor_enabled  bool        two-factor default false
two_factor
  id                  id          two-factor
  user_id             id          two-factor -> user.id on delete cascade, index
  secret              encrypted   two-factor
  backup_codes        encrypted   two-factor
```

### Column types

| fastauth type | Postgres | SQLite | MySQL |
|---|---|---|---|
| `Id` | `uuid` | `text` | `binary(16)` |
| `String` | `text` | `text` | `varchar(255)` / `text` |
| `bool` | `boolean` | `integer` | `tinyint(1)` |
| `i64` | `bigint` | `integer` | `bigint` |
| `Timestamp` | `timestamptz` | `integer` (unix ms) | `datetime(3)` |
| `Json<T>` | `jsonb` | `text` | `json` |
| `Hash` | `bytea` | `blob` | `binary(32)` |
| `Encrypted<T>` | `bytea` | `blob` | `varbinary` |

IDs are UUIDv7 by default: time-ordered, so inserts land at the end of the primary key
index instead of splitting pages at random. `.ids(IdStrategy::Custom(f))` plugs in your own.

## Migrations

fastauth computes the schema from your config at runtime (plugins decide it), so it can
diff that against the live database. The diff only ever **adds**: tables, columns, indexes,
foreign keys. Anything it would have to drop or alter (a removed plugin's table, a type
change) is reported as a warning and left for you.

Three ways to apply it:

```rust
// 1. At startup. Fine for development and small deployments.
auth.migrator().run().await?;

// 2. Inspect first.
let plan = auth.migrator().plan().await?;
for step in plan.steps() { println!("{step}"); }
for warning in plan.warnings() { eprintln!("{warning}"); }
plan.apply().await?;

// 3. As SQL, for sqlx migrate / your own tooling.
let sql: String = auth.migrator().plan().await?.to_sql();
```

Option 3 is what `cargo run --bin fastauth -- generate` does: it writes
`migrations/<timestamp>_fastauth.sql` in sqlx-cli's format. The binary is yours (three
lines, see [Quickstart](02-quickstart.md#4-tables)) because only your code knows your
config. That's the Rust version of Better Auth's CLI loading `auth.ts`.

```
cargo run --bin fastauth -- schema            # print the merged schema
cargo run --bin fastauth -- status            # what generate would write; exit 1 if non-empty (CI)
cargo run --bin fastauth -- generate --out migrations
cargo run --bin fastauth -- migrate           # apply directly
```

`status` in CI catches a forgotten migration after adding a plugin.

## Typed queries

Inside plugins and event handlers, `ctx.db()` gives a typed query builder over models:

```rust
let key = ctx.db().find::<ApiKey>(ApiKey::KEY_HASH.eq(hash)).one().await?;            // Option<ApiKey>

let keys = ctx.db()
    .find::<ApiKey>(ApiKey::USER_ID.eq(&user_id).and(ApiKey::EXPIRES_AT.gt(ctx.now())))
    .order_by(ApiKey::CREATED_AT.desc())
    .limit(50)
    .all()
    .await?;                                                                        // Vec<ApiKey>

ctx.db().update::<User>(User::ID.eq(&user_id))
    .set(TwoFactorUser::TWO_FACTOR_ENABLED, true)
    .exec()
    .await?;                                                                        // u64

ctx.db().delete::<ApiKey>(ApiKey::ID.eq(&id)).await?;
ctx.db().count::<Session>(Session::USER_ID.eq(&user_id)).await?;
```

`Col<M, T>` carries the model and the Rust type, so comparing `EXPIRES_AT` with a string,
or filtering `find::<ApiKey>` on a `Session` column, is a compile error. Filters support
`eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `in_`, `is_null`, `starts_with`, `and`, `or`; that is
enough for auth and keeps every adapter small.

Transactions:

```rust
let tx = ctx.db().begin().await?;
tx.insert(&member).await?;
tx.update::<Invitation>(Invitation::ID.eq(&invite.id)).set(Invitation::STATUS, Status::Accepted).exec().await?;
tx.commit().await?;   // dropping without commit rolls back
```

## The `Adapter` trait

This is what a new database implements. It's dynamic on purpose: rows are `Row`s of
`Value`s, and table and column names come from the schema, because the adapter can't
know at compile time which plugins an app uses.

```rust
pub trait Adapter: Send + Sync + 'static {
    type Tx: Transaction;

    fn capabilities(&self) -> Capabilities;   // json, returning, native uuid, transactions, ...

    fn create(&self, q: Create<'_>) -> impl Future<Output = DbResult<Row>> + Send;
    fn find_one(&self, q: Select<'_>) -> impl Future<Output = DbResult<Option<Row>>> + Send;
    fn find_many(&self, q: Select<'_>) -> impl Future<Output = DbResult<Vec<Row>>> + Send;
    fn update(&self, q: Update<'_>) -> impl Future<Output = DbResult<u64>> + Send;
    fn delete(&self, q: Delete<'_>) -> impl Future<Output = DbResult<u64>> + Send;
    fn count(&self, q: Select<'_>) -> impl Future<Output = DbResult<u64>> + Send;
    fn begin(&self) -> impl Future<Output = DbResult<Self::Tx>> + Send;

    // Introspection for the migrator. Adapters without DDL (a KV store) return Unsupported.
    fn introspect(&self) -> impl Future<Output = DbResult<LiveSchema>> + Send;
    fn apply(&self, plan: &MigrationPlan) -> impl Future<Output = DbResult<()>> + Send;

    // Fast path with a default. SQL adapters override it with one JOIN.
    fn session_with_user(&self, token_hash: &Hash) -> impl Future<Output = DbResult<Option<(Row, Row)>>> + Send {
        default_session_with_user(self, token_hash)   // two find_one calls
    }
}

pub trait Transaction: Adapter {
    fn commit(self) -> impl Future<Output = DbResult<()>> + Send;
}
```

`Select` holds a `TableRef` (name and resolved columns), a `Filter` tree, an order, a limit
and an offset. `Row` is positional: `row[col]` indexes by the column's position in that
table, which the schema fixed at build time.

### Conformance tests

`fastauth-core` ships the adapter test suite as a function behind its `testing` feature.
A new adapter is done when this passes:

```rust
// [dev-dependencies] fastauth-core = { version = "0.1", features = ["testing"] }
#[tokio::test]
async fn conformance() {
    fastauth_core::testing::run_adapter_conformance(async || MyAdapter::connect(&test_url()).await).await;
}
```

Each case gets a fresh adapter from the closure, so it must return an empty database. The
suite covers every `Filter` variant, ordering, limit and offset, updates and deletes,
unique violations (which must map to `DbError::UniqueViolation` so sign-up can answer
"email taken"), transaction commit, rollback and drop, `session_with_user`, and the
migrator round trip (create, then an empty plan, then added columns on a table with rows).
`MemoryAdapter` and both `fastauth-sqlx` databases run it. It is a function rather than
the `adapter_tests!` macro first sketched here: a plain `async fn` reports failures with
ordinary backtraces and needs no macro hygiene.

### Adapters we'd expect

- `fastauth-sqlx`: Postgres and SQLite, MySQL later. First party.
- `fastauth-diesel`: diesel-async. Community, same trait.
- `fastauth-seaorm`: for apps already on SeaORM.
- `fastauth-libsql`, `fastauth-d1` (Cloudflare Workers via `worker`): plausible, since
  core has no tokio dependency outside the sqlx and axum crates.

## Secondary storage

`SecondaryStorage` is a key-value trait (`get`, `set` with TTL, `delete`, `incr`) used
for sessions, rate-limit counters and verification values when configured:

```rust
.secondary_storage(Redis::new(fred_pool))
```

With it, sessions are written to both stores and read from Redis first. The database copy
keeps `list-sessions` and revocation working if Redis is flushed.
