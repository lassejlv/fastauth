# Migrating from Better Auth

fastauth can share one database with a Better Auth app, so a backend moves over in phases:
both apps run against the same tables, each resolves the sessions the other creates, and the
Better Auth app is switched off once nothing depends on it. Everything here is opt-in. An
app that sets none of it keeps fastauth's own schema and defaults.

This page covers the database: column names, session storage, account rows the other app
owns, migrations and verification rows. It is tested against the schema Better Auth 1.7.8's
own CLI creates for Postgres, MySQL and SQLite (`crates/fastauth-sqlx/tests/better-auth/`).

## Setup

```rust
use fastauth::config::SessionTokens;
use fastauth::migrate::Migrations;
use fastauth::prelude::*;
use fastauth::schema::ColumnNaming;
use serde::{Deserialize, Serialize};

/// The app's own Better Auth field, `customerId`.
#[derive(Fields, Serialize, Deserialize, Clone, Debug)]
pub struct Customer {
    pub customer_id: Option<String>,
}

pub fn build(pool: PgPool) -> anyhow::Result<Auth<Sqlx<Postgres>, Customer>> {
    Ok(FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        // fastauth's verification rows get a table of their own; see below.
        .database(Sqlx::new(pool).rename("verification", "fastauth_verification"))
        .user_fields::<Customer>()
        .column_naming(ColumnNaming::CamelCase)
        .rename_column("account", "password_hash", "password")
        .bytes_as_hex_text("account", "access_token")
        .bytes_as_hex_text("account", "refresh_token")
        .session_tokens(SessionTokens::Raw)
        .only_owned_accounts(true)
        .migrations(Migrations::ReviewOnly)
        .email_password(EmailPassword::default())
        .build()?)
}
```

| Setting | What it does |
|---|---|
| `.column_naming(ColumnNaming::CamelCase)` | Stores every column, core's, the plugins' and the app's, under its camelCase name: `email_verified` as `"emailVerified"`, `customer_id` as `"customerId"`. Code keeps the declared names (`User::EMAIL_VERIFIED`, the `Fields` field names); only the SQL changes. |
| `.rename_column(table, column, to)` | Stores one column under another name, over the strategy. Better Auth keeps the password hash in `account.password`. Use it for any custom field whose name doesn't follow the strategy. |
| `.bytes_as_hex_text(table, column)` | Stores a byte column as lowercase hex in a text column. Better Auth's `accessToken` and `refreshToken` are text; fastauth keeps writing its encrypted bytes there. |
| `.session_tokens(SessionTokens::Raw)` | Stores the session token itself in `session.token` and looks it up there, as Better Auth does, instead of its SHA-256 in `token_hash`. |
| `.only_owned_accounts(true)` | Leaves `account` rows of providers fastauth doesn't own alone (below). |
| `.migrations(Migrations::ReviewOnly)` | `fastauth migrate` and `auth.migrator().run()` refuse; `fastauth generate` writes the SQL for you to review. |
| `Sqlx::rename("verification", ..)` | Keeps fastauth's verification rows out of Better Auth's table. |

Better Auth's cookie format and its password hashes are configured on their own; this page
doesn't cover them.

## The schema

Better Auth's migrations own the tables during the cutover, so fastauth never changes them
itself. Run `fastauth generate` against the shared database: with
`Migrations::ReviewOnly` it writes one file per change, each for you to review and apply
with your own migrations, in order. On a database Better Auth 1.7.8 created, there are four:

1. `add_user_securityStamp`: `ALTER TABLE "user" ADD COLUMN "securityStamp" bigint NOT NULL DEFAULT 0`.
   fastauth changes the stamp whenever proof of the email claims a user, so a sign-in or link
   that started before the claim can't finish after it
   ([Claiming an email](../concepts/03-security.md#claiming-an-email)). Better Auth doesn't
   know the column and inserts users with the default.
2. `index_account_accountId`: an index on `account."accountId"`.
3. `unique_account_providerId_accountId`: `CREATE UNIQUE INDEX
   "account_providerId_accountId_key" ON "account" ("providerId", "accountId")`, so one
   provider account can't be linked to two users. The file starts with a comment holding a
   query that lists the rows the index would refuse; run it first, it must return no rows.
4. `create_verification`: `CREATE TABLE "fastauth_verification"` with its identifier index.

Afterwards `fastauth status` reports nothing pending and no warnings. fastauth recognises
Better Auth's own indexes (`session_userId_idx`, `account_userId_idx`) and its unique
constraints, so it plans nothing for them. Tables of Better Auth plugins that fastauth doesn't
have stay untouched.

## What the compatibility settings give up

Each of these relaxes a default for the length of the migration window. Turn them off once
the Better Auth app is gone.

- **Raw session tokens.** By default the `session` table holds only SHA-256 hashes, so a
  leaked backup or a SQL injection elsewhere in the app yields no usable session. With
  `SessionTokens::Raw` it holds the tokens themselves, as Better Auth's does: whoever can
  read the table can use every live session in it. The lookup is also an index lookup on the
  token itself rather than on a hash. A cookie still has to carry a valid signature before
  fastauth queries anything. Everything else that guards sessions stays as it is: the
  security stamp and the claim locks, sensitive and authoritative sessions, session gates,
  `rememberMe: false` and fixed expiries. A hashed mode that keeps sharing the table with
  Better Auth isn't built yet; switching back to `SessionTokens::Hashed` later needs a
  `token_hash` column and signs everyone out.
- **OAuth tokens as hex text.** fastauth's tokens stay encrypted; only their encoding changes.
  Tokens Better Auth stored for a provider both apps configure are plain text, which
  fastauth reads as their bytes and can't decrypt, so they are replaced the next time the
  user signs in with that provider through fastauth.
- **Review-only migrations.** Nothing changes the schema behind Better Auth's back, so every
  later fastauth upgrade that adds a column also goes through `fastauth generate` and review.

## Accounts another app owns

With `only_owned_accounts(true)`, fastauth owns the `credential` rows and the rows of each
social provider a plugin registers (`Social`'s providers). Rows of any other provider, such
as the `oidc` rows an SSO integration writes, are never read as a way to sign in, listed by
`/list-accounts`, unlinked, changed or deleted:

- a claim (a magic link, an email code, a verification link without the password, a verified
  social profile) deletes the user's sessions, tokens and owned accounts and leaves the
  foreign rows, which belong to identities the other app vouches for;
- `/unlink-account` answers `ACCOUNT_NOT_FOUND` for them, and they don't count as the user's
  last account;
- deleting a user (the admin plugin's `/admin/remove-user`, an anonymous user's cleanup)
  answers `409 USER_HAS_FOREIGN_ACCOUNTS` instead, since the foreign key would delete the
  rows with the user. Remove them in the app that owns them first.

Plugins that write their own provider ids declare them with
`PluginBuilder::account_provider`.

## Verification rows

fastauth stores the hash of each emailed token and data Better Auth's `verification` table
has no column for, so it keeps its rows in a table of its own (`fastauth_verification`
above) and never reads Better Auth's. A link Better Auth mailed before the cutover (a
password reset, a magic link, an email code, minutes to an hour old) doesn't work once
fastauth serves that route; the user asks for a new one.

fastauth deletes expired rows before it stores a new one. To keep the table small when few
new ones arrive, prune it yourself with `auth.prune_verifications()`, or start
`auth.prune_verifications_every(interval)` once at startup; the task stops when the
`Auth` is dropped.
