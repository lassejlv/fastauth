# Changelog

## Unreleased

### Breaking

- **Ids are ULIDs by default.** `FastAuth::builder().ids(..)` picks the strategy:
  `IdStrategy::Ulid` (default), `UuidV7`, `UuidV4`, or `IdStrategy::custom(|| ..)`. Custom ids
  are checked when generated (non-empty, at most 255 bytes); a bad one fails the request with
  a 500 and a log line.
- **Postgres id columns are `text` for new installs** under the default and custom strategies,
  and `uuid` under the UUID strategies. A database created with 0.1 has `uuid` columns: keep
  it working with `.ids(IdStrategy::UuidV7)`. The migrator never changes column types; it warns
  when the live id columns don't match the configured strategy. SQLite stores ids as `text`
  either way.
- `ctx.new_id()` returns `Result<Id, AuthError>`: use `ctx.new_id()?`.
- `fastauth_core::testing::conformance_schema` takes the `IdStrategy` to store ids with, and
  `run_adapter_conformance` runs every case with text ids and with UUID ids.

## 0.1.0 (2026-11-25)

First release.

- **fastauth-core**: `FastAuth::builder()`, the compile-checked plugin list (`plugins![..]`,
  `Has`, `Requires`), the plugin API (endpoints with `Access`, typed hooks, sign-in gates,
  session resolvers, events), sessions with hashed tokens, sliding expiry and an optional cookie
  cache, HKDF-derived keys with rotation, argon2id, CSRF origin checks, GCRA rate limiting, and
  the Better Auth-compatible core endpoints: email and password, sessions, email verification,
  password reset, user updates.
- **fastauth-axum**: `auth.router()`, `auth.service()`, `auth.session_layer()`, and the
  `Session`, `Option<Session>` and `FreshSession` extractors.
- **fastauth-sqlx**: Postgres and SQLite adapter, additive migrations, generated SQL, and
  shared transactions with per-call savepoints (`auth.api().in_tx(&tx)`).
- **fastauth-macros**: `#[derive(Fields)]`, `#[derive(Model)]`, `#[derive(AuthError)]`.
- **fastauth-oauth**: the `Social` plugin with GitHub and Google, PKCE, state bound to the
  browser, account linking by verified email, profile mapping, per-provider `disable_sign_up`.
- **fastauth-plugin-two-factor**: TOTP, email codes, backup codes, trusted devices.
- **fastauth-cli**: `fastauth secret`, plus `fastauth::cli::run` for schema, status, generate
  and migrate from your own binary.
- Tested against Better Auth's TypeScript client 1.7.28.
