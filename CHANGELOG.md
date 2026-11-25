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
- **Sign-in gates still run after a challenge.** Finishing a challenged sign-in with
  `ctx.internal().create_session(..)` skipped every other gate, so a banned user who answered
  a TOTP challenge got a session. Gates now belong to the plugin that registered them, and
  `ctx.internal().complete_sign_in(challenger, user, method, remember_me)` runs every gate except
  the challenger's before creating the session. `create_session` stays the low-level,
  gate-free primitive.
- `SignInAttempt::method` is a `Cow<'static, str>`, so a completed sign-in keeps its original
  method; `Internal::sign_in` takes `impl Into<Cow<'static, str>>`.
- `AuthInstance` has a required `try_plugin::<P>()`, implemented for `Auth`.
- `fastauth_core::adapter::Filter` is `#[non_exhaustive]`. Adapters need a fallback arm, which
  should answer `DbError::Unsupported`.
- **two-factor**: the verify endpoints finish a pending sign-in through the other plugins'
  gates. A gate that denies answers its error; a gate that challenges answers its JSON, so
  `VerifyOutput` is an enum (`Verified { token, user }` or `Challenge(json)`). A pending
  sign-in started before the upgrade must start again.

### Added

- `Filter::Contains` and `Filter::EndsWith`, with `Col::contains` and `Col::ends_with` on
  `String` columns. Like `StartsWith`, they are case-sensitive and match literally: `%`, `_`
  and `*` are not wildcards. Implemented in `MemoryAdapter` and fastauth-sqlx (Postgres
  `LIKE .. ESCAPE '\'`, SQLite `GLOB` with bracket escapes) and covered by the adapter
  conformance suite.
- `AuthInstance::try_plugin::<P>()`, for code generic over `AuthInstance` (an axum extractor)
  that can't name the `HasPlugin` index.

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
