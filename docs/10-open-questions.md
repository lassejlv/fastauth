# Decisions

Decisions that change the API or the data model, why they went the way they did, and
what was released. The first seven were settled before 0.1; [Since 0.1](#since-01) records
the ones made while building 0.2. What's planned next is in
[Overview](01-overview.md#planned).

## 1. Wire compatibility with Better Auth's client

If core endpoints use Better Auth's paths, JSON shapes (camelCase, `{ user, session }`)
and error format, then `better-auth/client` and its React, Vue and Svelte hooks work
against a Rust backend with no frontend work. That's the biggest adoption lever available.

Cost: Better Auth changes its API between minors (1.7 renamed the duplicate sign-up code
and moved the API key plugin to its own package), so we pin a version and run its client
against fastauth. Plugins we don't mirror would need our own TS client.

**Decided:** yes, for core and every first-party plugin that exists in both, pinned to
`better-auth` 1.7.28 and tested by the scripts in `compat/better-auth/`, run by hand for now
([Better Auth's client](11-better-auth-client.md)).

## 2. Adapter as a type parameter

`Auth<D, U, P>` is generic over the adapter. That gives typed transaction sharing
(`.in_tx(&tx)` on a `SharedTx<Postgres>`) and static dispatch, at the price of one more type
parameter in the alias. The alternative is `Arc<dyn Adapter>` with `Auth<U, P>`, and no
typed transaction sharing.

**Decided:** generic. The alias hides it, and shared transactions are a real need (create
the user and the team membership atomically).

## 3. Hashed session tokens

fastauth stores `SHA-256(token)`; Better Auth stores the raw token. Hashing protects against
database leaks, but it means:

- `list-sessions` can't return tokens, so revoking a listed session takes its `id`. Better
  Auth's `revokeSession({ token })` still works with a token the client holds, because
  fastauth hashes it on the way in.
- An app migrating from Better Auth can hash existing tokens in place, so nobody gets signed
  out, but it's a one-way step.

**Decided:** hash, and accept both `{ id }` and `{ token }` on `/revoke-session`. 0.2
applies the same rule to API keys, which are stored as hashes and shown once.

## 4. Alias order must match registration order

`plugins![A, B]` and `.plugin(B).plugin(A)` are different types. The error is clear, but
it's a sharp edge. Two alternatives:

- A `fastauth::auth!` macro that takes the plugin list once and emits both the alias and a
  pre-typed builder. Less repetition, more macro.
- Let the compiler infer the type and skip the alias: `fn auth() -> impl AuthInstance`.
  That doesn't work, because handlers need a nameable type for `Session<A>`.

**Decided:** ship with the alias and the clear error; add `auth!` only if users trip on it.

## 5. One crate per plugin, or features on one crate

Separate crates (`fastauth-plugin-two-factor`) compile in parallel and version
independently. Features on one `fastauth-plugins` crate are simpler to publish. Either way,
the facade re-exports them under `fastauth::plugins::*` behind features, so users don't see
the difference.

**Decided:** separate crates. Heavy dependencies stay isolated, and community plugins look
the same as first-party ones.

## 6. MSRV

The design needs return-position `impl Trait` in traits (1.75), `#[diagnostic::on_unimplemented]`
(1.78), edition 2024 (1.85), `if let` chains (1.88), and sqlx 0.9 needs 1.94.

**Decided:** MSRV 1.94 for the whole workspace, raised only in minor releases. Development
uses the latest stable.

## 7. Name

**Decided:** `fastauth` on crates.io, with `fastauth-*` for the other crates and
`fastauth-plugin-<name>` for plugins ([Overview](01-overview.md#crate-layout)).

## Since 0.1

### 8. ULID ids by default

0.1 generated UUIDv7s and stored them as Postgres `uuid`. 0.2 makes the id strategy a
builder option: `IdStrategy::Ulid` (the default), `UuidV7`, `UuidV4` or `custom(..)`.
ULIDs are as time-ordered as UUIDv7s, shorter, and readable in URLs; custom ids let apps
keep the ids they already have. Storage follows the strategy (`uuid` on Postgres for the
UUID strategies, `text` otherwise), and the migrator warns instead of converting columns.
`ctx.new_id()` became fallible, because a custom generator can return a bad id.

**Decided:** ULID by default, `Id` is an opaque string everywhere, and a Postgres database
from 0.1 keeps working with `.ids(IdStrategy::UuidV7)` ([Ids](06-database.md#ids)).

### 9. Sessions from API keys are opt-in

The API key plugin can turn an `x-api-key` header into a session for the key's owner, so
every `Session<A>` extractor accepts keys. Turning that on silently would let any key act
as its user on every route, and each such request counts against the key's rate limit.

**Decided:** off by default, on with `ApiKeys::new().sessions(true)`, like Better Auth's
`enableSessionForAPIKeys` ([API keys](14-api-keys.md#sessions-from-api-keys)).

### 10. Sign-in gates run after a challenge

In 0.1, a plugin that challenged a sign-in (two-factor) finished it with
`create_session`, which skipped every other gate: a banned user who answered a TOTP
challenge got a session. Inferring "who challenged" from the context doesn't work, because
hooks, gates and event handlers share it.

**Decided:** gates belong to the plugin that registered them, and
`ctx.internal().complete_sign_in(challenger, user, method, remember_me)` runs every gate but
the challenger's before creating the session. `create_session` stays the gate-free
primitive ([Sign-in gates](05-plugins.md#sign-in-gates)).

### 11. Text search is case-sensitive

The admin plugin's user search needed `contains` and `ends_with` filters. A
case-insensitive flag would mean `ILIKE` on Postgres and collation work on SQLite, and
Better Auth's own search is case-sensitive.

**Decided:** `Filter::Contains` and `Filter::EndsWith` join `StartsWith`, all
case-sensitive and literal, in SQL on every adapter. `Filter` is `#[non_exhaustive]`, so
adding a variant isn't a breaking change for adapters again.

### 12. `input` defaults to false

Better Auth's `additionalFields` default to `input: true`, so a forgotten attribute lets a
client set a column through sign-up or update-user.

**Decided:** columns are server-only unless marked `#[field(input)]`; a client that sets
any other column gets `400 INVALID_FIELD` ([User fields](03-configuration.md#user-fields)).

### 13. Plugin config from generic code

Extractors such as `RequireRole` are generic over `AuthInstance` and can't name the
`HasPlugin` index, so they couldn't reach their plugin's config.

**Decided:** `AuthInstance::try_plugin::<P>()` returns it as an `Option`, and
`auth.api().db()` gives typed queries outside a request. Apps with a concrete `Auth` keep
using the compile-checked extension traits.

## Released: 0.1.0 (2026-11-25)

1. `fastauth-core`: builder, plugin list, endpoints with `Access`, hooks, gates, events,
   sessions with a cookie cache, argon2id, cookies, CSRF, rate limits.
2. `fastauth-sqlx` for Postgres and SQLite, with the migrator, the adapter conformance suite,
   and shared transactions (`auth.api().in_tx(&tx)`).
3. `fastauth-axum`.
4. Email and password, email verification, password reset, and GitHub and Google through the
   `Social` plugin (with profile mapping and per-provider `disable_sign_up`).
5. `two-factor`: TOTP, email codes, backup codes, trusted devices.
6. `fastauth-macros` and `fastauth-cli`.
7. Better Auth client compatibility, tested with `compat/better-auth/run.sh`.

## Released: 0.2.0 (2026-11-26)

1. The [organization](12-organization.md), [admin](13-admin.md) and
   [API key](14-api-keys.md) plugins, each tested against Better Auth's client.
2. Configurable ids with ULID as the default (8).
3. Gates after challenges (10), case-sensitive `Contains` and `EndsWith` filters (11), and
   `AuthInstance::try_plugin` (13).

## Released: 0.3.0 (2026-11-26)

1. The [magic link](15-magic-link.md), [email OTP](16-email-otp.md), [bearer](17-bearer.md),
   [JWT](18-jwt.md) and [passkey](19-passkey.md) plugins, each tested against Better Auth's
   client.
2. Additive core APIs for them: `PluginBuilder::on_response`, `Internal::claim_unverified_user`,
   and public `routes::normalize_email` and `routes::user_input_fields`. Nothing breaks for 0.2
   apps.

The [CHANGELOG](../CHANGELOG.md) lists every change, including the breaking ones.
