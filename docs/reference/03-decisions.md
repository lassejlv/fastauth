# Decisions

Decisions that change the API or the data model, why they went the way they did, and
what was released. The first seven were settled before 0.1; [Since 0.1](#since-01) records
the ones made while building 0.2. What's planned next is in
[Overview](../get-started/01-overview.md#planned).

## 1. Wire compatibility with Better Auth's client

If core endpoints use Better Auth's paths, JSON shapes (camelCase, `{ user, session }`)
and error format, then `better-auth/client` and its React, Vue and Svelte hooks work
against a Rust backend with no frontend work. That's the biggest adoption lever available.

Cost: Better Auth changes its API between minors (1.7 renamed the duplicate sign-up code
and moved the API key plugin to its own package), so we pin a version and run its client
against fastauth. Plugins we don't mirror would need our own TS client.

**Decided:** yes, for core and every first-party plugin that exists in both, pinned to
`better-auth` 1.7.28 and tested by the scripts in `compat/better-auth/`, run by hand for now
([Better Auth's client](../integrations/02-better-auth-client.md)).

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

An app that shares one database with a running Better Auth app during a cutover can't hash in
place, since Better Auth looks tokens up as they are. For that window only,
`.session_tokens(SessionTokens::Raw)` stores and looks up raw tokens in `session.token`;
hashing stays the default ([Migrating from Better
Auth](../integrations/04-migrating-from-better-auth.md)).

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
`fastauth-plugin-<name>` for plugins ([Overview](../get-started/01-overview.md#crate-layout)).

## Since 0.1

### 8. ULID ids by default

0.1 generated UUIDv7s and stored them as Postgres `uuid`. 0.2 makes the id strategy a
builder option: `IdStrategy::Ulid` (the default), `UuidV7`, `UuidV4` or `custom(..)`.
ULIDs are as time-ordered as UUIDv7s, shorter, and readable in URLs; custom ids let apps
keep the ids they already have. Storage follows the strategy (`uuid` on Postgres for the
UUID strategies, `text` otherwise), and the migrator warns instead of converting columns.
`ctx.new_id()` became fallible, because a custom generator can return a bad id.

**Decided:** ULID by default, `Id` is an opaque string everywhere, and a Postgres database
from 0.1 keeps working with `.ids(IdStrategy::UuidV7)` ([Ids](../concepts/02-database.md#ids)).

### 9. Sessions from API keys are opt-in

The API key plugin can turn an `x-api-key` header into a session for the key's owner, so
every `Session<A>` extractor accepts keys. Turning that on silently would let any key act
as its user on every route, and each such request counts against the key's rate limit.

**Decided:** off by default, on with `ApiKeys::new().sessions(true)`, like Better Auth's
`enableSessionForAPIKeys` ([API keys](../plugins/tokens/03-api-keys.md#sessions-from-api-keys)).

### 10. Sign-in gates run after a challenge

In 0.1, a plugin that challenged a sign-in (two-factor) finished it with
`create_session`, which skipped every other gate: a banned user who answered a TOTP
challenge got a session. Inferring "who challenged" from the context doesn't work, because
hooks, gates and event handlers share it.

**Decided:** gates belong to the plugin that registered them, and
`ctx.internal().complete_sign_in(challenger, user, method, remember_me)` runs every gate but
the challenger's before creating the session. `create_session` stays the gate-free
primitive ([Sign-in gates](01-plugin-authoring.md#sign-in-gates)).

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
any other column gets `400 INVALID_FIELD` ([User fields](../get-started/03-configuration.md#user-fields)).

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

1. The [organization](../plugins/access/01-organization.md), [admin](../plugins/access/02-admin.md) and
   [API key](../plugins/tokens/03-api-keys.md) plugins, each tested against Better Auth's client.
2. Configurable ids with ULID as the default (8).
3. Gates after challenges (10), case-sensitive `Contains` and `EndsWith` filters (11), and
   `AuthInstance::try_plugin` (13).

## Released: 0.3.0 (2026-11-26)

1. The [magic link](../plugins/sign-in/01-magic-link.md), [email OTP](../plugins/sign-in/02-email-otp.md), [bearer](../plugins/tokens/01-bearer.md),
   [JWT](../plugins/tokens/02-jwt.md) and [passkey](../plugins/sign-in/03-passkey.md) plugins, each tested against Better Auth's
   client.
2. Additive core APIs for them: `PluginBuilder::on_response`, `Internal::claim_unverified_user`,
   and public `routes::normalize_email` and `routes::user_input_fields`. Nothing breaks for 0.2
   apps.

## Released: 0.4.0 (2026-11-26)

1. The [username](../plugins/sign-in/04-username.md), [anonymous](../plugins/sign-in/05-anonymous.md) and
   [multi-session](../plugins/access/03-multi-session.md) plugins, each tested against Better Auth's client.
2. Fixes for the 28 findings of the security review of 0.3.0, including both highs: the open
   redirect that allowed password-reset account takeover, and banned users keeping access
   through API keys. All versions before 0.4.0 are affected.
3. Session gates (`PluginBuilder::session_gate`) and `Ctx::sensitive_session()`, so sessions
   that didn't come from a sign-in (API keys, impersonation) can't mint credentials.
4. Safer defaults: a password reset revokes the user's sessions, and invitations need a
   verified email. `ClientIp::TrustedProxies` reads the client IP from `x-forwarded-for`.
5. Breaking for exhaustive matches only: `ClientIp` and `AdminError` gained variants. No
   public trait changed.

## Released: 0.5.0 (2026-11-26)

1. MySQL 8 in `fastauth-sqlx` (feature `mysql`, and `mysql-tls` on the facade), with every
   core and plugin table ([Databases](../concepts/02-database.md#mysql)).
2. [actix-web](../integrations/03-actix.md) through the new `fastauth-actix` crate, at parity
   with axum, the organization and admin extractors included.
3. MIT only. 0.4.0 and earlier stay MIT OR Apache-2.0.
4. A fix for 0.4 and earlier: claiming an unverified user now also deletes its passkeys and
   API keys, through core's new `UserClaimed` event.
5. Passkey-first sign-up (`Passkey::sign_up`) and changing the email with an email OTP code.
6. Breaking for exhaustive matches only: `EmailOtpError` gained variants. No public trait
   changed, and no table or column was added.

## Released: 0.6.0 (2026-11-27)

1. Fixes for the 41 findings of the second security review, of 0.5.0, and for two from
   fuzzing. Among them are the four highs, ways to take over an account by signing up with
   its email first (ATO-1 to ATO-4), and admin rights that outlived a revoked session under
   the cookie cache (SESS-1). All versions before 0.6.0 are affected.
2. One claim model: every proof of an email makes the prover the only owner of its user, in
   one transaction (`Internal::claim_user`, `PluginBuilder::on_claim`), and the new
   `user.security_stamp` column stops sign-ins that started before a claim
   ([Claiming an email](../concepts/03-security.md#claiming-an-email)).
3. Admin, organization and revoke decisions read the session from the database even when
   the cookie cache answered (`Ctx::authoritative_session`).
4. Unique constraints on `account`, `member` and `two_factor`. The migrator adds missing
   unique constraints to existing tables and refuses, naming the rows, when duplicates exist
   ([Unique constraints on an existing database](../concepts/02-database.md#unique-constraints-on-an-existing-database)).
5. Safer defaults: `.build()` refuses an `http://` `base_url` and a guessable secret on a
   production host (`allow_insecure_config` for development), a retired secret no longer
   verifies self-contained cookies, rate limits cover IPv6 /64s and each account, and request
   text with a NUL byte answers `400`. The [Production checklist](04-production-checklist.md)
   lists what to set.
6. Breaking for exhaustive matches and struct literals: `migrate::Step` and
   `OrganizationError` gained variants, `LiveSchema` a public field and `SessionView` a
   private one. No public trait changed.

## Released: 0.7.0 (2026-11-27)

1. Several instances: `.secondary_storage(..)` (core's `SecondaryStorage` trait) keeps rate
   limit counters in a store every instance shares, and the new `fastauth-redis` crate
   implements it for Redis and Valkey. Sessions, tokens and code attempts already lived in
   the database, so the rate limiter was the only state to move
   ([Running several instances](../concepts/04-multiple-instances.md)).
2. A fix for 0.6 and earlier (F61-1): a session-authorised write of a credential or identity
   (a password, passkey, API key, two-factor, linked account, email or profile change) runs
   under `Internal::lock_user_unless_claimed`, so a request the first registrant had in
   flight can't land on the account after the owner claims the address.
3. Breaking for plugins only: `Internal::set_password` takes the `&UserView` the request
   authorised instead of an id. No shim: an id-only version would bring the race back. No
   table or column was added.

## Released: 0.8.0 (2026-11-27)

1. Better Auth database compatibility, opt-in: a fastauth app shares one database and its
   sign-ins with a live Better Auth app during a migration
   ([Migrating from Better Auth](../integrations/04-migrating-from-better-auth.md)).
   `BetterAuthCompat` sets every piece, and each is also a setting of its own.
2. Cookies follow better-call's format and are checked against the one Better Auth secret
   only, as Better Auth 1.7.8 does; fastauth refuses its own cookie cache and never touches
   Better Auth's `session_data`. Sessions are extended by Better Auth's rule, counted from
   `expires_at` because Better Auth moves `updatedAt` on every update.
3. Passwords use Better Auth's scrypt format and are never rehashed, so a rollback to the
   Better Auth app loses nobody. Hashing runs in a bounded pool, since each hash takes 32 MiB.
4. On the database side: Better Auth's column names, raw session tokens in
   `session.token`, accounts of providers fastauth doesn't own left alone (deleting their
   user answers 409), review-only migrations, and fastauth's verification rows in a table
   of their own.
5. Provider tokens stay encrypted in compat mode. Storing them as plain text, as Better
   Auth does, so its `/get-access-token` works after a sign-in through fastauth, is a
   separate setting (`store_oauth_tokens_in_plaintext`) the preset never turns on, because
   it puts provider credentials in the clear.
6. No breaking change: an app that doesn't opt in behaves as on 0.7, and no table or column
   was added.

The [CHANGELOG](../../CHANGELOG.md) lists every change, including the breaking ones.
