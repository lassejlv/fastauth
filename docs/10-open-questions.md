# Open questions

Decisions that change the API or the data model, so they should be settled before v0.1.
Each has a recommendation.

## 1. Wire compatibility with Better Auth's client

If core endpoints use Better Auth's paths, JSON shapes (camelCase, `{ user, session }`)
and error format, then `better-auth/client` and its React, Vue and Svelte hooks work
against a Rust backend with no frontend work. That's the biggest adoption lever available,
and the docs already assume it (`/sign-in/email`, `/get-session`, `twoFactorRedirect`).

Cost: Better Auth changes its API between minors, so we'd pin a version and run its client
test suite against fastauth in CI. Plugins we don't mirror would need our own TS client.

**Recommendation:** yes, for core and the first-party plugins that exist in both, pinned to
one Better Auth minor and tested in CI.

## 2. Adapter as a type parameter

`Auth<D, U, P>` is generic over the adapter. That gives `.in_tx(&mut sqlx::Transaction)`
and static dispatch, at the price of one more type parameter in the alias. The alternative
is `Arc<dyn Adapter>` with `Auth<U, P>`, and no typed transaction sharing.

**Recommendation:** keep it generic. The alias hides it, and shared transactions are a real
need (create the user and the team membership atomically).

## 3. Hashed session tokens

fastauth stores `SHA-256(token)`; Better Auth stores the raw token. Hashing protects against
database leaks, but it means:

- `list-sessions` can't return tokens, so revoke takes an `id`. That breaks wire
  compatibility for `revokeSession({ token })` (we could accept both).
- An app migrating from Better Auth can hash existing tokens in place, so nobody gets signed
  out, but it's a one-way step.

**Recommendation:** hash, and accept `{ token }` on `/revoke-session` by hashing it on the way in.

## 4. Alias order must match registration order

`plugins![A, B]` and `.plugin(B).plugin(A)` are different types. The error is clear, but
it's a sharp edge. Two alternatives:

- A `fastauth::auth!` macro that takes the plugin list once and emits both the alias and a
  pre-typed builder. Less repetition, more macro.
- Let the compiler infer the type and skip the alias: `fn auth() -> impl AuthInstance<..>`.
  That doesn't work today, because handlers need a nameable type for `Session<A>`.

**Recommendation:** ship with the alias and the clear error, add `auth!` only if users trip
on it.

## 5. One crate per plugin, or features on one crate

Separate crates (`fastauth-plugins-two-factor`) compile in parallel and version
independently. Features on one `fastauth-plugins` crate are simpler to publish. Either way,
the facade re-exports them under `fastauth::plugins::*` behind features, so users don't see
the difference.

**Recommendation:** separate crates. The heavy dependencies (`webauthn-rs`, `jsonwebtoken`)
stay isolated, and community plugins look the same as first-party ones.

## 6. MSRV

The design needs return-position `impl Trait` in traits (1.75), `#[diagnostic::on_unimplemented]`
(1.78), async closures for hooks (1.85) and edition 2024 (1.85).

**Recommendation:** MSRV 1.85, raised only in minor releases.

## 7. Name

`fastauth` is available as this repo's name; check crates.io before the first publish, and
reserve `fastauth-*` names for the crate layout in [Overview](01-overview.md#crate-layout).

## Suggested v0.1 scope

1. `fastauth-core`: builder, plugin list, endpoints with `Access`, hooks, gates, events,
   sessions with all three tiers, argon2id, cookies, CSRF, rate limits.
2. `fastauth-sqlx` for Postgres and SQLite, with the migrator and the adapter test suite.
3. `fastauth-axum`.
4. Email and password, email verification, password reset, GitHub and Google.
5. One plugin end to end, to prove the plugin API on real code: `two-factor` (it uses user
   fields, a table, endpoints, a sign-in gate and encryption).

Organization, passkey, admin, API keys, actix and Redis follow in 0.2.
