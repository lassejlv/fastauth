# Changelog

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
