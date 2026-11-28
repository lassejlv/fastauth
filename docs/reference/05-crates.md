# Crates

fastauth is published as 21 crates. Most apps add only `fastauth`, which re-exports the
others behind [feature flags](../get-started/01-overview.md#feature-flags). In the repository
each crate lives in `crates/<folder>`: the folders drop the `fastauth-` prefix, and the plugins
sit together under `crates/plugins/`. A version in parentheses is the release that added the crate.

| Crate | Folder | What |
|---|---|---|
| [`fastauth`](https://crates.io/crates/fastauth) | `crates/fastauth` | The crate apps depend on: re-exports everything below behind features |
| [`fastauth-core`](https://crates.io/crates/fastauth-core) | `crates/core` | Builder, compile-checked plugin list, sessions, crypto, routing, email and password, verification, reset |
| [`fastauth-axum`](https://crates.io/crates/fastauth-axum) | `crates/axum` | `auth.router()`, `Session` / `FreshSession` extractors, the session layer |
| [`fastauth-actix`](https://crates.io/crates/fastauth-actix) | `crates/actix` | The same for actix-web: `auth.scope()`, the extractors, the session middleware (0.5) |
| [`fastauth-sqlx`](https://crates.io/crates/fastauth-sqlx) | `crates/sqlx` | Postgres, SQLite and MySQL adapter, migrations, shared transactions (`.in_tx`) |
| [`fastauth-redis`](https://crates.io/crates/fastauth-redis) | `crates/redis` | Secondary storage on Redis or Valkey, so rate limits hold across instances (0.7) |
| [`fastauth-macros`](https://crates.io/crates/fastauth-macros) | `crates/macros` | `#[derive(Fields, Model, AuthError)]` |
| [`fastauth-oauth`](https://crates.io/crates/fastauth-oauth) | `crates/oauth` | The `Social` plugin: GitHub and Google |
| [`fastauth-plugin-two-factor`](https://crates.io/crates/fastauth-plugin-two-factor) | `crates/plugins/two-factor` | TOTP, email codes, backup codes, trusted devices |
| [`fastauth-plugin-organization`](https://crates.io/crates/fastauth-plugin-organization) | `crates/plugins/organization` | Organizations, members, invitations, roles and permissions, axum extractors (0.2) |
| [`fastauth-plugin-admin`](https://crates.io/crates/fastauth-plugin-admin) | `crates/plugins/admin` | User management, roles and permissions, bans, impersonation, `RequireRole` (0.2) |
| [`fastauth-plugin-api-key`](https://crates.io/crates/fastauth-plugin-api-key) | `crates/plugins/api-key` | Hashed API keys with expiry, usage and rate limits, permissions, optional sessions from keys (0.2) |
| [`fastauth-plugin-magic-link`](https://crates.io/crates/fastauth-plugin-magic-link) | `crates/plugins/magic-link` | Sign-in links by email, with sign-up on first use (0.3) |
| [`fastauth-plugin-email-otp`](https://crates.io/crates/fastauth-plugin-email-otp) | `crates/plugins/email-otp` | One-time codes by email for sign-in, email verification and password reset (0.3) |
| [`fastauth-plugin-bearer`](https://crates.io/crates/fastauth-plugin-bearer) | `crates/plugins/bearer` | Sessions from `Authorization: Bearer`, and the `set-auth-token` header (0.3) |
| [`fastauth-plugin-jwt`](https://crates.io/crates/fastauth-plugin-jwt) | `crates/plugins/jwt` | JWTs for signed-in users, a JWKS with rotating keys, `JwksVerifier` for other services (0.3) |
| [`fastauth-plugin-passkey`](https://crates.io/crates/fastauth-plugin-passkey) | `crates/plugins/passkey` | Passkeys (WebAuthn) on webauthn-rs: registration, sign-in, management (0.3) |
| [`fastauth-plugin-username`](https://crates.io/crates/fastauth-plugin-username) | `crates/plugins/username` | Usernames next to emails, sign-in by username, availability checks (0.4) |
| [`fastauth-plugin-anonymous`](https://crates.io/crates/fastauth-plugin-anonymous) | `crates/plugins/anonymous` | Anonymous users, linked to the real account they sign up or in with (0.4) |
| [`fastauth-plugin-multi-session`](https://crates.io/crates/fastauth-plugin-multi-session) | `crates/plugins/multi-session` | Several signed-in accounts per browser, switching between them (0.4) |
| [`fastauth-cli`](https://crates.io/crates/fastauth-cli) | `crates/cli` | `fastauth secret`; schema and migration commands run from your app via `fastauth::cli::run` |
