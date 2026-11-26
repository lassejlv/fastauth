# Overview

fastauth is an authentication library for Rust servers. It takes Better Auth's shape (a
single config object, plugins that own their tables, endpoints and hooks, and a typed
server API) and moves the type safety from TypeScript inference into the Rust compiler.

## Goals

1. **Five minutes to a working login.** Add one dependency, call one builder, merge one
   router. No traits to implement for the common path (Postgres or SQLite with axum).
2. **Plugins checked at compile time.** Reading a plugin's state, calling its API,
   reading the columns it adds to `user`, and declaring that one plugin needs another
   are all checked by `rustc`, with error messages that name the missing plugin.
3. **Swappable databases and HTTP frameworks.** sqlx and axum are the defaults behind
   feature flags. Other databases and frameworks implement a small trait and get every
   plugin without changes.
4. **Fast session checks.** Checking a session is the operation that runs on every
   request. A cookie cache hit does no I/O at all; a cache miss is one indexed query.
5. **Safe defaults.** Hashed session tokens, argon2id, `__Secure-` cookies, origin
   checks and rate limits are on without configuration.

## Non-goals

- **An identity provider.** fastauth logs users into *your* app. Running an OAuth or OIDC
  server for other apps would be a plugin, not core.
- **A frontend SDK.** fastauth is wire-compatible with Better Auth's TypeScript client for
  the core endpoints and the first-party plugins, so existing React, Vue and Svelte clients
  work against a Rust backend ([Better Auth's client](11-better-auth-client.md)).
- **An ORM.** The adapter does the handful of queries auth needs. Your app keeps using
  sqlx (or whatever it uses) directly, and can share a transaction with fastauth.

## Crate layout

```
fastauth                       facade: re-exports, prelude, feature flags. The only crate most apps add.
fastauth-core                  Auth, builder, Plugin/Endpoint/Adapter traits, sessions, crypto, schema, router
fastauth-macros                #[derive(Fields)], #[derive(Model)], #[derive(AuthError)]
fastauth-sqlx                  Adapter for sqlx: Postgres and SQLite; migrations; shared transactions
fastauth-axum                  Router, Session extractors, session layer
fastauth-oauth                 Social plugin: OAuth providers (GitHub, Google), the outgoing HttpClient
fastauth-plugin-two-factor     TOTP, email codes, backup codes, trusted devices
fastauth-plugin-organization   organizations, members, invitations, roles and permissions
fastauth-plugin-admin          roles and permissions, bans, impersonation, user management
fastauth-plugin-api-key        hashed API keys, usage and rate limits, sessions from keys
fastauth-plugin-magic-link     sign-in links by email
fastauth-plugin-email-otp      one-time codes by email: sign-in, email verification, password reset
fastauth-plugin-bearer         sessions from Authorization: Bearer, the set-auth-token header
fastauth-plugin-jwt            JWTs and a JWKS with rotating keys, JwksVerifier for other services
fastauth-plugin-passkey        passkeys (WebAuthn) on webauthn-rs
fastauth-plugin-username       usernames, sign-in by username
fastauth-plugin-anonymous      anonymous users, linked when they sign up or in
fastauth-plugin-multi-session  several signed-in accounts per browser
fastauth-cli                   `fastauth secret`; schema and migrations run from your app's binary (`cli` feature)
```

`fastauth-core` depends on neither sqlx nor axum. It speaks `http` 1.x types and the
`Adapter` trait, which is what keeps every plugin portable.

## Feature flags

```toml
[dependencies]
fastauth = "0.3" # default = ["axum", "postgres", "macros"]

# SQLite instead of Postgres, plus social sign-in and two-factor:
fastauth = { version = "0.3", default-features = false, features = [
    "axum", "sqlite", "macros", "oauth", "two-factor",
] }
```

| Flag | Pulls in |
|---|---|
| `axum` | `fastauth-axum`, as `fastauth::axum`; also the axum extractors of the organization and admin plugins |
| `postgres`, `sqlite` | `fastauth-sqlx` with that sqlx driver, as `fastauth::sqlx`; `Sqlx` and the pool types join the prelude |
| `macros` | `#[derive(Fields, Model, AuthError)]` |
| `oauth` | `fastauth-oauth` (with the reqwest client), as `fastauth::social` |
| `two-factor` | `fastauth-plugin-two-factor`, as `fastauth::plugins::two_factor` |
| `organization` | `fastauth-plugin-organization`, as `fastauth::plugins::organization` |
| `admin` | `fastauth-plugin-admin`, as `fastauth::plugins::admin` |
| `api-key` | `fastauth-plugin-api-key`, as `fastauth::plugins::api_key` |
| `magic-link` | `fastauth-plugin-magic-link`, as `fastauth::plugins::magic_link` |
| `email-otp` | `fastauth-plugin-email-otp`, as `fastauth::plugins::email_otp` |
| `bearer` | `fastauth-plugin-bearer`, as `fastauth::plugins::bearer` |
| `jwt` | `fastauth-plugin-jwt`, as `fastauth::plugins::jwt` |
| `passkey` | `fastauth-plugin-passkey`, as `fastauth::plugins::passkey` |
| `username` | `fastauth-plugin-username`, as `fastauth::plugins::username` |
| `anonymous` | `fastauth-plugin-anonymous`, as `fastauth::plugins::anonymous` |
| `multi-session` | `fastauth-plugin-multi-session`, as `fastauth::plugins::multi_session` |
| `cli` | `fastauth::cli::run` for your app's `fastauth` binary: `schema`, `status`, `generate`, `migrate` |

argon2id is always on; it isn't a feature.

## The docs

| Page | What it covers |
|---|---|
| [Quickstart](02-quickstart.md) | From `cargo new` to sign-up, sign-in and a protected route |
| [Configuration](03-configuration.md) | Every builder option: secrets, email and password, social providers, sessions, cookies, rate limits, ids, user fields, events |
| [Sessions and the server API](04-sessions.md) | Extractors, typed user fields, calling auth from your own code, shared transactions |
| [Plugins](05-plugins.md) | Using plugins, and writing one: schema, endpoints, resolvers, hooks, gates, events, errors, dependencies |
| [Databases](06-database.md) | sqlx, the schema, ids, migrations, typed queries, writing an adapter |
| [HTTP integrations](07-http.md) | axum, tower, the outgoing HTTP client, writing an integration |
| [Internals](08-internals.md) | The type-level plugin list, the build step, the request path, the session hot path |
| [Security](09-security.md) | Tokens, cookies, password hashing, CSRF, OAuth, rate limiting, secret rotation |
| [Decisions](10-open-questions.md) | The design decisions, including the ones made since 0.1 |
| [Better Auth's client](11-better-auth-client.md) | Using `better-auth/client` with fastauth, the tested versions, known gaps |
| [Organization](12-organization.md) | Organizations, members, invitations, roles and permissions, extractors |
| [Admin](13-admin.md) | User management, roles and permissions, bans, impersonation, `RequireRole` |
| [API keys](14-api-keys.md) | Hashed API keys, limits, permissions, sessions from keys |
| [Magic links](15-magic-link.md) | Sign-in links by email, redirects, sign-up on first use |
| [Email OTP](16-email-otp.md) | One-time codes by email for sign-in, email verification and password reset |
| [Bearer tokens](17-bearer.md) | Sessions from `Authorization: Bearer` for clients without cookies |
| [JWT](18-jwt.md) | Tokens and a JWKS for other services, key rotation, verifying tokens elsewhere |
| [Passkeys](19-passkey.md) | WebAuthn registration and sign-in, the `passkey` table, managing passkeys |
| [Usernames](20-username.md) | Usernames on sign-up and update-user, sign-in by username, validation and normalization |
| [Anonymous users](21-anonymous.md) | Guest sign-in, linking to the real account, deleting anonymous users |
| [Multiple sessions](22-multi-session.md) | Several accounts per browser, device-session cookies, switching and revoking |

## The decisions that shape everything else

Each of these is explained in [Internals](08-internals.md); this is the short version.

**Plugins are a type-level list.** `.plugin(TwoFactor::new())` changes the builder's
plugin list type from `Nil` to `Cons<TwoFactor, Nil>`. Everything that needs to know "is
this plugin installed?" asks the compiler through a `Has<P, _>` bound. You name the final
type once, in an alias, using the `plugins![...]` macro.

**Generics stop at the build step.** After `.build()`, endpoints, hooks and routes are
type-erased into a route table. The per-request path is ordinary dynamic dispatch, so
the type-level list costs compile time in one place, not on every handler.

**The database is generic, the rows are not.** `Auth<D, ..>` is generic over the
adapter, so sqlx transactions stay typed and there is no boxing on the query path. Rows
between core and the adapter are a dynamic `Row` of `Value`s, because plugins add
tables and columns the adapter has never heard of. Typed models (`#[derive(Model)]`) sit
on top and give compile-checked column references.

**Endpoints are typed functions first, HTTP routes second.** An endpoint is a type with
`Input`, `Output` and an `async fn call`. The HTTP layer deserializes into `Input` and
calls it; the server API (`auth.api().sign_in_email(..)`) calls it directly with no JSON.

**Ids are opaque strings.** ULIDs by default, with UUID and custom strategies
([Ids](06-database.md#ids)). Plugins create them with `ctx.new_id()?` and never parse them.

## Planned

None of this exists yet. Don't write code against it; it may change shape before it lands.

- **Plugins:** an OIDC provider, CAPTCHA. Each shipped plugin's
  page lists what it doesn't build yet.
- **Organization:** teams, dynamic access control, invitation and membership limits beyond
  `organization_limit`.
- **Social:** Apple, Discord, Microsoft, GitLab and other providers, and a generic OIDC
  provider with `id_token` verification against the provider's JWKS.
- **Integrations and storage:** actix-web, MySQL in `fastauth-sqlx`, Redis secondary
  storage for sessions and rate-limit counters (rate limits are per process today).
- **Tooling:** importing Better Auth scrypt password hashes, re-encrypting columns after a
  secret rotation, an OpenAPI document of the registered endpoints, a `TestAuth` test
  helper, and an `#[endpoint]` attribute that writes an endpoint from a function.
