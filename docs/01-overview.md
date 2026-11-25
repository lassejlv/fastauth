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
   checks, rate limits and secret rotation are on without configuration.

## Non-goals

- **An identity provider.** fastauth logs users into *your* app. Running an OAuth or OIDC
  server for other apps is a plugin (`oidc-provider`), not core.
- **A frontend SDK.** The goal is wire compatibility with Better Auth's TypeScript client
  for the core endpoints, so existing React, Vue and Svelte clients work against a Rust
  backend. See [Open questions](10-open-questions.md#1-wire-compatibility-with-better-auths-client).
- **An ORM.** The adapter does the handful of queries auth needs. Your app keeps using
  sqlx (or whatever it uses) directly, and can share a transaction with fastauth.

## Crate layout

```
fastauth              facade: re-exports, prelude, feature flags. The only crate most apps add.
fastauth-core         Auth, builder, Plugin/Endpoint/Adapter traits, sessions, crypto, schema, router
fastauth-macros       #[derive(Fields)], #[derive(Model)], #[derive(AuthError)], #[endpoint]
fastauth-sqlx         Adapter for sqlx: Postgres, SQLite, MySQL; migrations
fastauth-axum         Router, Session extractor, tower layer
fastauth-actix        actix-web scope and extractor
fastauth-redis        SecondaryStorage on fred, for sessions and rate limits
fastauth-plugin-*     first-party plugins, one crate each (two-factor, organization, passkey, ...)
fastauth-cli          `fastauth secret`, plus the helpers behind your project's migrate binary
```

`fastauth-core` depends on neither sqlx nor axum. It speaks `http` 1.x types and the
`Adapter` trait, which is what keeps every plugin portable.

## Feature flags

```toml
[dependencies]
fastauth = "0.1" # default = ["axum", "postgres", "argon2", "reqwest"]

# SQLite instead of Postgres, plus two plugins:
fastauth = { version = "0.1", default-features = false, features = [
    "axum", "sqlite", "argon2", "reqwest",
    "two-factor", "organization",
] }
```

| Flag | Pulls in |
|---|---|
| `axum` | `fastauth-axum` |
| `actix` | `fastauth-actix` |
| `postgres`, `sqlite`, `mysql` | `fastauth-sqlx` with that sqlx driver |
| `redis` | `fastauth-redis` |
| `argon2` | argon2id password hashing (the default hasher) |
| `scrypt` | scrypt verification, for importing Better Auth password hashes |
| `reqwest` | the default outgoing HTTP client for OAuth |
| `lettre` | SMTP mailer |
| `two-factor`, `organization`, `passkey`, `magic-link`, `api-key`, `admin`, `username`, `jwt` | the matching `fastauth-plugin-*` crate, re-exported under `fastauth::plugins` |
| `openapi` | an OpenAPI 3.1 document for every registered endpoint |

## The decisions that shape everything else

Each of these is explained in [Internals](08-internals.md); this is the short version.

**Plugins are a type-level list.** `.plugin(TwoFactor::new())` changes the builder's
type from `Builder<.., Nil>` to `Builder<.., Cons<TwoFactor, Nil>>`. Everything that
needs to know "is this plugin installed?" asks the compiler through a `Has<P, _>` bound.
You name the final type once, in an alias, using the `plugins![...]` macro.

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
