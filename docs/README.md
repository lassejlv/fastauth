# fastauth docs

These pages are also the [docs site](https://fastauth.lassejlv.dev/docs/overview/), in the same
order. One folder per group.

### Get started

| Page | What it covers |
|---|---|
| [Overview](get-started/01-overview.md) | Goals, non-goals, crate layout, feature flags, the main design decisions, what's planned |
| [Quickstart](get-started/02-quickstart.md) | From `cargo new` to sign-up, sign-in and a protected route |
| [Configuration](get-started/03-configuration.md) | Every builder option: secrets, email and password, social providers, sessions, cookies, rate limits, ids, user fields, events |

### Core concepts

| Page | What it covers |
|---|---|
| [Sessions and the server API](concepts/01-sessions.md) | Extractors, typed user fields, calling auth from your own code, shared transactions |
| [Databases](concepts/02-database.md) | sqlx, the schema, ids, migrations, typed queries, writing an adapter |
| [Security](concepts/03-security.md) | Tokens, cookies, password hashing, CSRF, OAuth, rate limiting, secret rotation |
| [Running several instances](concepts/04-multiple-instances.md) | What instances share, secondary storage on Redis or Valkey, the cookie cache across instances |

### Integrations

| Page | What it covers |
|---|---|
| [HTTP and axum](integrations/01-http.md) | axum, `tower`, the outgoing HTTP client, writing an integration |
| [actix-web](integrations/03-actix.md) | The auth scope, extractors and session middleware for actix-web 4 |
| [Better Auth client](integrations/02-better-auth-client.md) | Using `better-auth/client` with fastauth, the tested versions, known gaps |

### Plugins

| Page | What it covers |
|---|---|
| [All plugins](plugins/README.md) | Every first-party plugin with its crate and feature, and how to register plugins |
| [Magic links](plugins/sign-in/01-magic-link.md) | Sign-in links by email, redirects, sign-up on first use |
| [Email OTP](plugins/sign-in/02-email-otp.md) | One-time codes by email for sign-in, email verification and password reset |
| [Passkeys](plugins/sign-in/03-passkey.md) | WebAuthn registration and sign-in, the `passkey` table, managing passkeys |
| [Usernames](plugins/sign-in/04-username.md) | Usernames on sign-up and update-user, sign-in by username, validation and normalization |
| [Anonymous users](plugins/sign-in/05-anonymous.md) | Guest sign-in, linking to the real account, deleting anonymous users |
| [Bearer tokens](plugins/tokens/01-bearer.md) | Sessions from `Authorization: Bearer` for clients without cookies |
| [JWT](plugins/tokens/02-jwt.md) | Tokens and a JWKS for other services, key rotation, verifying tokens elsewhere |
| [API keys](plugins/tokens/03-api-keys.md) | Hashed API keys, limits, permissions, sessions from keys |
| [Organizations](plugins/access/01-organization.md) | Organizations, members, invitations, roles and permissions, extractors |
| [Admin](plugins/access/02-admin.md) | User management, roles and permissions, bans, impersonation, `RequireRole` |
| [Multiple sessions](plugins/access/03-multi-session.md) | Several accounts per browser, device-session cookies, switching and revoking |

### Reference

| Page | What it covers |
|---|---|
| [Plugin authoring](reference/01-plugin-authoring.md) | Writing a plugin: schema, endpoints, resolvers, hooks, gates, events, errors, dependencies, tests |
| [Internals](reference/02-internals.md) | How it works: the type-level plugin list, the build step, the request path, the session hot path |
| [Decisions](reference/03-decisions.md) | The design decisions, including the ones made since 0.1 |
| [Production checklist](reference/04-production-checklist.md) | What to set before real users: client IP, https, the secret, mail, cookie cache, rate limits and several instances, database TLS, logs |
| [Crates](reference/05-crates.md) | Every published crate, its folder in the repository and what it holds |
