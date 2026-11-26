# All plugins

Everything beyond email and password is a plugin: a value you pass to `.plugin(..)` and
list in your `AppAuth` alias. Each first-party plugin is its own crate, and the `fastauth`
facade turns it on with a feature, so most apps depend only on `fastauth`.

## Sign-in methods

Ways to sign in next to email and password, and a second step after it.

| Plugin | What it adds | Crate | Feature |
|---|---|---|---|
| [Social sign-in](../get-started/03-configuration.md#social-providers) | GitHub, Google and your own `OAuthProvider`s, linked accounts | `fastauth-oauth` | `oauth` |
| [Magic links](sign-in/01-magic-link.md) | Sign-in links by email, with sign-up on first use | `fastauth-plugin-magic-link` | `magic-link` |
| [Email OTP](sign-in/02-email-otp.md) | One-time codes by email for sign-in, email verification and password reset | `fastauth-plugin-email-otp` | `email-otp` |
| [Passkeys](sign-in/03-passkey.md) | WebAuthn registration and sign-in, a `passkey` table | `fastauth-plugin-passkey` | `passkey` |
| [Usernames](sign-in/04-username.md) | Usernames next to emails, sign-in by username, availability checks | `fastauth-plugin-username` | `username` |
| [Anonymous users](sign-in/05-anonymous.md) | Guest sign-in, linked to the real account on sign-up or sign-in | `fastauth-plugin-anonymous` | `anonymous` |
| [Two-factor](../get-started/02-quickstart.md#7-add-a-plugin) | TOTP, codes by email, backup codes and trusted devices, as a sign-in gate | `fastauth-plugin-two-factor` | `two-factor` |

## Tokens

Credentials for clients and services that can't use the session cookie.

| Plugin | What it adds | Crate | Feature |
|---|---|---|---|
| [Bearer tokens](tokens/01-bearer.md) | Sessions from `Authorization: Bearer`, and the `set-auth-token` header | `fastauth-plugin-bearer` | `bearer` |
| [JWT](tokens/02-jwt.md) | JWTs for signed-in users, a JWKS with rotating keys, `JwksVerifier` for other services | `fastauth-plugin-jwt` | `jwt` |
| [API keys](tokens/03-api-keys.md) | Hashed API keys with expiry, usage and rate limits, permissions, optional sessions from keys | `fastauth-plugin-api-key` | `api-key` |

## Organizations and access

Who can do what, and how many accounts one browser holds.

| Plugin | What it adds | Crate | Feature |
|---|---|---|---|
| [Organizations](access/01-organization.md) | Organizations, members, invitations, roles and permissions, axum extractors | `fastauth-plugin-organization` | `organization` |
| [Admin](access/02-admin.md) | User management, roles and permissions, bans, impersonation, `RequireRole` | `fastauth-plugin-admin` | `admin` |
| [Multiple sessions](access/03-multi-session.md) | Several signed-in accounts per browser, switching between them | `fastauth-plugin-multi-session` | `multi-session` |

## Using plugins

```rust
use fastauth::plugins::{admin::Admin, api_key::ApiKeys, organization::Organization, two_factor::TwoFactor};

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![TwoFactor, Organization, Admin, ApiKeys]>;

FastAuth::builder()
    // ...
    .plugin(TwoFactor::new().issuer("Acme").backup_codes(10))
    .plugin(Organization::default().allow_user_to_create_organization(true).invitation_ttl(Duration::days(3)))
    .plugin(Admin::new())
    .plugin(ApiKeys::new())
    .build()
```

The alias lists plugins **in registration order**. If the order differs, the compiler
says so (here with `plugins![Admin, TwoFactor]` and `TwoFactor` registered first):

```
error[E0308]: mismatched types
  --> src/auth.rs:8:5
   |
 7 |   pub fn build() -> Result<AppAuth, BuildError> {
   |                     --------------------------- expected `Result<Auth<MemoryAdapter, (), Cons<Admin, Cons<TwoFactor, Nil>>>, _>` because of return type
...
14 | |         .build()
   | |________________^ expected `Admin`, found `TwoFactor`
```

The order matters for two reasons: a plugin's dependencies must come before it, and hooks
and sign-in gates run in registration order. Run your migrations after adding a plugin
that adds tables or columns ([Databases](../concepts/02-database.md#migrations)).

Plugin types live under `fastauth::plugins::<name>`, and social sign-in under
`fastauth::social`. More plugins are [planned](../get-started/01-overview.md#planned), and
[Plugin authoring](../reference/01-plugin-authoring.md) shows how to write your own.
