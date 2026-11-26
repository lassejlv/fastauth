//! Authentication for Rust web apps, modelled on [Better Auth](https://www.better-auth.com).
//!
//! This is the crate apps depend on. It re-exports [`fastauth_core`] and, behind features,
//! everything else:
//!
//! | Feature | Adds |
//! |---|---|
//! | `axum` (default) | [`fastauth::axum`](crate::axum): `auth.router()`, the `Session` extractors, the session layer |
//! | `postgres` (default), `sqlite` | [`fastauth::sqlx`](crate::sqlx): `Sqlx::new(pool)`, and the pool types in the prelude |
//! | `macros` (default) | `#[derive(Fields, Model, AuthError)]` |
//! | `oauth` | [`fastauth::social`](crate::social): the `Social` plugin with GitHub and Google |
//! | `two-factor` | [`fastauth::plugins::two_factor`](mod@crate::plugins): TOTP, email OTP, backup codes |
//! | `organization` | [`fastauth::plugins::organization`](mod@crate::plugins): organizations, members, invitations, roles |
//! | `admin` | [`fastauth::plugins::admin`](mod@crate::plugins): roles, bans, impersonation, user management |
//! | `api-key` | [`fastauth::plugins::api_key`](mod@crate::plugins): per-user API keys |
//! | `bearer` | [`fastauth::plugins::bearer`](mod@crate::plugins): `Authorization: Bearer` sessions and `set-auth-token` |
//! | `jwt` | [`fastauth::plugins::jwt`](mod@crate::plugins): `/token`, `/jwks` and a verifier for resource servers |
//! | `cli` | [`fastauth::cli`](crate::cli): `schema`, `status`, `generate` and `migrate` for your app's binary |
//!
//! `crates/fastauth/examples/axum_sqlite.rs` is a complete app.

pub use fastauth_core::*;

/// Everything an app needs to configure auth.
pub mod prelude {
    #[cfg(feature = "axum")]
    pub use fastauth_axum::{AuthRouter, FreshSession, Session};
    pub use fastauth_core::prelude::*;
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub use fastauth_sqlx::{InTx, SharedTx, Sqlx};
    #[cfg(feature = "postgres")]
    pub use fastauth_sqlx::{PgPool, Postgres};
    #[cfg(feature = "sqlite")]
    pub use fastauth_sqlx::{Sqlite, SqlitePool};
}

/// The axum integration: `AuthRouter`, the `Session` and `FreshSession` extractors, and
/// the session layer.
#[cfg(feature = "axum")]
pub use fastauth_axum as axum;

/// The sqlx adapter for Postgres and SQLite.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub use fastauth_sqlx as sqlx;

/// Social sign-in: `.plugin(Social::new().provider(Github::new(id, secret)))`.
#[cfg(feature = "oauth")]
pub use fastauth_oauth as social;

#[cfg(feature = "cli")]
pub mod cli;

/// First-party plugins.
pub mod plugins {
    /// Two-factor authentication: `.plugin(TwoFactor::new().issuer("Acme"))`.
    #[cfg(feature = "two-factor")]
    pub use fastauth_plugin_two_factor as two_factor;

    /// Organizations, members, invitations, roles: `.plugin(Organization::default())`.
    #[cfg(feature = "organization")]
    pub use fastauth_plugin_organization as organization;

    /// Roles, bans, impersonation and user management: `.plugin(Admin::new())`.
    #[cfg(feature = "admin")]
    pub use fastauth_plugin_admin as admin;

    /// Per-user API keys: `.plugin(ApiKeys::new())`.
    #[cfg(feature = "api-key")]
    pub use fastauth_plugin_api_key as api_key;

    /// Bearer tokens instead of cookies: `.plugin(Bearer::new())`.
    #[cfg(feature = "bearer")]
    pub use fastauth_plugin_bearer as bearer;

    /// JWTs and a JWKS for other services: `.plugin(Jwt::new())`.
    #[cfg(feature = "jwt")]
    pub use fastauth_plugin_jwt as jwt;
}

/// Paths the derive macros expand to. Not public API.
#[doc(hidden)]
pub mod __private {
    pub use fastauth_core as core;
}
