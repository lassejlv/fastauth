//! Authentication for Rust web apps, modelled on [Better Auth](https://www.better-auth.com).
//!
//! This is the crate apps depend on. It re-exports [`fastauth_core`] and, with the default
//! `axum` feature, the axum integration as [`fastauth::axum`](crate::axum).
//!
//! ```rust,ignore
//! use fastauth::axum::Session;
//! use fastauth::prelude::*;
//!
//! pub type AppAuth = Auth<MemoryAdapter>;
//!
//! let auth: AppAuth = FastAuth::builder()
//!     .secret(Secret::from_env("FASTAUTH_SECRET")?)
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .email_password(EmailPassword::default())
//!     .build()?;
//!
//! let app = Router::new()
//!     .route("/me", get(me))
//!     .merge(auth.router())
//!     .with_state(auth);
//! ```
//!
//! `crates/fastauth/examples/axum_memory.rs` is the complete version.

pub use fastauth_core::*;

/// Everything an app needs to configure auth, plus `AuthRouter` (for `auth.router()`) with
/// the `axum` feature.
pub mod prelude {
    #[cfg(feature = "axum")]
    pub use fastauth_axum::AuthRouter;
    pub use fastauth_core::prelude::*;
}

/// The axum integration: `AuthRouter`, the `Session` and `FreshSession` extractors, and
/// the session layer.
#[cfg(feature = "axum")]
pub use fastauth_axum as axum;
