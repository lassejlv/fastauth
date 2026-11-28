//! [axum](https://docs.rs/axum) integration for [fastauth](https://github.com/lassejlv/fastauth).
//!
//! ```rust,ignore
//! use fastauth::axum::{AuthRouter, Session};
//!
//! let app = Router::new()
//!     .route("/me", get(me))
//!     .merge(auth.router())          // every auth route under base_path
//!     .layer(auth.session_layer())   // optional: one lookup per request, refreshed cookies
//!     .with_state(auth);
//! ```

mod extract;
mod layer;
mod service;

use axum::Router;
use axum::extract::{FromRef, Request, State};
use axum::routing::any;
use fastauth_core::AuthInstance;

pub use extract::{FreshSession, Session};
pub use layer::{SessionLayer, SessionService};
pub use service::AuthService;

/// Mounts an auth instance in axum. Implemented for every `AuthInstance`.
pub trait AuthRouter: AuthInstance {
    /// Every auth route under `base_path` (`/api/auth` by default), for a router whose
    /// state holds this instance (`Self: FromRef<S>`). Merge it into your app's router.
    fn router<S>(&self) -> Router<S>
    where
        Self: FromRef<S>,
        S: Clone + Send + Sync + 'static;

    /// The auth routes as a `tower::Service` for any request body, e.g. for
    /// `Router::nest_service` or plain hyper. Requests must arrive with the full path,
    /// `base_path` included; under `nest_service` the original URI is used.
    fn service(&self) -> AuthService<Self>;

    /// A layer that resolves the session lazily, at most once per request, and adds the
    /// refreshed or cleared session cookies to the response.
    fn session_layer(&self) -> SessionLayer<Self>;
}

impl<A: AuthInstance> AuthRouter for A {
    fn router<S>(&self) -> Router<S>
    where
        A: FromRef<S>,
        S: Clone + Send + Sync + 'static,
    {
        let base = self.config().base_path.trim_end_matches('/');
        let handler = any(|State(auth): State<A>, request: Request| service::serve(auth, request));
        Router::new()
            .route(if base.is_empty() { "/" } else { base }, handler.clone())
            .route(&format!("{base}/{{*path}}"), handler)
    }

    fn service(&self) -> AuthService<A> {
        AuthService::new(self.clone())
    }

    fn session_layer(&self) -> SessionLayer<A> {
        SessionLayer::new()
    }
}
