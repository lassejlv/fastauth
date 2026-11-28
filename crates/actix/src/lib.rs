//! [actix-web](https://docs.rs/actix-web) integration for [fastauth](https://github.com/lassejlv/fastauth).
//!
//! ```rust,ignore
//! use actix_web::{App, HttpServer, web};
//! use fastauth::actix::{AuthScope, Session};
//!
//! HttpServer::new(move || {
//!     App::new()
//!         .app_data(web::Data::new(auth.clone())) // the extractors find the instance here
//!         .wrap(auth.session_middleware())         // optional: one lookup per request, refreshed cookies
//!         .service(auth.scope())                   // every auth route under base_path
//!         .route("/me", web::get().to(me))
//! })
//! ```

mod convert;
mod extract;
mod middleware;
mod scope;

use actix_web::{HttpRequest, Scope, web};
use fastauth_core::{AuthError, AuthInstance};

pub use extract::{FreshSession, OptionalSession, Session};
pub use middleware::{SessionMiddleware, SessionMiddlewareService};

/// Mounts an auth instance in actix-web. Implemented for every `AuthInstance`.
pub trait AuthScope: AuthInstance {
    /// Every auth route under `base_path` (`/api/auth` by default), as a scope to register
    /// with `App::service` at the app's root: the routes match on the full request path.
    fn scope(&self) -> Scope;

    /// A middleware that resolves the session lazily, at most once per request, and adds the
    /// refreshed or cleared session cookies to the response.
    fn session_middleware(&self) -> SessionMiddleware<Self>;
}

impl<A: AuthInstance> AuthScope for A {
    fn scope(&self) -> Scope {
        let auth = self.clone();
        let base = self.config().base_path.trim_end_matches('/');
        web::scope(base).default_service(web::to(
            move |request: HttpRequest, payload: web::Payload| {
                scope::serve(auth.clone(), request, payload)
            },
        ))
    }

    fn session_middleware(&self) -> SessionMiddleware<A> {
        SessionMiddleware::new()
    }
}

/// The request's headers as the `http` 1 `HeaderMap` the server API takes:
/// `auth.api().headers(&fastauth_actix::headers(&request)).sign_out()`. actix-web 4 is built on
/// `http` 0.2, so its own `HeaderMap` is a different type.
pub fn headers(request: &HttpRequest) -> http::HeaderMap {
    convert::headers(request.headers())
}

/// The auth instance registered with `App::app_data`, as `web::Data<A>` or as `A` itself.
/// The extractors find it this way; so can your own extractors.
pub fn auth<A: AuthInstance>(request: &HttpRequest) -> Result<A, AuthError> {
    request
        .app_data::<web::Data<A>>()
        .map(|data| data.get_ref().clone())
        .or_else(|| request.app_data::<A>().cloned())
        .ok_or_else(|| {
            AuthError::internal(
                "no auth instance in app data: register it with `App::app_data(web::Data::new(auth))`",
            )
        })
}
