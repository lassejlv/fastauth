//! `RequireRole<A, R>` for actix-web (feature `actix`): lets a route through only for a role.
//!
//! ```
//! use actix_web::web;
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_admin::actix::RequireRole;
//! use fastauth_plugin_admin::{Admin, role};
//!
//! type AppAuth = Auth<MemoryAdapter, (), plugins![Admin]>;
//!
//! role!(pub Support = "support");
//!
//! async fn dashboard(admin: RequireRole<AppAuth, role::Admin>) -> String {
//!     format!("hello {}", admin.user.email)
//! }
//!
//! async fn tickets(agent: RequireRole<AppAuth, Support>) -> String {
//!     agent.user.name.clone()
//! }
//!
//! fn routes(config: &mut web::ServiceConfig) {
//!     config
//!         .route("/admin", web::get().to(dashboard))
//!         .route("/tickets", web::get().to(tickets));
//! }
//! ```

use std::future::Future;
use std::marker::PhantomData;
use std::ops::Deref;
use std::pin::Pin;

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest};
use fastauth_actix::Session;
use fastauth_core::{AuthError, AuthInstance};

use crate::Role;

/// The signed-in session of a user who holds role `R`. Rejects with `401 UNAUTHORIZED`
/// without a session and `403 FORBIDDEN` without the role, like the axum `RequireRole`.
/// Derefs to the [`Session`].
pub struct RequireRole<A: AuthInstance, R>(Session<A>, PhantomData<fn() -> R>);

impl<A: AuthInstance, R> RequireRole<A, R> {
    /// The session.
    pub fn into_session(self) -> Session<A> {
        self.0
    }
}

impl<A: AuthInstance, R> Clone for RequireRole<A, R> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

impl<A: AuthInstance, R> Deref for RequireRole<A, R> {
    type Target = Session<A>;

    fn deref(&self) -> &Session<A> {
        &self.0
    }
}

impl<A: AuthInstance, R: Role> FromRequest for RequireRole<A, R> {
    type Error = AuthError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, AuthError>>>>;

    fn from_request(request: &HttpRequest, _: &mut Payload) -> Self::Future {
        let request = request.clone();
        Box::pin(async move {
            let session = Session::<A>::extract(&request).await?;
            crate::roles::require::<R, A>(&fastauth_actix::auth::<A>(&request)?, &session)?;
            Ok(Self(session, PhantomData))
        })
    }
}
