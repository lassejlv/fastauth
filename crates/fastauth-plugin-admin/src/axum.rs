//! `RequireRole<A, R>`: an axum extractor that lets a route through only for a role.

use std::marker::PhantomData;
use std::ops::Deref;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use fastauth_axum::Session;
use fastauth_core::plugin_prelude::*;

use crate::Role;

/// The signed-in session of a user who holds role `R`. Rejects with `401 UNAUTHORIZED`
/// without a session and `403 FORBIDDEN` without the role. A user holds every role in
/// their comma-separated `user.role` (the default role while it is empty); admins hold every
/// configured admin role, so `RequireRole<A, role::Admin>` also lets `admin_user_ids` in.
///
/// ```ignore
/// async fn dashboard(admin: RequireRole<AppAuth, role::Admin>) -> String {
///     format!("hello {}", admin.user.email)
/// }
/// ```
///
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

impl<A, R, S> FromRequestParts<S> for RequireRole<A, R>
where
    A: AuthInstance + FromRef<S>,
    R: Role,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, AuthError> {
        let session = Session::<A>::from_request_parts(parts, state).await?;
        crate::roles::require::<R, A>(&A::from_ref(state), &session)?;
        Ok(Self(session, PhantomData))
    }
}
