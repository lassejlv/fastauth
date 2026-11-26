//! `RequireRole<A, R>`: an axum extractor that lets a route through only for a role.

use std::marker::PhantomData;
use std::ops::Deref;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use fastauth_axum::Session;
use fastauth_core::plugin_prelude::*;

use crate::{Admin, AdminUser};

/// A role a route can require, named as it is stored in `user.role`. Implement it with
/// [`role!`](crate::role!).
pub trait Role: Send + Sync + 'static {
    /// The role's name: `"admin"`, `"support"`.
    const NAME: &'static str;

    /// Whether a user with this id and `user.role` value holds the role. Default:
    /// [`Admin::has_role`] with [`NAME`](Self::NAME).
    fn held_by(admin: &Admin, user_id: &Id, role: Option<&str>) -> bool {
        admin.has_role(user_id, role, Self::NAME)
    }
}

/// The built-in roles, plus [`role!`](crate::role!) for your own.
pub mod role {
    /// Any admin: a holder of one of the configured admin roles, or a user in
    /// `admin_user_ids`.
    #[derive(Clone, Copy, Debug)]
    pub struct Admin;

    /// Holders of the `user` role, which every user gets by default.
    #[derive(Clone, Copy, Debug)]
    pub struct User;

    impl super::Role for Admin {
        const NAME: &'static str = "admin";

        /// [`Admin::is_admin`](crate::Admin::is_admin), the check the admin endpoints use
        /// too: whatever the configured admin roles are called.
        fn held_by(admin: &crate::Admin, user_id: &super::Id, role: Option<&str>) -> bool {
            admin.is_admin(user_id, role)
        }
    }

    impl super::Role for User {
        const NAME: &'static str = "user";
    }

    /// Declares a role marker for [`RequireRole`](crate::RequireRole):
    ///
    /// ```
    /// fastauth_plugin_admin::role!(pub Support = "support");
    /// ```
    #[macro_export]
    macro_rules! role {
        ($(#[$meta:meta])* $vis:vis $name:ident = $role:literal) => {
            $(#[$meta])*
            #[derive(Clone, Copy, Debug)]
            $vis struct $name;

            impl $crate::Role for $name {
                const NAME: &'static str = $role;
            }
        };
    }

    pub use role;
}

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
        let user = &session.view().user;
        let role = user
            .fields::<AdminUser>()
            .map_err(AuthError::internal)?
            .role;
        let auth = A::from_ref(state);
        let plugin = auth
            .try_plugin::<Admin>()
            .ok_or_else(|| AuthError::internal("RequireRole needs the admin plugin registered"))?;
        if !R::held_by(plugin, &user.id, role.as_deref()) {
            return Err(AuthError::forbidden());
        }
        Ok(Self(session, PhantomData))
    }
}
