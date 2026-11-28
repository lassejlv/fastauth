//! Role markers for the `RequireRole` extractors (features `axum` and `actix`).

use fastauth_core::plugin_prelude::*;
use fastauth_core::prelude::SessionData;

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

    /// Declares a role marker for the `RequireRole` extractors:
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

/// `Ok` when the session's user holds role `R`, else `403 FORBIDDEN`. Both integrations'
/// `RequireRole` end here.
pub(crate) fn require<R: Role, A: AuthInstance>(
    auth: &A,
    session: &SessionData<A::UserFields, A::Plugins>,
) -> Result<(), AuthError> {
    let user = &session.view().user;
    let role = user
        .fields::<AdminUser>()
        .map_err(AuthError::internal)?
        .role;
    let plugin = auth
        .try_plugin::<Admin>()
        .ok_or_else(|| AuthError::internal("RequireRole needs the admin plugin registered"))?;
    if !R::held_by(plugin, &user.id, role.as_deref()) {
        return Err(AuthError::forbidden());
    }
    Ok(())
}
