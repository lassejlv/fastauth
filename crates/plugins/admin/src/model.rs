//! The columns the admin plugin adds to `user` and `session`.

use fastauth_core::plugin_prelude::*;

/// The columns admin adds to `user`. None of them is client-settable; only admin endpoints
/// and the server API change them. Apps read them with `session.user.plugin::<Admin, _>()`.
#[derive(Fields, Clone, Debug, PartialEq, Eq)]
#[fields(table = User)]
pub struct AdminUser {
    /// The user's roles, comma-separated (`"admin,support"`). Filled with the configured
    /// default role right after the user is created; read it with [`Admin::roles_of`](crate::Admin::roles_of),
    /// which falls back to the default role while it is empty.
    pub role: Option<String>,
    /// Whether the user is banned. Banned users can't sign in.
    #[field(default = false)]
    pub banned: bool,
    /// Why the user is banned.
    pub ban_reason: Option<String>,
    /// When the ban lifts; `None` bans for good. Expired bans lift at the next sign-in.
    pub ban_expires: Option<OffsetDateTime>,
}

/// The column admin adds to `session`: who is impersonating through it.
#[derive(Fields, Clone, Debug, PartialEq, Eq)]
#[fields(table = Session)]
pub struct AdminSession {
    /// The admin's user id, on sessions created by `/admin/impersonate-user`.
    pub impersonated_by: Option<Id>,
}
