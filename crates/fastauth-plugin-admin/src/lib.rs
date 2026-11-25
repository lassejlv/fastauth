//! The admin plugin for [fastauth](https://github.com/lassejlv/fastauth): roles and
//! statement-based permissions, bans, impersonation and user management. The routes and
//! JSON match Better Auth's admin plugin, so its `adminClient` works unchanged.
//!
//! ```
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_admin::{Admin, AdminExt, Permissions};
//!
//! let auth: Auth<MemoryAdapter, (), plugins![Admin]> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .email_password(EmailPassword::default())
//!     .plugin(
//!         Admin::new()
//!             .role("support", Permissions::new().allow("user", ["list", "get"]))
//!             .impersonation_session_duration(Duration::minutes(30)),
//!     )
//!     .build()?;
//! let _admin = auth.admin();
//! # Ok::<(), BuildError>(())
//! ```
//!
//! It adds `role`, `banned`, `ban_reason` and `ban_expires` to `user` and
//! `impersonated_by` to `session`, none of them client-settable, and serves
//! `/admin/create-user`, `list-users`, `get-user`, `set-role`, `ban-user`, `unban-user`,
//! `update-user`, `set-user-password`, `remove-user`, `list-user-sessions`,
//! `revoke-user-session`, `revoke-user-sessions`, `impersonate-user`, `stop-impersonating`
//! and `has-permission`. Each checks the caller's roles against the action it performs
//! and answers 403 with Better Auth's code when they don't allow it; `auth.admin()` runs
//! the same operations from server code without a session.
//!
//! A sign-in gate refuses banned users with `403 BANNED_USER` for every sign-in method,
//! and lifts expired bans. Register `Admin` before plugins whose gates challenge (such as
//! two-factor): a challenge that finishes later creates the session without the gates, so
//! the plugin also drops any session a banned user ends up with.
//!
//! With the `axum` feature, [`RequireRole`] guards your own routes by role.

mod access;
#[cfg(feature = "axum")]
mod axum;
mod endpoints;
mod error;
mod model;

use std::collections::BTreeMap;

use fastauth_core::ApiResponse;
use fastauth_core::events::{SessionCreated, UserCreated};
use fastauth_core::plugin_prelude::*;
use fastauth_core::routes::ListSessions;
use serde_json::{Map, Value as Json};

pub use access::{Permissions, STATEMENTS};
#[cfg(feature = "axum")]
pub use axum::{RequireRole, Role, role};
pub use endpoints::{
    BanUser, BanUserInput, CreateUser, CreateUserInput, GetUser, GetUserQuery, HasPermission,
    HasPermissionInput, ImpersonateUser, ListUserSessions, ListUsers, ListUsersQuery,
    PermissionOutput, RemoveUser, RevokeUserSession, RevokeUserSessionInput, RevokeUserSessions,
    Roles, SearchField, SearchOperator, SessionList, SessionOutput, SetRole, SetRoleInput,
    SetUserPassword, SetUserPasswordInput, SortDirection, StopImpersonating, Success, UnbanUser,
    UpdateUser, UpdateUserInput, UserIdInput, UserList, UserOutput, WhereOperator,
};
pub use error::AdminError;
pub use model::{AdminSession, AdminUser};

const DEFAULT_BANNED_MESSAGE: &str = "You have been banned from this application. Please contact support if you believe this is an error.";

/// The admin plugin: `.plugin(Admin::new())`.
#[derive(Clone, Debug)]
pub struct Admin {
    default_role: String,
    admin_roles: Vec<String>,
    admin_user_ids: Vec<Id>,
    impersonation_session_duration: Duration,
    default_ban_reason: Option<String>,
    default_ban_expires_in: Option<Duration>,
    banned_user_message: String,
    roles: BTreeMap<String, Permissions>,
}

impl Default for Admin {
    fn default() -> Self {
        Self {
            default_role: "user".to_owned(),
            admin_roles: vec!["admin".to_owned()],
            admin_user_ids: Vec::new(),
            impersonation_session_duration: Duration::hours(1),
            default_ban_reason: None,
            default_ban_expires_in: None,
            banned_user_message: DEFAULT_BANNED_MESSAGE.to_owned(),
            roles: BTreeMap::from([
                ("admin".to_owned(), Permissions::admin()),
                ("user".to_owned(), Permissions::new()),
            ]),
        }
    }
}

impl Admin {
    /// The default config: roles `admin` (every admin action but impersonating admins) and
    /// `user` (none), new users get `user`, and `admin` counts as an admin role.
    pub fn new() -> Self {
        Self::default()
    }

    /// The role new users get (default `"user"`).
    pub fn default_role(mut self, role: impl Into<String>) -> Self {
        self.default_role = role.into();
        self
    }

    /// Roles whose holders count as admins (default `["admin"]`): they can't be impersonated
    /// without `user:impersonate-admins`, and they pass `RequireRole<_, role::Admin>`. Each
    /// must be a defined role; `.build()` panics otherwise, like Better Auth.
    pub fn admin_roles(mut self, roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.admin_roles = roles.into_iter().map(Into::into).collect();
        self
    }

    /// Users who are admins whatever their role: every permission check passes for them.
    pub fn admin_user_ids(mut self, ids: impl IntoIterator<Item = impl Into<Id>>) -> Self {
        self.admin_user_ids = ids.into_iter().map(Into::into).collect();
        self
    }

    /// How long an impersonation session lasts (default one hour).
    pub fn impersonation_session_duration(mut self, duration: Duration) -> Self {
        self.impersonation_session_duration = duration;
        self
    }

    /// The reason stored when a ban gives none (default `"No reason"`).
    pub fn default_ban_reason(mut self, reason: impl Into<String>) -> Self {
        self.default_ban_reason = Some(reason.into());
        self
    }

    /// How long bans last when the request gives no expiry (default: for good).
    pub fn default_ban_expires_in(mut self, duration: Duration) -> Self {
        self.default_ban_expires_in = Some(duration);
        self
    }

    /// What a banned user's sign-in answers with, before the ban's reason.
    pub fn banned_user_message(mut self, message: impl Into<String>) -> Self {
        self.banned_user_message = message.into();
        self
    }

    /// Defines a role, or replaces a built-in one (`admin`, `user`).
    pub fn role(mut self, name: impl Into<String>, permissions: Permissions) -> Self {
        self.roles.insert(name.into(), permissions);
        self
    }

    /// The role names in a `user.role` value, or the default role when it is empty.
    pub fn roles_of<'a>(&'a self, role: Option<&'a str>) -> impl Iterator<Item = &'a str> {
        role.filter(|r| !r.trim().is_empty())
            .unwrap_or(&self.default_role)
            .split(',')
            .map(str::trim)
            .filter(|r| !r.is_empty())
    }

    /// Whether the role is defined.
    pub fn has_role_defined(&self, role: &str) -> bool {
        self.roles.contains_key(role)
    }

    /// Whether this user is an admin: listed in `admin_user_ids`, or holding an admin role.
    pub fn is_admin(&self, user_id: &Id, role: Option<&str>) -> bool {
        self.admin_user_ids.contains(user_id)
            || self
                .roles_of(role)
                .any(|r| self.admin_roles.iter().any(|a| a == r))
    }

    /// Whether a user with this id and `user.role` value may do everything in
    /// `permissions`: true for `admin_user_ids`, else when one of their roles grants it all.
    pub fn has_permission(
        &self,
        user_id: &Id,
        role: Option<&str>,
        permissions: &Permissions,
    ) -> bool {
        self.admin_user_ids.contains(user_id)
            || self
                .roles_of(role)
                .any(|r| self.roles.get(r).is_some_and(|p| p.authorize(permissions)))
    }

    /// Whether the user holds `name`, counting every admin as holding each admin role.
    pub fn has_role(&self, user_id: &Id, role: Option<&str>, name: &str) -> bool {
        self.roles_of(role).any(|r| r == name)
            || (self.admin_roles.iter().any(|a| a == name) && self.is_admin(user_id, role))
    }

    fn banned_error(&self, reason: Option<&str>) -> AuthError {
        let message = match reason {
            Some(reason) if !reason.is_empty() => {
                format!("{} Reason: {reason}", self.banned_user_message)
            }
            _ => self.banned_user_message.clone(),
        };
        AdminError::BannedUser { message }.into()
    }
}

impl Plugin for Admin {
    const ID: &'static str = "admin";
    type Requires = ();
    type UserFields = AdminUser;
    type SessionFields = AdminSession;

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        let undefined: Vec<&str> = self
            .admin_roles
            .iter()
            .filter(|r| !self.roles.contains_key(r.as_str()))
            .map(String::as_str)
            .collect();
        assert!(
            undefined.is_empty(),
            "invalid admin roles: {}; admin roles must be defined with `Admin::role`",
            undefined.join(", ")
        );
        let caller = endpoints::Caller::http(self.clone());
        app.endpoint(CreateUser(caller.clone()))
            .endpoint(ListUsers(caller.clone()))
            .endpoint(GetUser(caller.clone()))
            .endpoint(SetRole(caller.clone()))
            .endpoint(BanUser(caller.clone()))
            .endpoint(UnbanUser(caller.clone()))
            .endpoint(UpdateUser(caller.clone()))
            .endpoint(SetUserPassword(caller.clone()))
            .endpoint(RemoveUser(caller.clone()))
            .endpoint(ListUserSessions(caller.clone()))
            .endpoint(RevokeUserSession(caller.clone()))
            .endpoint(RevokeUserSessions(caller.clone()))
            .endpoint(HasPermission(caller))
            .endpoint(ImpersonateUser(self.clone()))
            .endpoint(StopImpersonating)
            .errors::<AdminError>();

        let plugin = self.clone();
        app.sign_in_gate(move |ctx, attempt| {
            let plugin = plugin.clone();
            async move {
                Ok(
                    match endpoints::ban_error(&plugin, &ctx, &attempt.user).await? {
                        Some(err) => Gate::Deny(err),
                        None => Gate::Allow,
                    },
                )
            }
        });

        let plugin = self.clone();
        app.on(move |event: SessionCreated, ctx: Ctx<D>| {
            let plugin = plugin.clone();
            async move {
                let Some(user) = ctx.internal().find_user_by_id(&event.user_id).await? else {
                    return Ok(());
                };
                if endpoints::ban_error(&plugin, &ctx, &user).await?.is_some() {
                    ctx.internal()
                        .revoke_session(&event.user_id, &event.session_id)
                        .await?;
                }
                Ok(())
            }
        });

        let plugin = self.clone();
        app.on(move |event: UserCreated, ctx: Ctx<D>| {
            let default_role = plugin.default_role.clone();
            async move {
                ctx.db()
                    .update::<User>(User::ID.eq(&event.user_id).and(AdminUser::ROLE.is_null()))
                    .set(AdminUser::ROLE, Some(default_role))
                    .exec()
                    .await?;
                Ok(())
            }
        });

        app.hook::<ListSessions>()
            .after(|_, sessions: Vec<Map<String, Json>>| async move {
                Ok(After::Continue(
                    sessions
                        .into_iter()
                        .filter(|s| s.get("impersonatedBy").is_none_or(Json::is_null))
                        .collect(),
                ))
            });
    }
}

/// `auth.admin()`: the server API. Only compiles on an `Auth` with `Admin` registered.
pub trait AdminExt: AuthInstance + Sized {
    fn admin<I>(&self) -> AdminApi<'_, Self>
    where
        Self: HasPlugin<Admin, I>,
    {
        AdminApi {
            auth: self,
            plugin: self.plugin_arc().clone(),
        }
    }
}

impl<A: AuthInstance> AdminExt for A {}

/// Runs admin operations from server code. Calls are trusted: they need no session and skip
/// the permission checks, but run the same hooks and events as the HTTP routes.
/// Impersonation acts for a signed-in admin, so it takes the request's headers.
pub struct AdminApi<'a, A> {
    auth: &'a A,
    plugin: Arc<Admin>,
}

impl<A: AuthInstance> AdminApi<'_, A> {
    fn caller(&self) -> endpoints::Caller {
        endpoints::Caller::server(self.plugin.clone())
    }

    async fn run<E: Endpoint<A::Db>>(
        &self,
        endpoint: E,
        input: E::Input,
    ) -> Result<E::Output, AuthError> {
        Ok(self.auth.api().call(&endpoint, input).await?.data)
    }

    /// Creates a user with a role, a password and any user columns.
    pub async fn create_user(&self, input: CreateUserInput) -> Result<UserView, AuthError> {
        Ok(self.run(CreateUser(self.caller()), input).await?.user)
    }

    /// Lists users with search, filter, sort and pagination.
    pub async fn list_users(&self, query: ListUsersQuery) -> Result<UserList, AuthError> {
        self.run(ListUsers(self.caller()), query).await
    }

    /// One user by id.
    pub async fn get_user(&self, id: &Id) -> Result<UserView, AuthError> {
        self.run(GetUser(self.caller()), GetUserQuery { id: id.clone() })
            .await
    }

    /// Replaces a user's roles.
    pub async fn set_role(
        &self,
        user_id: &Id,
        role: impl Into<Roles>,
    ) -> Result<UserView, AuthError> {
        let input = SetRoleInput {
            user_id: user_id.clone(),
            role: role.into(),
        };
        Ok(self.run(SetRole(self.caller()), input).await?.user)
    }

    /// Bans a user and revokes every session they have.
    pub async fn ban(&self, input: BanUserInput) -> Result<UserView, AuthError> {
        Ok(self.run(BanUser(self.caller()), input).await?.user)
    }

    /// Lifts a user's ban.
    pub async fn unban(&self, user_id: &Id) -> Result<UserView, AuthError> {
        let input = UserIdInput {
            user_id: user_id.clone(),
        };
        Ok(self.run(UnbanUser(self.caller()), input).await?.user)
    }

    /// Updates user columns by camelCase name, as `/admin/update-user` does.
    pub async fn update_user(
        &self,
        user_id: &Id,
        data: Map<String, Json>,
    ) -> Result<UserView, AuthError> {
        let input = UpdateUserInput {
            user_id: user_id.clone(),
            data,
        };
        self.run(UpdateUser(self.caller()), input).await
    }

    /// Sets a user's password, creating their credential account if needed.
    pub async fn set_user_password(
        &self,
        user_id: &Id,
        new_password: &str,
    ) -> Result<(), AuthError> {
        let input = SetUserPasswordInput {
            user_id: user_id.clone(),
            new_password: new_password.to_owned(),
        };
        self.run(SetUserPassword(self.caller()), input).await?;
        Ok(())
    }

    /// Deletes a user with their sessions and accounts.
    pub async fn remove_user(&self, user_id: &Id) -> Result<(), AuthError> {
        let input = UserIdInput {
            user_id: user_id.clone(),
        };
        self.run(RemoveUser(self.caller()), input).await?;
        Ok(())
    }

    /// A user's unexpired sessions, as client JSON.
    pub async fn list_user_sessions(
        &self,
        user_id: &Id,
    ) -> Result<Vec<Map<String, Json>>, AuthError> {
        let input = UserIdInput {
            user_id: user_id.clone(),
        };
        Ok(self
            .run(ListUserSessions(self.caller()), input)
            .await?
            .sessions)
    }

    /// Revokes the session with this raw token.
    pub async fn revoke_user_session(&self, session_token: &str) -> Result<(), AuthError> {
        let input = RevokeUserSessionInput {
            session_token: session_token.to_owned(),
        };
        self.run(RevokeUserSession(self.caller()), input).await?;
        Ok(())
    }

    /// Revokes every session of a user.
    pub async fn revoke_user_sessions(&self, user_id: &Id) -> Result<(), AuthError> {
        let input = UserIdInput {
            user_id: user_id.clone(),
        };
        self.run(RevokeUserSessions(self.caller()), input).await?;
        Ok(())
    }

    /// Whether the user may do everything in `permissions`. Unknown users may do nothing.
    pub async fn has_permission(
        &self,
        user_id: &Id,
        permissions: Permissions,
    ) -> Result<bool, AuthError> {
        let input = HasPermissionInput {
            user_id: Some(user_id.clone()),
            permissions: Some(permissions),
            ..HasPermissionInput::default()
        };
        match self.run(HasPermission(self.caller()), input).await {
            Ok(output) => Ok(output.success),
            Err(err) if err.status() == StatusCode::BAD_REQUEST => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// `POST /admin/impersonate-user` as the admin whose session cookie is in `headers`.
    /// The response's cookies switch the browser to the user.
    pub async fn impersonate(
        &self,
        headers: &HeaderMap,
        user_id: &Id,
    ) -> Result<ApiResponse<SessionOutput>, AuthError> {
        let input = UserIdInput {
            user_id: user_id.clone(),
        };
        self.auth
            .api()
            .headers(headers)
            .call(&ImpersonateUser(self.plugin.clone()), input)
            .await
    }

    /// `POST /admin/stop-impersonating` for the impersonation session in `headers`.
    pub async fn stop_impersonating(
        &self,
        headers: &HeaderMap,
    ) -> Result<ApiResponse<SessionOutput>, AuthError> {
        self.auth
            .api()
            .headers(headers)
            .call(&StopImpersonating, Empty {})
            .await
    }
}
