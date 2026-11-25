//! The error codes admin answers with.

use fastauth_core::plugin_prelude::*;

/// Why an admin request failed. Codes, statuses and messages match Better Auth's admin
/// plugin; `USER_NOT_FOUND`, `INVALID_EMAIL` and `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL`
/// come from core.
#[derive(AuthError, Clone, Debug, PartialEq, Eq)]
pub enum AdminError {
    #[auth_error(status = 400, message = "You cannot ban yourself")]
    YouCannotBanYourself,
    #[auth_error(status = 403, message = "You are not allowed to change users role")]
    YouAreNotAllowedToChangeUsersRole,
    #[auth_error(status = 403, message = "You are not allowed to create users")]
    YouAreNotAllowedToCreateUsers,
    #[auth_error(status = 403, message = "You are not allowed to list users")]
    YouAreNotAllowedToListUsers,
    #[auth_error(status = 403, message = "You are not allowed to list users sessions")]
    YouAreNotAllowedToListUsersSessions,
    #[auth_error(status = 403, message = "You are not allowed to ban users")]
    YouAreNotAllowedToBanUsers,
    #[auth_error(status = 403, message = "You are not allowed to impersonate users")]
    YouAreNotAllowedToImpersonateUsers,
    #[auth_error(status = 403, message = "You are not allowed to revoke users sessions")]
    YouAreNotAllowedToRevokeUsersSessions,
    #[auth_error(status = 403, message = "You are not allowed to delete users")]
    YouAreNotAllowedToDeleteUsers,
    #[auth_error(status = 403, message = "You are not allowed to set users password")]
    YouAreNotAllowedToSetUsersPassword,
    /// A banned user tried to sign in. The message is the configured banned-user message
    /// plus the ban's reason.
    #[auth_error(status = 403, message = "{message}")]
    BannedUser { message: String },
    #[auth_error(status = 403, message = "You are not allowed to get user")]
    YouAreNotAllowedToGetUser,
    #[auth_error(status = 400, message = "No data to update")]
    NoDataToUpdate,
    #[auth_error(status = 403, message = "You are not allowed to update users")]
    YouAreNotAllowedToUpdateUsers,
    #[auth_error(status = 400, message = "You cannot remove yourself")]
    YouCannotRemoveYourself,
    #[auth_error(
        status = 400,
        message = "You are not allowed to set a non-existent role value"
    )]
    YouAreNotAllowedToSetNonExistentValue,
    #[auth_error(status = 403, message = "You cannot impersonate admins")]
    YouCannotImpersonateAdmins,
    #[auth_error(status = 400, message = "Invalid role type")]
    InvalidRoleType,
    #[auth_error(status = 403, message = "You are not allowed to update users email")]
    YouAreNotAllowedToSetUsersEmail,
    #[auth_error(
        status = 400,
        message = "Password cannot be updated through update-user. Use the set-user-password endpoint instead"
    )]
    PasswordCannotBeUpdatedViaUpdateUser,
    #[auth_error(status = 400, message = "User id cannot be updated")]
    UserIdCannotBeUpdated,
    /// `/admin/stop-impersonating` from a session that isn't impersonating.
    #[auth_error(status = 400, message = "You are not impersonating anyone")]
    NotImpersonating,
}
