//! The error codes the organization endpoints answer with.

use fastauth_core::plugin_prelude::*;

/// Why an organization request failed. Codes, messages and statuses match Better Auth's
/// organization plugin, so its client's `error.code` checks keep working.
#[derive(AuthError, Clone, Debug, PartialEq, Eq)]
pub enum OrganizationError {
    #[auth_error(
        status = 403,
        message = "You are not allowed to create a new organization"
    )]
    YouAreNotAllowedToCreateANewOrganization,
    #[auth_error(
        status = 403,
        message = "You have reached the maximum number of organizations"
    )]
    YouHaveReachedTheMaximumNumberOfOrganizations,
    #[auth_error(status = 400, message = "Organization already exists")]
    OrganizationAlreadyExists,
    #[auth_error(status = 400, message = "Organization slug already taken")]
    OrganizationSlugAlreadyTaken,
    #[auth_error(status = 400, message = "Organization not found")]
    OrganizationNotFound,
    #[auth_error(status = 400, message = "User is not a member of the organization")]
    UserIsNotAMemberOfTheOrganization,
    #[auth_error(
        status = 403,
        message = "You are not allowed to update this organization"
    )]
    YouAreNotAllowedToUpdateThisOrganization,
    #[auth_error(
        status = 403,
        message = "You are not allowed to delete this organization"
    )]
    YouAreNotAllowedToDeleteThisOrganization,
    #[auth_error(status = 400, message = "No active organization")]
    NoActiveOrganization,
    #[auth_error(
        status = 400,
        message = "User is already a member of this organization"
    )]
    UserIsAlreadyAMemberOfThisOrganization,
    #[auth_error(status = 400, message = "Member not found")]
    MemberNotFound,
    #[auth_error(status = 400, message = "Role not found: {roles}")]
    RoleNotFound { roles: String },
    #[auth_error(
        status = 400,
        message = "You cannot leave the organization as the only owner"
    )]
    YouCannotLeaveTheOrganizationAsTheOnlyOwner,
    #[auth_error(
        status = 400,
        message = "You cannot leave the organization without an owner"
    )]
    YouCannotLeaveTheOrganizationWithoutAnOwner,
    #[auth_error(status = 401, message = "You are not allowed to delete this member")]
    YouAreNotAllowedToDeleteThisMember,
    #[auth_error(
        status = 403,
        message = "You are not allowed to invite users to this organization"
    )]
    YouAreNotAllowedToInviteUsersToThisOrganization,
    #[auth_error(status = 400, message = "User is already invited to this organization")]
    UserIsAlreadyInvitedToThisOrganization,
    #[auth_error(status = 400, message = "Invitation not found")]
    InvitationNotFound,
    #[auth_error(status = 403, message = "You are not the recipient of the invitation")]
    YouAreNotTheRecipientOfTheInvitation,
    #[auth_error(
        status = 403,
        message = "Email verification required before accepting or rejecting invitation"
    )]
    EmailVerificationRequiredBeforeAcceptingOrRejectingInvitation,
    #[auth_error(
        status = 403,
        message = "Email verification required to view or list invitations for the session email"
    )]
    EmailVerificationRequiredForInvitation,
    #[auth_error(
        status = 403,
        message = "You are not allowed to cancel this invitation"
    )]
    YouAreNotAllowedToCancelThisInvitation,
    #[auth_error(
        status = 403,
        message = "You are not allowed to list invitations for this organization"
    )]
    YouAreNotAllowedToListInvitations,
    #[auth_error(
        status = 400,
        message = "Inviter is no longer a member of the organization"
    )]
    InviterIsNoLongerAMemberOfTheOrganization,
    #[auth_error(
        status = 403,
        message = "You are not allowed to invite a user with this role"
    )]
    YouAreNotAllowedToInviteUserWithThisRole,
    #[auth_error(status = 403, message = "You are not allowed to update this member")]
    YouAreNotAllowedToUpdateThisMember,
    #[auth_error(status = 403, message = "You are not a member of this organization")]
    YouAreNotAMemberOfThisOrganization,
    /// Not a Better Auth code: the extractors' and `has_permission` callers' denial.
    #[auth_error(status = 403, message = "Missing permission {permission}")]
    PermissionDenied { permission: String },
}

impl OrganizationError {
    /// The same error with another HTTP status, for the few places where Better Auth answers
    /// one code with different statuses.
    pub(crate) fn with_status(self, status: StatusCode) -> AuthError {
        let err = AuthError::from(self);
        AuthError::with_message(status, err.code().to_owned(), err.message().to_owned())
    }
}
