//! `auth.organization()`: the server API.

use std::collections::BTreeMap;

use fastauth_core::ApiResponse;
use fastauth_core::plugin_prelude::*;
use fastauth_core::routes::Status;

use crate::endpoints::server::{
    AddMember, CheckPermission, CreateOrganizationFor, EmailQuery, NewMember, NewOrganization,
    PermissionCheck, UserInvitations,
};
use crate::endpoints::*;
use crate::{Invitation, Member, MemberWithUser, Organization, OrganizationRow, Roles};

/// `auth.organization()`: the server API. Only compiles on an `Auth` with `Organization`
/// registered.
pub trait OrganizationExt: AuthInstance + Sized {
    fn organization<I>(&self) -> OrganizationApi<'_, Self>
    where
        Self: HasPlugin<Organization, I>,
    {
        OrganizationApi {
            auth: self,
            plugin: self.plugin_arc().clone(),
        }
    }
}

impl<A: AuthInstance> OrganizationExt for A {}

/// Calls the organization endpoints without HTTP.
///
/// [`create`](Self::create), [`add_member`](Self::add_member),
/// [`has_permission`](Self::has_permission) and
/// [`invitations_for_email`](Self::invitations_for_email) act for the server and need no
/// session. Every other method calls the route of the same name as the session in
/// `headers` (their cookies, or whatever a session resolver reads), and answers what the
/// route would, plus the cookies it sets.
pub struct OrganizationApi<'a, A> {
    auth: &'a A,
    plugin: Arc<Organization>,
}

impl<A: AuthInstance> OrganizationApi<'_, A> {
    /// The configured roles.
    pub fn roles(&self) -> &Roles {
        &self.plugin.roles
    }

    /// Creates an organization owned by `user_id`. Ignores
    /// `allow_user_to_create_organization`, but not `organization_limit`. Emits
    /// `OrganizationCreated` and `MemberAdded`.
    pub async fn create(
        &self,
        user_id: &Id,
        input: CreateOrganizationInput,
    ) -> Result<OrganizationWithMembers, AuthError> {
        let input = NewOrganization {
            user_id: user_id.clone(),
            organization: input,
        };
        Ok(self
            .auth
            .api()
            .call(&CreateOrganizationFor, input)
            .await?
            .data)
    }

    /// Adds a user to an organization without an invitation. `role` is one role or a
    /// comma-separated list; each must exist. Emits `MemberAdded`.
    pub async fn add_member(
        &self,
        organization_id: &Id,
        user_id: &Id,
        role: &str,
    ) -> Result<Member, AuthError> {
        let input = NewMember {
            organization_id: organization_id.clone(),
            user_id: user_id.clone(),
            role: role.into(),
        };
        Ok(self.auth.api().call(&AddMember, input).await?.data)
    }

    /// Whether the user's role in the organization grants `permissions`; `false` when they
    /// aren't a member.
    pub async fn has_permission(
        &self,
        organization_id: &Id,
        user_id: &Id,
        permissions: &[(&str, &[&str])],
    ) -> Result<bool, AuthError> {
        let input = PermissionCheck {
            organization_id: organization_id.clone(),
            user_id: user_id.clone(),
            permissions: permissions
                .iter()
                .map(|(resource, actions)| {
                    let actions = actions.iter().map(|a| (*a).to_owned()).collect();
                    ((*resource).to_owned(), actions)
                })
                .collect::<BTreeMap<_, _>>(),
        };
        Ok(self.auth.api().call(&CheckPermission, input).await?.data)
    }

    /// Pending invitations addressed to `email`, with their organizations' names.
    pub async fn invitations_for_email(
        &self,
        email: &str,
    ) -> Result<Vec<InvitationWithOrganization>, AuthError> {
        let input = EmailQuery {
            email: email.to_owned(),
        };
        Ok(self.auth.api().call(&UserInvitations, input).await?.data)
    }
}

macro_rules! session_calls {
    ($($route:literal $name:ident($endpoint:ident, $input:ty) -> $output:ty;)*) => {
        impl<A: AuthInstance> OrganizationApi<'_, A> {
            $(
                #[doc = concat!("`", $route, "` as the session in `headers`.")]
                pub async fn $name(
                    &self,
                    headers: &HeaderMap,
                    input: $input,
                ) -> Result<ApiResponse<$output>, AuthError> {
                    self.auth.api().headers(headers).call(&$endpoint, input).await
                }
            )*
        }
    };
}

session_calls! {
    "POST /organization/create" create_as(CreateOrganization, CreateOrganizationInput) -> OrganizationWithMembers;
    "POST /organization/update" update(UpdateOrganization, UpdateOrganizationInput) -> OrganizationRow;
    "POST /organization/delete" delete(DeleteOrganization, DeleteOrganizationInput) -> OrganizationRow;
    "GET /organization/list" list(ListOrganizations, Empty) -> Vec<OrganizationRow>;
    "GET /organization/get-full-organization" get_full(GetFullOrganization, GetFullOrganizationQuery) -> Option<FullOrganization>;
    "POST /organization/set-active" set_active(SetActiveOrganization, SetActiveOrganizationInput) -> Option<OrganizationRow>;
    "POST /organization/check-slug" check_slug(CheckSlug, CheckSlugInput) -> Status;
    "POST /organization/invite-member" invite_member(InviteMember, InviteMemberInput) -> Invitation;
    "POST /organization/accept-invitation" accept_invitation(AcceptInvitation, InvitationIdInput) -> InvitationResponse;
    "POST /organization/reject-invitation" reject_invitation(RejectInvitation, InvitationIdInput) -> InvitationResponse;
    "POST /organization/cancel-invitation" cancel_invitation(CancelInvitation, InvitationIdInput) -> Invitation;
    "GET /organization/get-invitation" get_invitation(GetInvitation, InvitationIdQuery) -> InvitationDetails;
    "GET /organization/list-invitations" list_invitations(ListInvitations, OrganizationIdQuery) -> Vec<Invitation>;
    "GET /organization/list-user-invitations" list_user_invitations(ListUserInvitations, Empty) -> Vec<InvitationWithOrganization>;
    "POST /organization/remove-member" remove_member(RemoveMember, RemoveMemberInput) -> RemoveMemberOutput;
    "POST /organization/update-member-role" update_member_role(UpdateMemberRole, UpdateMemberRoleInput) -> Member;
    "POST /organization/leave" leave(LeaveOrganization, LeaveOrganizationInput) -> Member;
    "GET /organization/get-active-member" get_active_member(GetActiveMember, Empty) -> MemberWithUser;
    "GET /organization/list-members" list_members(ListMembers, ListMembersQuery) -> ListMembersOutput;
    "POST /organization/has-permission" check_permission(HasPermission, HasPermissionInput) -> HasPermissionOutput;
}
