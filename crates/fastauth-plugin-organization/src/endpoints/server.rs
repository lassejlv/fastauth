//! Server-only endpoints: no HTTP route, called through `auth.organization()` and the axum
//! extractors.

use std::collections::BTreeMap;

use fastauth_core::plugin_prelude::*;

use super::members::allows_map;
use super::{
    RoleInput, active_organization, checked_roles, find_member, insert_member, organization, plugin,
};
use crate::OrganizationError;
use crate::endpoints::invitations::{InvitationWithOrganization, invitations_for};
use crate::endpoints::org::{CreateOrganizationInput, OrganizationWithMembers, create};
use crate::model::Member;

fn user_not_found() -> AuthError {
    AuthError::bad_request(codes::USER_NOT_FOUND, "User not found")
}

/// An organization to create for a user, without a session.
#[derive(Clone, Debug, Deserialize)]
pub struct NewOrganization {
    /// The creator, who becomes the owner.
    pub user_id: Id,
    #[serde(flatten)]
    pub organization: CreateOrganizationInput,
}

/// Creates an organization for `user_id`, skipping `allow_user_to_create_organization`
/// (the server decided) but not `organization_limit`.
#[derive(Clone, Copy, Debug, Default)]
pub struct CreateOrganizationFor;

impl<D: Adapter> Endpoint<D> for CreateOrganizationFor {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/organization/create";
    type Access = Public;
    type Input = NewOrganization;
    type Output = OrganizationWithMembers;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: NewOrganization,
    ) -> Result<OrganizationWithMembers, AuthError> {
        let user = ctx
            .internal()
            .find_user_by_id(&input.user_id)
            .await?
            .ok_or_else(user_not_found)?;
        create(&ctx, &user.id, input.organization).await
    }
}

/// A membership to add without an invitation.
#[derive(Clone, Debug, Deserialize)]
pub struct NewMember {
    pub organization_id: Id,
    pub user_id: Id,
    pub role: RoleInput,
}

/// Adds a user to an organization directly, Better Auth's server-only `addMember`.
#[derive(Clone, Copy, Debug, Default)]
pub struct AddMember;

impl<D: Adapter> Endpoint<D> for AddMember {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/organization/add-member";
    type Access = Public;
    type Input = NewMember;
    type Output = Member;

    async fn call(&self, ctx: Ctx<D, Public>, input: NewMember) -> Result<Member, AuthError> {
        let role = checked_roles(plugin(&ctx), &input.role)?;
        ctx.internal()
            .find_user_by_id(&input.user_id)
            .await?
            .ok_or_else(user_not_found)?;
        organization(&ctx, &input.organization_id).await?;
        insert_member(&ctx, &input.organization_id, &input.user_id, role).await
    }
}

/// A permission question about a user, without a session.
#[derive(Clone, Debug, Deserialize)]
pub struct PermissionCheck {
    pub organization_id: Id,
    pub user_id: Id,
    pub permissions: BTreeMap<String, Vec<String>>,
}

/// Whether the user's role in the organization grants the permissions; `false` for
/// non-members.
#[derive(Clone, Copy, Debug, Default)]
pub struct CheckPermission;

impl<D: Adapter> Endpoint<D> for CheckPermission {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/organization/has-permission";
    type Access = Public;
    type Input = PermissionCheck;
    type Output = bool;

    async fn call(&self, ctx: Ctx<D, Public>, input: PermissionCheck) -> Result<bool, AuthError> {
        Ok(find_member(&ctx, &input.organization_id, &input.user_id)
            .await?
            .is_some_and(|m| allows_map(&plugin(&ctx).roles, &m.role, &input.permissions)))
    }
}

/// Input of [`ResolveMember`].
#[derive(Clone, Debug, Default, Deserialize)]
pub struct MemberQuery {
    /// `None` for the session's active organization.
    pub organization_id: Option<Id>,
    /// A resource and the actions on it the member must be allowed.
    pub permission: Option<(String, Vec<String>)>,
}

/// The session user's membership in an organization, for the axum extractors: 403
/// `NO_ACTIVE_ORGANIZATION` without one, 403 `YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION`, and
/// 403 `PERMISSION_DENIED` when a requested permission isn't granted.
#[derive(Clone, Copy, Debug, Default)]
pub struct ResolveMember;

impl<D: Adapter> Endpoint<D> for ResolveMember {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/organization/get-active-member";
    type Access = Authenticated;
    type Input = MemberQuery;
    type Output = Member;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: MemberQuery,
    ) -> Result<Member, AuthError> {
        let session = ctx.session();
        let organization_id = match input.organization_id {
            Some(id) => id,
            None => active_organization(session)?.ok_or_else(|| {
                OrganizationError::NoActiveOrganization.with_status(StatusCode::FORBIDDEN)
            })?,
        };
        let member = find_member(&ctx, &organization_id, &session.user.id)
            .await?
            .ok_or(OrganizationError::YouAreNotAMemberOfThisOrganization)?;
        if let Some((resource, actions)) = input.permission {
            let request: Vec<&str> = actions.iter().map(String::as_str).collect();
            if !plugin(&ctx)
                .roles
                .allows(&member.role, &[(resource.as_str(), &request)])
            {
                return Err(OrganizationError::PermissionDenied {
                    permission: format!("{resource}: [{}]", actions.join(", ")),
                }
                .into());
            }
        }
        Ok(member)
    }
}

/// Input of [`UserInvitations`].
#[derive(Clone, Debug, Deserialize)]
pub struct EmailQuery {
    pub email: String,
}

/// Pending invitations addressed to any email.
#[derive(Clone, Copy, Debug, Default)]
pub struct UserInvitations;

impl<D: Adapter> Endpoint<D> for UserInvitations {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/organization/list-user-invitations";
    type Access = Public;
    type Input = EmailQuery;
    type Output = Vec<InvitationWithOrganization>;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: EmailQuery,
    ) -> Result<Vec<InvitationWithOrganization>, AuthError> {
        invitations_for(&ctx, &input.email).await
    }
}
