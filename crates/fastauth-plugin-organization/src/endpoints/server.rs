//! Server-only endpoints: no HTTP route, called through `auth.organization()`. `init`
//! declares them with `server_endpoint`, so hooks can target them.

use std::collections::BTreeMap;

use fastauth_core::plugin_prelude::*;

use super::members::allows_map;
use super::{
    RoleInput, checked_roles, find_member, insert_member, organization, plugin, user_not_found,
};
use crate::endpoints::invitations::{InvitationWithOrganization, invitations_for};
use crate::model::Member;

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
