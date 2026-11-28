//! Members: removing, changing roles, leaving, listing, and permission checks.

use std::collections::BTreeMap;

use fastauth_core::plugin_prelude::*;

use super::{
    RoleInput, active_organization, checked_roles, find_member, find_organization_by_slug,
    has_owner, is_last_owner, plugin, requested_organization, set_active, with_users,
};
use crate::access::{OWNER, Roles};
use crate::model::{Member, MemberWithUser};
use crate::{MemberRemoved, OrganizationError};

/// Body of `/organization/remove-member`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveMemberInput {
    /// A member id, or the member's email (anything containing `@`).
    pub member_id_or_email: String,
    /// Defaults to the active organization.
    pub organization_id: Option<String>,
}

/// What `/organization/remove-member` answers.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RemoveMemberOutput {
    pub member: Member,
}

/// `POST /organization/remove-member`: needs `member: [delete]`. Only owners remove owners,
/// and never the last one.
#[derive(Clone, Copy, Debug, Default)]
pub struct RemoveMember;

impl<D: Adapter> Endpoint<D> for RemoveMember {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/organization/remove-member";
    type Access = Authenticated;
    type Input = RemoveMemberInput;
    type Output = RemoveMemberOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: RemoveMemberInput,
    ) -> Result<RemoveMemberOutput, AuthError> {
        let session = &ctx.authoritative_session().await?;
        let organization_id = requested_organization(session, input.organization_id.as_deref())?
            .ok_or(OrganizationError::NoActiveOrganization)?;
        let caller = find_member(&ctx, &organization_id, &session.user.id)
            .await?
            .ok_or(OrganizationError::MemberNotFound)?;
        let target = if input.member_id_or_email.contains('@') {
            match ctx
                .internal()
                .find_user_by_email(&input.member_id_or_email)
                .await?
            {
                Some(user) => find_member(&ctx, &organization_id, &user.id).await?,
                None => None,
            }
        } else {
            ctx.db()
                .find::<Member>(Member::ID.eq(Id::from(input.member_id_or_email.as_str())))
                .one()
                .await?
        }
        .ok_or(OrganizationError::MemberNotFound)?;
        if target.organization_id != organization_id {
            return Err(OrganizationError::MemberNotFound.into());
        }
        if target.has_role(OWNER)
            && (!caller.has_role(OWNER) || is_last_owner(&ctx, &target).await?)
        {
            return Err(OrganizationError::YouCannotLeaveTheOrganizationAsTheOnlyOwner.into());
        }
        if !plugin(&ctx)
            .roles
            .allows(&caller.role, &[("member", &["delete"])])
        {
            return Err(OrganizationError::YouAreNotAllowedToDeleteThisMember.into());
        }
        remove(&ctx, &target).await?;
        if target.user_id == session.user.id
            && active_organization(session)?.as_ref() == Some(&organization_id)
        {
            set_active(&ctx, session, None).await?;
        }
        Ok(RemoveMemberOutput { member: target })
    }
}

/// Deletes a membership and emits `MemberRemoved`. Puts an owner's membership back and
/// refuses when no owner is left, which concurrent removals can cause.
pub(crate) async fn remove<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    member: &Member,
) -> Result<(), AuthError> {
    ctx.db().delete::<Member>(Member::ID.eq(&member.id)).await?;
    if member.has_role(OWNER) && !has_owner(ctx, &member.organization_id).await? {
        ctx.db().insert(member).await?;
        return Err(OrganizationError::YouCannotLeaveTheOrganizationAsTheOnlyOwner.into());
    }
    ctx.emit(MemberRemoved {
        organization_id: member.organization_id.clone(),
        user_id: member.user_id.clone(),
        member_id: member.id.clone(),
    });
    Ok(())
}

/// Body of `/organization/update-member-role`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMemberRoleInput {
    pub role: RoleInput,
    pub member_id: String,
    /// Defaults to the active organization.
    pub organization_id: Option<String>,
}

/// `POST /organization/update-member-role`: needs `member: [update]` (owners always may).
/// Only owners grant or change the owner role, and the last owner can't demote themselves.
#[derive(Clone, Copy, Debug, Default)]
pub struct UpdateMemberRole;

impl<D: Adapter> Endpoint<D> for UpdateMemberRole {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/organization/update-member-role";
    type Access = Authenticated;
    type Input = UpdateMemberRoleInput;
    type Output = Member;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: UpdateMemberRoleInput,
    ) -> Result<Member, AuthError> {
        let session = &ctx.authoritative_session().await?;
        let plugin = plugin(&ctx);
        let organization_id = requested_organization(session, input.organization_id.as_deref())?
            .ok_or(OrganizationError::NoActiveOrganization)?;
        let caller = find_member(&ctx, &organization_id, &session.user.id)
            .await?
            .ok_or(OrganizationError::MemberNotFound)?;
        let target_id = Id::from(input.member_id);
        let target = if caller.id == target_id {
            caller.clone()
        } else {
            ctx.db()
                .find::<Member>(Member::ID.eq(&target_id))
                .one()
                .await?
                .ok_or(OrganizationError::MemberNotFound)?
        };
        if target.organization_id != organization_id {
            return Err(OrganizationError::YouAreNotAllowedToUpdateThisMember.into());
        }
        let role = checked_roles(plugin, &input.role)?;
        let caller_is_owner = caller.has_role(OWNER);
        let grants_owner = crate::access::role_list(&role).any(|r| r == OWNER);
        if (target.has_role(OWNER) || grants_owner) && !caller_is_owner {
            return Err(OrganizationError::YouAreNotAllowedToUpdateThisMember.into());
        }
        if caller_is_owner
            && caller.id == target.id
            && !grants_owner
            && is_last_owner(&ctx, &caller).await?
        {
            return Err(OrganizationError::YouCannotLeaveTheOrganizationWithoutAnOwner.into());
        }
        if !caller_is_owner
            && !plugin
                .roles
                .allows(&caller.role, &[("member", &["update"])])
        {
            return Err(OrganizationError::YouAreNotAllowedToUpdateThisMember.into());
        }
        ctx.db()
            .update::<Member>(Member::ID.eq(&target.id))
            .set(Member::ROLE, role.clone())
            .exec()
            .await?;
        if target.has_role(OWNER)
            && !grants_owner
            && !has_owner(&ctx, &target.organization_id).await?
        {
            ctx.db()
                .update::<Member>(Member::ID.eq(&target.id))
                .set(Member::ROLE, target.role.clone())
                .exec()
                .await?;
            return Err(OrganizationError::YouCannotLeaveTheOrganizationWithoutAnOwner.into());
        }
        Ok(Member { role, ..target })
    }
}

/// Body of `/organization/leave`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaveOrganizationInput {
    pub organization_id: String,
}

/// `POST /organization/leave`: ends the caller's own membership, unless they are the last
/// owner. Answers the removed membership.
#[derive(Clone, Copy, Debug, Default)]
pub struct LeaveOrganization;

impl<D: Adapter> Endpoint<D> for LeaveOrganization {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/organization/leave";
    type Access = Authenticated;
    type Input = LeaveOrganizationInput;
    type Output = Member;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: LeaveOrganizationInput,
    ) -> Result<Member, AuthError> {
        let session = &ctx.authoritative_session().await?;
        let organization_id = Id::from(input.organization_id);
        let member = find_member(&ctx, &organization_id, &session.user.id)
            .await?
            .ok_or(OrganizationError::MemberNotFound)?;
        if is_last_owner(&ctx, &member).await? {
            return Err(OrganizationError::YouCannotLeaveTheOrganizationAsTheOnlyOwner.into());
        }
        remove(&ctx, &member).await?;
        if active_organization(session)?.as_ref() == Some(&organization_id) {
            set_active(&ctx, session, None).await?;
        }
        Ok(member)
    }
}

/// `GET /organization/get-active-member`: the caller's membership in the active
/// organization, with their user.
#[derive(Clone, Copy, Debug, Default)]
pub struct GetActiveMember;

impl<D: Adapter> Endpoint<D> for GetActiveMember {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/organization/get-active-member";
    type Access = Authenticated;
    type Input = Empty;
    type Output = MemberWithUser;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        _input: Empty,
    ) -> Result<MemberWithUser, AuthError> {
        let session = ctx.session();
        let organization_id =
            active_organization(session)?.ok_or(OrganizationError::NoActiveOrganization)?;
        let member = find_member(&ctx, &organization_id, &session.user.id)
            .await?
            .ok_or(OrganizationError::MemberNotFound)?;
        with_users(&ctx, vec![member])
            .await?
            .pop()
            .ok_or_else(|| AuthError::internal("member lookup returned nothing"))
    }
}

/// `sortDirection` of `/organization/list-members`.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    #[default]
    Asc,
    Desc,
}

/// Query of `/organization/list-members`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListMembersQuery {
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    /// `createdAt` (the default), `role`, `userId` or `id`.
    pub sort_by: Option<String>,
    pub sort_direction: Option<SortDirection>,
    pub organization_id: Option<String>,
    pub organization_slug: Option<String>,
}

/// What `/organization/list-members` answers: a page of members and the total count.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ListMembersOutput {
    pub members: Vec<MemberWithUser>,
    pub total: u64,
}

/// `GET /organization/list-members`: members of the requested (or active) organization,
/// with their users. Members only.
#[derive(Clone, Copy, Debug, Default)]
pub struct ListMembers;

impl<D: Adapter> Endpoint<D> for ListMembers {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/organization/list-members";
    type Access = Authenticated;
    type Input = ListMembersQuery;
    type Output = ListMembersOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: ListMembersQuery,
    ) -> Result<ListMembersOutput, AuthError> {
        let session = ctx.session();
        let organization_id = match &input.organization_slug {
            Some(slug) => Some(
                find_organization_by_slug(&ctx, slug)
                    .await?
                    .ok_or(OrganizationError::OrganizationNotFound)?
                    .id,
            ),
            None => requested_organization(session, input.organization_id.as_deref())?,
        }
        .ok_or(OrganizationError::NoActiveOrganization)?;
        if find_member(&ctx, &organization_id, &session.user.id)
            .await?
            .is_none()
        {
            return Err(OrganizationError::YouAreNotAMemberOfThisOrganization.into());
        }
        let column = match input.sort_by.as_deref().unwrap_or("createdAt") {
            "createdAt" => Member::CREATED_AT.name(),
            "role" => Member::ROLE.name(),
            "userId" => Member::USER_ID.name(),
            "id" => Member::ID.name(),
            other => {
                return Err(AuthError::bad_request(
                    codes::INVALID_BODY,
                    format!("members can't be sorted by `{other}`"),
                ));
            }
        };
        let order = match input.sort_direction.unwrap_or_default() {
            SortDirection::Asc => Order::Asc,
            SortDirection::Desc => Order::Desc,
        };
        let filter = || Member::ORGANIZATION_ID.eq(&organization_id);
        let mut page = ctx.db().find::<Member>(filter()).order_by((column, order));
        if let Some(limit) = input.limit {
            page = page.limit(limit);
        }
        if let Some(offset) = input.offset {
            page = page.offset(offset);
        }
        let members = with_users(&ctx, page.all().await?).await?;
        let total = ctx.db().count::<Member>(filter()).await?;
        Ok(ListMembersOutput { members, total })
    }
}

/// Body of `/organization/has-permission`: `{ "permissions": { "member": ["delete"] } }`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HasPermissionInput {
    /// Resource to the actions required on it; all must be granted.
    #[serde(alias = "permission")]
    pub permissions: BTreeMap<String, Vec<String>>,
    /// Defaults to the active organization.
    pub organization_id: Option<String>,
}

/// What `/organization/has-permission` answers: `{ "error": null, "success": bool }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HasPermissionOutput {
    pub error: Option<String>,
    pub success: bool,
}

/// `POST /organization/has-permission`: whether the caller's role in the organization
/// grants the permissions.
#[derive(Clone, Copy, Debug, Default)]
pub struct HasPermission;

impl<D: Adapter> Endpoint<D> for HasPermission {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/organization/has-permission";
    type Access = Authenticated;
    type Input = HasPermissionInput;
    type Output = HasPermissionOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: HasPermissionInput,
    ) -> Result<HasPermissionOutput, AuthError> {
        let session = &ctx.authoritative_session().await?;
        let organization_id = requested_organization(session, input.organization_id.as_deref())?
            .ok_or(OrganizationError::NoActiveOrganization)?;
        let member = find_member(&ctx, &organization_id, &session.user.id)
            .await?
            .ok_or_else(|| {
                OrganizationError::UserIsNotAMemberOfTheOrganization
                    .with_status(StatusCode::UNAUTHORIZED)
            })?;
        Ok(HasPermissionOutput {
            error: None,
            success: allows_map(&plugin(&ctx).roles, &member.role, &input.permissions),
        })
    }
}

/// `Roles::allows` for a permission map from JSON.
pub(crate) fn allows_map(
    roles: &Roles,
    role: &str,
    permissions: &BTreeMap<String, Vec<String>>,
) -> bool {
    let actions: Vec<Vec<&str>> = permissions
        .values()
        .map(|actions| actions.iter().map(String::as_str).collect())
        .collect();
    let request: Vec<(&str, &[&str])> = permissions
        .keys()
        .map(String::as_str)
        .zip(actions.iter().map(Vec::as_slice))
        .collect();
    roles.allows(role, &request)
}
