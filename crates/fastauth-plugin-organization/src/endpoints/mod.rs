//! The `/organization/*` endpoints and the lookups they share.

mod invitations;
mod members;
mod org;
pub(crate) mod server;

use fastauth_core::adapter::DbError;
use fastauth_core::plugin_prelude::*;
use serde::Deserializer;

pub use invitations::{
    AcceptInvitation, CancelInvitation, GetInvitation, InvitationDetails, InvitationIdInput,
    InvitationIdQuery, InvitationResponse, InvitationWithOrganization, InviteMember,
    InviteMemberInput, ListInvitations, ListUserInvitations, OrganizationIdQuery, RejectInvitation,
};
pub use members::{
    GetActiveMember, HasPermission, HasPermissionInput, HasPermissionOutput, LeaveOrganization,
    LeaveOrganizationInput, ListMembers, ListMembersOutput, ListMembersQuery, RemoveMember,
    RemoveMemberInput, RemoveMemberOutput, SortDirection, UpdateMemberRole, UpdateMemberRoleInput,
};
pub use org::{
    CheckSlug, CheckSlugInput, CreateOrganization, CreateOrganizationInput, DeleteOrganization,
    DeleteOrganizationInput, FullOrganization, GetFullOrganization, GetFullOrganizationQuery,
    ListOrganizations, OrganizationWithMembers, SetActiveOrganization, SetActiveOrganizationInput,
    UpdateOrganization, UpdateOrganizationData, UpdateOrganizationInput,
};

use crate::access::OWNER;
use crate::model::{Member, MemberUser, MemberWithUser, OrganizationRow, OrganizationSession};
use crate::{MemberAdded, Organization, OrganizationError};

const SESSION_CACHE_COOKIE: &str = "session_data";

/// A role in a request body: `"admin"`, `"admin,billing"` or `["admin", "billing"]`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RoleInput {
    One(String),
    Many(Vec<String>),
}

impl RoleInput {
    fn names(&self) -> Vec<&str> {
        match self {
            Self::One(role) => crate::access::role_list(role).collect(),
            Self::Many(roles) => roles
                .iter()
                .flat_map(|r| crate::access::role_list(r))
                .collect(),
        }
    }
}

impl From<&str> for RoleInput {
    fn from(role: &str) -> Self {
        Self::One(role.to_owned())
    }
}

/// Checks every role exists and returns them in their stored, comma-separated form.
fn checked_roles(plugin: &Organization, roles: &RoleInput) -> Result<String, AuthError> {
    let names = roles.names();
    let unknown: Vec<&str> = names
        .iter()
        .copied()
        .filter(|r| !plugin.roles.contains(r))
        .collect();
    if names.is_empty() || !unknown.is_empty() {
        return Err(OrganizationError::RoleNotFound {
            roles: unknown.join(", "),
        }
        .into());
    }
    Ok(names.join(","))
}

/// For fields where `null` and absent mean different things: absent is `None`, `null` is
/// `Some(None)`.
fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(deserializer).map(Some)
}

fn plugin<D: Adapter, A>(ctx: &Ctx<D, A>) -> &Organization {
    ctx.plugin::<Organization>()
}

fn active_organization(session: &SessionView) -> Result<Option<Id>, AuthError> {
    Ok(session
        .fields::<OrganizationSession>()
        .map_err(AuthError::internal)?
        .active_organization_id)
}

/// Sets or clears the session's active organization and drops the session cookie cache,
/// which still holds the old value.
async fn set_active<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    session: &SessionView,
    organization_id: Option<&Id>,
) -> Result<(), AuthError> {
    if session.ephemeral {
        return Ok(());
    }
    ctx.db()
        .update::<Session>(Session::ID.eq(&session.session.id))
        .set(
            OrganizationSession::ACTIVE_ORGANIZATION_ID,
            organization_id.cloned(),
        )
        .exec()
        .await?;
    ctx.delete_cookie(SESSION_CACHE_COOKIE);
    Ok(())
}

async fn find_organization<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    id: &Id,
) -> Result<Option<OrganizationRow>, AuthError> {
    Ok(ctx
        .db()
        .find::<OrganizationRow>(OrganizationRow::ID.eq(id))
        .one()
        .await?)
}

async fn find_organization_by_slug<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    slug: &str,
) -> Result<Option<OrganizationRow>, AuthError> {
    Ok(ctx
        .db()
        .find::<OrganizationRow>(OrganizationRow::SLUG.eq(slug))
        .one()
        .await?)
}

/// The organization by id, or the 400 `ORGANIZATION_NOT_FOUND` Better Auth answers.
async fn organization<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    id: &Id,
) -> Result<OrganizationRow, AuthError> {
    Ok(find_organization(ctx, id)
        .await?
        .ok_or(OrganizationError::OrganizationNotFound)?)
}

async fn find_member<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    organization_id: &Id,
    user_id: &Id,
) -> Result<Option<Member>, AuthError> {
    Ok(ctx
        .db()
        .find::<Member>(
            Member::ORGANIZATION_ID
                .eq(organization_id)
                .and(Member::USER_ID.eq(user_id)),
        )
        .one()
        .await?)
}

async fn members_of<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    organization_id: &Id,
) -> Result<Vec<Member>, AuthError> {
    Ok(ctx
        .db()
        .find::<Member>(Member::ORGANIZATION_ID.eq(organization_id))
        .order_by(Member::CREATED_AT.asc())
        .all()
        .await?)
}

/// Whether `member` holds the only owner role of its organization.
async fn is_last_owner<D: Adapter, A>(ctx: &Ctx<D, A>, member: &Member) -> Result<bool, AuthError> {
    if !member.has_role(OWNER) {
        return Ok(false);
    }
    let owners = members_of(ctx, &member.organization_id)
        .await?
        .iter()
        .filter(|m| m.has_role(OWNER))
        .count();
    Ok(owners <= 1)
}

/// The organization a request acts on: the one it names, else the session's active one.
fn requested_organization(
    session: &SessionView,
    organization_id: Option<&str>,
) -> Result<Option<Id>, AuthError> {
    match organization_id {
        Some(id) if !id.is_empty() => Ok(Some(Id::from(id))),
        _ => active_organization(session),
    }
}

/// Inserts a membership, refusing a second one for the same user and organization, and
/// emits `MemberAdded`.
async fn insert_member<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    organization_id: &Id,
    user_id: &Id,
    role: String,
) -> Result<Member, AuthError> {
    if find_member(ctx, organization_id, user_id).await?.is_some() {
        return Err(OrganizationError::UserIsAlreadyAMemberOfThisOrganization.into());
    }
    let member = ctx
        .db()
        .insert(&Member {
            id: ctx.new_id()?,
            organization_id: organization_id.clone(),
            user_id: user_id.clone(),
            role,
            created_at: ctx.now(),
        })
        .await?;
    ctx.emit(MemberAdded {
        organization_id: member.organization_id.clone(),
        user_id: member.user_id.clone(),
        member_id: member.id.clone(),
        role: member.role.clone(),
    });
    Ok(member)
}

/// Attaches `{ id, name, email, image }` of each member's user.
async fn with_users<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    members: Vec<Member>,
) -> Result<Vec<MemberWithUser>, AuthError> {
    if members.is_empty() {
        return Ok(Vec::new());
    }
    let users = ctx
        .db()
        .find::<User>(User::ID.in_(members.iter().map(|m| m.user_id.clone())))
        .all()
        .await?;
    members
        .into_iter()
        .map(|member| {
            let user = users
                .iter()
                .find(|u| u.id == member.user_id)
                .ok_or_else(|| AuthError::internal("member without a user"))?;
            Ok(MemberWithUser {
                user: MemberUser {
                    id: user.id.clone(),
                    name: user.name.clone(),
                    email: user.email.clone(),
                    image: user.image.clone(),
                },
                member,
            })
        })
        .collect()
}

fn slug_taken(err: DbError) -> AuthError {
    match err {
        DbError::UniqueViolation { ref table, .. } if table == OrganizationRow::TABLE => {
            OrganizationError::OrganizationAlreadyExists.into()
        }
        other => other.into(),
    }
}

fn require_text(value: &str, field: &str) -> Result<(), AuthError> {
    if value.trim().is_empty() {
        return Err(AuthError::bad_request(
            codes::INVALID_BODY,
            format!("{field} must not be empty"),
        ));
    }
    Ok(())
}
