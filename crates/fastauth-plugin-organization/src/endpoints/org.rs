//! Creating, updating, deleting, listing and activating organizations.

use fastauth_core::adapter::Transaction;
use fastauth_core::plugin_prelude::*;
use fastauth_core::routes::Status;
use serde_json::{Map, Value as JsonValue};

use super::{
    active_organization, find_member, find_organization, find_organization_by_slug, nullable,
    organization, plugin, requested_organization, require_text, set_active, slug_taken, with_users,
};
use crate::access::OWNER;
use crate::model::{Invitation, Member, MemberWithUser, OrganizationRow, OrganizationSession};
use crate::{MemberAdded, Organization, OrganizationCreated, OrganizationError};

/// Body of `/organization/create`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOrganizationInput {
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: Option<Map<String, JsonValue>>,
    /// Leave the session's active organization as it is instead of switching to the new one.
    #[serde(default)]
    pub keep_current_active_organization: bool,
}

/// An organization with its members: what `/organization/create` answers.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct OrganizationWithMembers {
    #[serde(flatten)]
    pub organization: OrganizationRow,
    pub members: Vec<Member>,
}

/// `POST /organization/create`: creates an organization with the caller as its owner and
/// makes it the session's active organization.
#[derive(Clone, Copy, Debug, Default)]
pub struct CreateOrganization;

impl<D: Adapter> Endpoint<D> for CreateOrganization {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/organization/create";
    type Access = Authenticated;
    type Input = CreateOrganizationInput;
    type Output = OrganizationWithMembers;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: CreateOrganizationInput,
    ) -> Result<OrganizationWithMembers, AuthError> {
        let session = ctx.session();
        if !plugin(&ctx).allow_user_to_create_organization {
            return Err(OrganizationError::YouAreNotAllowedToCreateANewOrganization.into());
        }
        let keep_active = input.keep_current_active_organization;
        let created = create(&ctx, &session.user.id, input).await?;
        if !keep_active {
            set_active(&ctx, session, Some(&created.organization.id)).await?;
        }
        Ok(created)
    }
}

/// Creates the organization and its owner membership in one transaction. Shared by the
/// HTTP endpoint and the server-only `auth.organization().create(..)`.
pub(crate) async fn create<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    user_id: &Id,
    input: CreateOrganizationInput,
) -> Result<OrganizationWithMembers, AuthError> {
    require_text(&input.name, "name")?;
    require_text(&input.slug, "slug")?;
    if let Some(limit) = plugin(ctx).organization_limit {
        let owned = ctx
            .db()
            .count::<Member>(Member::USER_ID.eq(user_id))
            .await?;
        if owned >= limit {
            return Err(OrganizationError::YouHaveReachedTheMaximumNumberOfOrganizations.into());
        }
    }
    if find_organization_by_slug(ctx, &input.slug).await?.is_some() {
        return Err(OrganizationError::OrganizationAlreadyExists.into());
    }
    let now = ctx.now();
    let organization = OrganizationRow {
        id: ctx.new_id()?,
        name: input.name,
        slug: input.slug,
        logo: input.logo,
        metadata: input.metadata.map(Json),
        created_at: now,
    };
    let member = Member {
        id: ctx.new_id()?,
        organization_id: organization.id.clone(),
        user_id: user_id.clone(),
        role: OWNER.to_owned(),
        created_at: now,
    };
    let tx = ctx.adapter().begin().await?;
    let db = ctx.db_on(&tx);
    let organization = db.insert(&organization).await.map_err(slug_taken)?;
    let member = db.insert(&member).await?;
    tx.commit().await?;
    ctx.emit(OrganizationCreated {
        organization_id: organization.id.clone(),
        user_id: user_id.clone(),
    });
    ctx.emit(MemberAdded {
        organization_id: organization.id.clone(),
        user_id: user_id.clone(),
        member_id: member.id.clone(),
        role: member.role.clone(),
    });
    Ok(OrganizationWithMembers {
        organization,
        members: vec![member],
    })
}

/// The fields `/organization/update` changes; absent fields stay as they are.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateOrganizationData {
    pub name: Option<String>,
    pub slug: Option<String>,
    /// `null` removes the logo.
    #[serde(default, deserialize_with = "nullable")]
    pub logo: Option<Option<String>>,
    pub metadata: Option<Map<String, JsonValue>>,
}

/// Body of `/organization/update`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateOrganizationInput {
    pub data: UpdateOrganizationData,
    /// Defaults to the active organization.
    pub organization_id: Option<String>,
}

/// `POST /organization/update`: needs `organization: [update]`.
#[derive(Clone, Copy, Debug, Default)]
pub struct UpdateOrganization;

impl<D: Adapter> Endpoint<D> for UpdateOrganization {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/organization/update";
    type Access = Authenticated;
    type Input = UpdateOrganizationInput;
    type Output = OrganizationRow;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: UpdateOrganizationInput,
    ) -> Result<OrganizationRow, AuthError> {
        let session = ctx.session();
        let organization_id = requested_organization(session, input.organization_id.as_deref())?
            .ok_or(OrganizationError::OrganizationNotFound)?;
        let member = find_member(&ctx, &organization_id, &session.user.id)
            .await?
            .ok_or(OrganizationError::UserIsNotAMemberOfTheOrganization)?;
        if !plugin(&ctx)
            .roles
            .allows(&member.role, &[("organization", &["update"])])
        {
            return Err(OrganizationError::YouAreNotAllowedToUpdateThisOrganization.into());
        }
        let data = input.data;
        if let Some(slug) = &data.slug {
            require_text(slug, "slug")?;
            if find_organization_by_slug(&ctx, slug)
                .await?
                .is_some_and(|o| o.id != organization_id)
            {
                return Err(OrganizationError::OrganizationSlugAlreadyTaken.into());
            }
        }
        let mut update = ctx
            .db()
            .update::<OrganizationRow>(OrganizationRow::ID.eq(&organization_id));
        let mut changed = false;
        if let Some(name) = data.name {
            require_text(&name, "name")?;
            update = update.set(OrganizationRow::NAME, name);
            changed = true;
        }
        if let Some(slug) = data.slug {
            update = update.set(OrganizationRow::SLUG, slug);
            changed = true;
        }
        if let Some(logo) = data.logo {
            update = update.set(OrganizationRow::LOGO, logo);
            changed = true;
        }
        if let Some(metadata) = data.metadata {
            update = update.set(OrganizationRow::METADATA, Some(Json(metadata)));
            changed = true;
        }
        if changed {
            update.exec().await.map_err(slug_taken)?;
        }
        organization(&ctx, &organization_id).await
    }
}

/// Body of `/organization/delete`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteOrganizationInput {
    pub organization_id: String,
}

/// `POST /organization/delete`: needs `organization: [delete]`. Deletes the organization
/// with its members and invitations, and clears it as any session's active organization.
/// Answers the deleted organization.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeleteOrganization;

impl<D: Adapter> Endpoint<D> for DeleteOrganization {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/organization/delete";
    type Access = Authenticated;
    type Input = DeleteOrganizationInput;
    type Output = OrganizationRow;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: DeleteOrganizationInput,
    ) -> Result<OrganizationRow, AuthError> {
        let session = ctx.session();
        let organization_id = Id::from(input.organization_id);
        let member = find_member(&ctx, &organization_id, &session.user.id)
            .await?
            .ok_or(OrganizationError::UserIsNotAMemberOfTheOrganization)?;
        if !plugin(&ctx)
            .roles
            .allows(&member.role, &[("organization", &["delete"])])
        {
            return Err(OrganizationError::YouAreNotAllowedToDeleteThisOrganization.into());
        }
        let deleted = organization(&ctx, &organization_id).await?;
        delete(&ctx, &organization_id).await?;
        if active_organization(session)?.as_ref() == Some(&organization_id) {
            ctx.delete_cookie(super::SESSION_CACHE_COOKIE);
        }
        Ok(deleted)
    }
}

/// Deletes the organization, its members and invitations in one transaction, without
/// relying on the database's cascades, and clears it from sessions.
pub(crate) async fn delete<D: Adapter, A>(ctx: &Ctx<D, A>, id: &Id) -> Result<(), AuthError> {
    let tx = ctx.adapter().begin().await?;
    let db = ctx.db_on(&tx);
    db.delete::<Invitation>(Invitation::ORGANIZATION_ID.eq(id))
        .await?;
    db.delete::<Member>(Member::ORGANIZATION_ID.eq(id)).await?;
    db.delete::<OrganizationRow>(OrganizationRow::ID.eq(id))
        .await?;
    db.update::<Session>(OrganizationSession::ACTIVE_ORGANIZATION_ID.eq(Some(id.clone())))
        .set(OrganizationSession::ACTIVE_ORGANIZATION_ID, None::<Id>)
        .exec()
        .await?;
    tx.commit().await?;
    Ok(())
}

/// `GET /organization/list`: the organizations the caller is a member of.
#[derive(Clone, Copy, Debug, Default)]
pub struct ListOrganizations;

impl<D: Adapter> Endpoint<D> for ListOrganizations {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/organization/list";
    type Access = Authenticated;
    type Input = Empty;
    type Output = Vec<OrganizationRow>;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        _input: Empty,
    ) -> Result<Vec<OrganizationRow>, AuthError> {
        let memberships = ctx
            .db()
            .find::<Member>(Member::USER_ID.eq(&ctx.session().user.id))
            .order_by(Member::CREATED_AT.asc())
            .all()
            .await?;
        if memberships.is_empty() {
            return Ok(Vec::new());
        }
        let organizations = ctx
            .db()
            .find::<OrganizationRow>(
                OrganizationRow::ID.in_(memberships.iter().map(|m| m.organization_id.clone())),
            )
            .all()
            .await?;
        Ok(memberships
            .iter()
            .filter_map(|m| {
                organizations
                    .iter()
                    .find(|o| o.id == m.organization_id)
                    .cloned()
            })
            .collect())
    }
}

/// Query of `/organization/get-full-organization`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetFullOrganizationQuery {
    pub organization_id: Option<String>,
    pub organization_slug: Option<String>,
    pub members_limit: Option<u64>,
}

/// An organization with its members (and their users) and invitations.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FullOrganization {
    #[serde(flatten)]
    pub organization: OrganizationRow,
    pub members: Vec<MemberWithUser>,
    /// Empty unless the caller may create invitations; invitations granting `owner` only
    /// show to owners.
    pub invitations: Vec<Invitation>,
}

/// `GET /organization/get-full-organization`: the requested organization (by id or slug,
/// else the active one) with members and invitations. `null` when there is no active
/// organization.
#[derive(Clone, Copy, Debug, Default)]
pub struct GetFullOrganization;

impl<D: Adapter> Endpoint<D> for GetFullOrganization {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/organization/get-full-organization";
    type Access = Authenticated;
    type Input = GetFullOrganizationQuery;
    type Output = Option<FullOrganization>;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: GetFullOrganizationQuery,
    ) -> Result<Option<FullOrganization>, AuthError> {
        let session = ctx.session();
        let active = active_organization(session)?;
        let found = match (&input.organization_slug, &input.organization_id, &active) {
            (Some(slug), _, _) => find_organization_by_slug(&ctx, slug).await?,
            (None, Some(id), _) => find_organization(&ctx, &Id::from(id.as_str())).await?,
            (None, None, Some(id)) => find_organization(&ctx, id).await?,
            (None, None, None) => return Ok(None),
        };
        let organization = found.ok_or(OrganizationError::OrganizationNotFound)?;
        let Some(member) = find_member(&ctx, &organization.id, &session.user.id).await? else {
            if active.as_ref() == Some(&organization.id) {
                set_active(&ctx, session, None).await?;
            }
            return Err(OrganizationError::UserIsNotAMemberOfTheOrganization
                .with_status(StatusCode::FORBIDDEN));
        };
        let mut members = ctx
            .db()
            .find::<Member>(Member::ORGANIZATION_ID.eq(&organization.id))
            .order_by(Member::CREATED_AT.asc());
        if let Some(limit) = input.members_limit {
            members = members.limit(limit);
        }
        let members = with_users(&ctx, members.all().await?).await?;
        let invitations = visible_invitations(&ctx, plugin(&ctx), &member).await?;
        Ok(Some(FullOrganization {
            organization,
            members,
            invitations,
        }))
    }
}

/// The member's organization's invitations, as far as the member may see them: none
/// without `invitation: [create]` (an invitation id works as a link), and none granting
/// `owner` unless the member is an owner.
pub(crate) async fn visible_invitations<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    plugin: &Organization,
    member: &Member,
) -> Result<Vec<Invitation>, AuthError> {
    if !plugin
        .roles
        .allows(&member.role, &[("invitation", &["create"])])
    {
        return Ok(Vec::new());
    }
    let invitations = ctx
        .db()
        .find::<Invitation>(Invitation::ORGANIZATION_ID.eq(&member.organization_id))
        .order_by(Invitation::CREATED_AT.asc())
        .all()
        .await?;
    let is_owner = member.has_role(OWNER);
    Ok(invitations
        .into_iter()
        .filter(|i| is_owner || !crate::access::role_list(&i.role).any(|r| r == OWNER))
        .collect())
}

/// Body of `/organization/set-active`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetActiveOrganizationInput {
    /// `null` clears the active organization.
    #[serde(default, deserialize_with = "nullable")]
    pub organization_id: Option<Option<String>>,
    pub organization_slug: Option<String>,
}

/// `POST /organization/set-active`: makes an organization the caller is a member of the
/// session's active one, or clears it with `organizationId: null`. Answers the organization,
/// or `null`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SetActiveOrganization;

impl<D: Adapter> Endpoint<D> for SetActiveOrganization {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/organization/set-active";
    type Access = Authenticated;
    type Input = SetActiveOrganizationInput;
    type Output = Option<OrganizationRow>;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: SetActiveOrganizationInput,
    ) -> Result<Option<OrganizationRow>, AuthError> {
        let session = ctx.session();
        let active = active_organization(session)?;
        let organization_id = match (input.organization_id, input.organization_slug) {
            (Some(None), _) => {
                if active.is_some() {
                    set_active(&ctx, session, None).await?;
                }
                return Ok(None);
            }
            (Some(Some(id)), _) => Id::from(id),
            (None, Some(slug)) => {
                find_organization_by_slug(&ctx, &slug)
                    .await?
                    .ok_or(OrganizationError::OrganizationNotFound)?
                    .id
            }
            (None, None) => match &active {
                Some(id) => id.clone(),
                None => return Ok(None),
            },
        };
        if find_member(&ctx, &organization_id, &session.user.id)
            .await?
            .is_none()
        {
            if active.is_some() {
                set_active(&ctx, session, None).await?;
            }
            return Err(OrganizationError::UserIsNotAMemberOfTheOrganization
                .with_status(StatusCode::FORBIDDEN));
        }
        let organization = organization(&ctx, &organization_id).await?;
        set_active(&ctx, session, Some(&organization.id)).await?;
        Ok(Some(organization))
    }
}

/// Body of `/organization/check-slug`.
#[derive(Clone, Debug, Deserialize)]
pub struct CheckSlugInput {
    pub slug: String,
}

/// `POST /organization/check-slug`: `{ "status": true }` when the slug is free, else 400
/// `ORGANIZATION_SLUG_ALREADY_TAKEN`.
#[derive(Clone, Copy, Debug, Default)]
pub struct CheckSlug;

impl<D: Adapter> Endpoint<D> for CheckSlug {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/organization/check-slug";
    type Access = Authenticated;
    type Input = CheckSlugInput;
    type Output = Status;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: CheckSlugInput,
    ) -> Result<Status, AuthError> {
        if find_organization_by_slug(&ctx, &input.slug)
            .await?
            .is_some()
        {
            return Err(OrganizationError::OrganizationSlugAlreadyTaken.into());
        }
        Ok(Status { status: true })
    }
}
