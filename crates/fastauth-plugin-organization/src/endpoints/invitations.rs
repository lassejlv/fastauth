//! Invitations: sending, answering, cancelling and listing them.

use fastauth_core::mail::{AuthEmail, PluginEmail};
use fastauth_core::plugin_prelude::*;
use time::format_description::well_known::Rfc3339;

use super::{
    RoleInput, checked_roles, find_member, find_organization, insert_member, organization, plugin,
    requested_organization, set_active,
};
use crate::access::OWNER;
use crate::endpoints::org::visible_invitations;
use crate::model::{Invitation, InvitationStatus, Member, OrganizationRow};
use crate::{InvitationAccepted, Organization, OrganizationError};

/// Body of `/organization/invite-member`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteMemberInput {
    pub email: String,
    pub role: RoleInput,
    /// Defaults to the active organization.
    pub organization_id: Option<String>,
    /// For an address with a pending invitation: extend it and send the email again,
    /// instead of answering `USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION`.
    #[serde(default)]
    pub resend: bool,
}

/// `POST /organization/invite-member`: needs `invitation: [create]`; only owners invite
/// owners. Stores a pending invitation that expires after the configured TTL and, when a
/// mailer is configured, emails the invitee a link (`AuthEmail::Plugin`, kind
/// `"organization-invitation"`). Answers the invitation.
#[derive(Clone, Copy, Debug, Default)]
pub struct InviteMember;

impl<D: Adapter> Endpoint<D> for InviteMember {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/organization/invite-member";
    type Access = Authenticated;
    type Input = InviteMemberInput;
    type Output = Invitation;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: InviteMemberInput,
    ) -> Result<Invitation, AuthError> {
        let session = &ctx.authoritative_session().await?;
        let plugin = plugin(&ctx);
        let organization_id = requested_organization(session, input.organization_id.as_deref())?
            .ok_or(OrganizationError::OrganizationNotFound)?;
        let email = normalized_email(&input.email)?;
        let inviter = find_member(&ctx, &organization_id, &session.user.id)
            .await?
            .ok_or(OrganizationError::MemberNotFound)?;
        if !plugin
            .roles
            .allows(&inviter.role, &[("invitation", &["create"])])
        {
            return Err(OrganizationError::YouAreNotAllowedToInviteUsersToThisOrganization.into());
        }
        let role = checked_roles(plugin, &input.role)?;
        let grants_owner = |role: &str| crate::access::role_list(role).any(|r| r == OWNER);
        if grants_owner(&role) && !inviter.has_role(OWNER) {
            return Err(OrganizationError::YouAreNotAllowedToInviteUserWithThisRole.into());
        }
        if let Some(user) = ctx.internal().find_user_by_email(&email).await?
            && find_member(&ctx, &organization_id, &user.id)
                .await?
                .is_some()
        {
            return Err(OrganizationError::UserIsAlreadyAMemberOfThisOrganization.into());
        }
        let organization = organization(&ctx, &organization_id).await?;
        let expires_at = ctx.now() + plugin.invitation_ttl;
        let pending = ctx
            .db()
            .find::<Invitation>(
                Invitation::ORGANIZATION_ID
                    .eq(&organization_id)
                    .and(Invitation::EMAIL.eq(email.as_str()))
                    .and(Invitation::STATUS.eq(InvitationStatus::Pending))
                    .and(Invitation::EXPIRES_AT.gt(ctx.now())),
            )
            .one()
            .await?;
        let invitation = match pending {
            Some(_) if !input.resend => {
                return Err(OrganizationError::UserIsAlreadyInvitedToThisOrganization.into());
            }
            Some(existing) => {
                if grants_owner(&existing.role) && !inviter.has_role(OWNER) {
                    return Err(OrganizationError::YouAreNotAllowedToInviteUserWithThisRole.into());
                }
                ctx.db()
                    .update::<Invitation>(Invitation::ID.eq(&existing.id))
                    .set(Invitation::EXPIRES_AT, expires_at)
                    .exec()
                    .await?;
                Invitation {
                    expires_at,
                    ..existing
                }
            }
            None => {
                let pending = ctx
                    .db()
                    .count::<Invitation>(
                        Invitation::ORGANIZATION_ID
                            .eq(&organization_id)
                            .and(Invitation::STATUS.eq(InvitationStatus::Pending))
                            .and(Invitation::EXPIRES_AT.gt(ctx.now())),
                    )
                    .await?;
                if pending >= plugin.invitation_limit {
                    return Err(OrganizationError::InvitationLimitReached.into());
                }
                ctx.db()
                    .insert(&Invitation {
                        id: ctx.new_id()?,
                        organization_id,
                        email,
                        role,
                        status: InvitationStatus::Pending,
                        inviter_id: session.user.id.clone(),
                        expires_at,
                        created_at: ctx.now(),
                    })
                    .await?
            }
        };
        send_invitation_email(&ctx, plugin, &invitation, &organization, &session.user).await?;
        Ok(invitation)
    }
}

fn normalized_email(email: &str) -> Result<String, AuthError> {
    fastauth_core::routes::normalize_email(email)
}

async fn send_invitation_email<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    plugin: &Organization,
    invitation: &Invitation,
    organization: &OrganizationRow,
    inviter: &UserView,
) -> Result<(), AuthError> {
    let internal = ctx.internal();
    if !internal.can_send_email() {
        return Ok(());
    }
    let url = plugin.invitation_url_for(ctx.config(), &invitation.id);
    let expires = invitation
        .expires_at
        .format(&Rfc3339)
        .map_err(AuthError::internal)?;
    internal
        .send_email(AuthEmail::Plugin(PluginEmail {
            kind: "organization-invitation",
            to: invitation.email.clone(),
            subject: format!("{} invited you to {}", inviter.name, organization.name),
            text: format!(
                "{} ({}) invited you to join {} as {}.\n\nAccept the invitation: {url}\n\nThe invitation expires at {expires}.\n",
                inviter.name, inviter.email, organization.name, invitation.role
            ),
            url: Some(url),
            code: Some(invitation.id.to_string()),
        }))
        .await
}

/// Body of the endpoints that act on one invitation.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationIdInput {
    pub invitation_id: String,
}

/// What accepting or rejecting answers: the invitation and the new membership (`null`
/// on rejection).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct InvitationResponse {
    pub invitation: Invitation,
    pub member: Option<Member>,
}

/// The invitation, if it is addressed to the session's user and they may act on it.
async fn own_invitation<D: Adapter>(
    ctx: &Ctx<D, Authenticated>,
    id: &str,
    must_be_live: bool,
) -> Result<Invitation, AuthError> {
    let invitation = ctx
        .db()
        .find::<Invitation>(Invitation::ID.eq(Id::from(id)))
        .one()
        .await?
        .filter(|i| {
            i.status == InvitationStatus::Pending && (!must_be_live || i.expires_at > ctx.now())
        })
        .ok_or(OrganizationError::InvitationNotFound)?;
    let user = &ctx.authoritative_session().await?.user;
    if !invitation.email.eq_ignore_ascii_case(&user.email) {
        return Err(OrganizationError::YouAreNotTheRecipientOfTheInvitation.into());
    }
    if plugin(ctx).require_email_verification_on_invitation && !user.email_verified {
        return Err(
            OrganizationError::EmailVerificationRequiredBeforeAcceptingOrRejectingInvitation.into(),
        );
    }
    Ok(invitation)
}

/// `POST /organization/accept-invitation`: the invitee joins with the invited role, and the
/// organization becomes the session's active one.
#[derive(Clone, Copy, Debug, Default)]
pub struct AcceptInvitation;

impl<D: Adapter> Endpoint<D> for AcceptInvitation {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/organization/accept-invitation";
    type Access = Authenticated;
    type Input = InvitationIdInput;
    type Output = InvitationResponse;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: InvitationIdInput,
    ) -> Result<InvitationResponse, AuthError> {
        let invitation = own_invitation(&ctx, &input.invitation_id, true).await?;
        let session = &ctx.authoritative_session().await?;
        organization(&ctx, &invitation.organization_id).await?;
        if find_member(&ctx, &invitation.organization_id, &session.user.id)
            .await?
            .is_some()
        {
            return Err(OrganizationError::UserIsAlreadyAMemberOfThisOrganization.into());
        }
        let claimed = update_status(
            &ctx,
            &invitation.id,
            InvitationStatus::Pending,
            InvitationStatus::Accepted,
        )
        .await?;
        if !claimed {
            return Err(OrganizationError::InvitationNotFound.into());
        }
        let member = match insert_member(
            &ctx,
            &invitation.organization_id,
            &session.user.id,
            invitation.role.clone(),
        )
        .await
        {
            Ok(member) => member,
            Err(err) => {
                update_status(
                    &ctx,
                    &invitation.id,
                    InvitationStatus::Accepted,
                    InvitationStatus::Pending,
                )
                .await?;
                return Err(err);
            }
        };
        set_active(&ctx, session, Some(&invitation.organization_id)).await?;
        ctx.emit(InvitationAccepted {
            invitation_id: invitation.id.clone(),
            organization_id: invitation.organization_id.clone(),
            user_id: session.user.id.clone(),
            member_id: member.id.clone(),
        });
        Ok(InvitationResponse {
            invitation: Invitation {
                status: InvitationStatus::Accepted,
                ..invitation
            },
            member: Some(member),
        })
    }
}

/// Moves an invitation from `from` to `to`; false when it wasn't in `from` any more.
async fn update_status<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    id: &Id,
    from: InvitationStatus,
    to: InvitationStatus,
) -> Result<bool, AuthError> {
    let updated = ctx
        .db()
        .update::<Invitation>(Invitation::ID.eq(id).and(Invitation::STATUS.eq(from)))
        .set(Invitation::STATUS, to)
        .exec()
        .await?;
    Ok(updated == 1)
}

/// `POST /organization/reject-invitation`: the invitee declines.
#[derive(Clone, Copy, Debug, Default)]
pub struct RejectInvitation;

impl<D: Adapter> Endpoint<D> for RejectInvitation {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/organization/reject-invitation";
    type Access = Authenticated;
    type Input = InvitationIdInput;
    type Output = InvitationResponse;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: InvitationIdInput,
    ) -> Result<InvitationResponse, AuthError> {
        let invitation = own_invitation(&ctx, &input.invitation_id, false).await?;
        organization(&ctx, &invitation.organization_id).await?;
        update_status(
            &ctx,
            &invitation.id,
            InvitationStatus::Pending,
            InvitationStatus::Rejected,
        )
        .await?;
        Ok(InvitationResponse {
            invitation: Invitation {
                status: InvitationStatus::Rejected,
                ..invitation
            },
            member: None,
        })
    }
}

/// `POST /organization/cancel-invitation`: needs `invitation: [cancel]` in the
/// invitation's organization. Answers the cancelled invitation. Only a pending invitation can
/// be cancelled; an accepted, rejected or cancelled one answers `INVITATION_NOT_FOUND`.
#[derive(Clone, Copy, Debug, Default)]
pub struct CancelInvitation;

impl<D: Adapter> Endpoint<D> for CancelInvitation {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/organization/cancel-invitation";
    type Access = Authenticated;
    type Input = InvitationIdInput;
    type Output = Invitation;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: InvitationIdInput,
    ) -> Result<Invitation, AuthError> {
        let invitation = ctx
            .db()
            .find::<Invitation>(Invitation::ID.eq(Id::from(input.invitation_id)))
            .one()
            .await?
            .ok_or(OrganizationError::InvitationNotFound)?;
        let member = find_member(
            &ctx,
            &invitation.organization_id,
            &ctx.authoritative_session().await?.user.id,
        )
        .await?
        .ok_or(OrganizationError::MemberNotFound)?;
        if !plugin(&ctx)
            .roles
            .allows(&member.role, &[("invitation", &["cancel"])])
        {
            return Err(OrganizationError::YouAreNotAllowedToCancelThisInvitation.into());
        }
        organization(&ctx, &invitation.organization_id).await?;
        if !update_status(
            &ctx,
            &invitation.id,
            InvitationStatus::Pending,
            InvitationStatus::Canceled,
        )
        .await?
        {
            return Err(OrganizationError::InvitationNotFound.into());
        }
        Ok(Invitation {
            status: InvitationStatus::Canceled,
            ..invitation
        })
    }
}

/// Query of `/organization/get-invitation`.
#[derive(Clone, Debug, Deserialize)]
pub struct InvitationIdQuery {
    pub id: String,
}

/// An invitation with what an invitee needs to decide: `/organization/get-invitation`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationDetails {
    #[serde(flatten)]
    pub invitation: Invitation,
    pub organization_name: String,
    pub organization_slug: String,
    pub inviter_email: String,
}

/// `GET /organization/get-invitation?id=..`: a live invitation addressed to the caller.
#[derive(Clone, Copy, Debug, Default)]
pub struct GetInvitation;

impl<D: Adapter> Endpoint<D> for GetInvitation {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/organization/get-invitation";
    type Access = Authenticated;
    type Input = InvitationIdQuery;
    type Output = InvitationDetails;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: InvitationIdQuery,
    ) -> Result<InvitationDetails, AuthError> {
        let invitation = ctx
            .db()
            .find::<Invitation>(Invitation::ID.eq(Id::from(input.id)))
            .one()
            .await?
            .filter(|i| i.status == InvitationStatus::Pending && i.expires_at > ctx.now())
            .ok_or(OrganizationError::InvitationNotFound)?;
        let user = &ctx.session().user;
        if !invitation.email.eq_ignore_ascii_case(&user.email) {
            return Err(OrganizationError::YouAreNotTheRecipientOfTheInvitation.into());
        }
        if plugin(&ctx).require_email_verification_on_invitation && !user.email_verified {
            return Err(OrganizationError::EmailVerificationRequiredForInvitation.into());
        }
        let organization = organization(&ctx, &invitation.organization_id).await?;
        let inviter =
            match find_member(&ctx, &invitation.organization_id, &invitation.inviter_id).await? {
                Some(_) => {
                    ctx.internal()
                        .find_user_by_id(&invitation.inviter_id)
                        .await?
                }
                None => None,
            }
            .ok_or(OrganizationError::InviterIsNoLongerAMemberOfTheOrganization)?;
        Ok(InvitationDetails {
            invitation,
            organization_name: organization.name,
            organization_slug: organization.slug,
            inviter_email: inviter.email.clone(),
        })
    }
}

/// Query of `/organization/list-invitations`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationIdQuery {
    /// Defaults to the active organization.
    pub organization_id: Option<String>,
}

/// `GET /organization/list-invitations`: the organization's invitations, for members who
/// may create them. Invitations granting `owner` only show to owners.
#[derive(Clone, Copy, Debug, Default)]
pub struct ListInvitations;

impl<D: Adapter> Endpoint<D> for ListInvitations {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/organization/list-invitations";
    type Access = Authenticated;
    type Input = OrganizationIdQuery;
    type Output = Vec<Invitation>;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: OrganizationIdQuery,
    ) -> Result<Vec<Invitation>, AuthError> {
        let session = ctx.session();
        let organization_id = requested_organization(session, input.organization_id.as_deref())?
            .ok_or(OrganizationError::NoActiveOrganization)?;
        let member = find_member(&ctx, &organization_id, &session.user.id)
            .await?
            .ok_or(OrganizationError::YouAreNotAMemberOfThisOrganization)?;
        let plugin = plugin(&ctx);
        if !plugin
            .roles
            .allows(&member.role, &[("invitation", &["create"])])
        {
            return Err(OrganizationError::YouAreNotAllowedToListInvitations.into());
        }
        visible_invitations(&ctx, plugin, &member).await
    }
}

/// A pending invitation with its organization's name: `/organization/list-user-invitations`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationWithOrganization {
    #[serde(flatten)]
    pub invitation: Invitation,
    pub organization_name: String,
}

/// `GET /organization/list-user-invitations`: the pending invitations addressed to the
/// caller's email, which must be verified. The server API lists any address's with
/// `auth.organization().invitations_for_email(email)`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ListUserInvitations;

impl<D: Adapter> Endpoint<D> for ListUserInvitations {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/organization/list-user-invitations";
    type Access = Authenticated;
    type Input = Empty;
    type Output = Vec<InvitationWithOrganization>;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        _input: Empty,
    ) -> Result<Vec<InvitationWithOrganization>, AuthError> {
        let user = &ctx.session().user;
        if !user.email_verified {
            return Err(OrganizationError::EmailVerificationRequiredForInvitation.into());
        }
        invitations_for(&ctx, &user.email).await
    }
}

/// Pending invitations addressed to `email`, with their organizations' names.
pub(crate) async fn invitations_for<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    email: &str,
) -> Result<Vec<InvitationWithOrganization>, AuthError> {
    let invitations = ctx
        .db()
        .find::<Invitation>(
            Invitation::EMAIL
                .eq(email.trim().to_lowercase())
                .and(Invitation::STATUS.eq(InvitationStatus::Pending)),
        )
        .order_by(Invitation::CREATED_AT.asc())
        .all()
        .await?;
    let mut out = Vec::with_capacity(invitations.len());
    for invitation in invitations {
        if let Some(organization) = find_organization(ctx, &invitation.organization_id).await? {
            out.push(InvitationWithOrganization {
                invitation,
                organization_name: organization.name,
            });
        }
    }
    Ok(out)
}
