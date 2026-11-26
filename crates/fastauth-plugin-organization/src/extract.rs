//! Extractors for organization membership and permissions: axum (feature `axum`) and
//! actix-web (feature `actix`) share these types, so a handler's signature is the same in
//! both.
//!
//! ```
//! # #[cfg(feature = "axum")]
//! # mod example {
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_organization::extract::{ActiveMember, FromPath, OrgMember, RequirePermission};
//! use fastauth_plugin_organization::{Organization, access::MemberDelete, path_param};
//!
//! type AppAuth = Auth<MemoryAdapter, (), plugins![Organization]>;
//!
//! path_param!(pub OrgId = "org_id");
//!
//! // The session's active organization; 403 without one or without a membership.
//! async fn dashboard(member: ActiveMember<AppAuth>) -> String {
//!     member.role.clone()
//! }
//!
//! // `/orgs/{org_id}/...`: the membership in the organization the path names.
//! async fn org_page(member: OrgMember<AppAuth, FromPath<OrgId>>) -> String {
//!     member.organization_id.to_string()
//! }
//!
//! // 403 unless the member's role grants `member: [delete]`.
//! async fn remove(member: RequirePermission<AppAuth, MemberDelete>) -> String {
//!     member.user_id.to_string()
//! }
//!
//! pub fn app() -> axum::Router<AppAuth> {
//!     axum::Router::new()
//!         .route("/dashboard", axum::routing::get(dashboard))
//!         .route("/orgs/{org_id}", axum::routing::get(org_page))
//!         .route("/members", axum::routing::delete(remove))
//! }
//! # }
//! # fn main() {}
//! ```
//!
//! In actix-web the handlers are the same and the routes use actix's `{org_id}` path
//! syntax; see [`crate::actix`].
//!
//! `OrgMember<A, FromPath<"org_id">>` would need `&str` const generics, which stable Rust
//! doesn't have, so the parameter name is a type implementing [`PathParam`], written with
//! [`path_param!`](crate::path_param).
//!
//! Each extractor reads the session through the integration's `Session` extractor
//! (`fastauth_axum::Session` or `fastauth_actix::Session`), so it shares that request's
//! single session lookup. It then loads the membership with one query and checks
//! permissions with the plugin's configured roles (`AuthInstance::try_plugin`), through the
//! same function as the endpoints, [`Roles::allows`](crate::Roles::allows).

#[cfg(feature = "axum")]
use std::future::Future;
use std::marker::PhantomData;
use std::ops::Deref;

#[cfg(feature = "axum")]
use ::axum::extract::{FromRef, FromRequestParts, RawPathParams};
#[cfg(feature = "axum")]
use ::axum::http::request::Parts;
use fastauth_core::plugin_prelude::StatusCode;
use fastauth_core::prelude::SessionData;
use fastauth_core::value::Id;
use fastauth_core::{AuthError, AuthInstance};

#[cfg(feature = "axum")]
use crate::Permission;
use crate::model::{Member, OrganizationSession};
use crate::{Organization, OrganizationError};

/// Where an axum extractor finds the organization. actix-web's counterpart is
/// [`crate::actix::OrgSource`].
#[cfg(feature = "axum")]
pub trait OrgSource: Send + Sync + 'static {
    /// The organization id, or `None` for the session's active organization.
    fn organization_id(
        parts: &mut Parts,
    ) -> impl Future<Output = Result<Option<Id>, AuthError>> + Send;
}

/// The session's active organization, set with `/organization/set-active`.
#[derive(Debug)]
pub struct Active;

#[cfg(feature = "axum")]
impl OrgSource for Active {
    async fn organization_id(_parts: &mut Parts) -> Result<Option<Id>, AuthError> {
        Ok(None)
    }
}

/// Names a route's path parameter for [`FromPath`]. Write one with
/// [`path_param!`](crate::path_param).
pub trait PathParam: Send + Sync + 'static {
    const NAME: &'static str;
}

/// Declares a [`PathParam`] type: `path_param!(pub OrgId = "org_id");`.
#[macro_export]
macro_rules! path_param {
    ($vis:vis $name:ident = $param:literal) => {
        #[derive(Debug)]
        $vis struct $name;

        impl $crate::extract::PathParam for $name {
            const NAME: &'static str = $param;
        }
    };
}

/// The organization id in the path parameter `P::NAME`. A route without that parameter is
/// a programming error and answers 500.
pub struct FromPath<P>(PhantomData<fn() -> P>);

#[cfg(feature = "axum")]
impl<P: PathParam> OrgSource for FromPath<P> {
    async fn organization_id(parts: &mut Parts) -> Result<Option<Id>, AuthError> {
        let params = RawPathParams::from_request_parts(parts, &())
            .await
            .map_err(AuthError::internal)?;
        params
            .iter()
            .find(|(name, _)| *name == P::NAME)
            .map(|(_, value)| Some(Id::from(value)))
            .ok_or_else(|| {
                AuthError::internal(format!("the route has no `{{{}}}` parameter", P::NAME))
            })
    }
}

#[cfg(feature = "axum")]
async fn resolve<A, S, St>(
    parts: &mut Parts,
    state: &St,
    permission: Option<(&'static str, &'static [&'static str])>,
) -> Result<Member, AuthError>
where
    A: AuthInstance + FromRef<St>,
    S: OrgSource,
    St: Send + Sync,
{
    let session = fastauth_axum::Session::<A>::from_request_parts(parts, state).await?;
    let organization_id = S::organization_id(parts).await?;
    membership(&A::from_ref(state), &session, organization_id, permission).await
}

/// The signed-in user's membership in `organization_id` (the session's active organization
/// when `None`), checked against `permission`. Both integrations' extractors end here.
pub(crate) async fn membership<A: AuthInstance>(
    auth: &A,
    session: &SessionData<A::UserFields, A::Plugins>,
    organization_id: Option<Id>,
    permission: Option<(&'static str, &'static [&'static str])>,
) -> Result<Member, AuthError> {
    let organization_id = match organization_id {
        Some(id) => id,
        None => session
            .view()
            .fields::<OrganizationSession>()
            .map_err(AuthError::internal)?
            .active_organization_id
            .ok_or_else(|| {
                OrganizationError::NoActiveOrganization.with_status(StatusCode::FORBIDDEN)
            })?,
    };
    let plugin = auth
        .try_plugin::<Organization>()
        .ok_or_else(|| AuthError::internal("the Organization plugin is not registered"))?;
    let member = auth
        .api()
        .db()
        .find::<Member>(
            Member::ORGANIZATION_ID
                .eq(&organization_id)
                .and(Member::USER_ID.eq(&session.user.id)),
        )
        .one()
        .await?
        .ok_or(OrganizationError::YouAreNotAMemberOfThisOrganization)?;
    if let Some((resource, actions)) = permission
        && !plugin.roles.allows(&member.role, &[(resource, actions)])
    {
        return Err(OrganizationError::PermissionDenied {
            permission: format!("{resource}: [{}]", actions.join(", ")),
        }
        .into());
    }
    Ok(member)
}

/// The signed-in user's membership in the organization `S` names. Rejects with 401 without
/// a session, 403 `NO_ACTIVE_ORGANIZATION` when `S` is [`Active`] and none is set, and 403
/// `YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION`. Derefs to [`Member`].
pub struct OrgMember<A, S = Active> {
    member: Member,
    _marker: PhantomData<fn() -> (A, S)>,
}

/// The membership in the session's active organization.
pub type ActiveMember<A> = OrgMember<A, Active>;

impl<A, S> OrgMember<A, S> {
    pub(crate) fn new(member: Member) -> Self {
        Self {
            member,
            _marker: PhantomData,
        }
    }

    pub fn into_inner(self) -> Member {
        self.member
    }
}

impl<A, S> Deref for OrgMember<A, S> {
    type Target = Member;

    fn deref(&self) -> &Member {
        &self.member
    }
}

#[cfg(feature = "axum")]
impl<A, S, St> FromRequestParts<St> for OrgMember<A, S>
where
    A: AuthInstance + FromRef<St>,
    S: OrgSource,
    St: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &St) -> Result<Self, AuthError> {
        Ok(Self::new(resolve::<A, S, St>(parts, state, None).await?))
    }
}

/// Like [`OrgMember`], and also 403 `PERMISSION_DENIED` unless the member's role grants
/// permission `P`.
pub struct RequirePermission<A, P, S = Active> {
    member: Member,
    #[allow(clippy::type_complexity)]
    _marker: PhantomData<fn() -> (A, P, S)>,
}

impl<A, P, S> RequirePermission<A, P, S> {
    pub(crate) fn new(member: Member) -> Self {
        Self {
            member,
            _marker: PhantomData,
        }
    }

    pub fn into_inner(self) -> Member {
        self.member
    }
}

impl<A, P, S> Deref for RequirePermission<A, P, S> {
    type Target = Member;

    fn deref(&self) -> &Member {
        &self.member
    }
}

#[cfg(feature = "axum")]
impl<A, P, S, St> FromRequestParts<St> for RequirePermission<A, P, S>
where
    A: AuthInstance + FromRef<St>,
    P: Permission,
    S: OrgSource,
    St: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &St) -> Result<Self, AuthError> {
        Ok(Self::new(
            resolve::<A, S, St>(parts, state, Some((P::RESOURCE, P::ACTIONS))).await?,
        ))
    }
}
