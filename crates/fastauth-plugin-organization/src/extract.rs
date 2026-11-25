//! axum extractors for organization membership and permissions (feature `axum`).
//!
//! ```
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
//! let _app: axum::Router<AppAuth> = axum::Router::new()
//!     .route("/dashboard", axum::routing::get(dashboard))
//!     .route("/orgs/{org_id}", axum::routing::get(org_page))
//!     .route("/members", axum::routing::delete(remove));
//! ```
//!
//! `OrgMember<A, FromPath<"org_id">>` would need `&str` const generics, which stable Rust
//! doesn't have, so the parameter name is a type implementing [`PathParam`], written with
//! [`path_param!`](crate::path_param).
//!
//! Each extractor reads the session through `fastauth_axum::Session`, so it shares that
//! request's single session lookup, then checks membership and permissions through the same
//! code as the endpoints, [`Roles::allows`](crate::Roles::allows).

use std::future::Future;
use std::marker::PhantomData;
use std::ops::Deref;

use ::axum::extract::{FromRef, FromRequestParts, RawPathParams};
use ::axum::http::request::Parts;
use fastauth_axum::Session;
use fastauth_core::value::Id;
use fastauth_core::{AuthError, AuthInstance};

use crate::Permission;
use crate::endpoints::server::{MemberQuery, ResolveMember};
use crate::model::Member;

/// Where an extractor finds the organization.
pub trait OrgSource: Send + Sync + 'static {
    /// The organization id, or `None` for the session's active organization.
    fn organization_id(
        parts: &mut Parts,
    ) -> impl Future<Output = Result<Option<Id>, AuthError>> + Send;
}

/// The session's active organization, set with `/organization/set-active`.
#[derive(Debug)]
pub struct Active;

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

async fn resolve<A, S, St>(
    parts: &mut Parts,
    state: &St,
    permission: Option<(String, Vec<String>)>,
) -> Result<Member, AuthError>
where
    A: AuthInstance + FromRef<St>,
    S: OrgSource,
    St: Send + Sync,
{
    Session::<A>::from_request_parts(parts, state).await?;
    let organization_id = S::organization_id(parts).await?;
    let auth = A::from_ref(state);
    let query = MemberQuery {
        organization_id,
        permission,
    };
    let response = auth
        .api()
        .headers(&parts.headers)
        .call(&ResolveMember, query)
        .await?;
    Ok(response.data)
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

impl<A, S, St> FromRequestParts<St> for OrgMember<A, S>
where
    A: AuthInstance + FromRef<St>,
    S: OrgSource,
    St: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &St) -> Result<Self, AuthError> {
        Ok(Self {
            member: resolve::<A, S, St>(parts, state, None).await?,
            _marker: PhantomData,
        })
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

impl<A, P, S, St> FromRequestParts<St> for RequirePermission<A, P, S>
where
    A: AuthInstance + FromRef<St>,
    P: Permission,
    S: OrgSource,
    St: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &St) -> Result<Self, AuthError> {
        let permission = (
            P::RESOURCE.to_owned(),
            P::ACTIONS.iter().map(|a| (*a).to_owned()).collect(),
        );
        Ok(Self {
            member: resolve::<A, S, St>(parts, state, Some(permission)).await?,
            _marker: PhantomData,
        })
    }
}
