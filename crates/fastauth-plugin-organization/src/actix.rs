//! actix-web extractors for organization membership and permissions (feature `actix`).
//!
//! The extractor types are the ones in [`crate::extract`]: `OrgMember`, `ActiveMember`
//! and `RequirePermission`, with [`Active`] or [`FromPath`] naming the organization. This
//! module adds their actix-web side, [`OrgSource`].
//!
//! ```
//! use actix_web::{App, web};
//! use fastauth_actix::AuthScope;
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
//! fn routes(config: &mut web::ServiceConfig) {
//!     config
//!         .route("/dashboard", web::get().to(dashboard))
//!         .route("/orgs/{org_id}", web::get().to(org_page))
//!         .route("/members", web::delete().to(remove));
//! }
//! ```
//!
//! The extractors find the auth instance in app data, like `fastauth_actix::Session`, and
//! share that request's single session lookup.

use std::future::Future;
use std::pin::Pin;

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest};
use fastauth_actix::Session;
use fastauth_core::value::Id;
use fastauth_core::{AuthError, AuthInstance};

use crate::Permission;
use crate::extract::{Active, FromPath, OrgMember, PathParam, RequirePermission, membership};
use crate::model::Member;

type LocalBoxFuture<T> = Pin<Box<dyn Future<Output = T>>>;

/// Where an actix-web extractor finds the organization. axum's counterpart is
/// [`crate::extract::OrgSource`].
pub trait OrgSource: 'static {
    /// The organization id, or `None` for the session's active organization.
    fn organization_id(request: &HttpRequest) -> Result<Option<Id>, AuthError>;
}

impl OrgSource for Active {
    fn organization_id(_request: &HttpRequest) -> Result<Option<Id>, AuthError> {
        Ok(None)
    }
}

/// The organization id in the path segment `P::NAME`. A route without that segment is a
/// programming error and answers 500.
impl<P: PathParam> OrgSource for FromPath<P> {
    fn organization_id(request: &HttpRequest) -> Result<Option<Id>, AuthError> {
        request
            .match_info()
            .get(P::NAME)
            .map(|value| Some(Id::from(value)))
            .ok_or_else(|| {
                AuthError::internal(format!("the route has no `{{{}}}` segment", P::NAME))
            })
    }
}

async fn resolve<A: AuthInstance, S: OrgSource>(
    request: HttpRequest,
    permission: Option<(&'static str, &'static [&'static str])>,
) -> Result<Member, AuthError> {
    let session = Session::<A>::extract(&request).await?;
    let organization_id = S::organization_id(&request)?;
    let auth = fastauth_actix::auth::<A>(&request)?;
    membership(&auth, &session, organization_id, permission).await
}

impl<A: AuthInstance, S: OrgSource> FromRequest for OrgMember<A, S> {
    type Error = AuthError;
    type Future = LocalBoxFuture<Result<Self, AuthError>>;

    fn from_request(request: &HttpRequest, _: &mut Payload) -> Self::Future {
        let request = request.clone();
        Box::pin(async move { Ok(Self::new(resolve::<A, S>(request, None).await?)) })
    }
}

impl<A: AuthInstance, P: Permission, S: OrgSource> FromRequest for RequirePermission<A, P, S> {
    type Error = AuthError;
    type Future = LocalBoxFuture<Result<Self, AuthError>>;

    fn from_request(request: &HttpRequest, _: &mut Payload) -> Self::Future {
        let request = request.clone();
        Box::pin(async move {
            Ok(Self::new(
                resolve::<A, S>(request, Some((P::RESOURCE, P::ACTIONS))).await?,
            ))
        })
    }
}
