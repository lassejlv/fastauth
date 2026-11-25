//! Organizations for [fastauth](https://github.com/lassejlv/fastauth): organizations, members,
//! invitations, roles and permissions. The `/organization/*` routes, JSON and error codes
//! match Better Auth's organization plugin, so its `organizationClient` works unchanged.
//!
//! ```
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_organization::{Organization, OrganizationExt, Roles};
//!
//! let auth: Auth<MemoryAdapter, (), plugins![Organization]> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .email_password(EmailPassword::default())
//!     .plugin(
//!         Organization::default()
//!             .organization_limit(5)
//!             .invitation_ttl(Duration::days(7))
//!             .roles(Roles::new().role("billing", [("invoice", &["read", "pay"])])),
//!     )
//!     .build()?;
//! assert!(auth.organization().roles().allows("billing", &[("invoice", &["pay"])]));
//! # Ok::<(), BuildError>(())
//! ```
//!
//! The plugin adds the `organization`, `member` and `invitation` tables and an
//! `active_organization_id` column on `session`. A creator becomes the organization's
//! `owner`, and the last owner can neither leave nor be demoted. What each role may do is
//! decided in one place, [`Roles::allows`], which the endpoints, the server API
//! ([`OrganizationExt`]) and the axum extractors (feature `axum`) all call.
//!
//! Without the plugin registered, `auth.organization()` doesn't compile:
//!
//! ```compile_fail
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_organization::OrganizationExt;
//!
//! let auth: Auth<MemoryAdapter> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .build()
//!     .unwrap();
//! let _ = auth.organization();
//! ```

pub mod access;
mod api;
mod endpoints;
mod error;
#[cfg(feature = "axum")]
pub mod extract;
mod model;

use fastauth_core::config::CoreConfig;
use fastauth_core::plugin_prelude::*;

pub use access::{Permission, Roles};
pub use api::{OrganizationApi, OrganizationExt};
pub use endpoints::server::{
    AddMember, CheckPermission, CreateOrganizationFor, EmailQuery, NewMember, NewOrganization,
    PermissionCheck, UserInvitations,
};
pub use endpoints::*;
pub use error::OrganizationError;
pub use model::{
    Invitation, InvitationStatus, Member, MemberUser, MemberWithUser, OrganizationRow,
    OrganizationSession,
};

/// The organization plugin: `.plugin(Organization::default())`.
#[derive(Clone, Debug)]
pub struct Organization {
    pub(crate) roles: Roles,
    pub(crate) allow_user_to_create_organization: bool,
    pub(crate) organization_limit: Option<u64>,
    pub(crate) invitation_ttl: Duration,
    pub(crate) invitation_url: Option<String>,
    pub(crate) require_email_verification_on_invitation: bool,
}

impl Default for Organization {
    fn default() -> Self {
        Self {
            roles: Roles::new(),
            allow_user_to_create_organization: true,
            organization_limit: None,
            invitation_ttl: Duration::hours(48),
            invitation_url: None,
            require_email_verification_on_invitation: false,
        }
    }
}

impl Organization {
    /// The roles members can hold and what each may do. Default: [`Roles::new()`].
    pub fn roles(mut self, roles: Roles) -> Self {
        self.roles = roles;
        self
    }

    /// Whether signed-in users may create organizations over HTTP (default `true`). The
    /// server API's `create` works either way.
    pub fn allow_user_to_create_organization(mut self, allow: bool) -> Self {
        self.allow_user_to_create_organization = allow;
        self
    }

    /// How many organizations one user may belong to before creating another is refused
    /// (default: no limit).
    pub fn organization_limit(mut self, limit: u64) -> Self {
        self.organization_limit = Some(limit);
        self
    }

    /// How long an invitation can be accepted (default 48 hours).
    pub fn invitation_ttl(mut self, ttl: Duration) -> Self {
        self.invitation_ttl = ttl;
        self
    }

    /// The link invitation emails carry, with `{id}` replaced by the invitation id, e.g.
    /// `"https://app.acme.dk/invite/{id}"`. Default: `{base_url}/accept-invitation/{id}`. The
    /// page behind it calls `/organization/accept-invitation` with the id.
    pub fn invitation_url(mut self, template: impl Into<String>) -> Self {
        self.invitation_url = Some(template.into());
        self
    }

    /// Only users with a verified email may view, accept or reject invitations (default
    /// `false`). Invitation ids are unguessable, so possessing the link is the default proof.
    pub fn require_email_verification_on_invitation(mut self, require: bool) -> Self {
        self.require_email_verification_on_invitation = require;
        self
    }

    pub(crate) fn invitation_url_for(&self, config: &CoreConfig, id: &Id) -> String {
        match &self.invitation_url {
            Some(template) => template.replace("{id}", id.as_str()),
            None => format!(
                "{}/accept-invitation/{id}",
                config.base_url.as_str().trim_end_matches('/')
            ),
        }
    }
}

impl Plugin for Organization {
    const ID: &'static str = "organization";
    type Requires = ();
    type UserFields = ();
    type SessionFields = OrganizationSession;

    fn schema(&self, schema: &mut SchemaBuilder) {
        schema
            .model::<OrganizationRow>()
            .model::<Member>()
            .model::<Invitation>();
    }

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.endpoint(CreateOrganization)
            .endpoint(UpdateOrganization)
            .endpoint(DeleteOrganization)
            .endpoint(ListOrganizations)
            .endpoint(GetFullOrganization)
            .endpoint(SetActiveOrganization)
            .endpoint(CheckSlug)
            .endpoint(InviteMember)
            .endpoint(AcceptInvitation)
            .endpoint(RejectInvitation)
            .endpoint(CancelInvitation)
            .endpoint(GetInvitation)
            .endpoint(ListInvitations)
            .endpoint(ListUserInvitations)
            .endpoint(RemoveMember)
            .endpoint(UpdateMemberRole)
            .endpoint(LeaveOrganization)
            .endpoint(GetActiveMember)
            .endpoint(ListMembers)
            .endpoint(HasPermission)
            .errors::<OrganizationError>();
    }
}

/// Emitted when an organization is created, over HTTP or by the server API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganizationCreated {
    pub organization_id: Id,
    /// The creator, now its owner.
    pub user_id: Id,
}

/// Emitted for every new membership: the creator's, `add_member`'s and an accepted
/// invitation's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberAdded {
    pub organization_id: Id,
    pub user_id: Id,
    pub member_id: Id,
    pub role: String,
}

/// Emitted when a member is removed or leaves. Deleting an organization doesn't emit it
/// per member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberRemoved {
    pub organization_id: Id,
    pub user_id: Id,
    pub member_id: Id,
}

/// Emitted when an invitee accepts; `MemberAdded` fires for the new membership too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationAccepted {
    pub invitation_id: Id,
    pub organization_id: Id,
    pub user_id: Id,
    pub member_id: Id,
}

impl Event for OrganizationCreated {}
impl Event for MemberAdded {}
impl Event for MemberRemoved {}
impl Event for InvitationAccepted {}
