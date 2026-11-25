//! Roles, the statements they grant, and the one permission check every endpoint and
//! extractor goes through.
//!
//! A statement pairs a resource with the actions allowed on it: `("member", &["delete"])`.
//! A role is a named set of statements. A member holds one role or several (stored
//! comma-separated), and is allowed a request when any one of its roles grants every action
//! on every resource the request names, the rule Better Auth's access control uses.

use std::collections::{BTreeMap, BTreeSet};

/// The role an organization's creator gets. The last member holding it can't leave or be
/// demoted.
pub const OWNER: &str = "owner";
/// Manages members and invitations and updates the organization, but can't delete it.
pub const ADMIN: &str = "admin";
/// The default role: no organization, member or invitation actions.
pub const MEMBER: &str = "member";

/// The roles an organization knows, with what each may do. `Roles::new()` holds Better
/// Auth's three defaults; add your own with [`role`](Roles::role) and give existing roles more
/// with [`grant`](Roles::grant):
///
/// ```
/// use fastauth_plugin_organization::{Organization, Roles};
///
/// let roles = Roles::new()
///     .role("billing", [("invoice", &["read", "pay"]), ("organization", &["update"])])
///     .grant("owner", [("invoice", &["read", "pay", "refund"])]);
/// assert!(roles.allows("billing", &[("invoice", &["pay"])]));
/// assert!(roles.allows("member,billing", &[("invoice", &["read"])]));
/// assert!(!roles.allows("admin", &[("invoice", &["read"])]));
/// let _plugin = Organization::default().roles(roles);
/// ```
///
/// Resources and actions are plain strings because clients send them as JSON to
/// `/organization/has-permission`; the [`Permission`] trait gives them a type for handlers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roles {
    roles: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
}

impl Default for Roles {
    fn default() -> Self {
        Self::new()
    }
}

impl Roles {
    /// Better Auth's default roles: `owner` (every action), `admin` (everything but deleting
    /// the organization) and `member` (reading access control only).
    pub fn new() -> Self {
        let roles = Self {
            roles: BTreeMap::new(),
        };
        roles
            .role(
                OWNER,
                [
                    ("organization", &["update", "delete"]),
                    ("member", &["create", "update", "delete"]),
                    ("invitation", &["create", "cancel"]),
                    ("team", &["create", "update", "delete"]),
                    ("ac", &["create", "read", "update", "delete"]),
                ],
            )
            .role(
                ADMIN,
                [
                    ("organization", &["update"]),
                    ("member", &["create", "update", "delete"]),
                    ("invitation", &["create", "cancel"]),
                    ("team", &["create", "update", "delete"]),
                    ("ac", &["create", "read", "update", "delete"]),
                ],
            )
            .role(
                MEMBER,
                [
                    ("organization", &[]),
                    ("member", &[]),
                    ("invitation", &[]),
                    ("team", &[]),
                    ("ac", &["read"]),
                ],
            )
    }

    /// Defines `name` with exactly these statements, replacing a role of the same name.
    pub fn role<const N: usize>(mut self, name: &str, statements: [(&str, &[&str]); N]) -> Self {
        self.roles.insert(name.to_owned(), BTreeMap::new());
        self.grant(name, statements)
    }

    /// Adds actions to `name`, defining it if it doesn't exist yet. Use it to let the
    /// built-in roles act on your own resources.
    pub fn grant<const N: usize>(mut self, name: &str, statements: [(&str, &[&str]); N]) -> Self {
        let role = self.roles.entry(name.to_owned()).or_default();
        for (resource, actions) in statements {
            role.entry(resource.to_owned())
                .or_default()
                .extend(actions.iter().map(|a| (*a).to_owned()));
        }
        self
    }

    /// Whether a role of this name exists.
    pub fn contains(&self, role: &str) -> bool {
        self.roles.contains_key(role)
    }

    /// The permission check. `role` is one role or a comma-separated list; the answer is yes
    /// when one of them grants every action on every resource in `permissions`. An empty
    /// request, or a resource with no actions, is never allowed.
    pub fn allows(&self, role: &str, permissions: &[(&str, &[&str])]) -> bool {
        if permissions.is_empty() {
            return false;
        }
        role_list(role).any(|name| {
            self.roles.get(name).is_some_and(|statements| {
                permissions.iter().all(|(resource, actions)| {
                    !actions.is_empty()
                        && statements
                            .get(*resource)
                            .is_some_and(|allowed| actions.iter().all(|a| allowed.contains(*a)))
                })
            })
        })
    }
}

/// Splits a stored role value into trimmed, non-empty role names.
pub(crate) fn role_list(role: &str) -> impl Iterator<Item = &str> {
    role.split(',').map(str::trim).filter(|r| !r.is_empty())
}

/// A permission as a type, so a handler's signature names what it requires:
/// `RequirePermission<AppAuth, InvoicePay>` with the `axum` feature.
///
/// ```
/// use fastauth_plugin_organization::Permission;
///
/// pub struct InvoicePay;
///
/// impl Permission for InvoicePay {
///     const RESOURCE: &'static str = "invoice";
///     const ACTIONS: &'static [&'static str] = &["pay"];
/// }
/// ```
pub trait Permission: Send + Sync + 'static {
    /// The resource, e.g. `"member"`.
    const RESOURCE: &'static str;
    /// The actions on it, all of which are required.
    const ACTIONS: &'static [&'static str];
}

macro_rules! permissions {
    ($($(#[$doc:meta])* $name:ident = $resource:literal: [$($action:literal),+];)*) => {
        $(
            $(#[$doc])*
            #[derive(Clone, Copy, Debug, Default)]
            pub struct $name;

            impl Permission for $name {
                const RESOURCE: &'static str = $resource;
                const ACTIONS: &'static [&'static str] = &[$($action),+];
            }
        )*
    };
}

permissions! {
    /// `organization: [update]`: owners and admins.
    OrganizationUpdate = "organization": ["update"];
    /// `organization: [delete]`: owners.
    OrganizationDelete = "organization": ["delete"];
    /// `member: [create]`: owners and admins.
    MemberCreate = "member": ["create"];
    /// `member: [update]`: owners and admins.
    MemberUpdate = "member": ["update"];
    /// `member: [delete]`: owners and admins.
    MemberDelete = "member": ["delete"];
    /// `invitation: [create]`: owners and admins.
    InvitationCreate = "invitation": ["create"];
    /// `invitation: [cancel]`: owners and admins.
    InvitationCancel = "invitation": ["cancel"];
}
