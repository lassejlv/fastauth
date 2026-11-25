//! Statement-based access control, the same design as Better Auth's admin plugin: a role is
//! a set of actions per resource, and a request is allowed when one of the user's roles
//! grants every action it asks for.

use std::collections::{BTreeMap, BTreeSet};

use fastauth_core::plugin_prelude::*;

/// Every resource and action the admin endpoints check, as Better Auth defines them.
pub const STATEMENTS: &[(&str, &[&str])] = &[
    (
        "user",
        &[
            "create",
            "list",
            "set-role",
            "ban",
            "impersonate",
            "impersonate-admins",
            "delete",
            "set-password",
            "set-email",
            "get",
            "update",
        ],
    ),
    ("session", &["list", "revoke", "delete"]),
];

/// Actions per resource: `{ "user": ["list", "ban"] }`. A role's grants, or the actions a
/// permission check asks for.
///
/// ```
/// use fastauth_plugin_admin::Permissions;
///
/// let support = Permissions::new().allow("user", ["list", "get"]).allow("session", ["list"]);
/// assert!(support.authorize(&Permissions::new().allow("user", ["list"])));
/// assert!(!support.authorize(&Permissions::new().allow("user", ["ban"])));
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Permissions(BTreeMap<String, BTreeSet<String>>);

impl Permissions {
    /// No actions at all: the built-in `user` role.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `actions` on `resource`.
    pub fn allow(
        mut self,
        resource: impl Into<String>,
        actions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.0
            .entry(resource.into())
            .or_default()
            .extend(actions.into_iter().map(Into::into));
        self
    }

    /// The built-in `admin` role: every action in [`STATEMENTS`] except
    /// `user:impersonate-admins`.
    pub fn admin() -> Self {
        STATEMENTS
            .iter()
            .fold(Self::new(), |permissions, (resource, actions)| {
                permissions.allow(
                    *resource,
                    actions
                        .iter()
                        .copied()
                        .filter(|action| *action != "impersonate-admins"),
                )
            })
    }

    /// Whether these grants cover every action of every resource in `request`. An empty
    /// request, or a resource with no actions, is never allowed.
    pub fn authorize(&self, request: &Permissions) -> bool {
        !request.0.is_empty()
            && request.0.iter().all(|(resource, actions)| {
                !actions.is_empty()
                    && self
                        .0
                        .get(resource)
                        .is_some_and(|granted| actions.is_subset(granted))
            })
    }
}
