//! The organization plugin's tables and the column it adds to `session`.

use fastauth_core::plugin_prelude::*;
use serde_json::{Map, Value as JsonValue};

/// A row of `organization`. Named `OrganizationRow` because `Organization` is the plugin.
#[derive(Model, Clone, Debug, PartialEq, Serialize)]
#[model(table = "organization")]
#[serde(rename_all = "camelCase")]
pub struct OrganizationRow {
    #[model(id)]
    pub id: Id,
    pub name: String,
    /// Unique across organizations; clients can address an organization by it.
    #[model(unique)]
    pub slug: String,
    pub logo: Option<String>,
    /// Free-form JSON the app attaches to the organization.
    pub metadata: Option<Json<Map<String, JsonValue>>>,
    #[model(default = now)]
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// A row of `member`: one user's membership and role in one organization. A user is a
/// member of an organization at most once; the plugin checks that before every insert.
#[derive(Model, Clone, Debug, PartialEq, Serialize)]
#[model(table = "member")]
#[serde(rename_all = "camelCase")]
pub struct Member {
    #[model(id)]
    pub id: Id,
    #[model(references = OrganizationRow, on_delete = Cascade, index)]
    pub organization_id: Id,
    #[model(references = User, on_delete = Cascade, index)]
    pub user_id: Id,
    /// One role or several, comma-separated (`"admin,billing"`), as Better Auth stores them.
    #[model(default = "member")]
    pub role: String,
    #[model(default = now)]
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl Member {
    /// The member's roles, split from the stored comma-separated list.
    pub fn roles(&self) -> impl Iterator<Item = &str> {
        crate::access::role_list(&self.role)
    }

    /// Whether one of the member's roles is `role`.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles().any(|r| r == role)
    }
}

/// Where an invitation stands. Only `Pending` invitations can be accepted, rejected or
/// resent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Rejected,
    Canceled,
}

impl InvitationStatus {
    /// The stored and serialized name: `"pending"`, `"accepted"`, `"rejected"`, `"canceled"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Canceled => "canceled",
        }
    }
}

impl ColumnValue for InvitationStatus {
    const TYPE: ColumnType = ColumnType::Text;

    fn into_value(self) -> Value {
        Value::Text(self.as_str().to_owned())
    }

    fn from_value(value: Value) -> Result<Self, String> {
        match value {
            Value::Text(text) => match text.as_str() {
                "pending" => Ok(Self::Pending),
                "accepted" => Ok(Self::Accepted),
                "rejected" => Ok(Self::Rejected),
                "canceled" => Ok(Self::Canceled),
                other => Err(format!("unknown invitation status `{other}`")),
            },
            other => Err(format!("expected Text, got {other:?}")),
        }
    }
}

/// A row of `invitation`. Its id is the secret in the invitation link.
#[derive(Model, Clone, Debug, PartialEq, Serialize)]
#[model(table = "invitation")]
#[serde(rename_all = "camelCase")]
pub struct Invitation {
    #[model(id)]
    pub id: Id,
    #[model(references = OrganizationRow, on_delete = Cascade, index)]
    pub organization_id: Id,
    /// Lowercased. Only a user signed in with this email can accept or reject it.
    #[model(index)]
    pub email: String,
    /// The role or comma-separated roles the invitee gets on accepting.
    pub role: String,
    #[model(default = "pending")]
    pub status: InvitationStatus,
    #[model(references = User, on_delete = Cascade)]
    pub inviter_id: Id,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[model(default = now)]
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// The column the plugin adds to `session`. Clients see it as `activeOrganizationId`;
/// handlers read it with `session.session_plugin::<Organization, _>()`.
#[derive(Fields, Clone, Debug, Default, PartialEq)]
#[fields(table = Session)]
pub struct OrganizationSession {
    /// The organization `/organization/set-active` chose, which endpoints without an
    /// explicit `organizationId` act on.
    pub active_organization_id: Option<Id>,
}

/// The user part of a member in list responses: `{ id, name, email, image }`.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MemberUser {
    pub id: Id,
    pub name: String,
    pub email: String,
    pub image: Option<String>,
}

/// A member with its user, as `/organization/list-members` and
/// `/organization/get-active-member` answer.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MemberWithUser {
    #[serde(flatten)]
    pub member: Member,
    pub user: MemberUser,
}
