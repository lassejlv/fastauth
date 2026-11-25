//! The `apikey` table.

use std::collections::BTreeMap;

use fastauth_core::plugin_prelude::*;

/// What a key may do: resource name to allowed actions, `{ "files": ["read", "write"] }`.
pub type Permissions = BTreeMap<String, Vec<String>>;

/// A row of `apikey`. Only the SHA-256 of the key is stored; the key itself is returned
/// once, by `/api-key/create`.
#[derive(Model, Clone)]
#[model(table = "apikey")]
pub struct ApiKey {
    #[model(id)]
    pub id: Id,
    /// A label the owner picked.
    pub name: Option<String>,
    /// The first characters of the key, so owners can tell keys apart.
    pub start: Option<String>,
    /// The prefix the key starts with, when it has one.
    pub prefix: Option<String>,
    /// SHA-256 of the full key.
    #[model(unique, hidden)]
    pub key_hash: Hash,
    /// The user the key acts as.
    #[model(references = User, on_delete = Cascade, index)]
    pub user_id: Id,
    /// A disabled key fails verification with `KEY_DISABLED`.
    #[model(default = true)]
    pub enabled: bool,
    /// After this, verification deletes the key and fails with `KEY_EXPIRED`.
    pub expires_at: Option<OffsetDateTime>,
    /// Whether the per-key rate limit applies.
    #[model(default = true)]
    pub rate_limit_enabled: bool,
    /// The rate-limit window in milliseconds.
    pub rate_limit_time_window: Option<i64>,
    /// Requests allowed per window.
    pub rate_limit_max: Option<i64>,
    /// Requests counted in the current window.
    #[model(default = 0)]
    pub request_count: i64,
    /// When the key was last verified.
    pub last_request: Option<OffsetDateTime>,
    /// Verifications left; `None` is unlimited.
    pub remaining: Option<i64>,
    /// What `remaining` is reset to every `refill_interval`.
    pub refill_amount: Option<i64>,
    /// The refill interval in milliseconds.
    pub refill_interval: Option<i64>,
    /// When `remaining` was last refilled.
    pub last_refill_at: Option<OffsetDateTime>,
    pub permissions: Option<Json<Permissions>>,
    pub metadata: Option<Json<serde_json::Value>>,
    #[model(default = now)]
    pub created_at: OffsetDateTime,
    #[model(default = now)]
    pub updated_at: OffsetDateTime,
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKey")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("name", &self.name)
            .field("start", &self.start)
            .finish_non_exhaustive()
    }
}
