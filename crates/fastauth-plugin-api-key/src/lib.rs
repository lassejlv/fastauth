//! API keys for [fastauth](https://github.com/lassejlv/fastauth): per-user keys with expiry,
//! usage limits that refill, per-key rate limits and permissions. The routes, JSON and error
//! codes match Better Auth's `apiKey` plugin, so its `apiKeyClient` works unchanged.
//!
//! Only the SHA-256 of a key is stored; `/api-key/create` returns the key once. With
//! `.sessions(true)`, a request carrying a key in `x-api-key` (or the configured header) gets
//! a session for the key's owner that exists only for that request, so every
//! `Session<AppAuth>` extractor accepts API keys with no handler changes. Each such request
//! counts against the key's rate limit (10 per day by default; see `ApiKeys::rate_limit`).
//!
//! ```
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_api_key::{ApiKeys, ApiKeysExt, CreateApiKeyInput};
//!
//! # tokio_test(async {
//! let auth: Auth<MemoryAdapter, (), plugins![ApiKeys]> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .email_password(EmailPassword::default())
//!     .plugin(ApiKeys::new().default_prefix("ak_"))
//!     .build()?;
//! # let user = auth.api().create_user(fastauth_core::routes::CreateUserInput {
//! #     email: "ada@example.com".into(), name: "Ada".into(), ..Default::default()
//! # }).await?;
//! let created = auth
//!     .api_keys()
//!     .create(CreateApiKeyInput {
//!         name: Some("ci".into()),
//!         user_id: Some(user.id.clone()),
//!         ..Default::default()
//!     })
//!     .await?;
//! assert!(created.key.starts_with("ak_"));
//!
//! let verified = auth.api_keys().verify(&created.key, None).await?;
//! assert!(verified.valid);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # });
//! # fn tokio_test<F: std::future::Future>(f: F) -> F::Output {
//! #     tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
//! # }
//! ```
//!
//! Without the plugin registered, `auth.api_keys()` doesn't compile:
//!
//! ```compile_fail
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_api_key::ApiKeysExt;
//!
//! let auth: Auth<MemoryAdapter> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .build()
//!     .unwrap();
//! let _keys = auth.api_keys();
//! ```
//!
//! Fields that change what a key may do (`remaining`, `refill*`, `rateLimit*`,
//! `permissions`) are server-only: over HTTP they answer `SERVER_ONLY_PROPERTY`, through
//! `auth.api_keys()` they are accepted. `/api-key/verify` and
//! `/api-key/delete-all-expired-api-keys` have no HTTP route, as in Better Auth.

mod endpoints;
mod error;
mod model;
mod verify;

use fastauth_core::plugin_prelude::*;
use http::HeaderName;

pub use endpoints::{
    ApiKeyList, ApiKeyView, CreateApiKey, CreateApiKeyInput, CreatedApiKey,
    DeleteAllExpiredApiKeys, DeleteApiKey, DeleteApiKeyInput, DeleteExpiredOutput, GetApiKey,
    GetApiKeyInput, ListApiKeys, ListApiKeysInput, SortDirection, Success, UpdateApiKey,
    UpdateApiKeyInput, VerifyApiKey, VerifyApiKeyInput, VerifyError, VerifyOutput,
};
pub use error::ApiKeyError;
pub use model::{ApiKey, Permissions};

type KeyGetter = Arc<dyn Fn(&HeaderMap) -> Option<String> + Send + Sync>;

/// The defaults new keys get for their per-key rate limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RateLimitDefaults {
    enabled: bool,
    window: Duration,
    max: i64,
}

/// The API key plugin: `.plugin(ApiKeys::new().default_prefix("ak_"))`.
///
/// Defaults match Better Auth: 64-character keys with no prefix, the first 6 characters
/// stored as `start`, no default expiry, `expiresIn` between 1 and 365 days, metadata off,
/// a rate limit of 10 verifications per day per key, and no sessions from keys until
/// `.sessions(true)`.
#[derive(Clone)]
pub struct ApiKeys {
    key_length: usize,
    default_prefix: Option<String>,
    start_length: usize,
    default_expires_in: Option<Duration>,
    min_expires_in: Duration,
    max_expires_in: Duration,
    enable_metadata: bool,
    require_name: bool,
    default_permissions: Option<Permissions>,
    rate_limit: RateLimitDefaults,
    header: HeaderName,
    getter: Option<KeyGetter>,
    sessions: bool,
}

impl std::fmt::Debug for ApiKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeys")
            .field("key_length", &self.key_length)
            .field("default_prefix", &self.default_prefix)
            .field("header", &self.header)
            .field("sessions", &self.sessions)
            .finish_non_exhaustive()
    }
}

impl Default for ApiKeys {
    fn default() -> Self {
        Self {
            key_length: 64,
            default_prefix: None,
            start_length: 6,
            default_expires_in: None,
            min_expires_in: Duration::days(1),
            max_expires_in: Duration::days(365),
            enable_metadata: false,
            require_name: false,
            default_permissions: None,
            rate_limit: RateLimitDefaults {
                enabled: true,
                window: Duration::days(1),
                max: 10,
            },
            header: HeaderName::from_static("x-api-key"),
            getter: None,
            sessions: false,
        }
    }
}

impl ApiKeys {
    pub fn new() -> Self {
        Self::default()
    }

    /// Random characters per key, after the prefix (default 64). Keys shorter than this are
    /// refused by the session resolver with 403 `INVALID_API_KEY` before any lookup.
    pub fn key_length(mut self, length: usize) -> Self {
        assert!(length >= 16, "API keys need at least 16 random characters");
        self.key_length = length;
        self
    }

    /// The prefix keys start with unless the create request names one, e.g. `"ak_"`.
    pub fn default_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.default_prefix = Some(prefix.into());
        self
    }

    /// How many leading characters of each key are stored as `start` (default 6; 0 stores
    /// none).
    pub fn start_length(mut self, length: usize) -> Self {
        self.start_length = length;
        self
    }

    /// The expiry of keys created without `expiresIn` (default: never).
    pub fn default_expires_in(mut self, ttl: Duration) -> Self {
        self.default_expires_in = Some(ttl);
        self
    }

    /// The smallest `expiresIn` a create or update may ask for (default 1 day).
    pub fn min_expires_in(mut self, min: Duration) -> Self {
        self.min_expires_in = min;
        self
    }

    /// The largest `expiresIn` a create or update may ask for (default 365 days).
    pub fn max_expires_in(mut self, max: Duration) -> Self {
        self.max_expires_in = max;
        self
    }

    /// Lets keys carry a JSON object of `metadata` (default off).
    pub fn enable_metadata(mut self, enabled: bool) -> Self {
        self.enable_metadata = enabled;
        self
    }

    /// Refuses creates without a `name` with `NAME_REQUIRED` (default off).
    pub fn require_name(mut self, required: bool) -> Self {
        self.require_name = required;
        self
    }

    /// The permissions keys created without `permissions` get.
    pub fn default_permissions(mut self, permissions: Permissions) -> Self {
        self.default_permissions = Some(permissions);
        self
    }

    /// The per-key rate limit new keys get: `max` verifications per `window`
    /// (default 10 per day). The server API can set other values per key.
    pub fn rate_limit(mut self, window: Duration, max: i64) -> Self {
        self.rate_limit.window = window;
        self.rate_limit.max = max;
        self
    }

    /// Turns per-key rate limiting off for every key, whatever the key says.
    pub fn disable_rate_limit(mut self) -> Self {
        self.rate_limit.enabled = false;
        self
    }

    /// The header the session resolver reads keys from (default `x-api-key`).
    pub fn header(mut self, name: HeaderName) -> Self {
        self.header = name;
        self
    }

    /// Reads the key from the request some other way (e.g. `Authorization: Bearer`).
    /// Replaces the header lookup.
    pub fn key_getter(
        mut self,
        getter: impl Fn(&HeaderMap) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        self.getter = Some(Arc::new(getter));
        self
    }

    /// Whether requests carrying a key get a session for its owner, like Better Auth's
    /// `enableSessionForAPIKeys` (default off). Off, keys are only checked through
    /// `auth.api_keys().verify(..)`. On, every such request is a verification and counts
    /// against the key's rate limit and `remaining`.
    pub fn sessions(mut self, enabled: bool) -> Self {
        self.sessions = enabled;
        self
    }

    fn key_from(&self, headers: &HeaderMap) -> Option<String> {
        match &self.getter {
            Some(getter) => getter(headers),
            None => headers
                .get(&self.header)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
        }
        .filter(|key| !key.is_empty())
    }
}

impl Plugin for ApiKeys {
    const ID: &'static str = "api-key";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn schema(&self, schema: &mut SchemaBuilder) {
        schema.model::<ApiKey>();
    }

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.endpoint(CreateApiKey::client(self.clone()))
            .endpoint(GetApiKey::client())
            .endpoint(UpdateApiKey::client(self.clone()))
            .endpoint(DeleteApiKey::client())
            .endpoint(ListApiKeys::client())
            .errors::<ApiKeyError>();
        if self.sessions {
            app.session_resolver(verify::KeyResolver(self.clone()));
        }
    }
}

/// Emitted when a key is created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiKeyCreated {
    pub id: Id,
    pub user_id: Id,
}

/// Emitted when a key is deleted through `/api-key/delete`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiKeyDeleted {
    pub id: Id,
    pub user_id: Id,
}

impl Event for ApiKeyCreated {}
impl Event for ApiKeyDeleted {}

/// `auth.api_keys()`: the server API. Only compiles on an `Auth` with `ApiKeys` registered.
pub trait ApiKeysExt: AuthInstance + Sized {
    fn api_keys<I>(&self) -> ApiKeysApi<'_, Self>
    where
        Self: HasPlugin<ApiKeys, I>,
    {
        ApiKeysApi {
            auth: self,
            plugin: self.plugin_arc().clone(),
            headers: HeaderMap::new(),
        }
    }
}

impl<A: AuthInstance> ApiKeysExt for A {}

/// Calls the API key endpoints without HTTP, as the server: server-only fields are accepted,
/// and `user_id` names the owner when no session is passed with `headers`.
pub struct ApiKeysApi<'a, A> {
    auth: &'a A,
    plugin: Arc<ApiKeys>,
    headers: HeaderMap,
}

impl<A> std::fmt::Debug for ApiKeysApi<'_, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKeysApi")
    }
}

impl<A: AuthInstance> ApiKeysApi<'_, A> {
    /// Acts for the session in these request headers. A `user_id` in an input must then
    /// name the same user.
    pub fn headers(mut self, headers: &HeaderMap) -> Self {
        self.headers = headers.clone();
        self
    }

    async fn call<E: Endpoint<A::Db>>(
        &self,
        endpoint: &E,
        input: E::Input,
    ) -> Result<E::Output, AuthError> {
        Ok(self
            .auth
            .api()
            .headers(&self.headers)
            .call(endpoint, input)
            .await?
            .data)
    }

    /// Creates a key. The response's `key` is the only copy of it.
    pub async fn create(&self, input: CreateApiKeyInput) -> Result<CreatedApiKey, AuthError> {
        self.call(&CreateApiKey::server(self.plugin.clone()), input)
            .await
    }

    /// Verifies `key` and counts the use against its limits. A refused key is
    /// `Ok` with `valid: false` and the error; `Err` is for failures unrelated to the key.
    pub async fn verify(
        &self,
        key: &str,
        permissions: Option<Permissions>,
    ) -> Result<VerifyOutput, AuthError> {
        let input = VerifyApiKeyInput {
            key: key.to_owned(),
            permissions,
        };
        self.call(&VerifyApiKey(self.plugin.clone()), input).await
    }

    /// One key of its owner.
    pub async fn get(&self, input: GetApiKeyInput) -> Result<ApiKeyView, AuthError> {
        self.call(&GetApiKey::server(), input).await
    }

    /// Changes a key.
    pub async fn update(&self, input: UpdateApiKeyInput) -> Result<ApiKeyView, AuthError> {
        self.call(&UpdateApiKey::server(self.plugin.clone()), input)
            .await
    }

    /// Deletes a key.
    pub async fn delete(&self, input: DeleteApiKeyInput) -> Result<Success, AuthError> {
        self.call(&DeleteApiKey::server(), input).await
    }

    /// The keys of one owner.
    pub async fn list(&self, input: ListApiKeysInput) -> Result<ApiKeyList, AuthError> {
        self.call(&ListApiKeys::server(), input).await
    }

    /// Deletes every expired key.
    pub async fn delete_all_expired(&self) -> Result<DeleteExpiredOutput, AuthError> {
        self.call(&DeleteAllExpiredApiKeys, Empty {}).await
    }
}
