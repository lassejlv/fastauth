//! The `/api-key/*` endpoints, their inputs and outputs.

use fastauth_core::plugin_prelude::*;
use serde::Deserializer;

use crate::model::{ApiKey, Permissions};
use crate::verify::{Failure, verify};
use crate::{ApiKeyCreated, ApiKeyDeleted, ApiKeyError, ApiKeys};

const NAME_LENGTH: std::ops::RangeInclusive<usize> = 1..=32;
const PREFIX_LENGTH: std::ops::RangeInclusive<usize> = 1..=32;
const KEY_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// An API key as clients see it: every column except the hash, camelCase, with the owner
/// as `referenceId` (and `userId`) like Better Auth.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyView {
    pub id: Id,
    /// Always `"default"`: fastauth has one key configuration.
    pub config_id: &'static str,
    pub name: Option<String>,
    pub start: Option<String>,
    pub prefix: Option<String>,
    pub reference_id: Id,
    pub user_id: Id,
    pub refill_interval: Option<i64>,
    pub refill_amount: Option<i64>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_refill_at: Option<OffsetDateTime>,
    pub enabled: bool,
    pub rate_limit_enabled: bool,
    pub rate_limit_time_window: Option<i64>,
    pub rate_limit_max: Option<i64>,
    pub request_count: i64,
    pub remaining: Option<i64>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_request: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub metadata: Option<serde_json::Value>,
    pub permissions: Option<Permissions>,
}

impl From<ApiKey> for ApiKeyView {
    fn from(key: ApiKey) -> Self {
        Self {
            id: key.id,
            config_id: "default",
            name: key.name,
            start: key.start,
            prefix: key.prefix,
            reference_id: key.user_id.clone(),
            user_id: key.user_id,
            refill_interval: key.refill_interval,
            refill_amount: key.refill_amount,
            last_refill_at: key.last_refill_at,
            enabled: key.enabled,
            rate_limit_enabled: key.rate_limit_enabled,
            rate_limit_time_window: key.rate_limit_time_window,
            rate_limit_max: key.rate_limit_max,
            request_count: key.request_count,
            remaining: key.remaining,
            last_request: key.last_request,
            expires_at: key.expires_at,
            created_at: key.created_at,
            updated_at: key.updated_at,
            metadata: key.metadata.map(|m| m.0).filter(|m| !m.is_null()),
            permissions: key.permissions.map(|p| p.0),
        }
    }
}

/// `{ "success": true }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Success {
    pub success: bool,
}

/// `Some(None)` for an explicit `null`, `None` when the field is absent.
fn double_option<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(deserializer).map(Some)
}

fn invalid(message: &'static str) -> AuthError {
    AuthError::bad_request(codes::INVALID_BODY, message)
}

/// Who the request acts for. Client requests use the session and may not name a user;
/// server calls use the session, or `userId` when there is none.
fn owner(
    session: Option<&SessionView>,
    user_id: Option<Id>,
    trusted: bool,
    missing: AuthError,
) -> Result<Id, AuthError> {
    let session = session.map(|s| s.user.id.clone());
    if !trusted {
        if user_id.is_some() {
            return Err(ApiKeyError::UnauthorizedSession.into());
        }
        return session.ok_or(missing);
    }
    match (session, user_id) {
        (Some(session), Some(user)) if session != user => {
            Err(ApiKeyError::UnauthorizedSession.into())
        }
        (Some(id), _) | (None, Some(id)) => Ok(id),
        (None, None) => Err(ApiKeyError::UnauthorizedSession.into()),
    }
}

/// The caller's key `id`, or `KEY_NOT_FOUND` (also for another user's key).
async fn owned_key<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    id: &Id,
    owner: &Id,
) -> Result<ApiKey, AuthError> {
    ctx.db()
        .find::<ApiKey>(ApiKey::ID.eq(id))
        .one()
        .await?
        .filter(|key| &key.user_id == owner)
        .ok_or_else(|| ApiKeyError::KeyNotFound.into())
}

fn check_expires_in(plugin: &ApiKeys, seconds: i64) -> Result<Duration, AuthError> {
    if seconds < 1 {
        return Err(invalid("expiresIn must be at least 1"));
    }
    let expires_in = Duration::seconds(seconds);
    if expires_in < plugin.min_expires_in {
        return Err(ApiKeyError::ExpiresInIsTooSmall.into());
    }
    if expires_in > plugin.max_expires_in {
        return Err(ApiKeyError::ExpiresInIsTooLarge.into());
    }
    Ok(expires_in)
}

fn check_name(name: &str) -> Result<(), AuthError> {
    if NAME_LENGTH.contains(&name.chars().count()) {
        Ok(())
    } else {
        Err(ApiKeyError::InvalidNameLength.into())
    }
}

fn check_refill(amount: Option<i64>, interval: Option<i64>) -> Result<(), AuthError> {
    match (amount, interval) {
        (Some(_), None) => Err(ApiKeyError::RefillAmountAndIntervalRequired.into()),
        (None, Some(_)) => Err(ApiKeyError::RefillIntervalAndAmountRequired.into()),
        (Some(amount), _) if amount < 1 => Err(invalid("refillAmount must be at least 1")),
        _ => Ok(()),
    }
}

fn check_non_negative(values: &[Option<i64>]) -> Result<(), AuthError> {
    if values.iter().flatten().any(|v| *v < 0) {
        return Err(invalid("numbers must not be negative"));
    }
    Ok(())
}

/// `POST /api-key/create`.
#[derive(Clone, Debug)]
pub struct CreateApiKey {
    plugin: Arc<ApiKeys>,
    trusted: bool,
}

impl CreateApiKey {
    /// The HTTP route: server-only fields are refused, the session owns the key.
    pub fn client(plugin: Arc<ApiKeys>) -> Self {
        Self {
            plugin,
            trusted: false,
        }
    }

    /// The server API: every field is accepted, and `userId` names the owner when there is
    /// no session.
    pub fn server(plugin: Arc<ApiKeys>) -> Self {
        Self {
            plugin,
            trusted: true,
        }
    }
}

/// The body of `/api-key/create`. Fields marked server-only answer `SERVER_ONLY_PROPERTY`
/// when they come from a client.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateApiKeyInput {
    pub name: Option<String>,
    /// Seconds until the key expires. Default: the plugin's `default_expires_in`.
    pub expires_in: Option<i64>,
    /// Overrides the plugin's default prefix: letters, digits, `_` and `-`.
    pub prefix: Option<String>,
    /// Requires `enable_metadata`; must be a JSON object.
    pub metadata: Option<serde_json::Value>,
    /// Server-only. Verifications allowed before the key is used up.
    pub remaining: Option<i64>,
    /// Server-only, with `refill_interval`.
    pub refill_amount: Option<i64>,
    /// Server-only, milliseconds, with `refill_amount`.
    pub refill_interval: Option<i64>,
    /// Server-only, milliseconds.
    pub rate_limit_time_window: Option<i64>,
    /// Server-only.
    pub rate_limit_max: Option<i64>,
    /// Server-only.
    pub rate_limit_enabled: Option<bool>,
    /// Server-only.
    pub permissions: Option<Permissions>,
    /// Server-only: the owner when there is no session.
    pub user_id: Option<Id>,
}

/// The created key plus the full `key`, the only time it is shown.
#[derive(Clone, Debug, Serialize)]
pub struct CreatedApiKey {
    #[serde(flatten)]
    pub api_key: ApiKeyView,
    pub key: String,
}

impl<D: Adapter> Endpoint<D> for CreateApiKey {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/api-key/create";
    type Access = MaybeAuthenticated;
    type Input = CreateApiKeyInput;
    type Output = CreatedApiKey;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: CreateApiKeyInput,
    ) -> Result<CreatedApiKey, AuthError> {
        let plugin = &self.plugin;
        let server_only = input.remaining.is_some()
            || input.refill_amount.is_some()
            || input.refill_interval.is_some()
            || input.rate_limit_time_window.is_some()
            || input.rate_limit_max.is_some()
            || input.rate_limit_enabled.is_some()
            || input.permissions.is_some();
        if !self.trusted && server_only {
            return Err(ApiKeyError::ServerOnlyProperty.into());
        }
        let user_id = owner(
            ctx.session(),
            input.user_id,
            self.trusted,
            ApiKeyError::UnauthorizedSession.into(),
        )?;
        let metadata = input.metadata.filter(|m| !m.is_null());
        if let Some(metadata) = &metadata {
            if !plugin.enable_metadata {
                return Err(ApiKeyError::MetadataDisabled.into());
            }
            if !metadata.is_object() {
                return Err(ApiKeyError::InvalidMetadataType.into());
            }
        }
        check_refill(input.refill_amount, input.refill_interval)?;
        check_non_negative(&[
            input.remaining,
            input.refill_interval,
            input.rate_limit_time_window,
            input.rate_limit_max,
        ])?;
        let expires_in = input
            .expires_in
            .map(|seconds| check_expires_in(plugin, seconds))
            .transpose()?;
        if let Some(prefix) = &input.prefix {
            if !PREFIX_LENGTH.contains(&prefix.len()) {
                return Err(ApiKeyError::InvalidPrefixLength.into());
            }
            if !prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return Err(invalid(
                    "Invalid prefix format, must be alphanumeric and contain only underscores and hyphens.",
                ));
            }
        }
        match &input.name {
            Some(name) => check_name(name)?,
            None if plugin.require_name => return Err(ApiKeyError::NameRequired.into()),
            None => {}
        }

        let prefix = input.prefix.or_else(|| plugin.default_prefix.clone());
        let key = format!(
            "{}{}",
            prefix.as_deref().unwrap_or(""),
            random_string(plugin.key_length, KEY_ALPHABET)
        );
        let start =
            (plugin.start_length > 0).then(|| key.chars().take(plugin.start_length).collect());
        let now = ctx.now();
        let row = ApiKey {
            id: ctx.new_id()?,
            name: input.name,
            start,
            prefix,
            key_hash: Hash::sha256(&key),
            user_id,
            enabled: true,
            expires_at: expires_in
                .or(plugin.default_expires_in)
                .map(|ttl| now + ttl),
            rate_limit_enabled: input
                .rate_limit_enabled
                .unwrap_or(plugin.rate_limit.enabled),
            rate_limit_time_window: Some(
                input
                    .rate_limit_time_window
                    .unwrap_or(plugin.rate_limit.window.whole_milliseconds() as i64),
            ),
            rate_limit_max: Some(input.rate_limit_max.unwrap_or(plugin.rate_limit.max)),
            request_count: 0,
            last_request: None,
            remaining: input.remaining.or(input.refill_amount),
            refill_amount: input.refill_amount,
            refill_interval: input.refill_interval,
            last_refill_at: None,
            permissions: input
                .permissions
                .or_else(|| plugin.default_permissions.clone())
                .map(Json),
            metadata: metadata.map(Json),
            created_at: now,
            updated_at: now,
        };
        let row = ctx.db().insert(&row).await?;
        ctx.emit(ApiKeyCreated {
            id: row.id.clone(),
            user_id: row.user_id.clone(),
        });
        Ok(CreatedApiKey {
            api_key: row.into(),
            key,
        })
    }
}

/// `GET /api-key/get?id=..`.
#[derive(Clone, Copy, Debug)]
pub struct GetApiKey {
    trusted: bool,
}

impl GetApiKey {
    /// The HTTP route: the session's own keys only.
    pub fn client() -> Self {
        Self { trusted: false }
    }

    /// The server API: `userId` names the owner when there is no session.
    pub fn server() -> Self {
        Self { trusted: true }
    }
}

/// The query of `/api-key/get`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetApiKeyInput {
    pub id: Id,
    /// Server-only: the owner when there is no session.
    #[serde(default)]
    pub user_id: Option<Id>,
}

impl<D: Adapter> Endpoint<D> for GetApiKey {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/api-key/get";
    type Access = MaybeAuthenticated;
    type Input = GetApiKeyInput;
    type Output = ApiKeyView;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: GetApiKeyInput,
    ) -> Result<ApiKeyView, AuthError> {
        let owner = owner(
            ctx.session(),
            input.user_id,
            self.trusted,
            AuthError::unauthorized(),
        )?;
        Ok(owned_key(&ctx, &input.id, &owner).await?.into())
    }
}

/// `POST /api-key/update`.
#[derive(Clone, Debug)]
pub struct UpdateApiKey {
    plugin: Arc<ApiKeys>,
    trusted: bool,
}

impl UpdateApiKey {
    /// The HTTP route: server-only fields are refused.
    pub fn client(plugin: Arc<ApiKeys>) -> Self {
        Self {
            plugin,
            trusted: false,
        }
    }

    /// The server API: every field is accepted.
    pub fn server(plugin: Arc<ApiKeys>) -> Self {
        Self {
            plugin,
            trusted: true,
        }
    }
}

/// The body of `/api-key/update`. Absent fields are left alone. `Some(None)` (JSON
/// `null`) clears `expires_in`, `metadata` and `permissions`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateApiKeyInput {
    pub key_id: Id,
    /// Server-only: the owner when there is no session.
    #[serde(default)]
    pub user_id: Option<Id>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Seconds from now; `null` removes the expiry.
    #[serde(default, deserialize_with = "double_option")]
    pub expires_in: Option<Option<i64>>,
    /// Ignored unless `enable_metadata` is on.
    #[serde(default, deserialize_with = "double_option")]
    pub metadata: Option<Option<serde_json::Value>>,
    /// Server-only, at least 1.
    #[serde(default)]
    pub remaining: Option<i64>,
    /// Server-only, with `refill_interval`.
    #[serde(default)]
    pub refill_amount: Option<i64>,
    /// Server-only, with `refill_amount`.
    #[serde(default)]
    pub refill_interval: Option<i64>,
    /// Server-only.
    #[serde(default)]
    pub rate_limit_enabled: Option<bool>,
    /// Server-only.
    #[serde(default)]
    pub rate_limit_time_window: Option<i64>,
    /// Server-only.
    #[serde(default)]
    pub rate_limit_max: Option<i64>,
    /// Server-only.
    #[serde(default, deserialize_with = "double_option")]
    pub permissions: Option<Option<Permissions>>,
}

impl UpdateApiKeyInput {
    /// An update of `key_id` that changes nothing yet.
    pub fn new(key_id: impl Into<Id>) -> Self {
        Self {
            key_id: key_id.into(),
            user_id: None,
            name: None,
            enabled: None,
            expires_in: None,
            metadata: None,
            remaining: None,
            refill_amount: None,
            refill_interval: None,
            rate_limit_enabled: None,
            rate_limit_time_window: None,
            rate_limit_max: None,
            permissions: None,
        }
    }
}

impl<D: Adapter> Endpoint<D> for UpdateApiKey {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/api-key/update";
    type Access = MaybeAuthenticated;
    type Input = UpdateApiKeyInput;
    type Output = ApiKeyView;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: UpdateApiKeyInput,
    ) -> Result<ApiKeyView, AuthError> {
        let owner = owner(
            ctx.session(),
            input.user_id,
            self.trusted,
            ApiKeyError::UnauthorizedSession.into(),
        )?;
        let server_only = input.remaining.is_some()
            || input.refill_amount.is_some()
            || input.refill_interval.is_some()
            || input.rate_limit_enabled.is_some()
            || input.rate_limit_time_window.is_some()
            || input.rate_limit_max.is_some()
            || input.permissions.is_some();
        if !self.trusted && server_only {
            return Err(ApiKeyError::ServerOnlyProperty.into());
        }
        let key = owned_key(&ctx, &input.key_id, &owner).await?;

        let mut changed = false;
        let mut update = ctx.db().update::<ApiKey>(ApiKey::ID.eq(&key.id));
        if let Some(name) = input.name {
            check_name(&name)?;
            update = update.set(ApiKey::NAME, Some(name));
            changed = true;
        }
        if let Some(enabled) = input.enabled {
            update = update.set(ApiKey::ENABLED, enabled);
            changed = true;
        }
        if let Some(expires_in) = input.expires_in {
            let expires_at = expires_in
                .map(|seconds| check_expires_in(&self.plugin, seconds))
                .transpose()?
                .map(|ttl| ctx.now() + ttl);
            update = update.set(ApiKey::EXPIRES_AT, expires_at);
            changed = true;
        }
        if let Some(metadata) = input.metadata.filter(|_| self.plugin.enable_metadata) {
            let metadata = metadata.filter(|m| !m.is_null());
            if metadata.as_ref().is_some_and(|m| !m.is_object()) {
                return Err(ApiKeyError::InvalidMetadataType.into());
            }
            update = update.set(ApiKey::METADATA, metadata.map(Json));
            changed = true;
        }
        if let Some(remaining) = input.remaining {
            if remaining < 1 {
                return Err(invalid("remaining must be at least 1"));
            }
            update = update.set(ApiKey::REMAINING, Some(remaining));
            changed = true;
        }
        if input.refill_amount.is_some() || input.refill_interval.is_some() {
            check_refill(input.refill_amount, input.refill_interval)?;
            check_non_negative(&[input.refill_interval])?;
            update = update
                .set(ApiKey::REFILL_AMOUNT, input.refill_amount)
                .set(ApiKey::REFILL_INTERVAL, input.refill_interval);
            changed = true;
        }
        check_non_negative(&[input.rate_limit_time_window, input.rate_limit_max])?;
        if let Some(enabled) = input.rate_limit_enabled {
            update = update.set(ApiKey::RATE_LIMIT_ENABLED, enabled);
            changed = true;
        }
        if let Some(window) = input.rate_limit_time_window {
            update = update.set(ApiKey::RATE_LIMIT_TIME_WINDOW, Some(window));
            changed = true;
        }
        if let Some(max) = input.rate_limit_max {
            update = update.set(ApiKey::RATE_LIMIT_MAX, Some(max));
            changed = true;
        }
        if let Some(permissions) = input.permissions {
            update = update.set(ApiKey::PERMISSIONS, permissions.map(Json));
            changed = true;
        }
        if !changed {
            return Err(ApiKeyError::NoValuesToUpdate.into());
        }
        update.exec().await?;
        Ok(owned_key(&ctx, &key.id, &owner).await?.into())
    }
}

/// `POST /api-key/delete`.
#[derive(Clone, Copy, Debug)]
pub struct DeleteApiKey {
    trusted: bool,
}

impl DeleteApiKey {
    /// The HTTP route: the session's own keys only.
    pub fn client() -> Self {
        Self { trusted: false }
    }

    /// The server API: `userId` names the owner when there is no session.
    pub fn server() -> Self {
        Self { trusted: true }
    }
}

/// The body of `/api-key/delete`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteApiKeyInput {
    pub key_id: Id,
    /// Server-only: the owner when there is no session.
    #[serde(default)]
    pub user_id: Option<Id>,
}

impl<D: Adapter> Endpoint<D> for DeleteApiKey {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/api-key/delete";
    type Access = MaybeAuthenticated;
    type Input = DeleteApiKeyInput;
    type Output = Success;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: DeleteApiKeyInput,
    ) -> Result<Success, AuthError> {
        let owner = owner(
            ctx.session(),
            input.user_id,
            self.trusted,
            AuthError::unauthorized(),
        )?;
        let key = owned_key(&ctx, &input.key_id, &owner).await?;
        ctx.db().delete::<ApiKey>(ApiKey::ID.eq(&key.id)).await?;
        ctx.emit(ApiKeyDeleted {
            id: key.id,
            user_id: key.user_id,
        });
        Ok(Success { success: true })
    }
}

/// `GET /api-key/list`.
#[derive(Clone, Copy, Debug)]
pub struct ListApiKeys {
    trusted: bool,
}

impl ListApiKeys {
    /// The HTTP route: the session's own keys.
    pub fn client() -> Self {
        Self { trusted: false }
    }

    /// The server API: `userId` names the owner when there is no session.
    pub fn server() -> Self {
        Self { trusted: true }
    }
}

/// Sort order for `/api-key/list`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    #[default]
    Asc,
    Desc,
}

/// The query of `/api-key/list`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListApiKeysInput {
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    /// A field name: `createdAt` (the default), `updatedAt`, `name`, `expiresAt`,
    /// `lastRequest`, `remaining`, `requestCount` or `enabled`.
    pub sort_by: Option<String>,
    pub sort_direction: Option<SortDirection>,
    /// Server-only: the owner when there is no session.
    pub user_id: Option<Id>,
}

/// `{ "apiKeys": [..], "total": n, "limit": .., "offset": .. }`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyList {
    pub api_keys: Vec<ApiKeyView>,
    /// Every key the owner has, ignoring `limit` and `offset`.
    pub total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

impl<D: Adapter> Endpoint<D> for ListApiKeys {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/api-key/list";
    type Access = MaybeAuthenticated;
    type Input = ListApiKeysInput;
    type Output = ApiKeyList;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: ListApiKeysInput,
    ) -> Result<ApiKeyList, AuthError> {
        let owner = owner(
            ctx.session(),
            input.user_id,
            self.trusted,
            AuthError::unauthorized(),
        )?;
        let column = match input.sort_by.as_deref().unwrap_or("createdAt") {
            "createdAt" => ApiKey::CREATED_AT.name(),
            "updatedAt" => ApiKey::UPDATED_AT.name(),
            "name" => ApiKey::NAME.name(),
            "expiresAt" => ApiKey::EXPIRES_AT.name(),
            "lastRequest" => ApiKey::LAST_REQUEST.name(),
            "remaining" => ApiKey::REMAINING.name(),
            "requestCount" => ApiKey::REQUEST_COUNT.name(),
            "enabled" => ApiKey::ENABLED.name(),
            _ => return Err(invalid("sortBy names an unknown field")),
        };
        let order = match input.sort_direction.unwrap_or_default() {
            SortDirection::Asc => Order::Asc,
            SortDirection::Desc => Order::Desc,
        };
        let db = ctx.db();
        let mut find = db
            .find::<ApiKey>(ApiKey::USER_ID.eq(&owner))
            .order_by((column, order));
        if let Some(limit) = input.limit {
            find = find.limit(limit);
        }
        if let Some(offset) = input.offset {
            find = find.offset(offset);
        }
        let keys = find.all().await?;
        let total = db.count::<ApiKey>(ApiKey::USER_ID.eq(&owner)).await?;
        Ok(ApiKeyList {
            api_keys: keys.into_iter().map(ApiKeyView::from).collect(),
            total,
            limit: input.limit,
            offset: input.offset,
        })
    }
}

/// `/api-key/verify`. Server-only, like Better Auth: not routed over HTTP, called through
/// `auth.api_keys().verify(..)`.
#[derive(Clone, Debug)]
pub struct VerifyApiKey(pub Arc<ApiKeys>);

/// The input of `/api-key/verify`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyApiKeyInput {
    pub key: String,
    /// Every action of every resource listed must be granted to the key.
    #[serde(default)]
    pub permissions: Option<Permissions>,
}

/// Why verification failed: Better Auth's `{ "message", "code" }`, plus
/// `details.tryAgainIn` (milliseconds) for `RATE_LIMITED`.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct VerifyError {
    pub message: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// `{ "valid": true, "error": null, "key": {..} }`, or `valid: false` with an error and
/// `key: null`.
#[derive(Clone, Debug, Serialize)]
pub struct VerifyOutput {
    pub valid: bool,
    pub error: Option<VerifyError>,
    pub key: Option<ApiKeyView>,
}

impl<D: Adapter> Endpoint<D> for VerifyApiKey {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/api-key/verify";
    type Access = Public;
    type Input = VerifyApiKeyInput;
    type Output = VerifyOutput;

    async fn call(&self, ctx: Ctx<D>, input: VerifyApiKeyInput) -> Result<VerifyOutput, AuthError> {
        match verify(&ctx, &self.0, &input.key, input.permissions.as_ref()).await {
            Ok(key) => Ok(VerifyOutput {
                valid: true,
                error: None,
                key: Some(key.into()),
            }),
            Err(Failure::Key {
                error,
                try_again_in,
            }) => {
                let error = AuthError::from(error);
                Ok(VerifyOutput {
                    valid: false,
                    error: Some(VerifyError {
                        message: error.message().to_owned(),
                        code: error.code().to_owned(),
                        details: try_again_in.map(|ms| serde_json::json!({ "tryAgainIn": ms })),
                    }),
                    key: None,
                })
            }
            Err(Failure::Other(error)) => Err(error),
        }
    }
}

/// `/api-key/delete-all-expired-api-keys`. Server-only, like Better Auth.
#[derive(Clone, Copy, Debug)]
pub struct DeleteAllExpiredApiKeys;

/// `{ "success": true, "error": null }`.
#[derive(Clone, Debug, Serialize)]
pub struct DeleteExpiredOutput {
    pub success: bool,
    pub error: Option<String>,
    /// How many keys were deleted (a fastauth addition).
    pub deleted: u64,
}

impl<D: Adapter> Endpoint<D> for DeleteAllExpiredApiKeys {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/api-key/delete-all-expired-api-keys";
    type Access = Public;
    type Input = Empty;
    type Output = DeleteExpiredOutput;

    async fn call(&self, ctx: Ctx<D>, _: Empty) -> Result<DeleteExpiredOutput, AuthError> {
        let deleted = ctx
            .db()
            .delete::<ApiKey>(
                ApiKey::EXPIRES_AT
                    .is_not_null()
                    .and(ApiKey::EXPIRES_AT.lt(Some(ctx.now()))),
            )
            .await?;
        Ok(DeleteExpiredOutput {
            success: true,
            error: None,
            deleted,
        })
    }
}
