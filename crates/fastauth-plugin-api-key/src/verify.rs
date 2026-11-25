//! Key verification: the checks, the usage counters, and the session resolver built on them.

use fastauth_core::adapter::DbError;
use fastauth_core::model::Col;
use fastauth_core::plugin_prelude::*;
use fastauth_core::value::ColumnValue;

use crate::model::{ApiKey, Permissions};
use crate::{ApiKeyError, ApiKeys};

/// Why a key failed verification: a key error clients see (with the rate limit's retry
/// delay), or something else that went wrong.
pub(crate) enum Failure {
    Key {
        error: ApiKeyError,
        try_again_in: Option<i64>,
    },
    Other(AuthError),
}

impl From<ApiKeyError> for Failure {
    fn from(error: ApiKeyError) -> Self {
        Failure::Key {
            error,
            try_again_in: None,
        }
    }
}

impl From<AuthError> for Failure {
    fn from(error: AuthError) -> Self {
        Failure::Other(error)
    }
}

impl From<DbError> for Failure {
    fn from(error: DbError) -> Self {
        Failure::Other(error.into())
    }
}

impl From<Failure> for AuthError {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Key { error, .. } => error.into(),
            Failure::Other(error) => error,
        }
    }
}

/// The counters one successful verification writes.
#[derive(PartialEq)]
struct Usage {
    remaining: Option<i64>,
    last_refill_at: Option<OffsetDateTime>,
    request_count: i64,
    last_request: Option<OffsetDateTime>,
}

impl Usage {
    fn of(key: &ApiKey) -> Self {
        Self {
            remaining: key.remaining,
            last_refill_at: key.last_refill_at,
            request_count: key.request_count,
            last_request: key.last_request,
        }
    }
}

fn millis(ms: i64) -> Duration {
    Duration::milliseconds(ms)
}

/// What this verification does to `key`'s counters, or why it is refused. Pure: the caller
/// writes the result with a conditional update, and recomputes it from a fresh row when
/// another request changed the counters first.
fn consume(plugin: &ApiKeys, key: &ApiKey, now: OffsetDateTime) -> Result<Usage, Failure> {
    let mut usage = Usage::of(key);

    if let Some(remaining) = key.remaining {
        let refill = match (key.refill_interval, key.refill_amount) {
            (Some(interval), Some(amount)) if interval > 0 && amount > 0 => {
                let last = key.last_refill_at.unwrap_or(key.created_at);
                (now - last > millis(interval)).then_some(amount)
            }
            _ => None,
        };
        if let Some(amount) = refill {
            usage.remaining = Some(amount - 1);
            usage.last_refill_at = Some(now);
        } else if remaining > 0 {
            usage.remaining = Some(remaining - 1);
        } else {
            return Err(ApiKeyError::UsageExceeded.into());
        }
    }

    if !plugin.rate_limit.enabled || !key.rate_limit_enabled {
        usage.last_request = Some(now);
        return Ok(usage);
    }
    let (Some(window), Some(max)) = (key.rate_limit_time_window, key.rate_limit_max) else {
        return Ok(usage);
    };
    let since = key.last_request.map(|last| now - last);
    match since {
        Some(since) if since <= millis(window) && key.request_count >= max => {
            let wait = millis(window) - since;
            return Err(Failure::Key {
                error: ApiKeyError::RateLimited,
                try_again_in: Some(wait.whole_milliseconds().max(0) as i64),
            });
        }
        Some(since) if since <= millis(window) => usage.request_count = key.request_count + 1,
        _ => usage.request_count = 1,
    }
    usage.last_request = Some(now);
    Ok(usage)
}

/// `column = value`, or `column IS NULL` for `None`.
fn same<T: ColumnValue + Clone>(
    column: Col<ApiKey, Option<T>>,
    value: &Option<T>,
) -> Where<ApiKey> {
    match value {
        Some(v) => column.eq(Some(v.clone())),
        None => column.is_null(),
    }
}

/// Whether `granted` covers every action of every resource in `requested`. An empty request
/// is refused, as Better Auth's `role().authorize` does.
pub(crate) fn authorized(granted: &Permissions, requested: &Permissions) -> bool {
    !requested.is_empty()
        && requested.iter().all(|(resource, actions)| {
            granted
                .get(resource)
                .is_some_and(|allowed| actions.iter().all(|a| allowed.contains(a)))
        })
}

/// How many times a verification re-reads the row after losing a race before giving up.
/// Every lost race means another request's update went through, so this only runs out
/// under extreme contention on one key.
const MAX_ATTEMPTS: usize = 64;

/// Verifies `key`: it exists, is enabled and unexpired, has the requested permissions, has
/// usage left (refilling it when due) and is within its rate limit. Returns the row with the
/// counters this verification wrote.
///
/// The counters change with one conditional update that only applies while `remaining`,
/// `last_refill_at`, `request_count` and `last_request` still hold the values the decision
/// was made from (compare-and-swap). When another request got there first the update
/// matches no row, and the decision is made again from a fresh read. So concurrent
/// verifications can't spend the same unit of `remaining` or the same rate-limit slot, on
/// any adapter whose `UPDATE ... WHERE` is atomic per row, without needing increment
/// support in the adapter contract.
pub(crate) async fn verify<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    plugin: &ApiKeys,
    key: &str,
    permissions: Option<&Permissions>,
) -> Result<ApiKey, Failure> {
    let db = ctx.db();
    let Some(mut row) = db
        .find::<ApiKey>(ApiKey::KEY_HASH.eq(Hash::sha256(key)))
        .one()
        .await?
    else {
        return Err(ApiKeyError::InvalidApiKey.into());
    };
    if !row.enabled {
        return Err(ApiKeyError::KeyDisabled.into());
    }
    if row.expires_at.is_some_and(|at| ctx.now() > at) {
        db.delete::<ApiKey>(ApiKey::ID.eq(&row.id)).await?;
        return Err(ApiKeyError::KeyExpired.into());
    }
    if let Some(requested) = permissions {
        let granted = row.permissions.as_ref().map(|p| &p.0);
        if !granted.is_some_and(|granted| authorized(granted, requested)) {
            return Err(ApiKeyError::KeyNotFound.into());
        }
    }
    if row.remaining == Some(0) && row.refill_amount.is_none() {
        db.delete::<ApiKey>(ApiKey::ID.eq(&row.id)).await?;
        return Err(ApiKeyError::UsageExceeded.into());
    }

    for _ in 0..MAX_ATTEMPTS {
        let now = ctx.now();
        let usage = consume(plugin, &row, now)?;
        if usage == Usage::of(&row) {
            return Ok(row);
        }
        let guard = ApiKey::ID
            .eq(&row.id)
            .and(same(ApiKey::REMAINING, &row.remaining))
            .and(same(ApiKey::LAST_REFILL_AT, &row.last_refill_at))
            .and(ApiKey::REQUEST_COUNT.eq(row.request_count))
            .and(same(ApiKey::LAST_REQUEST, &row.last_request));
        let updated = db
            .update::<ApiKey>(guard)
            .set(ApiKey::REMAINING, usage.remaining)
            .set(ApiKey::LAST_REFILL_AT, usage.last_refill_at)
            .set(ApiKey::REQUEST_COUNT, usage.request_count)
            .set(ApiKey::LAST_REQUEST, usage.last_request)
            .set(ApiKey::UPDATED_AT, now)
            .exec()
            .await?;
        if updated == 1 {
            row.remaining = usage.remaining;
            row.last_refill_at = usage.last_refill_at;
            row.request_count = usage.request_count;
            row.last_request = usage.last_request;
            row.updated_at = now;
            return Ok(row);
        }
        row = db
            .find::<ApiKey>(ApiKey::ID.eq(&row.id))
            .one()
            .await?
            .ok_or(ApiKeyError::InvalidApiKey)?;
    }
    Err(ApiKeyError::FailedToUpdateApiKey.into())
}

/// Turns the configured header (or the custom getter's value) into an ephemeral session for
/// the key's owner. Requests without one pass through untouched.
pub(crate) struct KeyResolver(pub(crate) Arc<ApiKeys>);

impl<D: Adapter> SessionResolver<D> for KeyResolver {
    async fn resolve(
        &self,
        ctx: &Ctx<D>,
        headers: &HeaderMap,
    ) -> Result<Option<Resolved>, AuthError> {
        let Some(key) = self.0.key_from(headers) else {
            return Ok(None);
        };
        if key.len() < self.0.key_length {
            return Err(AuthError::new(
                StatusCode::FORBIDDEN,
                "INVALID_API_KEY",
                "Invalid API key.",
            ));
        }
        let row = verify(ctx, &self.0, &key, None).await?;
        Ok(Some(Resolved::User(row.user_id)))
    }
}
