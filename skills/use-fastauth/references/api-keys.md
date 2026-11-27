# API keys (feature `api-key`)

```rust
use axum::Json;
use fastauth::plugins::api_key::{ApiKeys, ApiKeysExt, CreateApiKeyInput, Permissions};
use fastauth::prelude::*;
use serde_json::{Value, json};

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![ApiKeys]>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .plugin(ApiKeys::new().default_prefix("acme_").sessions(true))
        .build()
}

// With .sessions(true), x-api-key: <key> signs the request in as the key's owner.
pub async fn me(session: Session<AppAuth>) -> Json<Value> {
    Json(json!({ "id": session.user.id, "viaApiKey": session.view().ephemeral }))
}

pub async fn issue_key(auth: &AppAuth, user_id: Id) -> Result<String, AuthError> {
    let created = auth
        .api_keys()
        .create(CreateApiKeyInput {
            name: Some("deploy".into()),
            user_id: Some(user_id),
            permissions: Some(Permissions::from([("deploys".to_owned(), vec!["create".to_owned()])])),
            ..Default::default()
        })
        .await?;
    Ok(created.key)
}

pub async fn can_deploy(auth: &AppAuth, key: &str) -> Result<bool, AuthError> {
    let wanted = Permissions::from([("deploys".to_owned(), vec!["create".to_owned()])]);
    Ok(auth.api_keys().verify(key, Some(wanted)).await?.valid)
}
```

Full page: `docs/plugins/tokens/03-api-keys.md`.

## Setup

- `fastauth = { version = "0.7", features = ["api-key"] }`; path `fastauth::plugins::api_key`.
- Add `ApiKeys` to `.plugin(..)` and to the `plugins![..]` alias, in registration order.
- It adds the `apikey` table (`key_hash`, `start`, `prefix`, `permissions`, `remaining`,
  `refill_*`, `rate_limit_*`, `request_count`, `metadata`, ...). Run migrations after adding
  it. There's no `api_key` table and no `scopes` column.
- Defaults match Better Auth: 64 random letters, no prefix, `start` = first 6 characters,
  no expiry, `expiresIn` between 1 and 365 days, metadata off, 10 requests per day per key,
  sessions off.
- A magic link, email code, password reset, verification link or social sign-in that claims
  an unverified user deletes that user's keys, inside the claim's transaction (`on_claim`).

## Routes (under `/api/auth`, session required)

- `POST /api-key/create` `{ name?, expiresIn? (s), prefix?, metadata? }`: returns the key in
  `key`, once. Store or show it then; it can't be read back.
- `GET /api-key/get?id=`, `POST /api-key/update` `{ keyId, name?, enabled?, expiresIn?, metadata? }`,
  `POST /api-key/delete` `{ keyId }`, `GET /api-key/list` `?limit&offset&sortBy&sortDirection`.
  A user only sees their own keys; others' are `404 KEY_NOT_FOUND`.
- Server-only fields (`remaining`, `refillAmount`, `refillInterval`, `rateLimitEnabled`,
  `rateLimitTimeWindow`, `rateLimitMax`, `permissions`) answer `400 SERVER_ONLY_PROPERTY` over
  HTTP. A client `userId` answers `401 UNAUTHORIZED_SESSION`.
- `/api-key/verify` and `/api-key/delete-all-expired-api-keys` have no HTTP route (404).
- Responses use Better Auth's shape: camelCase, owner in `referenceId` and `userId`,
  `configId: "default"`, never the key or its hash.

## Server API (`ApiKeysExt`)

- `auth.api_keys()`: `create`, `verify`, `get`, `update`, `delete`, `list`,
  `delete_all_expired`. Only compiles with `ApiKeys` in the alias.
- Set `user_id` on each input to name the owner, or call `.headers(&headers)` to act for the
  request's session (then `user_id` must match). Server-only fields are accepted here.
- `UpdateApiKeyInput::new(key_id)` then set fields; `Some(None)` clears `expires_in`,
  `metadata`, `permissions`.
- `verify(key, perms)` returns `Ok` with `valid: false` and `error.code` for a bad key;
  `Err` only for other failures. It counts as a use (`remaining`, rate limit).
- `verify` with `Some(perms)` needs every listed action of every listed resource; an empty map
  or a key with no permissions fails with `KEY_NOT_FOUND`. Names are yours; `"*"` is literal.
- Run `delete_all_expired()` on a schedule; only used keys are cleaned up on their own.

## Sessions from keys (`.sessions(true)`)

- Off by default. On, `x-api-key` (or `.header(name)`, or `.key_getter(|headers| ..)`)
  gives the request an ephemeral session for the owner, so `Session<AppAuth>` and
  `/get-session` work. No extra extractors.
- Every such request is a verification: the default 10 per day per key means the 11th
  request gets `429 RATE_LIMITED`. Use `.rate_limit(window, max)` (new keys only),
  `rate_limit_*` on one key via `update`, or `.disable_rate_limit()` (all keys).
- A session cookie wins: with one, the key isn't read.
- A bad key fails the request even on `Option<Session<_>>` routes (401 `INVALID_API_KEY`,
  `KEY_DISABLED`, ...); shorter than `key_length` is 403.
- The session isn't stored, `session.session.id == "ephemeral"`, `FreshSession` accepts it,
  and permissions aren't checked. To enforce permissions, keep sessions off for that route
  and call `verify` with them.
- A `key_getter` on `Authorization: Bearer` should return only your own keys (check the
  prefix); anything it returns is verified and can fail the request.

## Events and errors

- Events: `ApiKeyCreated { id, user_id }` and `ApiKeyDeleted { id, user_id }` (only for
  `delete`; expiry, used-up keys and `delete_all_expired` emit nothing).
- Codes are Better Auth's: `INVALID_API_KEY`, `KEY_NOT_FOUND`, `KEY_DISABLED`,
  `KEY_EXPIRED`, `USAGE_EXCEEDED` (429), `RATE_LIMITED` (429, `details.tryAgainIn` from
  `verify`), `SERVER_ONLY_PROPERTY`, `UNAUTHORIZED_SESSION`, `METADATA_DISABLED`,
  `NAME_REQUIRED`, `NO_VALUES_TO_UPDATE`, ...

## Client

- `import { apiKeyClient } from "@better-auth/api-key/client"` (1.7.28), then
  `authClient.apiKey.create/get/update/delete/list`.
