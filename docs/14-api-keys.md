# API keys

The `ApiKeys` plugin gives each user API keys for scripts, CI and other services. It
matches Better Auth's `apiKey` plugin, including its routes, JSON and error codes, so the
`@better-auth/api-key` client works unchanged. Keys can expire, run out of uses and refill,
carry per-key rate limits and permissions, and can optionally sign a request in as their
owner.

## Setup

Turn on the facade's `api-key` feature:

```toml
[dependencies]
fastauth = { version = "0.3", features = ["api-key"] }
```

or `cargo add fastauth --features api-key`. The plugin lives at
`fastauth::plugins::api_key` (crate `fastauth-plugin-api-key`).

Register it on the builder and list it in your `Auth` alias:

```rust
use fastauth::plugins::api_key::ApiKeys;
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![ApiKeys]>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .plugin(ApiKeys::new().default_prefix("acme_"))
        .build()
}
```

With other plugins, the alias lists them in registration order, for example
`plugins![TwoFactor, Organization, Admin, ApiKeys]` ([Plugins](05-plugins.md#using-plugins)).
`ApiKeys` depends on no other plugin.

### The `apikey` table

The plugin adds one table, `apikey`. Run migrations after adding it, at startup or with
your `fastauth` binary ([Migrations](06-database.md#migrations)):

```rust
let auth = build(pool)?;
auth.migrator().run().await?;
```

`cargo run --bin fastauth -- schema` prints it:

```
apikey
  id                        id         api-key primary key
  name                      text       api-key nullable
  start                     text       api-key nullable
  prefix                    text       api-key nullable
  key_hash                  bytes      api-key unique
  user_id                   id         api-key -> user.id on delete cascade, index
  enabled                   bool       api-key default true
  expires_at                timestamp  api-key nullable
  rate_limit_enabled        bool       api-key default true
  rate_limit_time_window    int        api-key nullable
  rate_limit_max            int        api-key nullable
  request_count             int        api-key default 0
  last_request              timestamp  api-key nullable
  remaining                 int        api-key nullable
  refill_amount             int        api-key nullable
  refill_interval           int        api-key nullable
  last_refill_at            timestamp  api-key nullable
  permissions               json       api-key nullable
  metadata                  json       api-key nullable
  created_at                timestamp  api-key default now
  updated_at                timestamp  api-key default now
```

| Column | Meaning |
|---|---|
| `name` | A label the owner picks, 1 to 32 characters |
| `start` | The key's first characters (6 by default, prefix included), so owners can tell keys apart |
| `prefix` | The prefix the key starts with, if any |
| `key_hash` | SHA-256 of the full key. The key itself is never stored |
| `user_id` | The owner. Deleting the user deletes their keys |
| `enabled` | A disabled key fails with `KEY_DISABLED` |
| `expires_at` | After this, the key fails with `KEY_EXPIRED` and is deleted |
| `rate_limit_enabled`, `rate_limit_time_window` (ms), `rate_limit_max` | The per-key rate limit |
| `request_count`, `last_request` | The rate limit's counters |
| `remaining` | Uses left; empty means unlimited |
| `refill_amount`, `refill_interval` (ms), `last_refill_at` | Resets `remaining` to `refill_amount` every interval |
| `permissions` | `{ "resource": ["action", ..] }`, see [Permissions](#permissions) |
| `metadata` | A JSON object, when `.enable_metadata(true)` |

Ids follow the app's id strategy (ULID by default). The column names are fastauth's
snake_case ones, and Better Auth stores its hash differently, so an `apikey` table from a
Better Auth app can't be reused as is.

## Configuration

Every option, with the value it sets:

```rust
ApiKeys::new()
    .key_length(64)
    .default_prefix("acme_")
    .start_length(6)
    .default_expires_in(Duration::days(90))
    .min_expires_in(Duration::days(1))
    .max_expires_in(Duration::days(365))
    .enable_metadata(true)
    .require_name(true)
    .default_permissions(Permissions::from([(
        "files".to_owned(),
        vec!["read".to_owned()],
    )]))
    .rate_limit(Duration::minutes(1), 60)
    .header(HeaderName::from_static("x-acme-key"))
    .sessions(true)
```

| Option | Default | What it does |
|---|---|---|
| `key_length(n)` | 64 | Random characters per key, after the prefix. Panics below 16 |
| `default_prefix(p)` | none | Prefix for keys whose create request names none |
| `start_length(n)` | 6 | Leading characters stored as `start`; 0 stores none |
| `default_expires_in(d)` | never | Expiry for keys created without `expiresIn` |
| `min_expires_in(d)` | 1 day | Smallest `expiresIn` a create or update accepts |
| `max_expires_in(d)` | 365 days | Largest `expiresIn` a create or update accepts |
| `enable_metadata(b)` | off | Lets keys carry a `metadata` object |
| `require_name(b)` | off | Refuses creates without `name` (`NAME_REQUIRED`) |
| `default_permissions(p)` | none | Permissions for keys created without `permissions` |
| `rate_limit(window, max)` | 1 day, 10 | The rate limit new keys get |
| `disable_rate_limit()` | limits on | Turns per-key rate limits off for every key, existing ones included |
| `header(name)` | `x-api-key` | The header sessions from keys read |
| `key_getter(f)` | none | Reads the key from the request your way; replaces `header` |
| `sessions(b)` | off | Lets a key sign a request in as its owner ([Sessions from API keys](#sessions-from-api-keys)) |

These match Better Auth's defaults. Some limits are fixed: names are 1 to 32 characters,
prefixes are 1 to 32 characters of letters, digits, `_` and `-`, and the random part uses
`a-z` and `A-Z`.

`rate_limit(..)` and `default_permissions(..)` are copied onto each key when it's created,
so changing them doesn't affect existing keys; change those through the
[server API](#server-api). `disable_rate_limit()` is checked on every request, so it does
apply to existing keys.

## Endpoints

Under your `base_path` (`/api/auth` by default):

| Method | Path | Better Auth client | Access | Notes |
|---|---|---|---|---|
| `POST` | `/api-key/create` | `authClient.apiKey.create` | session | `name`, `expiresIn` (seconds), `prefix`, `metadata`. Returns the key, once |
| `GET` | `/api-key/get?id=..` | `authClient.apiKey.get({ query: { id } })` | session, own keys | Another user's key is `404 KEY_NOT_FOUND` |
| `POST` | `/api-key/update` | `authClient.apiKey.update` | session, own keys | `keyId` plus `name`, `enabled`, `expiresIn` (`null` removes the expiry), `metadata` |
| `POST` | `/api-key/delete` | `authClient.apiKey.delete` | session, own keys | `{ "keyId" }`, answers `{ "success": true }` |
| `GET` | `/api-key/list` | `authClient.apiKey.list` | session | `limit`, `offset`, `sortBy`, `sortDirection`; answers `{ apiKeys, total, limit, offset }` |

Two endpoints are server-only, as in Better Auth. They have no HTTP route (a request gets
`404`), and you call them through the [server API](#server-api):

| Endpoint | Server API |
|---|---|
| `/api-key/verify` | `auth.api_keys().verify(key, permissions)` |
| `/api-key/delete-all-expired-api-keys` | `auth.api_keys().delete_all_expired()` |

Some fields change what a key may do, so only the server can set them: `remaining`,
`refillAmount`, `refillInterval`, `rateLimitEnabled`, `rateLimitTimeWindow`, `rateLimitMax`
and `permissions`. Over HTTP, any of them answers `400 SERVER_ONLY_PROPERTY`. A `userId` in
a client request answers `401 UNAUTHORIZED_SESSION`, because the session decides the owner.
Without a session, `create` and `update` answer `401 UNAUTHORIZED_SESSION`, and `get`,
`list` and `delete` answer `401 UNAUTHORIZED`.

Keys come back in Better Auth's shape: every column except the hash, in camelCase, with the
owner as both `referenceId` and `userId`, and `configId: "default"`. `create` adds `key`, the
only copy of the key there will ever be. `sortBy` takes `createdAt` (the default),
`updatedAt`, `name`, `expiresAt`, `lastRequest`, `remaining`, `requestCount` or `enabled`.

Each endpoint type has two constructors: `CreateApiKey::client(..)` is what the plugin
routes, with the rules above, and `CreateApiKey::server(..)` is what `auth.api_keys()`
calls, which accepts every field. `GetApiKey`, `UpdateApiKey`, `DeleteApiKey` and
`ListApiKeys` work the same way.

## Server API

`auth.api_keys()` (trait `ApiKeysExt`) calls the endpoints without HTTP, as the server:

| Method | Input | Output |
|---|---|---|
| `create` | `CreateApiKeyInput` | `CreatedApiKey` (`api_key` plus `key`) |
| `verify` | `&str`, `Option<Permissions>` | `VerifyOutput` (`valid`, `error`, `key`) |
| `get` | `GetApiKeyInput` | `ApiKeyView` |
| `update` | `UpdateApiKeyInput` | `ApiKeyView` |
| `delete` | `DeleteApiKeyInput` | `Success` |
| `list` | `ListApiKeysInput` | `ApiKeyList` |
| `delete_all_expired` | none | `DeleteExpiredOutput` (`success`, `deleted`) |

Every input has a `user_id` that names the owner, since there's no session. Server-only
fields are accepted:

```rust
pub async fn issue_ci_key(auth: &AppAuth, user_id: Id) -> Result<CreatedApiKey, AuthError> {
    auth.api_keys()
        .create(CreateApiKeyInput {
            name: Some("ci".into()),
            user_id: Some(user_id),
            expires_in: Some(30 * 24 * 60 * 60),
            refill_amount: Some(1_000),
            refill_interval: Some(24 * 60 * 60 * 1000),
            rate_limit_max: Some(100),
            rate_limit_time_window: Some(60 * 1000),
            permissions: Some(Permissions::from([(
                "files".to_owned(),
                vec!["read".to_owned(), "write".to_owned()],
            )])),
            ..Default::default()
        })
        .await
}
```

`.headers(&headers)` acts for the session in a request's headers instead. A `user_id` must
then name the same user, or the call fails with `UNAUTHORIZED_SESSION`:

```rust
pub async fn keys_of(auth: &AppAuth, headers: &HeaderMap) -> Result<ApiKeyList, AuthError> {
    auth.api_keys()
        .headers(headers)
        .list(ListApiKeysInput::default())
        .await
}
```

`UpdateApiKeyInput::new(id)` starts an update that changes nothing; set the fields you want.
`expires_in`, `metadata` and `permissions` are `Option<Option<_>>`, where `Some(None)`
clears the value:

```rust
let mut update = UpdateApiKeyInput::new(key_id);
update.user_id = Some(user_id);
update.remaining = Some(5_000);
update.rate_limit_enabled = Some(false);
auth.api_keys().update(update).await
```

Expired keys are deleted when someone uses them, but keys nobody uses stay until you clean
up. Run this from a scheduled job:

```rust
pub async fn nightly_cleanup(auth: &AppAuth) -> Result<u64, AuthError> {
    let out = auth.api_keys().delete_all_expired().await?;
    Ok(out.deleted)
}
```

`auth.api_keys()` only compiles when `ApiKeys` is in the alias:

```
error[E0277]: plugin `ApiKeys` is not registered on this auth instance
 --> src/lib.rs:7:13
  |
7 |     Ok(auth.api_keys().delete_all_expired().await?.deleted)
  |             ^^^^^^^^ `ApiKeys` is not in this plugin list
  |
  = help: the trait `Has<ApiKeys, _>` is not implemented for `fastauth::Nil`
  = note: register it with `.plugin(...)` on the builder, before any plugin that requires it, and list it in your `plugins![..]` alias
```

### Verifying a key

`verify` checks a key and counts the use. A refused key is still `Ok`, with `valid: false`
and Better Auth's `{ message, code }` in `error`. `Err` is only for failures unrelated to
the key, such as the database. With sessions off, this is how a route checks a key:

```rust
async fn upload(State(auth): State<AppAuth>, headers: HeaderMap) -> Result<String, Response> {
    let key = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let needed = Permissions::from([("files".to_owned(), vec!["write".to_owned()])]);
    let verified = auth
        .api_keys()
        .verify(key, Some(needed))
        .await
        .map_err(IntoResponse::into_response)?;
    match (verified.key, verified.error) {
        (Some(api_key), _) => Ok(format!("uploading for {}", api_key.user_id.as_str())),
        (None, error) => Err((StatusCode::UNAUTHORIZED, Json(error)).into_response()),
    }
}
```

The checks run in this order:

1. No key has that hash: `INVALID_API_KEY`.
2. `enabled` is false: `KEY_DISABLED`.
3. `expires_at` has passed: the key is deleted, `KEY_EXPIRED`.
4. Permissions were requested and the key lacks one: `KEY_NOT_FOUND`, as in Better Auth.
5. `remaining` is 0 and there's no refill: the key is deleted, `USAGE_EXCEEDED`.
6. If a refill is due (`refill_interval` has passed since the last refill, or since
   creation), `remaining` goes back to `refill_amount` and this use is taken from it.
   Otherwise `remaining` goes down by one, or the key fails with `USAGE_EXCEEDED` at 0.
7. The rate limit: if the last counted request was within the window and `request_count`
   has reached `rate_limit_max`, the key fails with `RATE_LIMITED` and
   `details.tryAgainIn` in milliseconds. A request more than a window after the last
   counted one starts a new count, so steady traffic doesn't reset the count until it
   pauses for a full window. Better Auth counts the same way.

A key created with `refill_amount` and no `remaining` starts with `remaining` equal to
`refill_amount`. A used-up key with a refill is kept and works again after the next refill.

## Sessions from API keys

This is off by default, like Better Auth's `enableSessionForAPIKeys`. Turn it on with
`.sessions(true)`:

```rust
.plugin(ApiKeys::new().sessions(true))
```

A request with a key in `x-api-key` then gets a session for the key's owner, so every
`Session<AppAuth>` extractor and every endpoint that needs a session accepts API keys with no
handler changes ([Sessions](04-sessions.md)). `/get-session` answers with the owner too.

```rust
async fn whoami(session: Session<AppAuth>) -> Json<Value> {
    Json(json!({
        "email": session.user.email,
        "viaApiKey": session.view().ephemeral,
    }))
}
```

The plugin adds no extractors of its own. What changes:

- **Each request counts against the key's rate limit and `remaining`.** Resolving the
  session is a verification. With the defaults, that's 10 requests per day per key, and the
  11th gets `429 RATE_LIMITED`. Give new keys a different limit with
  `.rate_limit(window, max)`, change one key through the server API, or turn limits off
  with `.disable_rate_limit()`. The axum extractors resolve once per request, so a handler
  with several of them counts once, but a call to `auth.get_session(&headers)` counts again.
- **The session is ephemeral.** It exists only for that request and isn't stored.
  `session.view().ephemeral` is `true`, `session.session.id` is `"ephemeral"`, and
  `/sign-out` has nothing to revoke. It is never fresh: `FreshSession` and `Fresh` endpoints
  answer `403 SESSION_NOT_FRESH`.
- **It can't mint credentials.** Creating or updating a key, registering a passkey, linking
  a social account and turning two-factor on or off need a stored session and answer
  `401 UNAUTHORIZED` to a key's session, so a limited key can't create an unlimited one or
  lift its own expiry. Better Auth lets a key's session create and update keys.
- **Bans apply.** The core session gates run on it, so a banned owner's key answers
  `403 BANNED_USER` ([Admin](13-admin.md#bans)), and banning disables the owner's keys.
- **Permissions aren't checked.** A key with `{ "files": ["read"] }` gets a full session for
  its owner, as in Better Auth: every route that takes a session, `/admin/*` included for an
  admin's key. The handler can't tell which key was used, so to enforce permissions, call
  [`verify`](#verifying-a-key) with them instead, or leave `.sessions` off.
- **A session cookie wins.** If the request has a session cookie, the key isn't read at all.
  Better Auth checks the key first.
- **A bad key fails the request**, even on routes that take `Option<Session<AppAuth>>`: an
  unknown key is `401 INVALID_API_KEY`, a disabled one `401 KEY_DISABLED`, and so on. A key
  shorter than `key_length` is `403 INVALID_API_KEY` without a database lookup. Routes that
  never read the session, such as `/sign-in/email`, ignore the key.

To read the key from somewhere else, use `.header(name)` or a `key_getter`. Have the getter
return only values that are yours, because whatever it returns is checked as a key:

```rust
ApiKeys::new()
    .default_prefix("acme_")
    .sessions(true)
    .key_getter(|headers: &HeaderMap| {
        let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
        let key = value.strip_prefix("Bearer ")?;
        key.starts_with("acme_").then(|| key.to_owned())
    })
```

## How keys are stored

- **Only a hash.** A key is `prefix` plus `key_length` random letters. fastauth stores its
  SHA-256 (of the whole key, prefix included) as 32 bytes in `key_hash`, under a unique
  index, and looks keys up by that hash. `create` returns the key once; `get` and `list`
  never return it or the hash. A fast hash is enough because keys are long random strings,
  not passwords.
- **`start` isn't secret.** It's the first `start_length` characters, prefix included, so
  with a long prefix it holds little of the random part.
- **The counters are atomic.** One verification writes `remaining`, `last_refill_at`,
  `request_count` and `last_request` in a single conditional update, which only applies if
  those columns still hold the values it read. If another request changed them first, it
  reads the row again and decides again. So concurrent requests can't spend the same unit of
  `remaining` or the same rate-limit slot. This works on any adapter whose `UPDATE .. WHERE`
  is atomic per row, and is tested with 64 concurrent verifications on the memory adapter
  and 32 on a SQLite file. After 64 lost races in a row, the request fails with
  `500 FAILED_TO_UPDATE_API_KEY`.

## Events

| Event | Fields | Fires when |
|---|---|---|
| `ApiKeyCreated` | `id`, `user_id` | A key is created, over HTTP or through the server API |
| `ApiKeyDeleted` | `id`, `user_id` | A key is deleted through `/api-key/delete` or `auth.api_keys().delete` |

Keys removed any other way emit nothing: expired or used-up keys deleted during
verification, `delete_all_expired`, and keys deleted along with their user. Listen with
`.on(..)` ([Events](03-configuration.md#events)):

```rust
.plugin(ApiKeys::new())
.on(|e: ApiKeyCreated, _ctx: Ctx<_>| async move {
    println!("key {} created for {}", e.id.as_str(), e.user_id.as_str());
    Ok(())
})
.on(|e: ApiKeyDeleted, _ctx: Ctx<_>| async move {
    println!("key {} deleted", e.id.as_str());
    Ok(())
})
```

`Ctx` is `fastauth::endpoint::Ctx`. The plugin registers no hooks or sign-in gates
([Hooks](05-plugins.md#hooks)).

## Permissions

There are no roles. A key's permissions are a map from resource to actions,
`Permissions = BTreeMap<String, Vec<String>>`, for example `{ "files": ["read", "write"] }`.
You choose the names; nothing needs registering, and only `verify` reads them.

- Keys have no permissions unless the server sets them with `create` or `update`, or the
  plugin has `.default_permissions(..)`. Clients can't set them (`SERVER_ONLY_PROPERTY`).
- `verify(key, Some(wanted))` passes only if the key has every action of every resource in
  `wanted`. A key without permissions, or an empty `wanted`, fails. A failure is
  `KEY_NOT_FOUND`, as in Better Auth.
- Actions are compared as plain strings, so `"*"` is just an action named `*`.
- `verify(key, None)` and sessions from keys don't check permissions.

## Error codes

| Code | Status | When |
|---|---|---|
| `INVALID_API_KEY` | 401 | No key has that hash |
| `INVALID_API_KEY` | 403 | Sessions on, and the key is shorter than `key_length` |
| `KEY_NOT_FOUND` | 404 | `get`, `update` or `delete` of an unknown key or another user's key; also `verify` when the key lacks a requested permission |
| `KEY_DISABLED` | 401 | The key has `enabled: false` |
| `KEY_EXPIRED` | 401 | The key's `expires_at` has passed; the key is deleted |
| `USAGE_EXCEEDED` | 429 | `remaining` is 0 |
| `RATE_LIMITED` | 429 | Over the key's rate limit; `verify` adds `details.tryAgainIn` (ms) |
| `SERVER_ONLY_PROPERTY` | 400 | A client sent a server-only field |
| `UNAUTHORIZED_SESSION` | 401 | `create` or `update` with no session, a client sent `userId`, or a server call's `user_id` differs from its session |
| `METADATA_DISABLED` | 400 | `create` with `metadata` while metadata is off (`update` ignores it) |
| `INVALID_METADATA_TYPE` | 400 | `metadata` isn't a JSON object |
| `REFILL_AMOUNT_AND_INTERVAL_REQUIRED` | 400 | `refillAmount` without `refillInterval` |
| `REFILL_INTERVAL_AND_AMOUNT_REQUIRED` | 400 | `refillInterval` without `refillAmount` |
| `EXPIRES_IN_IS_TOO_SMALL` | 400 | `expiresIn` below `min_expires_in` |
| `EXPIRES_IN_IS_TOO_LARGE` | 400 | `expiresIn` above `max_expires_in` |
| `INVALID_PREFIX_LENGTH` | 400 | `prefix` isn't 1 to 32 characters |
| `INVALID_NAME_LENGTH` | 400 | `name` isn't 1 to 32 characters |
| `NAME_REQUIRED` | 400 | No `name` while `require_name` is on |
| `NO_VALUES_TO_UPDATE` | 400 | An update that changes nothing |
| `FAILED_TO_UPDATE_API_KEY` | 500 | A verification lost 64 races in a row |

Core's codes appear too: `401 UNAUTHORIZED` for `get`, `list` and `delete` without a
session, and `400 INVALID_BODY` for an `expiresIn` below 1, a negative number, a
`refillAmount` or updated `remaining` below 1, a prefix with other characters, or an unknown
`sortBy`. Through `verify`, key errors come back in `error` with `valid: false` rather than
as an HTTP status.

## Better Auth's client

Add `apiKeyClient` from `@better-auth/api-key` (Better Auth 1.7 moved it out of
`better-auth`). The tested version is 1.7.28:

```ts
import { createAuthClient } from "better-auth/client";
import { apiKeyClient } from "@better-auth/api-key/client";

export const authClient = createAuthClient({
  baseURL: "http://localhost:3000",
  plugins: [apiKeyClient()],
});

const { data } = await authClient.apiKey.create({ name: "ci", prefix: "ci_" });
```

`compat/better-auth/compat.ts` checks, through the client: `create` (the key is returned
once, `start`, `referenceId`, `rateLimitMax` 10), `create` with `remaining`
(`400 SERVER_ONLY_PROPERTY`), `list` (no `key` or hash), `get`, `update`, `getSession` with
an `x-api-key` header (the example registers `.sessions(true)`), `delete`, and `get` after
delete (`KEY_NOT_FOUND`). [Better Auth's client](11-better-auth-client.md) shows how to run it.

Known gaps:

- In a session from a key, `session.id` is `"ephemeral"` and there's no token. Better Auth
  uses the key's id and the key itself.
- A request with both a session cookie and a key uses the cookie; Better Auth uses the key.
- `/api-key/create` and `/api-key/update` read the caller's session from the database, as
  Better Auth does, and also refuse a key's own session and an impersonation session, which
  Better Auth allows.
- Better Auth deletes every expired key each time a key signs a request in. fastauth only
  deletes the key being used, so call `delete_all_expired()` yourself.

## Not built

These Better Auth `apiKey` features don't exist in fastauth:

- Several key configurations (`configId` is always `"default"`).
- Keys owned by an organization (`references: "organization"`).
- `customKeyGenerator`, `customAPIKeyValidator`, `disableKeyHashing`, and a list of header
  names in `apiKeyHeaders`.
- Configurable name and prefix lengths, and `disableCustomExpiresTime`.
- `defaultPermissions` as a function.
- Keys in secondary storage (`storage`, `fallbackToDatabase`, `customStorage`) and
  `deferUpdates`.
