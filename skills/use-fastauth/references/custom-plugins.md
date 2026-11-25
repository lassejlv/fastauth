# Writing a plugin

A plugin is a value passed to `.plugin(..)` and listed in the alias. It can add tables and
user columns, endpoints, hooks, sign-in gates, session resolvers, events, rate limits and
error codes. Import everything from `fastauth::plugin_prelude` (a published plugin crate
depends on `fastauth-core` and imports `fastauth_core::plugin_prelude`). `docs/05-plugins.md`
explains the design; its `fastauth::plugin::prelude` path, `#[endpoint]`, `#[derive(Event)]`,
`ctx.random()` and `TestAuth` don't exist yet.

The running example is an API-key plugin, compiled and tested against `main`.

## Table, errors, events

```rust
use fastauth::events::PasswordChanged;
use fastauth::plugin_prelude::*;

#[derive(Model, Clone)]
#[model(table = "api_key")]
pub struct ApiKey {
    #[model(id)]
    pub id: Id,
    #[model(references = User, on_delete = Cascade, index)]
    pub user_id: Id,
    pub name: String,
    #[model(unique, hidden)]
    pub key_hash: Hash,
    pub expires_at: Option<OffsetDateTime>,
    #[model(default = now)]
    pub created_at: OffsetDateTime,
}

#[derive(AuthError, Debug)]
#[auth_error(prefix = "API_KEY")]
pub enum ApiKeyError {
    #[auth_error(status = 401, message = "API key expired")]
    Expired,
}

#[derive(Clone, Debug)]
pub struct ApiKeyCreated {
    pub user_id: Id,
    pub key_id: Id,
}

impl Event for ApiKeyCreated {}
```

`#[derive(Model)]` needs `#[model(table = "..")]` and declares every field as a column
(`Option<T>` is nullable; field types must be `Clone`). Field attributes: `id`,
`references = Model` with `on_delete = Cascade | SetNull | Restrict`, `unique`, `index`,
`hidden` (never sent to clients), `default = ..` (literal or `now`). It generates a typed
constant per column, `ApiKey::USER_ID: Col<ApiKey, Id>`, so filters are type-checked.
Add the table in `Plugin::schema` with `schema.model::<ApiKey>()`; the migrator creates it.

`#[derive(AuthError)]` turns each variant into an `AuthError` with code
`{PREFIX}_{VARIANT}` (`API_KEY_EXPIRED`), or the variant alone without a prefix. Register the
codes with `app.errors::<E>()` so two plugins can't claim one.

An event is any `Clone + Send + Sync + 'static` type with `impl Event`.

## The plugin

```rust
/// API keys: `.plugin(ApiKeys::new())`, then send `x-api-key: <key>`.
#[derive(Default)]
pub struct ApiKeys {
    ttl: Option<Duration>,
}

impl ApiKeys {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
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
        app.endpoint(CreateKey(self.clone()))
            .endpoint(ListKeys)
            .session_resolver(KeyResolver)
            .rate_limit("/api-key/create", Limit::per(Duration::minutes(1), 10))
            .errors::<ApiKeyError>();
        app.on(|e: PasswordChanged, ctx: Ctx<D>| async move {
            ctx.db().delete::<ApiKey>(ApiKey::USER_ID.eq(e.user_id)).await?;
            Ok(())
        });
    }
}
```

- `Requires` is a tuple of plugins that must be registered first, `()` for none.
- `UserFields` and `SessionFields` are `#[derive(Fields)]` structs of columns added to
  `user` and `session` ([gates](#gates) has one), `()` for none. They're added for you.
- `init` runs once, inside `.build()`. The builder methods chain.

## Endpoints

```rust
pub struct CreateKey(Arc<ApiKeys>);

#[derive(Deserialize)]
pub struct CreateKeyInput {
    pub name: String,
}

#[derive(Serialize)]
pub struct CreatedKey {
    pub id: Id,
    pub key: String,
}

impl<D: Adapter> Endpoint<D> for CreateKey {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/api-key/create";
    type Access = Authenticated;
    type Input = CreateKeyInput;
    type Output = CreatedKey;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: CreateKeyInput,
    ) -> Result<CreatedKey, AuthError> {
        let key = format!("ak_{}", random_token());
        let row = ApiKey {
            id: ctx.new_id(),
            user_id: ctx.session().user.id.clone(),
            name: input.name,
            key_hash: Hash::sha256(&key),
            expires_at: self.0.ttl.map(|ttl| ctx.now() + ttl),
            created_at: ctx.now(),
        };
        let row = ctx.db().insert(&row).await?;
        ctx.emit(ApiKeyCreated {
            user_id: row.user_id.clone(),
            key_id: row.id.clone(),
        });
        Ok(CreatedKey { id: row.id, key })
    }
}

pub struct ListKeys;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeySummary {
    pub id: Id,
    pub name: String,
    pub expires_at: Option<OffsetDateTime>,
}

impl<D: Adapter> Endpoint<D> for ListKeys {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/api-key/list";
    type Access = Authenticated;
    type Input = Empty;
    type Output = Vec<KeySummary>;

    async fn call(&self, ctx: Ctx<D, Authenticated>, _: Empty) -> Result<Vec<KeySummary>, AuthError> {
        let keys = ctx
            .db()
            .find::<ApiKey>(ApiKey::USER_ID.eq(&ctx.session().user.id))
            .order_by(ApiKey::CREATED_AT.desc())
            .all()
            .await?;
        Ok(keys
            .into_iter()
            .map(|k| KeySummary {
                id: k.id,
                name: k.name,
                expires_at: k.expires_at,
            })
            .collect())
    }
}
```

`PATH` is relative to the base path and may hold `{name}` parameters (`ctx.param("name")`).
`GET` reads `Input` from the query string, other methods from the JSON body; `Empty` is
`{}`. `Access` decides what `ctx.session()` is:

| `type Access` | Without a session | `ctx.session()` |
|---|---|---|
| `Public` | runs | doesn't exist |
| `MaybeAuthenticated` | runs | `Option<&SessionView>` |
| `Authenticated` | `401`, `call` never runs | `&SessionView` |
| `Fresh` | `401`, or `403 SESSION_NOT_FRESH` | `&SessionView` |

Also on `ctx`: `db()`, `new_id()`, `now()`, `emit(event)`, `plugin::<P>()` (panics
unless `P` is required) and `try_plugin::<P>()`, `config()`, `headers()`, `ip()`,
`set_signed_cookie`/`signed_cookie`, `redirect(url)`, and `internal()` for core
operations (`find_user_by_email`, `create_session`, `send_email`, verification values).
`ctx.db()` errors convert into `AuthError` with `?`.

## Session resolvers

```rust
struct KeyResolver;

impl<D: Adapter> SessionResolver<D> for KeyResolver {
    async fn resolve(&self, ctx: &Ctx<D>, headers: &HeaderMap) -> Result<Option<Resolved>, AuthError> {
        let Some(key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) else {
            return Ok(None);
        };
        let Some(row) = ctx
            .db()
            .find::<ApiKey>(ApiKey::KEY_HASH.eq(Hash::sha256(key)))
            .one()
            .await?
        else {
            return Ok(None);
        };
        if row.expires_at.is_some_and(|at| at < ctx.now()) {
            return Err(ApiKeyError::Expired.into());
        }
        Ok(Some(Resolved::User(row.user_id)))
    }
}
```

Requests without a session cookie go through resolvers in registration order.
`Resolved::User(id)` builds a session for this request only (`view().ephemeral` is true);
`Resolved::Token(token)` hands back a session token found elsewhere, such as a bearer
header. Every `Session<AppAuth>` extractor then accepts the key.

## A server API: extension traits

```rust
pub trait ApiKeysExt: AuthInstance + Sized {
    fn api_keys<I>(&self) -> ApiKeysApi<'_, Self>
    where
        Self: HasPlugin<ApiKeys, I>,
    {
        ApiKeysApi {
            auth: self,
            plugin: self.plugin_arc().clone(),
        }
    }
}

impl<A: AuthInstance> ApiKeysExt for A {}

pub struct ApiKeysApi<'a, A> {
    auth: &'a A,
    plugin: Arc<ApiKeys>,
}

impl<A: AuthInstance> ApiKeysApi<'_, A> {
    pub async fn create(&self, headers: &HeaderMap, input: CreateKeyInput) -> Result<CreatedKey, AuthError> {
        let created = self
            .auth
            .api()
            .headers(headers)
            .call(&CreateKey(self.plugin.clone()), input)
            .await?;
        Ok(created.data)
    }
}
```

The `HasPlugin` bound makes `auth.api_keys()` compile only on an `Auth` that registered
`ApiKeys`, with the same "not registered" error as `session.user.plugin::<P, _>()`.

## Gates

A gate runs after credentials check out and before a session exists, for every sign-in
method. It returns `Gate::Allow`, `Gate::Deny(err)` or `Gate::Challenge(json)` (answer with
that JSON and no session, as two-factor does):

```rust
#[derive(Fields, Clone, Debug)]
pub struct BanFields {
    #[field(default = false)]
    pub banned: bool,
}

#[derive(AuthError, Debug)]
pub enum BanError {
    #[auth_error(status = 403, message = "this account is banned")]
    Banned,
}

/// Refuses sign-in for users with `user.banned = true`, for every sign-in method.
pub struct Bans;

impl Plugin for Bans {
    const ID: &'static str = "bans";
    type Requires = ();
    type UserFields = BanFields;
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.errors::<BanError>();
        app.sign_in_gate(|_ctx, attempt: SignInAttempt| async move {
            let fields: BanFields = attempt.user.fields().map_err(AuthError::internal)?;
            if fields.banned {
                return Ok(Gate::Deny(BanError::Banned.into()));
            }
            Ok(Gate::Allow)
        });
    }
}
```

## Depending on another plugin

```rust
/// Logs every new key. Needs `ApiKeys` registered before it.
pub struct KeyAudit;

impl Plugin for KeyAudit {
    const ID: &'static str = "key-audit";
    type Requires = (ApiKeys,);
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.on(|e: ApiKeyCreated, ctx: Ctx<D>| async move {
            let keys: &ApiKeys = ctx.plugin::<ApiKeys>();
            println!("user {} created key {} (ttl {:?})", e.user_id, e.key_id, keys.ttl);
            Ok(())
        });
    }
}
```

Registering `KeyAudit` without `ApiKeys` before it fails at the `.plugin(KeyAudit)` call
(see Common mistakes in `SKILL.md`). For an optional dependency, leave `Requires` empty and
use `ctx.try_plugin::<P>()`.

## Registering it

```rust
pub type AppAuth<D> = Auth<D, Profile, plugins![ApiKeys, KeyAudit, Bans]>;

FastAuth::builder()
    // ...
    .plugin(ApiKeys::new().ttl(Duration::days(90)))
    .plugin(KeyAudit)
    .plugin(Bans)
```

Run migrations after adding a plugin that adds tables or columns.
