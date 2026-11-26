# Writing a plugin

A plugin is a value passed to `.plugin(..)` and listed in the alias. It can add tables and
user columns, endpoints, hooks, sign-in gates, session resolvers, events, rate limits and
error codes. Import everything from `fastauth::plugin_prelude` (a published plugin crate
depends on `fastauth-core` and imports `fastauth_core::plugin_prelude`). `docs/05-plugins.md`
explains the design with the same example.

The running example is a personal access token plugin (not the real API key plugin, which is
[api-keys.md](api-keys.md)), compiled and tested against `main`.

## Table, errors, events

```rust
use fastauth::events::PasswordChanged;
use fastauth::plugin_prelude::*;

#[derive(Model, Clone)]
#[model(table = "access_token")]
pub struct AccessToken {
    #[model(id)]
    pub id: Id,
    #[model(references = User, on_delete = Cascade, index)]
    pub user_id: Id,
    pub name: String,
    #[model(unique, hidden)]
    pub token_hash: Hash,
    pub expires_at: Option<OffsetDateTime>,
    #[model(default = now)]
    pub created_at: OffsetDateTime,
}

#[derive(AuthError, Debug)]
#[auth_error(prefix = "ACCESS_TOKEN")]
pub enum AccessTokenError {
    #[auth_error(status = 401, message = "access token expired")]
    Expired,
}

#[derive(Clone, Debug)]
pub struct AccessTokenCreated {
    pub user_id: Id,
    pub token_id: Id,
}

impl Event for AccessTokenCreated {}
```

`#[derive(Model)]` needs `#[model(table = "..")]` and declares every field as a column
(`Option<T>` is nullable; field types must be `Clone`). Field attributes: `id`,
`references = Model` with `on_delete = Cascade | SetNull | Restrict`, `unique`, `index`,
`hidden` (never sent to clients), `default = ..` (literal or `now`). It generates a typed
constant per column, `AccessToken::USER_ID: Col<AccessToken, Id>`, so filters are type-checked.
Add the table in `Plugin::schema` with `schema.model::<AccessToken>()`; the migrator creates it.

`#[derive(AuthError)]` turns each variant into an `AuthError` with code
`{PREFIX}_{VARIANT}` (`ACCESS_TOKEN_EXPIRED`), or the variant alone without a prefix. Register the
codes with `app.errors::<E>()` so two plugins can't claim one.

An event is any `Clone + Send + Sync + 'static` type with `impl Event`.

## The plugin

```rust
/// Personal access tokens: `.plugin(AccessTokens::new())`, then send `x-access-token: <token>`.
#[derive(Default)]
pub struct AccessTokens {
    ttl: Option<Duration>,
}

impl AccessTokens {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }
}

impl Plugin for AccessTokens {
    const ID: &'static str = "access-tokens";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn schema(&self, schema: &mut SchemaBuilder) {
        schema.model::<AccessToken>();
    }

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.endpoint(CreateToken(self.clone()))
            .endpoint(ListTokens)
            .session_resolver(TokenResolver)
            .rate_limit("/access-token/create", Limit::per(Duration::minutes(1), 10))
            .errors::<AccessTokenError>();
        app.on(|e: PasswordChanged, ctx: Ctx<D>| async move {
            ctx.db().delete::<AccessToken>(AccessToken::USER_ID.eq(e.user_id)).await?;
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
pub struct CreateToken(Arc<AccessTokens>);

#[derive(Deserialize)]
pub struct CreateTokenInput {
    pub name: String,
}

#[derive(Serialize)]
pub struct CreatedToken {
    pub id: Id,
    pub token: String,
}

impl<D: Adapter> Endpoint<D> for CreateToken {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/access-token/create";
    type Access = Authenticated;
    type Input = CreateTokenInput;
    type Output = CreatedToken;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: CreateTokenInput,
    ) -> Result<CreatedToken, AuthError> {
        let token = format!("at_{}", random_token());
        let row = AccessToken {
            id: ctx.new_id()?,
            user_id: ctx.session().user.id.clone(),
            name: input.name,
            token_hash: Hash::sha256(&token),
            expires_at: self.0.ttl.map(|ttl| ctx.now() + ttl),
            created_at: ctx.now(),
        };
        let row = ctx.db().insert(&row).await?;
        ctx.emit(AccessTokenCreated {
            user_id: row.user_id.clone(),
            token_id: row.id.clone(),
        });
        Ok(CreatedToken { id: row.id, token })
    }
}

pub struct ListTokens;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenSummary {
    pub id: Id,
    pub name: String,
    pub expires_at: Option<OffsetDateTime>,
}

impl<D: Adapter> Endpoint<D> for ListTokens {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/access-token/list";
    type Access = Authenticated;
    type Input = Empty;
    type Output = Vec<TokenSummary>;

    async fn call(&self, ctx: Ctx<D, Authenticated>, _: Empty) -> Result<Vec<TokenSummary>, AuthError> {
        let tokens = ctx
            .db()
            .find::<AccessToken>(AccessToken::USER_ID.eq(&ctx.session().user.id))
            .order_by(AccessToken::CREATED_AT.desc())
            .all()
            .await?;
        Ok(tokens
            .into_iter()
            .map(|k| TokenSummary {
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

Also on `ctx`: `db()`, `new_id()?` (fallible: a custom id strategy can fail; ids are opaque
strings, ULIDs by default), `now()`, `emit(event)`, `plugin::<P>()` (panics
unless `P` is required) and `try_plugin::<P>()`, `config()`, `headers()`, `ip()`,
`set_signed_cookie`/`signed_cookie`, `redirect(url)`, and `internal()` for core
operations (`find_user_by_email`, `complete_sign_in`, `send_email`, verification values).
Code outside a request that is generic over `AuthInstance` (an axum extractor) reads a
plugin's config with `auth.try_plugin::<P>()` and its tables with `auth.api().db()`.
`ctx.db()` errors convert into `AuthError` with `?`.

An endpoint only your server API calls gets no route: declare it with
`app.server_endpoint::<E>()` so hooks can still target it. When HTTP and the server API need
different rules, keep one type with a flag (`CreateApiKey::client(..)` / `::server(..)`) so
hooks on it run for both.

## Session resolvers

```rust
struct TokenResolver;

impl<D: Adapter> SessionResolver<D> for TokenResolver {
    async fn resolve(&self, ctx: &Ctx<D>, headers: &HeaderMap) -> Result<Option<Resolved>, AuthError> {
        let Some(token) = headers.get("x-access-token").and_then(|v| v.to_str().ok()) else {
            return Ok(None);
        };
        let Some(row) = ctx
            .db()
            .find::<AccessToken>(AccessToken::TOKEN_HASH.eq(Hash::sha256(token)))
            .one()
            .await?
        else {
            return Ok(None);
        };
        if row.expires_at.is_some_and(|at| at < ctx.now()) {
            return Err(AccessTokenError::Expired.into());
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
pub trait AccessTokensExt: AuthInstance + Sized {
    fn access_tokens<I>(&self) -> AccessTokensApi<'_, Self>
    where
        Self: HasPlugin<AccessTokens, I>,
    {
        AccessTokensApi {
            auth: self,
            plugin: self.plugin_arc().clone(),
        }
    }
}

impl<A: AuthInstance> AccessTokensExt for A {}

pub struct AccessTokensApi<'a, A> {
    auth: &'a A,
    plugin: Arc<AccessTokens>,
}

impl<A: AuthInstance> AccessTokensApi<'_, A> {
    pub async fn create(&self, headers: &HeaderMap, input: CreateTokenInput) -> Result<CreatedToken, AuthError> {
        let created = self
            .auth
            .api()
            .headers(headers)
            .call(&CreateToken(self.plugin.clone()), input)
            .await?;
        Ok(created.data)
    }
}
```

The `HasPlugin` bound makes `auth.access_tokens()` compile only on an `Auth` that registered
`AccessTokens`, with the same "not registered" error as `session.user.plugin::<P, _>()`.

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

A plugin that challenges finishes the sign-in itself, from the endpoint that checks the
answer, with `ctx.internal().complete_sign_in(MyPlugin::ID, user, method, remember_me)`. It
runs every other plugin's gate (so a banned user is still refused after a correct code) and
returns `SignInResult::SignedIn(session)` or `SignInResult::Challenge(json)`. Never finish a
sign-in with `create_session`, which skips the gates.

## Depending on another plugin

```rust
/// Logs every new token. Needs `AccessTokens` registered before it.
pub struct TokenAudit;

impl Plugin for TokenAudit {
    const ID: &'static str = "token-audit";
    type Requires = (AccessTokens,);
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.on(|e: AccessTokenCreated, ctx: Ctx<D>| async move {
            let tokens: &AccessTokens = ctx.plugin::<AccessTokens>();
            println!("user {} created token {} (ttl {:?})", e.user_id, e.token_id, tokens.ttl);
            Ok(())
        });
    }
}
```

Registering `TokenAudit` without `AccessTokens` before it fails at the `.plugin(TokenAudit)` call
(see Common mistakes in `SKILL.md`). For an optional dependency, leave `Requires` empty and
use `ctx.try_plugin::<P>()`.

## Registering it

```rust
pub type AppAuth<D> = Auth<D, Profile, plugins![AccessTokens, TokenAudit, Bans]>;

FastAuth::builder()
    // ...
    .plugin(AccessTokens::new().ttl(Duration::days(90)))
    .plugin(TokenAudit)
    .plugin(Bans)
```

Run migrations after adding a plugin that adds tables or columns.
