# Plugins

A plugin is a value you pass to `.plugin(..)`. It can add tables and columns, HTTP
endpoints, hooks around other endpoints, sign-in gates, session resolvers, events,
rate-limit rules, error codes, and typed server-side methods on `Auth`. Social sign-in and
every first-party feature beyond email and password are built this way, so a plugin can
do anything they do.

## Using plugins

```rust
use fastauth::plugins::{admin::Admin, api_key::ApiKeys, organization::Organization, two_factor::TwoFactor};

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![TwoFactor, Organization, Admin, ApiKeys]>;

FastAuth::builder()
    // ...
    .plugin(TwoFactor::new().issuer("Acme").backup_codes(10))
    .plugin(Organization::default().allow_user_to_create_organization(true).invitation_ttl(Duration::days(3)))
    .plugin(Admin::new())
    .plugin(ApiKeys::new())
    .build()
```

The alias lists plugins **in registration order**. If the order differs, the compiler
says so (here with `plugins![Admin, TwoFactor]` and `TwoFactor` registered first):

```
error[E0308]: mismatched types
  --> src/auth.rs:8:5
   |
 7 |   pub fn build() -> Result<AppAuth, BuildError> {
   |                     --------------------------- expected `Result<Auth<MemoryAdapter, (), Cons<Admin, Cons<TwoFactor, Nil>>>, _>` because of return type
...
14 | |         .build()
   | |________________^ expected `Admin`, found `TwoFactor`
```

The order matters for two reasons: a plugin's dependencies must come before it, and hooks
and sign-in gates run in registration order. Run your migrations after adding a plugin
that adds tables or columns ([Databases](06-database.md#migrations)).

### First-party plugins

| Plugin | Feature | Adds |
|---|---|---|
| `social::Social` (`fastauth-oauth`) | `oauth` | Social sign-in: GitHub, Google, your own `OAuthProvider`s; linked accounts ([Configuration](03-configuration.md#social-providers)) |
| `plugins::two_factor::TwoFactor` | `two-factor` | TOTP, OTP by email, backup codes, trusted devices; a sign-in gate |
| `plugins::organization::Organization` | `organization` | Organizations, members, invitations, roles and permissions ([Organization](12-organization.md)) |
| `plugins::admin::Admin` | `admin` | Roles and permissions, ban and unban, impersonation, user management ([Admin](13-admin.md)) |
| `plugins::api_key::ApiKeys` | `api-key` | Hashed API keys with expiry, usage limits and rate limits; optional sessions from keys ([API keys](14-api-keys.md)) |
| `plugins::magic_link::MagicLink` | `magic-link` | Sign-in links by email, with sign-up on first use ([Magic links](15-magic-link.md)) |
| `plugins::email_otp::EmailOtp` | `email-otp` | One-time codes by email for sign-in, email verification and password reset ([Email OTP](16-email-otp.md)) |
| `plugins::bearer::Bearer` | `bearer` | Sessions from `Authorization: Bearer`; the `set-auth-token` header; a session resolver ([Bearer tokens](17-bearer.md)) |
| `plugins::jwt::Jwt` | `jwt` | `/token`, `/jwks`, the `set-auth-jwt` header, rotating signing keys in a `jwks` table ([JWT](18-jwt.md)) |
| `plugins::passkey::Passkey` | `passkey` | WebAuthn registration and sign-in, a `passkey` table; sign-in runs the gates ([Passkeys](19-passkey.md)) |
| `plugins::username::Username` | `username` | `username` and `display_username` on `user`, `/sign-in/username`, `/is-username-available` ([Usernames](20-username.md)) |
| `plugins::anonymous::Anonymous` | `anonymous` | `/sign-in/anonymous`, `is_anonymous` on `user`, linking to the real account on sign-in ([Anonymous users](21-anonymous.md)) |
| `plugins::multi_session::MultiSession` | `multi-session` | Several accounts per browser: device-session cookies, `/multi-session/*` ([Multiple sessions](22-multi-session.md)) |

More plugins are [planned](01-overview.md#planned).

## Writing a plugin

This section builds a small plugin, `AccessTokens` (personal access tokens sent in an
`x-access-token` header), then covers each piece on its own. Everything comes from
`fastauth::plugin_prelude` (`fastauth_core::plugin_prelude` in a published plugin crate).
The code here is compiled and tested against `main`.

### The plugin value and its config

```rust
use fastauth::plugin_prelude::*;

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
```

### The `Plugin` impl

```rust
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

- `ID` names the plugin in error messages, schema ownership (`fastauth schema` shows it)
  and its derived key (`ctx.keys().derive_key(ID)`).
- `Requires` is a tuple of plugins that must be registered first, `()` for none.
- `UserFields` and `SessionFields` are `#[derive(Fields)]` structs of columns added to
  `user` and `session`, `()` for none. They're added to the schema for you.
- `init` runs once, inside `.build()`. Nothing it registers is generic at request time:
  the builder erases each endpoint and hook into the route table
  ([Internals](08-internals.md#the-build-step)).

### Tables: `#[derive(Model)]`

```rust
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
```

The derive generates the table definition (for migrations) and typed column constants,
`AccessToken::USER_ID: Col<AccessToken, Id>`, `AccessToken::TOKEN_HASH: Col<AccessToken, Hash>`.
Queries are checked against them: `AccessToken::EXPIRES_AT.eq("tomorrow")` doesn't compile.

Every field is a column, typed by its Rust type (`Option<T>` is nullable; field types must be
`Clone`). Field attributes:

| `#[model(..)]` | Column |
|---|---|
| `id` | primary key |
| `references = User` | foreign key to that model's `id` column |
| `on_delete = Cascade \| SetNull \| Restrict` | with `references`; default `Restrict` |
| `unique`, `index` | constraint and index |
| `hidden` | never serialized to clients |
| `default = ..` | a bool, integer or string literal, or `now`; checked against the column type at compile time |

`created_at` and `updated_at` are ordinary fields: declare them (usually `#[model(default = now)]`)
when the table wants them. Create ids with `ctx.new_id()?` and treat `Id` as an opaque
string: the app picks the [id strategy](06-database.md#ids).

### Columns on `user` and `session`: `#[derive(Fields)]`

`AccessTokens` doesn't need any, but a plugin that does looks like this:

```rust
#[derive(Fields, Clone, Debug)]
pub struct BanFields {
    #[field(default = false)]
    pub banned: bool,
}

/// Refuses sign-in for users with `user.banned = true`, for every sign-in method.
pub struct Bans;

impl Plugin for Bans {
    const ID: &'static str = "bans";
    type Requires = ();
    type UserFields = BanFields;
    type SessionFields = ();
```

Apps then read `session.user.plugin::<Bans, _>().banned`; the plugin itself reads
`ctx.session().user.fields::<BanFields>()` or `attempt.user.fields()` (it can't name the
app's plugin list). Two plugins adding the same column is a `BuildError` naming both.

`#[fields(table = ..)]` names the model the columns extend (`User` when omitted), so a
generated constant such as `BanFields::BANNED` filters `find::<User>`. A plugin's
`SessionFields` use `#[fields(table = Session)]`. Field attributes: `default = ..` (as for
models), `input` (sign-up and update-user bodies may set it; without it no client can, so
`banned` above is server-only), `returned = false`, `unique`, `index` and
`rename = "column_name"`.

### Endpoints

An endpoint is a type with an input, an output, an access level and an async `call`:

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
```

`Access` is a type, and it changes what `ctx` offers:

| `type Access` | Without a valid session | `ctx.session()` returns |
|---|---|---|
| `Public` | runs | method doesn't exist |
| `MaybeAuthenticated` | runs | `Option<&SessionView>` |
| `Authenticated` | `401 UNAUTHORIZED`, `call` never runs | `&SessionView` |
| `Fresh` | `401`, or `403 SESSION_NOT_FRESH` when too old or ephemeral (an API key's) | `&SessionView` |

So an endpoint can't forget to check the session, and can't unwrap one that might be
missing. `PATH` is relative to the base path and may hold `{name}` parameters
(`ctx.param("name")`). `GET` endpoints read `Input` from the query string, everything else
from the JSON body; `Empty` is `{}`. A body that doesn't deserialize answers `400`.

Also on `ctx`: `db()`, `new_id()`, `now()`, `emit(event)`, `plugin::<P>()` and
`try_plugin::<P>()`, `config()`, `keys()`, `headers()`, `ip()`, `user_agent()`, cookies
(`set_signed_cookie`, `signed_cookie`, `delete_cookie`), `redirect(url)`, and `internal()`
for the core operations plugins build on: finding and creating users, accounts and
sessions, `sign_in` and `complete_sign_in`, verification values, and `send_email`.

An endpoint that creates or changes a credential (a key, a passkey, a linked account,
two-factor) should act on `ctx.sensitive_session().await?` rather than `ctx.session()`. It
reads the session again from the database, skipping the cookie cache, so a session revoked
elsewhere gets `401`; it answers `401` for an ephemeral session (`Resolved::User`, such as an
API key's), which has nothing stored; and it runs the [session gates](#session-gates) with
`SessionUse::Sensitive`, where the admin plugin refuses impersonation sessions. Without a
session it answers `401`, whatever the access level. The API key, passkey, two-factor and
`/link-social` endpoints use it:

```rust
    async fn call(&self, ctx: Ctx<D, Authenticated>, input: CreateTokenInput) -> Result<CreatedToken, AuthError> {
        let session = ctx.sensitive_session().await?;
        let (row, token) = mint(&ctx, &session.user.id, input.name).await?;
        Ok(CreatedToken { id: row.id, token })
    }
```

A list endpoint:

```rust
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

An endpoint that only Rust code may call isn't registered with `app.endpoint(..)`, which
would give it a route. Declare it with `app.server_endpoint::<E>()` instead: it gets no
route, but hooks can target it like any other endpoint. Code runs it with
`auth.api().call(&endpoint, input)`. The API key plugin's
[server-only endpoints](14-api-keys.md#endpoints) and core's `CreateUser` work this way.

When the HTTP route and the server API need different rules on the same input, keep one
endpoint type with a flag, the way the API key plugin's `CreateApiKey::client(..)` and
`::server(..)` do: register the client variant with `app.endpoint(..)` and call the server
variant from the extension trait. Hooks on the type then run for both.

### Session resolvers

Requests without a session cookie go through resolvers in registration order:

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

`Resolved::User` builds a session that exists only for this request and is never written
to the `session` table (`session.view().ephemeral` is true). `Resolved::Token` hands back a
session token found somewhere other than the cookie, such as a bearer header. Every
`Session<AppAuth>` extractor in the app now accepts access tokens, with no handler changes.
An ephemeral session is never fresh and can't pass `ctx.sensitive_session()`, so it can't
mint credentials. The [session gates](#session-gates) run on resolved sessions of both kinds.
`ctx.internal().ephemeral_session(&user_id)` builds the same session for a user, gates
included, for plugins that act for a user outside a request's session.

### Errors

```rust
#[derive(AuthError, Debug)]
#[auth_error(prefix = "ACCESS_TOKEN")]
pub enum AccessTokenError {
    #[auth_error(status = 401, message = "access token expired")]
    Expired,
}
```

Every error leaves the server as `{ "code": "...", "message": "..." }` with the given
status; this one's code is `ACCESS_TOKEN_EXPIRED`. Without `prefix` the code is the variant
name alone, in upper snake case. Variants with named fields can put them in the message,
`message = "scope {scope} is not allowed"`. `app.errors::<AccessTokenError>()` registers the
codes, so two plugins can't claim the same one. For one-off errors, `AuthError` has
constructors: `AuthError::bad_request(code, message)`, `AuthError::forbidden()`,
`AuthError::unauthorized()`, `AuthError::internal(err)` (logged, never sent to the client).

### Events

```rust
#[derive(Clone, Debug)]
pub struct AccessTokenCreated {
    pub user_id: Id,
    pub token_id: Id,
}

impl Event for AccessTokenCreated {}
```

Any `Clone + Send + Sync + 'static` type with `impl Event` is an event. `ctx.emit(..)` queues
it, and handlers registered with `app.on(..)` (or the app's `.on(..)`) run after the endpoint
that emitted it succeeds. An event handler's error is logged and doesn't fail the request.
The `init` above already uses one: it deletes a user's tokens on `PasswordChanged`.

### The typed server API: extension traits

Plugin crates can't add inherent methods to `Auth`, so they ship an extension trait. Its
methods carry a `HasPlugin` bound, so they only compile on an `Auth` that registered the
plugin:

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

`auth.api().call(..)` runs the same access check, hooks and events as an HTTP request,
minus the JSON. Without `AccessTokens` registered, `auth.access_tokens()` fails with
`` plugin `AccessTokens` is not registered on this auth instance ``.

Code that's generic over `AuthInstance` and can't name the `HasPlugin` index, such as an
axum extractor, reads the plugin's config with `auth.try_plugin::<P>()`, an `Option`, and
its tables with `auth.api().db()`. The organization and admin extractors work this way.

### Hooks

Hooks run around endpoints, for every caller (HTTP and the server API). They name an
endpoint type and get its typed input or output by value.

```rust
fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
    // Block disposable domains at sign-up, and normalise the name.
    app.hook::<SignUpEmail>().before(|ctx, mut input: SignUpEmailInput| async move {
        if disposable::is_disposable(&input.email) {
            return Err(AuthError::bad_request("DISPOSABLE_EMAIL", "use a real email address"));
        }
        input.name = input.name.trim().to_owned();
        Ok(Before::Continue(input))
    });

    // Add a field to every get-session response.
    app.hook::<GetSession>().after(|ctx, output: Option<serde_json::Value>| async move {
        Ok(After::Continue(output.map(|mut o| {
            o["plan"] = json!("pro");
            o
        })))
    });
}
```

A before hook returns `Before::Continue(input)` (possibly changed) or `Before::Respond(response)`
to stop and answer; an after hook returns `After::Continue(output)` or `After::Respond(..)`;
either can return an error. Hooks get an owned `HookCtx<D>` (a `Ctx` with an optional
session), so their futures are `'static` and plain `async move` closures work.

A hook on an endpoint that isn't registered (say, `hook::<CreateOrganization>()` without
the organization plugin, or `hook::<SignUpEmail>()` without `.email_password(..)`) is a
`BuildError`. If your plugin lists `Organization` in `Requires`, that can't happen. The app
registers hooks the same way, with `.configure(|app| { app.hook::<SignUpEmail>().before(..); })`
on the builder.

### Sign-in gates

Anything that can stop a sign-in after the credentials check (two-factor, bans) is a gate
rather than a hook. Gates run after the credentials check and **before** the session is
created, for every sign-in method (password and social today), in registration order. A
gate answers `Gate::Allow`, `Gate::Deny(err)` or `Gate::Challenge(json)`:

```rust
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
```

`Gate::Deny(err)` refuses the sign-in with that error. `Gate::Challenge(json)` answers the
sign-in with that JSON and no session; gates registered after it don't run yet. The gate's
`ctx` shares the sign-in's response, so a cookie it sets goes out with the challenge. This
is two-factor's gate:

```rust
    let remember_me = if attempt.remember_me { "1" } else { "0" };
    let max_age = plugin.two_factor_cookie_max_age;
    let token = ctx
        .internal()
        .create_verification(
            &format!("{PENDING_PREFIX}{}", attempt.user.id),
            max_age,
            Some(format!("0|{remember_me}|{}", attempt.method)),
        )
        .await?;
    ctx.set_signed_cookie(PENDING_COOKIE, &token, Some(max_age));
    let methods: &[&str] = if ctx.internal().can_send_email() {
        &["totp", "otp"]
    } else {
        &["totp"]
    };
    Ok(Gate::Challenge(json!({
        "twoFactorRedirect": true,
        "twoFactorMethods": methods,
    })))
```

The pending sign-in lives in a `verification` row that counts the guesses made on it, and the
cookie only names that row. The endpoint that answers the challenge
(`/two-factor/verify-totp`) reads the row back through the cookie, deletes it, and finishes
with `complete_sign_in`, passing its own plugin id:

```rust
            match ctx
                .internal()
                .complete_sign_in(TwoFactor::ID, user, method, remember_me)
                .await?
            {
                SignInResult::SignedIn(session) => *session,
                SignInResult::Challenge(body) => return Ok(VerifyOutput::Challenge(body)),
            }
```

`complete_sign_in` runs **every other gate**, before and after the challenger's in
registration order, then creates the session. So a banned user who answers a TOTP challenge
is still refused, whichever of `TwoFactor` and `Admin` was registered first. A remaining
gate that denies returns its error; one that challenges returns `SignInResult::Challenge`.
`ctx.internal().create_session(..)` is the gate-free primitive underneath; don't use it to
finish a sign-in. Two gates that both challenge the same user keep challenging each other,
so a plugin should challenge only for its own reason.

### Session gates

Sign-in gates judge a sign-in once. A session gate judges a session every time a request uses
one: the cookie, the cookie cache, a bearer token, an API key's ephemeral session, and every
`ctx.sensitive_session()`. Answering `Err` refuses the session, and the request fails with
that error. The admin plugin's gate is how a ban reaches sessions that already exist and
sessions that never went through a sign-in:

```rust
app.session_gate(|_ctx, session: SessionView, usage: SessionUse| async move {
    let fields: BanFields = session.user.fields().map_err(AuthError::internal)?;
    if fields.banned {
        return Err(BanError::Banned.into());
    }
    if usage == SessionUse::Sensitive && is_borrowed(&session) {
        return Err(BanError::NotWithThisSession.into());
    }
    Ok(())
});
```

`SessionUse::Request` is the lookup every request with a session does, so keep that path
cheap: the user row is already in `session.user`. `SessionUse::Sensitive` comes from
`ctx.sensitive_session()`, before a credential is created or changed. With the cookie cache
on, a cached session's user row is as old as the cache cookie, so a gate that reads it sees
a change only once the cache expires; `ctx.sensitive_session()` always reads it fresh.

A plugin that creates sessions with a deliberately short life marks them with
`app.fixed_session_expiry(|session| ..)`: the refresh never extends a session it answers
true for. Every other session slides as usual. The admin plugin marks impersonation sessions:

```rust
app.fixed_session_expiry(|session| {
    session
        .fields::<AdminSession>()
        .is_ok_and(|fields| fields.impersonated_by.is_some())
});
```

### After a session is created

`app.on_session_created(..)` runs inside the request right after a session is stored and
its cookies are set, for every way one is created: any sign-in or sign-up method, a
finished challenge, impersonation. Its context still has the request's headers, so the
session cookie it reads is the session the browser had **before**; it can query the
database and set cookies, and an error fails the response (the new session already exists).
The anonymous plugin links accounts this way, and multi-session remembers each session in a
cookie:

```rust
app.on_session_created(|ctx, session: SessionView| async move {
    let previous = match ctx.signed_cookie("session_token") {
        Some(token) => ctx.internal().find_session_by_token(&token).await?,
        None => None,
    };
    if let Some(previous) = previous.filter(|p| p.user.id != session.user.id) {
        ctx.set_signed_cookie("switched_from", previous.user.id.as_str(), None);
    }
    Ok(())
});
```

Unlike the `SessionCreated` event, which runs after the endpoint without the request, this
hook runs inside the request, before the response is built.

### Depending on another plugin

```rust
impl Plugin for OrgBilling {
    const ID: &'static str = "org-billing";
    type Requires = (Organization,);
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.hook::<CreateOrganization>().after(|ctx, out: OrganizationWithMembers| async move {
            let org = ctx.plugin::<Organization>();   // infallible: Requires proved it's there
            stripe::create_customer(out.organization.id.as_str()).await?;
            Ok(After::Continue(out))
        });
    }
}
```

Registering `OrgBilling` without `Organization`, or before it, is a compile error at the
`.plugin(OrgBilling)` call:

```
error[E0277]: plugin `Organization` is not registered on this auth instance
   --> src/auth.rs:20:17
    |
 20 |         .plugin(OrgBilling)
    |          ------ ^^^^^^^^^^ `Organization` is not in this plugin list
    |          |
    |          required by a bound introduced by this call
    |
    = help: the trait `Has<Organization, _>` is not implemented for `fastauth::Nil`
    = note: register it with `.plugin(...)` on the builder, before any plugin that requires it, and list it in your `plugins![..]` alias
    = note: required for `(Organization,)` to implement `Satisfied<fastauth::Nil, (_,)>`
```

(Real output from rustc 1.100, trimmed.) For an optional dependency, skip `Requires` and
call `ctx.try_plugin::<Organization>()`, which returns an `Option`.

## Testing a plugin

Build an auth instance on `MemoryAdapter` (no database, no migrations) with only your
plugin, and drive it through the server API. `Argon2id::with_params(1024, 1, 1)` makes
password hashing fast and `RateLimit::disabled()` keeps repeated sign-ins from hitting the
limiter:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use fastauth::crypto::Argon2id;
    use fastauth::prelude::{EmailPassword, FastAuth, MemoryAdapter, RateLimit, Secret};
    use fastauth::routes::SignUpEmailInput;
    use fastauth::{Auth, plugins};

    #[tokio::test]
    async fn tokens_authenticate_requests() {
        let auth: Auth<MemoryAdapter, (), plugins![AccessTokens]> = FastAuth::builder()
            .secret(Secret::from_bytes([7; 32]))
            .base_url("http://localhost:3000")
            .database(MemoryAdapter::new())
            .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
            .rate_limit(RateLimit::disabled())
            .plugin(AccessTokens::new())
            .build()
            .unwrap();

        let signed_up = auth
            .api()
            .sign_up_email(SignUpEmailInput {
                name: "Alice".into(),
                email: "alice@acme.dk".into(),
                password: "correct horse battery".into(),
                image: None,
                callback_url: None,
                remember_me: None,
                extra: Default::default(),
            })
            .await
            .unwrap();
        let cookie = signed_up.set_cookies[0].to_str().unwrap().split(';').next().unwrap().to_owned();
        let mut headers = HeaderMap::new();
        headers.insert("cookie", cookie.parse().unwrap());

        let input = CreateTokenInput { name: "ci".into() };
        let created = auth.access_tokens().create(&headers, input).await.unwrap();

        let mut by_token = HeaderMap::new();
        by_token.insert("x-access-token", created.token.parse().unwrap());
        let session = auth.get_session(&by_token).await.unwrap().unwrap();
        assert_eq!(session.user.email, "alice@acme.dk");
        assert!(session.view().ephemeral);
    }
}
```

To run the same test on SQLite or Postgres, build with `Sqlx::new(pool)` and call
`auth.migrator().run()` first; `SqlitePool::connect("sqlite::memory:")` needs no server. To
go through the HTTP layer, put `auth.router()` in an axum `Router` and send requests with
`tower::ServiceExt::oneshot`. A test helper like Better Auth's `getTestInstance` is
[planned](01-overview.md#planned).

## Publishing

Name the crate `fastauth-plugin-<name>`, depend on `fastauth-core` (not the facade), and
import from `fastauth_core::plugin_prelude`. The derives need core's `macros` feature.
That module is the plugin API; while fastauth is 0.x, breaking changes to it come with a
minor version bump.
