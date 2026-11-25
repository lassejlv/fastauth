# Plugins

A plugin is a value you pass to `.plugin(..)`. It can add tables and columns, HTTP
endpoints, hooks around other endpoints, sign-in gates, session resolvers, events,
rate-limit rules, error codes, and typed server-side methods on `Auth`. Core features
(email and password, social sign-in) are built the same way, so plugins can do anything
core does.

## Using plugins

```rust
use fastauth::plugins::{admin::Admin, organization::Organization, passkey::Passkey, two_factor::TwoFactor};

pub type AppAuth = Auth<Sqlx<Postgres>, Profile, plugins![TwoFactor, Passkey, Organization, Admin]>;

FastAuth::builder()
    // ...
    .plugin(TwoFactor::new().issuer("Acme").backup_codes(10))
    .plugin(Passkey::new().rp_id("acme.dk").rp_name("Acme"))
    .plugin(Organization::default().allow_user_to_create(true).invitation_ttl(Duration::days(3)))
    .plugin(Admin::default())
    .build()?
```

The alias lists plugins **in registration order**. If the order differs, the compiler
says so with `expected Cons<Organization, ..>, found Cons<TwoFactor, ..>`. The order
matters for two reasons: a plugin's dependencies must come before it, and hooks run in
registration order.

### First-party plugins

| Plugin | Adds |
|---|---|
| `social::Social` (`fastauth-oauth`) | Social sign-in: GitHub, Google, your own `OAuthProvider`s; linked accounts |
| `two_factor::TwoFactor` | TOTP, OTP by email, backup codes, trusted devices; a sign-in gate |
| `passkey::Passkey` | WebAuthn registration and sign-in (on `webauthn-rs`) |
| `magic_link::MagicLink` | Passwordless sign-in by email link |
| `email_otp::EmailOtp` | Sign-in and verification with a 6-digit code |
| `username::Username` | Sign-in with username, `user.username` |
| `organization::Organization` | Organizations, members, invitations, teams, roles and permissions |
| `admin::Admin` | Roles, ban and unban, impersonation, user management endpoints |
| `api_key::ApiKeys` | Per-user API keys with scopes, expiry and per-key rate limits |
| `bearer::Bearer` | `Authorization: Bearer <session token>` for non-browser clients |
| `jwt::Jwt` | Short-lived JWTs and a JWKS endpoint, for services that verify without a DB call |
| `anonymous::Anonymous` | Guest users that can be upgraded to real accounts |
| `oidc_provider::OidcProvider` | Turns your app into an OpenID Connect provider |

## Writing a plugin

This section builds a complete plugin, `ApiKeys`, then covers each piece on its own.

### The plugin value and its config

```rust
use fastauth::plugin::prelude::*;

pub struct ApiKeys {
    prefix: &'static str,
    default_ttl: Option<Duration>,
    header: HeaderName,
}

impl Default for ApiKeys {
    fn default() -> Self {
        Self { prefix: "ak_", default_ttl: None, header: HeaderName::from_static("x-api-key") }
    }
}

impl ApiKeys {
    pub fn prefix(mut self, prefix: &'static str) -> Self {
        self.prefix = prefix;
        self
    }
}
```

### The `Plugin` impl

```rust
impl Plugin for ApiKeys {
    const ID: &'static str = "api-key";
    type Requires = ();          // tuple of plugins that must be registered first
    type UserFields = ();        // columns added to `user`, see below
    type SessionFields = ();     // columns added to `session`

    fn schema(&self, schema: &mut SchemaBuilder) {
        schema.model::<ApiKey>();
    }

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.endpoint(CreateKey(self.clone()));
        app.endpoint(ListKeys);
        app.endpoint(RevokeKey);
        app.session_resolver(KeyResolver(self.clone()));
        app.rate_limit("/api-key/create", Limit::per(Duration::minutes(1), 10));
        app.errors::<ApiKeyError>();
    }
}
```

`init` runs once, inside `.build()`. Nothing it registers is generic at request time: the
builder erases each endpoint and hook into the route table ([Internals](08-internals.md#the-build-step)).

### Tables: `#[derive(Model)]`

```rust
#[derive(Model, Clone)]
#[model(table = "api_key")]
pub struct ApiKey {
    #[model(id)]
    pub id: Id,
    #[model(references = User, on_delete = Cascade, index)]
    pub user_id: Id,
    pub name: String,
    #[model(unique)]
    pub key_hash: Hash,          // SHA-256 of the key; the key itself is shown once
    pub start: String,           // first 8 chars, so users can tell keys apart
    pub scopes: Json<Vec<String>>,
    pub expires_at: Option<Timestamp>,
    pub created_at: Timestamp,
}
```

The derive generates the table definition (for migrations) and typed column constants,
`ApiKey::USER_ID: Col<ApiKey, Id>`, `ApiKey::KEY_HASH: Col<ApiKey, Hash>`. Queries are
checked against them: `ApiKey::USER_ID.eq("not an id")` doesn't compile.

### Columns on `user`: `#[derive(Fields)]`

`ApiKeys` doesn't need any, but a plugin that does looks like this:

```rust
#[derive(Fields, Clone, Serialize)]
#[fields(table = User)]
pub struct TwoFactorUser {
    #[field(default = false, input = false)]
    pub two_factor_enabled: bool,
}

impl Plugin for TwoFactor {
    type UserFields = TwoFactorUser;
    // ...
}
```

Apps then read `session.user.plugin::<TwoFactor, _>().two_factor_enabled`. Two plugins
adding the same column is a `BuildError` naming both.

### Endpoints

An endpoint is a type with an input, an output, an access level and an async `call`:

```rust
pub struct CreateKey(Arc<ApiKeys>);

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateKeyInput {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub expires_in: Option<Duration>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreatedKey {
    pub id: Id,
    pub key: String,   // shown once
}

impl<D: Adapter> Endpoint<D> for CreateKey {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/api-key/create";
    type Access = Authenticated;
    type Input = CreateKeyInput;
    type Output = CreatedKey;

    async fn call(&self, ctx: Ctx<D, Authenticated>, input: CreateKeyInput) -> Result<CreatedKey, AuthError> {
        let user_id = ctx.session().user.id.clone();
        let key = format!("{}{}", self.0.prefix, ctx.random().token_base62(32));
        let row = ApiKey {
            id: ctx.new_id(),
            user_id,
            name: input.name,
            key_hash: Hash::sha256(&key),
            start: key[..8].to_owned(),
            scopes: Json(input.scopes),
            expires_at: input.expires_in.or(self.0.default_ttl).map(|ttl| ctx.now() + ttl),
            created_at: ctx.now(),
        };
        ctx.db().insert(&row).await?;
        ctx.emit(ApiKeyCreated { id: row.id.clone(), user_id: row.user_id.clone() });
        Ok(CreatedKey { id: row.id, key })
    }
}
```

`Access` is a type, and it changes what `ctx` offers:

| `type Access` | Without a valid session | `ctx.session()` returns |
|---|---|---|
| `Public` | runs | method doesn't exist |
| `MaybeAuthenticated` | runs | `Option<&SessionData>` |
| `Authenticated` | `401 UNAUTHORIZED`, `call` never runs | `&SessionData` |
| `Fresh` | `401`, or `403 SESSION_NOT_FRESH` when too old | `&SessionData` |

So an endpoint can't forget to check the session, and can't unwrap one that might be
missing. `GET` endpoints read `Input` from the query string, everything else from the
JSON body. Inputs that need validation beyond types implement `Validate` (or use the
`garde` feature), and failures return `400 VALIDATION_FAILED` with a per-field list.

The `#[endpoint]` attribute writes the same impl from a function, for endpoints that
don't need plugin config:

```rust
#[endpoint(GET "/api-key/list", access = Authenticated)]
async fn list_keys<D: Adapter>(ctx: Ctx<D, Authenticated>, _: Empty) -> Result<Vec<KeySummary>, AuthError> {
    let keys = ctx.db()
        .find::<ApiKey>(ApiKey::USER_ID.eq(&ctx.session().user.id))
        .order_by(ApiKey::CREATED_AT.desc())
        .all()
        .await?;
    Ok(keys.into_iter().map(KeySummary::from).collect())
}
// generates `pub struct ListKeys;` and `impl<D: Adapter> Endpoint<D> for ListKeys`
```

### Session resolvers

Requests without a session cookie go through resolvers in registration order. The API
key plugin turns `x-api-key` into a session for the key's owner:

```rust
struct KeyResolver(Arc<ApiKeys>);

impl<D: Adapter> SessionResolver<D> for KeyResolver {
    async fn resolve(&self, ctx: &Ctx<D>, headers: &HeaderMap) -> Result<Option<Resolved>, AuthError> {
        let Some(key) = headers.get(&self.0.header) else { return Ok(None) };
        let Some(row) = ctx.db().find::<ApiKey>(ApiKey::KEY_HASH.eq(Hash::sha256(key.as_bytes()))).one().await? else {
            return Err(ApiKeyError::NotFound.into());
        };
        if row.expires_at.is_some_and(|t| t < ctx.now()) {
            return Err(ApiKeyError::Expired.into());
        }
        Ok(Some(Resolved::User(row.user_id)))
    }
}
```

`Resolved::User` builds a session that exists only for this request and is never written to the `session` table (`session.view().ephemeral` is true). `Resolved::Token` hands back a session token found somewhere other than the cookie, such as a bearer header. Every
`Session<AppAuth>` extractor in the app now accepts API keys, with no handler changes.

### Errors

```rust
#[derive(AuthError, Debug)]
#[auth_error(prefix = "API_KEY")]
pub enum ApiKeyError {
    #[auth_error(status = 404, message = "API key not found")]
    NotFound,                                  // code: API_KEY_NOT_FOUND
    #[auth_error(status = 401, message = "API key expired")]
    Expired,                                   // code: API_KEY_EXPIRED
}
```

Every error leaves the server as `{ "code": "...", "message": "..." }` with the given
status. `app.errors::<ApiKeyError>()` registers the codes so the OpenAPI document and
`fastauth errors` list them, and so two plugins can't claim the same code.

### The typed server API: extension traits

Plugin crates can't add inherent methods to `Auth`, so they ship an extension trait. Its
methods carry a `HasPlugin` bound, so they only compile on an `Auth` that registered the
plugin:

```rust
pub trait ApiKeysExt: AuthHandle + Sized {
    fn api_keys<I>(&self) -> ApiKeysApi<'_, Self>
    where
        Self: HasPlugin<ApiKeys, I>,
    {
        ApiKeysApi { auth: self, plugin: self.plugin_arc().clone() }
    }
}

impl<D: Adapter, U: Fields, P: PluginSet> ApiKeysExt for Auth<D, U, P> {}

pub struct ApiKeysApi<'a, A: AuthHandle> {
    auth: &'a A,
    plugin: Arc<ApiKeys>,
}

impl<A: AuthHandle> ApiKeysApi<'_, A> {
    pub async fn create(&self, session: &impl AsSession, input: CreateKeyInput) -> Result<CreatedKey, AuthError> {
        self.auth.call(CreateKey(self.plugin.clone()), session, input).await
    }

    pub async fn revoke_all_for(&self, user_id: &Id) -> Result<u64, AuthError> {
        self.auth.db().delete::<ApiKey>(ApiKey::USER_ID.eq(user_id)).await
    }
}
```

`auth.call(endpoint, session, input)` runs the same access check, hooks and events as an
HTTP request, minus the JSON. Without `ApiKeys` registered, `auth.api_keys()` fails with
`plugin \`ApiKeys\` is not registered on this auth instance`.

### Hooks

Hooks run around endpoints, for every caller (HTTP and the server API). They name an
endpoint type and get its typed input or output by value:

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

A hook on an endpoint that isn't registered (say, `hook::<CreateOrg>()` without the
organization plugin) is a `BuildError`. If your plugin lists `Organization` in `Requires`,
that can't happen. The app registers hooks the same way, with
`.configure(|app| { app.hook::<SignUpEmail>().before(..); })` on the builder.

### Sign-in gates

Anything that can stop a sign-in after the credentials check (two-factor, bans, forced
password resets, email verification) is a gate rather than a hook. Gates run after
the credentials check and **before** the session is created, for every sign-in method:
password, social, magic link, passkey.

```rust
impl Plugin for TwoFactor {
    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.sign_in_gate(|ctx, attempt: SignInAttempt| async move {
            let tfa = attempt.user.fields::<TwoFactorUser>()?;
            if !tfa.two_factor_enabled || ctx.trusted_device(attempt).await? {
                return Ok(Gate::Allow);
            }
            Ok(Gate::Challenge(Challenge::new("two-factor").redirect(true)))
        });
        // /two-factor/verify-totp finishes the challenge with app.complete_challenge(..)
    }
}
```

`Gate::Challenge` answers the sign-in with `{ "twoFactorRedirect": true }` and a short-lived
signed cookie naming the pending user; no session exists until the challenge is completed.
`Gate::Deny(err)` refuses the sign-in outright (the admin plugin's ban check).

### Events

```rust
app.on(|e: UserDeleted, ctx: Ctx<D>| async move {
    ctx.db().delete::<ApiKey>(ApiKey::USER_ID.eq(&e.user_id)).await?;
    Ok(())
});

// Publish your own:
#[derive(Event, Clone)]
pub struct ApiKeyCreated { pub id: Id, pub user_id: Id }
```

Events are dispatched after the endpoint that emitted them succeeds. An event handler's
error is logged and doesn't fail the request.

### Depending on another plugin

```rust
impl Plugin for OrgBilling {
    const ID: &'static str = "org-billing";
    type Requires = (Organization,);
    // ...

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.hook::<CreateOrg>().after(|ctx, out: CreateOrgOutput| async move {
            let org = ctx.plugin::<Organization>();   // infallible: Requires proved it's there
            stripe::create_customer(&out.organization, org.billing_email()).await?;
            Ok(After::Continue(out))
        });
    }
}
```

Registering `OrgBilling` without `Organization`, or before it, is a compile error at the
`.plugin(OrgBilling)` call:

```
error[E0277]: plugin `Organization` is not registered on this auth instance
 --> src/auth.rs:3:54
  |
3 |     let _ = builder(MemoryAdapter::default()).plugin(OrgBilling).build();
  |                                               ------ ^^^^^^^^^^ `Organization` is not in this plugin list
  |                                               |
  |                                               required by a bound introduced by this call
  |
  = note: register it with `.plugin(...)` on the builder, before any plugin that requires it
  = note: required for `(Organization,)` to implement `Satisfied<Nil, (_,)>`
```

(Real output from the spike, trimmed.) For an optional dependency, skip `Requires` and
call `ctx.try_plugin::<Organization>()`, which returns an `Option`.

## Testing a plugin

`fastauth::testing` (feature `testing`) gives you an in-memory auth instance and a client
that speaks the real HTTP layer:

```rust
#[tokio::test]
async fn keys_authenticate_requests() {
    let t = TestAuth::new().plugin(ApiKeys::default()).build().await;
    let alice = t.sign_up("alice@acme.dk").await;

    let created: CreatedKey = t.post("/api-key/create").as_user(&alice).json(json!({ "name": "ci" })).send().await.json();

    let me = t.get("/get-session").header("x-api-key", &created.key).send().await;
    assert_eq!(me.json::<Value>()["user"]["email"], "alice@acme.dk");
}
```

`TestAuth` runs on `MemoryAdapter` by default. `TestAuth::with_adapter(..)` runs the same
test against SQLite or Postgres, and `fastauth-sqlx` uses that to run every first-party
plugin's tests on all three databases.

## Publishing

Name the crate `fastauth-plugin-<name>`, depend on `fastauth-core` (not the facade), and
import from `fastauth_core::plugin::prelude`. That module is the stable plugin API:
semver-breaking changes to it only happen in major versions of `fastauth-core`.
