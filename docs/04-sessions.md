# Sessions and the server API

## In axum handlers

```rust
use fastauth::axum::{Session, FreshSession};

// 401 without a valid session.
async fn dashboard(session: Session<AppAuth>) -> impl IntoResponse { /* ... */ }

// Signed in or not.
async fn home(session: Option<Session<AppAuth>>) -> impl IntoResponse { /* ... */ }

// 403 unless the session was created within fresh_age (default 1 day).
async fn delete_account(session: FreshSession<AppAuth>) -> impl IntoResponse { /* ... */ }
```

`Session<A>` derefs to `SessionData<A>`:

```rust
pub struct SessionData<A: AuthTypes> {
    pub session: SessionRow<A::SessionFields>, // id, user_id, expires_at, created_at, ip, user_agent, fields
    pub user: User<A::UserFields, A::Plugins>,
}

pub struct User<U, P: PluginSet> {
    pub id: Id,
    pub email: String,
    pub email_verified: bool,
    pub name: String,
    pub image: Option<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub fields: U,           // your #[derive(Fields)] struct
    ext: P::UserExt,         // one typed struct per plugin, reached through .plugin::<P, _>()
}
```

The extractor needs to find the auth instance in your router state. If the state *is*
the auth instance, that works already. Otherwise derive `FromRef`:

```rust
#[derive(Clone, FromRef)]
struct AppState {
    auth: AppAuth,
    pool: PgPool,
}
```

### Resolving once per request

Each `Session` extractor checks the request extensions first and only resolves the
session if nothing is there, so two extractors in one handler cost one lookup. To make
that lookup happen once for a whole router (and to let non-handler middleware see the
session), add the layer:

```rust
let app = Router::new()
    .route("/me", get(me))
    .merge(auth.router())
    .layer(auth.session_layer())   // resolves lazily on first use, caches in extensions
    .with_state(state);
```

## Typed plugin data on the user

Plugins that add columns to `user` expose them as a typed struct:

```rust
async fn settings(session: Session<AppAuth>) -> Json<Settings> {
    let tfa: &TwoFactorUser = session.user.plugin::<TwoFactor, _>();
    let admin: &AdminUser = session.user.plugin::<Admin, _>();
    Json(Settings {
        two_factor: tfa.two_factor_enabled,
        role: admin.role.clone(),
        banned: admin.banned,
    })
}
```

The `_` is the plugin's position in the list. You never write it; the compiler infers it.
If `Admin` isn't in `AppAuth`'s plugin list:

```
error[E0277]: plugin `Admin` is not registered on this auth instance
  --> src/routes/settings.rs:4:41
   |
 4 |     let admin = session.user.plugin::<Admin, _>();
   |                              ^^^^^^ `Admin` is not in this plugin list
   |
   = note: register it with `.plugin(...)` on the builder, before any plugin that requires it
```

(That's the spike's real error format, trimmed, with this example's names.)

## Guards from plugins

Plugins can ship extractors. The admin plugin's role guard is a type parameter, so the
required role is visible in the handler signature:

```rust
use fastauth::plugins::admin::{RequireRole, role};

async fn ban_user(
    _: RequireRole<AppAuth, role::Admin>,
    Path(id): Path<Id>,
    State(auth): State<AppAuth>,
) -> Result<StatusCode, AuthError> {
    auth.admin().ban(&id, BanOptions::default()).await?;
    Ok(StatusCode::NO_CONTENT)
}
```

The organization plugin does the same with `RequireMember<A, OrgFromPath<"org_id">>` and
`RequirePermission<A, perm::InviteMembers>`.

## The server API

Every endpoint can be called from Rust without HTTP. There's no JSON round trip: the call
goes straight to the endpoint's `call` with the typed input.

```rust
// Core endpoints live on auth.api().
let signed_in = auth
    .api()
    .sign_in_email(SignInEmail { email, password, remember_me: true })
    .meta(RequestMeta::from_headers(&headers))   // ip and user agent for the session row
    .await?;

// Plugin endpoints live on extension traits, which only compile with the plugin registered.
// They take the request's headers: their cookies carry the session (or, for verify_totp,
// the pending two-factor sign-in).
use fastauth::plugins::two_factor::{EnableInput, TwoFactorExt};
let setup = auth.two_factor().enable(&headers, EnableInput { password, issuer: None }).await?;

use fastauth::plugins::organization::OrganizationExt;
let org = auth.organization().create(&session, CreateOrg { name: "Acme".into(), slug: None }).await?;
```

Results that would set cookies over HTTP (`sign_in_email`, `sign_up_email`) return a
value carrying the session token, plus an `IntoResponse` impl that sets the cookie. A custom
sign-in handler can return it as is:

```rust
async fn sign_in_with_invite(
    State(auth): State<AppAuth>,
    headers: HeaderMap,
    Json(body): Json<InviteSignIn>,
) -> Result<SignedIn<AppAuth>, AuthError> {
    let invite = invites::redeem(&body.code).await?;
    auth.api()
        .sign_in_email(SignInEmail { email: invite.email, password: body.password, remember_me: true })
        .meta(RequestMeta::from_headers(&headers))
        .await
}
```

### Getting a session outside an extractor

```rust
let session = auth.get_session(&headers).await?;              // Option<SessionData<AppAuth>>
let session = auth.get_session_by_token(&token).await?;       // e.g. from a WebSocket query string
```

### Sharing a transaction

With sqlx, server API calls can join your transaction, so the user row and your own rows
commit or roll back together:

```rust
let mut tx = pool.begin().await?;
let user = auth.api()
    .create_user(CreateUser { email, name, password: None })
    .in_tx(&mut tx)
    .await?;
sqlx::query("insert into team_members (team_id, user_id) values ($1, $2)")
    .bind(team_id).bind(user.id)
    .execute(&mut *tx).await?;
tx.commit().await?;
// Events (UserCreated) fire here, after commit, not inside the transaction.
```

`.in_tx` is available because `Auth` is generic over the adapter: the compiler knows it is
`Sqlx<Postgres>` and accepts a `&mut sqlx::Transaction<'_, Postgres>`.

## Sessions, listed

| Operation | HTTP | Server API |
|---|---|---|
| Current session | `GET /get-session` | `auth.get_session(&headers)` |
| All sessions of the user | `GET /list-sessions` | `auth.api().list_sessions(&session)` |
| Revoke one | `POST /revoke-session` `{ id }` | `auth.api().revoke_session(&session, id)` |
| Revoke all but current | `POST /revoke-other-sessions` | `auth.api().revoke_other_sessions(&session)` |
| Revoke all | `POST /revoke-sessions` | `auth.api().revoke_sessions(&session)` |
| Update session fields | `POST /update-session` | `auth.api().update_session(&session, fields)` |
| Sign out | `POST /sign-out` | `auth.api().sign_out(&session)` |

Sessions are revoked by `id`, not by token: the database only stores a hash of each token,
so there is no token to hand back ([Security](09-security.md#session-tokens)).
