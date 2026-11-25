# Sessions and the server API

## In axum handlers

```rust
use fastauth::axum::{FreshSession, Session};

// 401 without a valid session.
async fn dashboard(session: Session<AppAuth>) -> impl IntoResponse { /* ... */ }

// Signed in or not.
async fn home(session: Option<Session<AppAuth>>) -> impl IntoResponse { /* ... */ }

// 403 unless the session was created within fresh_age (default 1 day).
async fn delete_account(session: FreshSession<AppAuth>) -> impl IntoResponse { /* ... */ }
```

`Session<A>` derefs to `SessionData`, which has three fields:

| Field | Type | What |
|---|---|---|
| `session.session` | `fastauth::models::Session` | The session row: `id`, `user_id`, `expires_at`, `ip_address`, `user_agent`, `created_at`, `updated_at` |
| `session.user` | `AuthUser<U, P>` | Derefs to the core `User` row (`id`, `email`, `email_verified`, `name`, `image`, `created_at`, `updated_at`); `.fields` is your `#[derive(Fields)]` struct; `.plugin::<P, _>()` reads a plugin's columns |
| `session.token` | `Option<String>` | The raw session token when the request carried one |

```rust
async fn whoami(session: Session<AppAuth>) -> String {
    let user = &session.user;               // AuthUser: derefs to the core User row
    let expires = session.session.expires_at; // the Session row
    format!("{} ({}), session {} until {expires}", user.name, user.email, session.session.id)
}
```

Ids are opaque strings (`Id`), ULIDs by default ([Databases](06-database.md#ids)).
`session.session_plugin::<P, _>()` reads columns a plugin added to `session`, such as the
organization plugin's active organization.

The extractor needs to find the auth instance in your router state. If the state *is*
the auth instance, that works already. Otherwise derive `FromRef` (axum's `macros`
feature):

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

The layer also adds the cookies that lookup produced to the response: a refreshed session
cookie (sliding expiry) or cleared cookies for an invalid one. Without it, extractors still
work, but a refresh that happens on one of your own routes doesn't reach the browser until
the next request to an auth route. A cookie the handler itself sets (say, after signing the
user out) wins over the layer's.

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
error[E0277]: plugin `fastauth::plugins::fastauth_plugin_admin::Admin` is not registered on this auth instance
   --> src/routes/settings.rs:18:42
    |
 18 |     let admin: &AdminUser = session.user.plugin::<Admin, _>();
    |                                          ^^^^^^ `fastauth::plugins::fastauth_plugin_admin::Admin` is not in this plugin list
    |
    = help: the trait `Has<fastauth::plugins::fastauth_plugin_admin::Admin, _>` is not implemented for `fastauth::Nil`
    = note: register it with `.plugin(...)` on the builder, before any plugin that requires it, and list it in your `plugins![..]` alias
```

(Real output from rustc 1.100, trimmed to the primary error, the help and the note. rustc
spells out the full path here because `admin::role::Admin` has the same name; a plugin
with a unique name, such as `TwoFactor`, shows as `TwoFactor`.)

## Guards from plugins

Plugins can ship extractors. The admin plugin's role guard is a type parameter, so the
required role is visible in the handler signature:

```rust
use fastauth::plugins::admin::{Admin, AdminExt, AdminUser, BanUserInput, RequireRole, role};

async fn ban_user(
    _: RequireRole<AppAuth, role::Admin>,
    Path(id): Path<String>,
    State(auth): State<AppAuth>,
) -> Result<StatusCode, AuthError> {
    auth.admin().ban(BanUserInput::new(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}
```

The organization plugin has `ActiveMember`, `OrgMember<A, FromPath<P>>` and
`RequirePermission<A, P, S>` ([Organization](12-organization.md#axum-extractors)); the
admin plugin's are on [Admin](13-admin.md#axum-extractor).

## The server API

Every endpoint can be called from Rust without HTTP. There's no JSON round trip: the call
goes straight to the endpoint's `call` with the typed input, through the same access
check, hooks and events as an HTTP request.

```rust
use fastauth::routes::{SignInEmailInput, SignInOutput};

// Core endpoints live on auth.api(). Pass the request's headers so the call sees its
// cookies, user agent and so on, or act as a session with .session_token(token).
let signed_in = auth
    .api()
    .headers(&headers)
    .sign_in_email(SignInEmailInput {
        email,
        password: password.clone(),
        callback_url: None,
        remember_me: Some(true),
    })
    .await?;

// Plugin endpoints live on extension traits, which only compile with the plugin registered.
// They take the request's headers: their cookies carry the session (or, for verify_totp,
// the pending two-factor sign-in).
use fastauth::plugins::two_factor::{EnableInput, TwoFactor, TwoFactorExt, TwoFactorUser};
let setup = auth.two_factor().enable(&headers, EnableInput { password, issuer: None }).await?;

// Any endpoint, core or plugin, runs through the same pipeline with `call`:
let sessions = auth.api().headers(&headers).call(&fastauth::routes::ListSessions, Default::default()).await?;
```

`auth.api()` has typed methods for `sign_up_email`, `sign_in_email`, `sign_out`,
`list_sessions`, `revoke_other_sessions`, `change_password`, `request_password_reset`,
`reset_password` and the server-only `create_user`; every other endpoint goes through
`.call(&Endpoint, input)`. The endpoint and input types are in `fastauth::routes` and in each
plugin crate. A call to an endpoint that needs a session, without `.headers(..)` or
`.session_token(..)`, fails with `401`.

Every call returns `ApiResponse<T>`: the typed output in `data` plus the `Set-Cookie` values the
endpoint produced in `set_cookies`. With the `axum` feature it implements `IntoResponse`, so a
custom sign-in handler can return it as is and the browser gets the session cookie:

```rust
async fn sign_in_with_invite(
    State(auth): State<AppAuth>,
    headers: HeaderMap,
    Json(body): Json<InviteSignIn>,
) -> Result<ApiResponse<SignInOutput>, AuthError> {
    let invite = invites::redeem(&body.code).await?;
    auth.api()
        .headers(&headers)
        .sign_in_email(SignInEmailInput {
            email: invite.email,
            password: body.password,
            callback_url: None,
            remember_me: Some(true),
        })
        .await
}
```

### Getting a session outside an extractor

```rust
let session = auth.get_session(&headers).await?;              // Option<SessionData<..>>
let session = auth.get_session_by_token(&token).await?;       // e.g. from a WebSocket query string
```

### Sharing a transaction

With sqlx, server API calls can join your transaction, so the user, account and session
rows they write commit or roll back together with your own rows. Hand your sqlx
transaction to a `SharedTx`, and pass that to `.in_tx`:

```rust
use fastauth::routes::CreateUserInput;
use fastauth::sqlx::{InTx, SharedTx};   // also in the prelude

let tx = SharedTx::new(pool.begin().await?);
let user = auth.api()
    .in_tx(&tx)
    .create_user(CreateUserInput { email, name, ..Default::default() })
    .await?;
sqlx::query("insert into team_members (team_id, user_id) values ($1, $2)")
    .bind(team_id).bind(user.id.as_str())
    .execute(&mut **tx.lock().await).await?;
tx.commit().await?;
// UserCreated fires here, after the commit. tx.rollback() (or dropping tx) discards it.
```

The rules:

- **Every query of the call runs on your transaction**: its writes, its reads, the session
  lookup, and the queries of hooks and sign-in gates. Nothing touches the pool, so the call
  can't wait on your own uncommitted writes (which deadlocks with in-memory SQLite).
- **A failed fastauth call leaves your transaction as it was.** Each call runs inside its own
  savepoint, and a failure of any kind (a taken email, a hook's error, a database error)
  rolls back to it. Your earlier writes stay, and the transaction stays usable, on Postgres
  too. A transaction fastauth opens inside the call, like `create_user`'s, is a nested
  savepoint.
- **Events fire after `tx.commit()` succeeds**, in the order the calls emitted them, and
  never on rollback. Handlers run on the pool, so they see the committed rows.
- **Don't hold `tx.lock()` across a fastauth call.** The call needs the connection, and
  waits for your guard. `.execute(&mut **tx.lock().await)` drops it at the end of the
  statement.

`.in_tx` sits on `Api` next to `.headers` and `.session_token`, and applies to every call
made through that `Api`. It takes a `SharedTx` rather than `&mut sqlx::Transaction` because
hooks and event handlers get an owned, `'static` context, which can't hold a borrow, and
because only fastauth's own `commit` can fire the events after the commit. It type-checks
because `Auth` is generic over the adapter: on `Auth<Sqlx<Postgres>, ..>` it accepts a
`SharedTx<Postgres>` and nothing else.

`create_user` is server-only (there's no HTTP route). It validates like sign-up, creates a
`credential` account when `password` is set, takes app and plugin `input` columns in
`fields`, and answers `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` (422) for a taken email.

## Sessions, listed

| Operation | HTTP | Server API |
|---|---|---|
| Current session | `GET /get-session` | `auth.get_session(&headers)` |
| All sessions of the user | `GET /list-sessions` | `auth.api().headers(&headers).list_sessions()` |
| Revoke one | `POST /revoke-session` `{ id }` or `{ token }` | `.call(&RevokeSession, RevokeSessionInput { .. })` |
| Revoke all but current | `POST /revoke-other-sessions` | `auth.api().headers(&headers).revoke_other_sessions()` |
| Revoke all | `POST /revoke-sessions` | `.call(&RevokeSessions, Empty {})` |
| Sign out | `POST /sign-out` | `auth.api().headers(&headers).sign_out()` |

Sessions are listed and revoked by `id`: the database only stores a hash of each token,
so there is no token to hand back ([Security](09-security.md#session-tokens)).
`/revoke-session` also takes `{ token }` and hashes it, for Better Auth's client.
