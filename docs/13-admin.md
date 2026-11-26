# Admin

The admin plugin adds roles and permissions, bans, impersonation and user management to
fastauth. Its routes, JSON and error codes match Better Auth's admin plugin, so Better Auth's
`adminClient` works against it unchanged. From Rust, `auth.admin()` runs the same operations
without a session.

## Setup

Turn on the facade's `admin` feature:

```bash
cargo add fastauth --features admin
```

```toml
[dependencies]
fastauth = { version = "0.2", features = ["admin"] }
```

The plugin lives at `fastauth::plugins::admin` (crate `fastauth-plugin-admin`). The
`RequireRole` extractor also needs the facade's `axum` feature, which is on by default and
turns on `fastauth-plugin-admin/axum`.

Register it with `.plugin(..)` and add `Admin` to your alias:

```rust
use fastauth::plugins::admin::{Admin, Permissions};
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![Admin]>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .plugin(Admin::new().role("support", Permissions::new().allow("user", ["list", "get"])))
        .build()
}
```

`Admin` requires no other plugin, and its position in the alias doesn't change what it does.
List it where you register it ([Plugins](05-plugins.md#using-plugins)).

### Migrations

The plugin adds no tables. It adds four columns to `user` and one to `session`, so run your
migrations after adding it ([Databases](06-database.md#migrations)):

```rust
auth.migrator().run().await?;
```

| Table | Column | JSON | Type | Meaning |
|---|---|---|---|---|
| `user` | `role` | `role` | text, nullable | The user's roles, comma-separated (`"admin,support"`). |
| `user` | `banned` | `banned` | bool, default `false` | Whether the user is banned. |
| `user` | `ban_reason` | `banReason` | text, nullable | Why. |
| `user` | `ban_expires` | `banExpires` | timestamp, nullable | When the ban lifts; null bans for good. |
| `session` | `impersonated_by` | `impersonatedBy` | id, nullable | The admin's user id, on sessions made by impersonate-user. |

Every column is returned to clients, and none is client-settable: `/sign-up/email` or
`/update-user` with `role` or `banned` answers `400 INVALID_FIELD`. Only the admin routes
and the server API change them. `create-user` writes the role with the user; every other new
user gets the default role from the plugin's `UserCreated` handler. Treat an empty `role` as
the default role; `Admin::roles_of` does that for you.

Read the columns in a handler with `session.user.plugin::<Admin, _>()`
([Sessions](04-sessions.md#typed-plugin-data-on-the-user)), or from a `UserView` with
`.fields()`:

```rust
use fastauth::plugins::admin::{Admin, AdminExt, AdminUser};

pub async fn me(session: Session<AppAuth>) -> Json<Me> {
    let admin: &AdminUser = session.user.plugin::<Admin, _>();
    Json(Me {
        email: session.user.email.clone(),
        role: admin.role.clone(),
    })
}

pub async fn is_banned(auth: &AppAuth, user_id: &Id) -> Result<bool, AuthError> {
    let user = auth.admin().get_user(user_id).await?;
    let admin: AdminUser = user.fields().map_err(AuthError::internal)?;
    Ok(admin.banned)
}
```

The session column is an `AdminSession`: `session.session_plugin::<Admin, _>()`.

## Configuration

Every option, with its default:

| Method | Default | What it does |
|---|---|---|
| `.role(name, Permissions)` | `admin` and `user` | Defines a role, or replaces a built-in one. See [Roles and permissions](#roles-and-permissions). |
| `.default_role(name)` | `"user"` | The role new users get, and the role of a user whose `role` is empty. |
| `.admin_roles([..])` | `["admin"]` | Roles whose holders count as admins. Each must be defined with `.role`, or `.build()` panics with `invalid admin roles: ..`. |
| `.admin_user_ids([..])` | none | Users who pass every permission check whatever their role. |
| `.impersonation_session_duration(Duration)` | 1 hour | How long an impersonation session lasts. |
| `.default_ban_reason(text)` | `"No reason"` | The reason stored when a ban gives none. |
| `.default_ban_expires_in(Duration)` | never | How long a ban lasts when the request gives no expiry. |
| `.banned_user_message(text)` | `"You have been banned from this application. Please contact support if you believe this is an error."` | The message on `403 BANNED_USER`. The ban's reason is appended as ` Reason: ..`. |

```rust
Admin::new()
    .role("member", Permissions::new())
    .role("owner", Permissions::admin().allow("user", ["impersonate-admins"]))
    .default_role("member")
    .admin_roles(["admin", "owner"])
    .admin_user_ids(["01JDQ4X5Y0Z9R8KZ3M6N7P2QAB"])
    .impersonation_session_duration(Duration::minutes(30))
    .default_ban_reason("Terms of service")
    .default_ban_expires_in(Duration::days(7))
    .banned_user_message("This account is suspended.")
```

A `default_role` that isn't defined isn't an error, but its holders can do nothing, so
define it.

## Endpoints

All routes sit under the base path (`/api/auth` by default). A route that needs a
permission answers `401 UNAUTHORIZED` without a session, and `403` with the code listed in
[Error codes](#error-codes) when the caller's roles don't grant it.

| Method | Path | Better Auth client | Needs | Notes |
|---|---|---|---|---|
| `POST` | `/admin/create-user` | `authClient.admin.createUser` | `user:create`, plus `user:set-role` to pass a role and `user:ban` to set ban columns in `data` | Body `{ email, password?, name, role?, data? }`. Without `password` there's no credential account. `data` sets other user columns by camelCase name. Answers `{ user }`. |
| `GET` | `/admin/list-users` | `authClient.admin.listUsers` | `user:list` | See [Listing users](#listing-users). Answers `{ users, total, limit?, offset? }`. |
| `GET` | `/admin/get-user?id=..` | `authClient.admin.getUser` | `user:get` | Answers the user itself, not `{ user }`. |
| `POST` | `/admin/set-role` | `authClient.admin.setRole` | `user:set-role` | `role` is a string or an array. Every role must be defined. Answers `{ user }`. |
| `POST` | `/admin/ban-user` | `authClient.admin.banUser` | `user:ban` | Body `{ userId, banReason?, banExpiresIn? }`, the expiry in seconds. Revokes every session of the user. Answers `{ user }`. |
| `POST` | `/admin/unban-user` | `authClient.admin.unbanUser` | `user:ban` | Clears `banned`, `banReason` and `banExpires`. Answers `{ user }`. |
| `POST` | `/admin/update-user` | `authClient.admin.updateUser` | `user:update`, plus `user:set-role` for `role`, `user:ban` for the ban columns, `user:set-email` for `email` and `emailVerified` | Body `{ userId, data }`. Refuses `password` and `id`. `banned: true` revokes the user's sessions. Answers the user itself. |
| `POST` | `/admin/set-user-password` | `authClient.admin.setUserPassword` | `user:set-password` | Body `{ userId, newPassword }`. Checks the password policy and creates the credential account if needed. Answers `{ status: true }`. |
| `POST` | `/admin/remove-user` | `authClient.admin.removeUser` | `user:delete` | Deletes the user's sessions and accounts, then the user. Answers `{ success: true }`. |
| `POST` | `/admin/list-user-sessions` | `authClient.admin.listUserSessions` | `session:list` | The user's unexpired sessions, newest first. Answers `{ sessions }`. |
| `POST` | `/admin/revoke-user-session` | `authClient.admin.revokeUserSession` | `session:revoke` | Body `{ sessionToken }`. Succeeds even when no such session exists. Answers `{ success: true }`. |
| `POST` | `/admin/revoke-user-sessions` | `authClient.admin.revokeUserSessions` | `session:revoke` | Body `{ userId }`. Answers `{ success: true }`. |
| `POST` | `/admin/impersonate-user` | `authClient.admin.impersonateUser` | `user:impersonate`, plus `user:impersonate-admins` when the target is an admin | See [Impersonation](#impersonation). Answers `{ session, user }`. |
| `POST` | `/admin/stop-impersonating` | `authClient.admin.stopImpersonating` | an impersonation session | Answers `{ session, user }` for the admin. |
| `POST` | `/admin/has-permission` | `authClient.admin.hasPermission` | any session | Body `{ permissions: { user: ["list"] } }` (`permission` also works). Answers `{ error: null, success }` for the caller's own roles. |

There are no server-only routes: every route is served over HTTP, and the server API calls
the same endpoints.

Admins can't ban or remove themselves (`400 YOU_CANNOT_BAN_YOURSELF`,
`400 YOU_CANNOT_REMOVE_YOURSELF`). The server API has no caller, so it can.

### Listing users

`/admin/list-users` takes Better Auth's query parameters and runs the search, filter, sort
and paging in the database:

| Parameter | Values | Default |
|---|---|---|
| `searchValue` | text | none |
| `searchField` | `email`, `name` | `email` |
| `searchOperator` | `contains`, `starts_with`, `ends_with` | `contains` |
| `filterField` | any user column, camelCase | `email` |
| `filterValue` | parsed as the column's type: `true`, `42`, an RFC 3339 timestamp, or text | none |
| `filterOperator` | `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `in`, `not_in`, `contains`, `starts_with`, `ends_with` | `eq` |
| `sortBy` | any user column, camelCase | none |
| `sortDirection` | `asc`, `desc` | `asc` |
| `limit`, `offset` | integers | every row |

Search and the text filters are **case-sensitive**, as in Better Auth: `searchValue=ACME`
doesn't find `ada@acme.dk`. Emails are stored lowercase, so lowercase an email search; names
keep the case they were stored with. `in` and `not_in` take a comma-separated list, and the
text operators work on text columns only. An unknown or hidden column answers
`400 INVALID_FIELD`. `total` counts every match, not just the page.

## Server API

`auth.admin()` (trait `AdminExt`) runs every admin operation from Rust. It only compiles on
an `Auth` whose plugin list has `Admin`. Calls are trusted: they need no session and skip
the permission checks, but run the same hooks and events as the HTTP routes.

```rust
use fastauth::plugins::admin::{
    AdminExt, BanUserInput, CreateUserInput, ListUsersQuery, SearchField, SearchOperator,
};
use fastauth::prelude::*;

pub async fn seed_admin(auth: &AppAuth) -> Result<Id, AuthError> {
    let user = auth
        .admin()
        .create_user(CreateUserInput {
            email: "ops@acme.dk".into(),
            password: Some("correct horse battery".into()),
            name: "Ops".into(),
            role: Some("admin".into()),
            ..CreateUserInput::default()
        })
        .await?;
    Ok(user.id.clone())
}

pub async fn suspend(auth: &AppAuth, user_id: &Id) -> Result<(), AuthError> {
    let ban = BanUserInput::new(user_id.clone())
        .reason("chargeback")
        .expires_in(Duration::days(7));
    auth.admin().ban(ban).await?;
    Ok(())
}

pub async fn names_starting_with(auth: &AppAuth, prefix: &str) -> Result<Vec<String>, AuthError> {
    let list = auth
        .admin()
        .list_users(ListUsersQuery {
            search_value: Some(prefix.to_owned()),
            search_field: Some(SearchField::Name),
            search_operator: Some(SearchOperator::StartsWith),
            limit: Some(20),
            ..ListUsersQuery::default()
        })
        .await?;
    Ok(list.users.iter().map(|u| u.name.clone()).collect())
}

pub async fn make_support(auth: &AppAuth, user_id: &Id) -> Result<(), AuthError> {
    auth.admin().set_role(user_id, ["support", "user"]).await?;
    Ok(())
}
```

| Method | Returns |
|---|---|
| `create_user(CreateUserInput)` | `UserView` |
| `list_users(ListUsersQuery)` | `UserList { users, total, limit, offset }` |
| `get_user(&Id)` | `UserView` |
| `set_role(&Id, role)` | `UserView`; `role` is a `&str`, a `String` or an array of `&str` |
| `ban(BanUserInput)` | `UserView`; build the input with `BanUserInput::new(id).reason(..).expires_in(..)` |
| `unban(&Id)` | `UserView` |
| `update_user(&Id, serde_json::Map)` | `UserView`; keys are camelCase column names, as on the route |
| `set_user_password(&Id, &str)` | `()` |
| `remove_user(&Id)` | `()` |
| `list_user_sessions(&Id)` | the sessions as client JSON |
| `revoke_user_session(&str)` | `()`; takes the raw session token |
| `revoke_user_sessions(&Id)` | `()` |
| `has_permission(&Id, Permissions)` | `bool`; `false` for an unknown user |
| `impersonate(&HeaderMap, &Id)` | `ApiResponse<SessionOutput>`, with the cookies to send |
| `stop_impersonating(&HeaderMap)` | `ApiResponse<SessionOutput>`, with the cookies to send |

`impersonate` and `stop_impersonating` act for the signed-in admin whose cookies are in the
headers, so they do run the permission checks. Pass the response's `set_cookies` on to the
browser:

```rust
async fn view_as(
    State(auth): State<AppAuth>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AuthError> {
    let res = auth.admin().impersonate(&headers, &Id::from(id)).await?;
    let mut response = Json(res.data).into_response();
    for cookie in res.set_cookies {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
    Ok(response)
}
```

The endpoint types (`BanUser`, `CreateUser`, `SetRole`, ...) are public, so you can hook
them like core endpoints ([Hooks](05-plugins.md#hooks)). This hook refuses bans without a
reason, over HTTP and from the server API alike:

```rust
use fastauth::plugin_prelude::Before;
use fastauth::plugins::admin::{Admin, BanUser, BanUserInput};

FastAuth::builder()
    // ...
    .plugin(Admin::new())
    .configure(|app| {
        app.hook::<BanUser>().before(|_ctx, input: BanUserInput| async move {
            if input.ban_reason.as_deref().is_none_or(str::is_empty) {
                return Err(AuthError::bad_request("BAN_REASON_REQUIRED", "Give a reason"));
            }
            Ok(Before::Continue(input))
        });
    })
    .build()
```

## Axum extractor

`RequireRole<A, R>` is an axum extractor for the signed-in session of a user who holds role
`R`. It answers `401 UNAUTHORIZED` without a session and `403 FORBIDDEN` without the role,
and derefs to the [`Session`](04-sessions.md#in-axum-handlers). `role::Admin` and
`role::User` are built in; `role!` declares a marker for a role you defined with `.role(..)`:

```rust
use fastauth::plugins::admin::{AdminExt, RequireRole, role};

role!(pub Support = "support");

async fn dashboard(admin: RequireRole<AppAuth, role::Admin>) -> String {
    format!("hello {}", admin.user.email)
}

async fn tickets(support: RequireRole<AppAuth, Support>) -> String {
    format!("tickets for {}", support.user.email)
}

pub fn app(auth: AppAuth) -> Router {
    Router::new()
        .route("/dashboard", get(dashboard))
        .route("/tickets", get(tickets))
        .route("/view-as/{id}", post(view_as))
        .merge(auth.router())
        .with_state(auth)
}
```

A user holds every role in their `role` column, or the default role while it's empty. Admins
also hold every admin role, but not your other roles, so an admin gets `403` from
`RequireRole<_, Support>` unless their `role` includes `support`.

`role::Admin` lets in every admin, by the same check the endpoints use to decide who's an
admin (`Admin::is_admin`): a user holding any of the configured `admin_roles`, whatever
they're called, or a user in `admin_user_ids`, whatever their role. With
`admin_roles(["superadmin"])`, a `superadmin` passes and a user whose `role` says `admin`
doesn't.

`RequireRole` checks a role, not a permission. To check a permission, call
`auth.admin().has_permission(..)` in the handler.

## Roles and permissions

Access control is statement-based, the same design as Better Auth's admin plugin: a role is a
set of actions per resource, and a request is allowed when one of the user's roles grants
every action it asks for.

The admin routes check these statements (`STATEMENTS` in the crate):

| Resource | Actions |
|---|---|
| `user` | `create`, `list`, `set-role`, `ban`, `impersonate`, `impersonate-admins`, `delete`, `set-password`, `set-email`, `get`, `update` |
| `session` | `list`, `revoke`, `delete` |

No route checks `session:delete`; it's there because Better Auth defines it.

Two roles are built in:

| Role | Grants |
|---|---|
| `admin` | `Permissions::admin()`: every action above except `user:impersonate-admins` |
| `user` | `Permissions::new()`: nothing |

Define more with `.role(name, Permissions)`, or pass `admin` or `user` to replace a built-in
role. Resources and actions are plain strings, so a role can grant actions on your own
resources too, and `has-permission` and `auth.admin().has_permission(..)` check them like the
built-in ones:

```rust
use fastauth::plugins::admin::{Admin, AdminExt, Permissions};

pub fn admin() -> Admin {
    let support = Permissions::new()
        .allow("user", ["list", "get"])
        .allow("session", ["list", "revoke"]);
    let billing = Permissions::new().allow("invoice", ["read", "refund"]);
    Admin::new().role("support", support).role("billing", billing)
}

pub async fn can_refund(auth: &AppAuth, user_id: &Id) -> Result<bool, AuthError> {
    auth.admin()
        .has_permission(user_id, Permissions::new().allow("invoice", ["refund"]))
        .await
}
```

A user can hold several roles (`set_role(id, ["support", "user"])`, stored as
`support,user`). Each role is checked on its own, so one of them must grant everything a
request asks for. Users in `admin_user_ids` pass every check, `user:impersonate-admins`
included. Admins (holders of an admin role, or users in `admin_user_ids`) can only be
impersonated by someone with `user:impersonate-admins`.

## Bans

`ban-user` sets `banned`, `banReason` (default `"No reason"`) and `banExpires`, and revokes
every session the user has. From then on the plugin's sign-in gate refuses the user with
`403 BANNED_USER` for every sign-in method: email and password, social sign-in (which
redirects to `errorCallbackURL?error=BANNED_USER`) and any plugin's. The gate applies
whatever the registration order. A user with two-factor turned on still gets the two-factor
challenge first, and a correct code then answers `403 BANNED_USER` with no session
([Sign-in gates](05-plugins.md#sign-in-gates)). Banned users can't be impersonated either.

The message is `banned_user_message` followed by ` Reason: <reason>`:

```json
{ "code": "BANNED_USER", "message": "You have been banned from this application. Please contact support if you believe this is an error. Reason: spam" }
```

An expired ban is lifted at the user's next sign-in, which clears all three columns. Until
then the row still says `banned: true`, so a `list-users` filter on `banned` includes
expired bans.

## Impersonation

`impersonate-user` signs the admin's browser in as another user:

1. The admin's session token goes into a signed cookie, `fastauth.admin_session` (the
   prefix follows [`CookieConfig`](03-configuration.md#cookies)). The admin's session stays
   valid.
2. A new session for the user is created, marked with `impersonatedBy`, expiring after
   `impersonation_session_duration` (one hour by default), and set as the session cookie.
3. `stop-impersonating` revokes that session, restores the admin's session cookie, and
   deletes the `admin_session` and cookie-cache cookies.

Impersonation sessions can't impersonate (`403 YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS`),
and they don't show up in the user's own `/list-sessions`. They do show up in
`/admin/list-user-sessions`. `stop-impersonating` from a normal session answers
`400 NOT_IMPERSONATING`. To show a banner while impersonating, read `impersonated_by` from
the session's `AdminSession`.

## Events

The admin routes emit core's events, so handlers registered with `app.on(..)`
([Configuration](03-configuration.md#events)) see admin changes too:

| Event | Emitted by |
|---|---|
| `UserCreated` | `create-user` |
| `UserUpdated` | `set-role`, `ban-user`, `unban-user`, `update-user` |
| `PasswordChanged` | `set-user-password` |
| `UserDeleted` | `remove-user`, after the user's sessions and accounts are gone |
| `SessionCreated` | `impersonate-user` |
| `SessionRevoked` | `ban-user`, `update-user` with `banned: true`, `revoke-user-session`, `revoke-user-sessions`, `remove-user` (when the user had sessions), `stop-impersonating` |

The plugin defines no events of its own. Lifting an expired ban at sign-in emits nothing.

## Error codes

Codes, statuses and messages match Better Auth's admin plugin (`AdminError`):

| Code | Status | When |
|---|---|---|
| `YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS` | 403 | `create-user` without `user:create` |
| `YOU_ARE_NOT_ALLOWED_TO_LIST_USERS` | 403 | `list-users` without `user:list` |
| `YOU_ARE_NOT_ALLOWED_TO_GET_USER` | 403 | `get-user` without `user:get` |
| `YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE` | 403 | setting a role without `user:set-role` |
| `YOU_ARE_NOT_ALLOWED_TO_BAN_USERS` | 403 | ban, unban or ban columns without `user:ban` |
| `YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS` | 403 | `update-user` without `user:update` |
| `YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL` | 403 | `email` or `emailVerified` in `update-user` without `user:set-email` |
| `YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD` | 403 | `set-user-password` without `user:set-password` |
| `YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS` | 403 | `remove-user` without `user:delete` |
| `YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS` | 403 | `list-user-sessions` without `session:list` |
| `YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS` | 403 | revoking sessions without `session:revoke` |
| `YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS` | 403 | `impersonate-user` without `user:impersonate`, or from an impersonation session |
| `YOU_CANNOT_IMPERSONATE_ADMINS` | 403 | the target is an admin and the caller lacks `user:impersonate-admins` |
| `BANNED_USER` | 403 | a banned user signs in, or is the impersonation target |
| `YOU_CANNOT_BAN_YOURSELF` | 400 | an admin bans themselves |
| `YOU_CANNOT_REMOVE_YOURSELF` | 400 | an admin removes themselves |
| `YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE` | 400 | a role that isn't defined |
| `INVALID_ROLE_TYPE` | 400 | a role that's empty, or not a string or an array |
| `NO_DATA_TO_UPDATE` | 400 | `update-user` with empty `data` |
| `PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER` | 400 | `password` in `update-user` |
| `USER_ID_CANNOT_BE_UPDATED` | 400 | `id` in `update-user` |
| `NOT_IMPERSONATING` | 400 | `stop-impersonating` from a normal session |

The admin routes also answer with core codes: `401 UNAUTHORIZED` (no session),
`404 USER_NOT_FOUND`, `400 INVALID_EMAIL`, `400 USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL`,
`400 INVALID_FIELD` (an unknown, hidden or read-only column, or a value of the wrong type),
`400 INVALID_REQUEST_BODY` (`has-permission` without permissions), and the password policy
codes such as `400 PASSWORD_TOO_SHORT`.

## Better Auth's client

Use Better Auth's `adminClient` from `better-auth/client/plugins`, set up as in
[Better Auth's client](11-better-auth-client.md):

```ts
import { createAuthClient } from "better-auth/client";
import { adminClient } from "better-auth/client/plugins";

export const authClient = createAuthClient({
  baseURL: "http://localhost:3000",
  plugins: [adminClient()],
});

await authClient.admin.banUser({ userId, banReason: "spam", banExpiresIn: 3600 });
```

`compat/better-auth/run-admin.sh` builds `crates/fastauth-plugin-admin/examples/admin_server.rs`,
runs `admin.ts` against it with `better-auth` 1.7.28, and exits non-zero when any check
fails. Its 40 checks cover signing in as an admin, `createUser` (and the taken-email code),
`listUsers` with search, sort, limit and a role filter, a non-admin's
`403 YOU_ARE_NOT_ALLOWED_TO_LIST_USERS`, `hasPermission`, a `RequireRole` route (403, then
200), `setRole`, `updateUser`, `impersonateUser` then `stopImpersonating` back to the
admin's session, `listUserSessions`, `revokeUserSessions`, `banUser` with sign-in refused as
`BANNED_USER`, `unbanUser`, `setUserPassword`, `removeUser`, and `getUser` answering
`USER_NOT_FOUND` afterwards.

```bash
compat/better-auth/run-admin.sh
```

Known gaps:

- **Not covered by the script:** `revokeUserSession` and a successful `getUser`. The crate's
  Rust tests cover both.
- **`checkRolePermission` runs in the browser.** It checks the roles you pass to
  `adminClient({ ac, roles })`, which fastauth doesn't generate. Mirror your roles in
  TypeScript with Better Auth's `createAccessControl`, or call `hasPermission`, which asks the
  server.
- **The impersonation cookie is `fastauth.admin_session`**, not `better-auth.admin_session`,
  and it's signed with fastauth's scheme. The client never reads it, so this only matters to
  server code that looks for it by name.

## Not built

- Renaming the admin columns (Better Auth's `schema` option).
- Better Auth's deprecated `allowImpersonatingAdmins` option. Grant
  `user:impersonate-admins` to a role instead.

Related: [Organization](12-organization.md) has per-organization roles, and
[API keys](14-api-keys.md) has per-user keys.
