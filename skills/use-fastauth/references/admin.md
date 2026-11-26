# Admin plugin (feature `admin`)

```rust
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use fastauth::plugins::admin::{
    Admin, AdminExt, AdminUser, BanUserInput, Permissions, RequireRole, role,
};
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![Admin]>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .plugin(
            Admin::new()
                .role("support", Permissions::new().allow("user", ["list", "get"]))
                .impersonation_session_duration(Duration::minutes(30)),
        )
        .build()
}

async fn ban_spammer(
    admin: RequireRole<AppAuth, role::Admin>,
    State(auth): State<AppAuth>,
    Path(id): Path<String>,
) -> Result<StatusCode, AuthError> {
    let reason = format!("spam, reported by {}", admin.user.email);
    auth.admin().ban(BanUserInput::new(id).reason(reason)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn my_role(session: Session<AppAuth>) -> String {
    let admin: &AdminUser = session.user.plugin::<Admin, _>();
    admin.role.clone().unwrap_or_default()
}

pub fn app(auth: AppAuth) -> Router {
    Router::new()
        .route("/ban/{id}", post(ban_spammer))
        .route("/me/role", get(my_role))
        .merge(auth.router())
        .with_state(auth)
}
```

## Setup

- `fastauth = { version = "0.4", features = ["admin"] }`; import from `fastauth::plugins::admin`.
  `RequireRole` also needs the facade's `axum` feature (on by default).
- Add `Admin` to the `plugins![..]` alias. It requires no other plugin.
- Run migrations after adding it: it adds `user.role`, `user.banned`, `user.ban_reason`,
  `user.ban_expires` and `session.impersonated_by`, and no tables.
- None of those columns is client-settable: sign-up or `/update-user` with `role` or
  `banned` answers `400 INVALID_FIELD`. Change them through the admin routes or `auth.admin()`.
- Options and defaults: `.default_role("user")`, `.admin_roles(["admin"])`,
  `.admin_user_ids([])`, `.impersonation_session_duration(1 hour)`,
  `.default_ban_reason("No reason")`, `.default_ban_expires_in(never)`,
  `.banned_user_message(..)`. Every name in `admin_roles` must be defined with `.role(..)`,
  or `.build()` panics.

## Roles

- A role is `Permissions::new().allow(resource, [actions])`. Built-in: `admin` =
  `Permissions::admin()` (everything except `user:impersonate-admins`), `user` = nothing.
  `.role(name, ..)` adds a role or replaces a built-in one.
- Route permissions: `user:` `create list set-role ban impersonate impersonate-admins delete
  set-password set-email get update`; `session:` `list revoke`. Custom resources work too.
- `user.role` is comma-separated (`"support,user"`); an empty value means the default role.
  One role must grant everything a check asks for; permissions aren't merged across roles.
- `admin_user_ids` pass every permission check. Impersonating an admin needs
  `user:impersonate-admins`, which the built-in `admin` role lacks.

## Routes (Better Auth's `adminClient` works unchanged)

- `POST /admin/create-user`, `GET /admin/list-users`, `GET /admin/get-user?id=`,
  `POST /admin/set-role`, `ban-user`, `unban-user`, `update-user`, `set-user-password`,
  `remove-user`, `list-user-sessions`, `revoke-user-session`, `revoke-user-sessions`,
  `impersonate-user`, `stop-impersonating`, `has-permission`, all under `/api/auth`.
- No session: `401 UNAUTHORIZED`. Missing permission: `403` with Better Auth's code, such as
  `YOU_ARE_NOT_ALLOWED_TO_LIST_USERS`.
- list-users search (`searchValue` on `email` or `name`) and the text filters are
  case-sensitive and run in SQL. Lowercase email searches.

## Server API: `auth.admin()` (trait `AdminExt`)

- `create_user`, `list_users`, `get_user`, `set_role(&id, "admin" | ["a", "b"])`,
  `ban(BanUserInput::new(id).reason(..).expires_in(..))`, `unban`, `update_user(&id, map)`,
  `set_user_password`, `remove_user`, `list_user_sessions`, `revoke_user_session(token)`,
  `revoke_user_sessions`, `has_permission`.
- These calls need no session and skip permission checks, but run hooks and events. They can
  ban or remove any user, including an admin.
- `impersonate(&headers, &id)` and `stop_impersonating(&headers)` act for the admin whose
  cookies are in `headers` and return `ApiResponse`: copy `set_cookies` into your response.
- Read the columns with `session.user.plugin::<Admin, _>()` (`&AdminUser`),
  `session.session_plugin::<Admin, _>()` (`&AdminSession`) or `user_view.fields::<AdminUser>()`.
- To change an admin route's behavior, hook its public endpoint type:
  `.configure(|app| { app.hook::<BanUser>().before(..); })`.

## Extractor: `RequireRole<AppAuth, R>`

- Rejects with `401 UNAUTHORIZED` (no session) or `403 FORBIDDEN` (missing role); derefs to
  `Session`.
- `R` is `role::Admin`, `role::User` or a marker from `role!(pub Support = "support")`.
- Admins pass `role::Admin` but not custom roles (give them `"admin,support"`). `role::Admin`
  means any admin (`Admin::is_admin`): a holder of any configured `admin_roles` entry, or a
  user in `admin_user_ids`.
- It checks roles, not permissions; for a permission call `auth.admin().has_permission(..)`.

## Gotchas

- Bans: `ban-user` revokes every session. Sign-in then answers `403 BANNED_USER` for every
  method, in any registration order, after a correct two-factor code too. Social sign-in
  redirects to `errorCallbackURL?error=BANNED_USER`.
- An expired ban is lifted only at the next sign-in, so `banned` stays `true` until then.
- Impersonation sessions last `impersonation_session_duration`, carry `impersonatedBy`, can't
  impersonate, and are hidden from the user's own `/list-sessions`. The admin's token waits in
  the signed `fastauth.admin_session` cookie until `stop-impersonating`.
- Events: `UserCreated` (create-user), `UserUpdated` (set-role, ban, unban, update-user),
  `PasswordChanged` (set-user-password), `UserDeleted` (remove-user), `SessionCreated`
  (impersonate), `SessionRevoked`.
- Better Auth's `checkRolePermission` is client-side and needs the roles mirrored in
  TypeScript. `hasPermission` asks the server.
