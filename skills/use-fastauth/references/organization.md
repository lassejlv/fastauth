# Organization plugin (feature `organization`)

```rust
use axum::Router;
use axum::routing::get;
use fastauth::plugins::organization::extract::{ActiveMember, RequirePermission};
use fastauth::plugins::organization::{Organization, Permission, Roles};
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![Organization]>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .mailer(LogMailer)
        .plugin(
            Organization::default()
                .roles(Roles::new().role("billing", [("invoice", &["read", "pay"])]))
                .invitation_url("https://acme.dk/invite/{id}"),
        )
        .build()
}

pub struct InvoicePay;

impl Permission for InvoicePay {
    const RESOURCE: &'static str = "invoice";
    const ACTIONS: &'static [&'static str] = &["pay"];
}

async fn dashboard(member: ActiveMember<AppAuth>) -> String {
    member.role.clone()
}

async fn pay(member: RequirePermission<AppAuth, InvoicePay>) -> String {
    format!("{} paid for {}", member.user_id, member.organization_id)
}

pub fn app(auth: AppAuth) -> Router {
    Router::new()
        .route("/dashboard", get(dashboard))
        .route("/invoices/pay", get(pay))
        .merge(auth.router())
        .layer(auth.session_layer())
        .with_state(auth)
}
```

## Setup

- `fastauth = { version = "0.7", features = ["organization"] }`. Import from
  `fastauth::plugins::organization`. The extractors need the `axum` feature (on by default).
- Plugin `Organization` (in `plugins![..]`, registration order); row type `OrganizationRow`.
  Adds tables `organization`, `member`, `invitation` and `session.active_organization_id`:
  run migrations after adding it.
- Options, with defaults: `.roles(Roles::new())`, `.allow_user_to_create_organization(true)`,
  `.organization_limit(n)` (none; counts memberships), `.invitation_ttl(Duration::hours(48))`,
  `.invitation_limit(100)` (pending invitations per organization; past it `invite-member`
  answers `403 INVITATION_LIMIT_REACHED`),
  `.invitation_url("…{id}…")` (`{base_url}/accept-invitation/{id}`),
  `.require_email_verification_on_invitation(true)`. It's `allow_user_to_create_organization`,
  not `allow_user_to_create`.

## Routes

Better Auth's paths and JSON under `/api/auth`; `organizationClient()` from
`better-auth/client/plugins` works unchanged. All need a session. Omitted `organizationId`
means the session's active organization.

- `POST /organization/create` `{ name, slug, logo?, metadata?, keepCurrentActiveOrganization? }`:
  caller becomes `owner`, org becomes active. `update`, `delete`, `set-active`
  (`organizationId: null` clears), `check-slug`, `GET list`, `GET get-full-organization`.
- `POST invite-member` `{ email, role, resend? }`, `accept-invitation`, `reject-invitation`,
  `cancel-invitation` (`{ invitationId }`), `GET get-invitation?id=`, `GET list-invitations`,
  `GET list-user-invitations` (needs a verified email).
- `POST remove-member` `{ memberIdOrEmail }`, `update-member-role` `{ memberId, role }`,
  `leave` `{ organizationId }`, `GET get-active-member`, `GET list-members`,
  `POST has-permission` `{ permissions: { member: ["delete"] } }` → `{ error: null, success }`.
- Roles in bodies: `"admin"`, `"admin,billing"` or `["admin", "billing"]`; stored
  comma-separated in `member.role`. Unknown roles: 400 `ROLE_NOT_FOUND`.
- No teams, dynamic roles, `get-organization`, `get-active-member-role` or `additionalFields`.

## Server API (`OrganizationExt`)

- Server-only, no session: `create(&user_id, input)` (skips
  `allow_user_to_create_organization`, keeps `organization_limit`), `add_member(&org, &user, role)`,
  `has_permission(&org, &user, &[("invoice", &["pay"])])` → `bool`,
  `invitations_for_email(email)`.
- One method per route, taking `&HeaderMap` (the caller's cookies) and the route's input:
  `create_as`, `update`, `invite_member`, `list_members`, … Returns `ApiResponse { data, set_cookies }`.
- Hooks: `.configure(|app| { app.hook::<CreateOrganization>().before(..); })` runs for the
  route, `create_as` and the server-only `create` (there `input.user_id` is the creator; over
  HTTP it's `None`). Hook `add_member` with `AddMember` (input `NewMember`).

## Extractors (`fastauth::plugins::organization::extract`)

- `ActiveMember<A>`: membership in the active org. `OrgMember<A, FromPath<P>>`: org id from
  the path param `P` names. `RequirePermission<A, P, S = Active>`: also checks permission `P`.
  All deref to `Member` (`role`, `organization_id`, `user_id`, `id`).
- `FromPath` takes a type, not a string: `path_param!(pub OrgId = "org_id");`. A route
  without `{org_id}` answers 500.
- Rejections: 401 `UNAUTHORIZED`, 403 `NO_ACTIVE_ORGANIZATION`,
  403 `YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION`, 403 `PERMISSION_DENIED`.
- Built-in permissions in `organization::access`: `OrganizationUpdate`, `OrganizationDelete`,
  `MemberCreate`, `MemberUpdate`, `MemberDelete`, `InvitationCreate`, `InvitationCancel`.
- Read the active org elsewhere: `session.session_plugin::<Organization, _>().active_organization_id`.

## Roles

- Defaults: `owner` (everything), `admin` (everything but `organization: [delete]`),
  `member` (nothing but `ac: [read]`).
- `Roles::new().role(name, [..])` defines or replaces a role; `.grant(name, [..])` adds
  actions. Owners don't get custom resources unless you `grant` them.
- `Roles::allows(role, &[(resource, &[actions])])` is the single check; any listed role that
  grants every action passes. An empty request is denied.
- Fixed owner rules: only owners invite, promote, demote or remove owners; the last owner
  can't leave or demote themselves.

## Gotchas

- Invitation email: `AuthEmail::Plugin` with `kind == "organization-invitation"`, `url` and
  `code` (the invitation id). No mailer means no email, not an error.
- The invitation link is a page you build; it calls `acceptInvitation({ invitationId })`.
  Only a user signed in with the invited email can accept.
- Events: `OrganizationCreated`, `MemberAdded`, `MemberRemoved`, `InvitationAccepted`.
  Deleting an org emits no `MemberRemoved`.
- Status quirks match Better Auth: `USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION` is 400, 403
  or 401 depending on the route; `YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER` is 401.
- Full reference: `docs/plugins/access/01-organization.md`.
