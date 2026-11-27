# Organizations

The organization plugin adds organizations, their members, invitations, and roles with
permissions. Its `/organization/*` routes, JSON and error codes match Better Auth's
organization plugin, so Better Auth's `organizationClient` works against it unchanged. On
the Rust side you get `auth.organization()` for server code and axum extractors that put
membership and permission checks in a handler's signature.

## Setup

Turn on the facade's `organization` feature:

```toml
[dependencies]
fastauth = { version = "0.6", features = ["organization"] }
```

or `cargo add fastauth --features organization`. Everything lives in
`fastauth::plugins::organization`. The extractors also need the `axum` feature, which is on
by default, or `actix` for actix-web. (Without the facade, depend on
`fastauth-plugin-organization` and enable its `axum` or `actix` feature.)

Register the plugin and list it in your auth alias, in registration order
([Plugins](../README.md#using-plugins)):

```rust
use fastauth::plugins::organization::Organization;
use fastauth::prelude::*;

pub type AppAuth = Auth<Sqlx<Postgres>, (), plugins![Organization]>;

pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .app_name("Acme")
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .mailer(LogMailer)
        .plugin(Organization::default())
        .build()
}
```

The mailer is optional: without one, invitations are still created but no email goes out
([Invitations and email](#invitations-and-email)).

### Tables

The plugin adds three tables and one column on `session`, so run migrations after adding it
(`auth.migrator().run().await?`, or your `fastauth` binary's `generate`; see
[Migrations](../../concepts/02-database.md#migrations)):

| Table | Columns |
|---|---|
| `organization` | `id`, `name`, `slug` (unique, at most 255 characters), `logo` (nullable), `metadata` (JSON, nullable), `created_at` |
| `member` | `id`, `organization_id` → organization (cascade, index), `user_id` → user (cascade, index), `role` (default `'member'`), `created_at`; unique on `(organization_id, user_id)` |
| `invitation` | `id`, `organization_id` → organization (cascade, index), `email` (index), `role`, `status` (default `'pending'`), `inviter_id` → user (cascade), `expires_at`, `created_at` |
| `session` | adds `active_organization_id` (nullable) |

The Rust row types are `OrganizationRow` (the name `Organization` is taken by the plugin),
`Member`, `Invitation` and `OrganizationSession`. JSON uses camelCase, so clients see
`organizationId`, `expiresAt` and `session.activeOrganizationId`.

`member.role` holds one role or several, comma-separated (`"admin,billing"`), as Better
Auth stores them. `Member::roles()` splits it and `Member::has_role("admin")` checks one.
Invitation emails are stored lowercased, and `status` is `pending`, `accepted`, `rejected`
or `canceled` (`InvitationStatus`).

## Configuration

```rust
use fastauth::plugins::organization::{Organization, Roles};
use fastauth::prelude::*;

pub fn organization() -> Organization {
    Organization::default()
        .roles(Roles::new().role("billing", [("invoice", &["read", "pay"])]))
        .allow_user_to_create_organization(false)
        .organization_limit(5)
        .invitation_ttl(Duration::days(7))
        .invitation_limit(20)
        .invitation_url("https://app.acme.dk/invite/{id}")
        .require_email_verification_on_invitation(true)
}
```

| Option | Default | What it does |
|---|---|---|
| `.roles(Roles)` | `Roles::new()`: `owner`, `admin`, `member` | The roles members can hold and what each may do ([Roles and permissions](#roles-and-permissions)). |
| `.allow_user_to_create_organization(bool)` | `true` | With `false`, `POST /organization/create` answers 403 `YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION` and only the server API's `create` makes organizations. |
| `.organization_limit(u64)` | no limit | How many organizations a user may belong to before creating another is refused (403 `YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS`). It counts memberships, not ownership, and applies to the server API's `create` too. It doesn't stop invitations or `add_member`. |
| `.invitation_ttl(Duration)` | 48 hours | How long an invitation can be accepted. Resending an invitation restarts the clock. |
| `.invitation_limit(u64)` | 100 | How many pending, unexpired invitations one organization may have. A new invitation past it answers 403 `INVITATION_LIMIT_REACHED`, as in Better Auth; resending an existing one isn't counted. Each invitation emails an address the inviter picks, so this bounds how many addresses one account can mail through your app. |
| `.invitation_url(template)` | `{base_url}/accept-invitation/{id}` | The link in invitation emails. `{id}` is replaced with the invitation id. |
| `.require_email_verification_on_invitation(bool)` | `true` | Invitees need a verified email to view, accept or reject an invitation. Without it, anyone who signs up with the invitee's address can accept an invitation whose id they know. Better Auth skips the check for its own random ids; turn it off only when sign-up verifies email or your ids are unguessable. |

The creator of an organization always gets the `owner` role; that name isn't configurable.

## Endpoints

The routes are mounted under your base path (`/api/auth` by default). Every route needs a
session and answers 401 `UNAUTHORIZED` without one. Where a body or query takes an optional
`organizationId`, leaving it out means the session's active organization.

| Method | Path | Better Auth client | Needs | Notes |
|---|---|---|---|---|
| `POST` | `/organization/create` | `authClient.organization.create` | `allow_user_to_create_organization` | `name`, `slug`, `logo?`, `metadata?`, `keepCurrentActiveOrganization?`. The caller becomes `owner` and the new organization becomes active. Answers the organization with `members`. |
| `POST` | `/organization/update` | `authClient.organization.update` | `organization: [update]` | `{ data: { name?, slug?, logo?, metadata? }, organizationId? }`. `logo: null` removes the logo. Answers the organization. |
| `POST` | `/organization/delete` | `authClient.organization.delete` | `organization: [delete]` | `organizationId` (required). Deletes its members and invitations and clears it as any session's active organization. Answers the deleted organization. |
| `GET` | `/organization/list` | `authClient.organization.list` | signed in | The caller's organizations. |
| `GET` | `/organization/get-full-organization` | `authClient.organization.getFullOrganization` | member | Query `organizationId`, `organizationSlug`, `membersLimit`. Members with their users, and invitations if the caller has `invitation: [create]`. `null` when nothing is named and no organization is active. |
| `POST` | `/organization/set-active` | `authClient.organization.setActive` | member | `organizationId` or `organizationSlug`; `organizationId: null` clears it. Answers the organization or `null`. |
| `POST` | `/organization/check-slug` | `authClient.organization.checkSlug` | signed in | `{ "status": true }` when the slug is free, 400 `ORGANIZATION_SLUG_ALREADY_TAKEN` when it isn't. |
| `POST` | `/organization/invite-member` | `authClient.organization.inviteMember` | `invitation: [create]` | `email`, `role` (a name, `"a,b"` or `["a", "b"]`), `organizationId?`, `resend?`. Only owners invite owners. Answers the invitation. |
| `POST` | `/organization/accept-invitation` | `authClient.organization.acceptInvitation` | the invitee | `invitationId`. Joins with the invited role and makes the organization active. Answers `{ invitation, member }`. |
| `POST` | `/organization/reject-invitation` | `authClient.organization.rejectInvitation` | the invitee | `invitationId`. Answers `{ invitation, member: null }`. |
| `POST` | `/organization/cancel-invitation` | `authClient.organization.cancelInvitation` | `invitation: [cancel]` | `invitationId`. Only a pending invitation can be canceled (else `INVITATION_NOT_FOUND`). Answers the canceled invitation. |
| `GET` | `/organization/get-invitation` | `authClient.organization.getInvitation` | the invitee | Query `id`. A pending, unexpired invitation with `organizationName`, `organizationSlug` and `inviterEmail`. |
| `GET` | `/organization/list-invitations` | `authClient.organization.listInvitations` | `invitation: [create]` | Query `organizationId?`. Every invitation, whatever its status. |
| `GET` | `/organization/list-user-invitations` | `authClient.organization.listUserInvitations` | a verified email | The pending invitations addressed to the caller, with `organizationName`. |
| `POST` | `/organization/remove-member` | `authClient.organization.removeMember` | `member: [delete]` | `memberIdOrEmail`, `organizationId?`. A member of another organization is `MEMBER_NOT_FOUND`, checked first. Only owners remove owners, and never the last one, even when two owners remove each other at once. Answers `{ member }`. |
| `POST` | `/organization/update-member-role` | `authClient.organization.updateMemberRole` | `member: [update]`, or owner | `memberId`, `role`, `organizationId?`. Only owners give or take away `owner`, and the last owner can't demote themselves, even concurrently. Answers the member. |
| `POST` | `/organization/leave` | `authClient.organization.leave` | member | `organizationId` (required). The last owner can't leave, even when two owners leave at once. Answers the ended membership. |
| `GET` | `/organization/get-active-member` | `authClient.organization.getActiveMember` | member of the active organization | The caller's membership with `user: { id, name, email, image }`. |
| `GET` | `/organization/list-members` | `authClient.organization.listMembers` | member | Query `limit`, `offset`, `sortBy` (`createdAt`, `role`, `userId`, `id`), `sortDirection` (`asc`, `desc`), `organizationId`, `organizationSlug`. Answers `{ members, total }`. |
| `POST` | `/organization/has-permission` | `authClient.organization.hasPermission` | member | `{ "permissions": { "member": ["delete"] }, "organizationId"? }`. Answers `{ "error": null, "success": bool }`. |

Four operations are server-only and have no route: creating an organization for a given
user, adding a member without an invitation, checking another user's permission, and
listing the invitations for any email address. They're on the [Server API](#server-api).

Invitations that grant `owner` only show up for owners in `get-full-organization` and
`list-invitations`.

### The active organization

Each session can have an active organization, stored in `session.active_organization_id`
and returned as `session.activeOrganizationId`. Creating an organization or accepting an
invitation makes it active; `set-active` changes it. Leaving, removing yourself or deleting
the organization clears it. In a handler, read it from the session:

```rust
async fn active_organization(session: Session<AppAuth>) -> String {
    let org = session.session_plugin::<Organization, _>();
    match &org.active_organization_id {
        Some(id) => id.to_string(),
        None => "none".into(),
    }
}
```

With the session cookie cache on ([Sessions](../../concepts/01-sessions.md)), the routes that change the
caller's active organization also drop the cache cookie, so the next request sees the new
value.

Every route that changes something (creating, updating or deleting an organization, setting
the active one, inviting, accepting, rejecting or cancelling an invitation, removing a member,
changing a role, leaving) and `/organization/has-permission` check the caller's role against
the session as the database holds it, not the cache cookie
([Security](../../concepts/03-security.md#sessions-that-arent-a-sign-in)). So a revoked session gets `401` at
once, and a member whose role was lowered can't use the old role until the cache expires.
Read-only lists still answer from the cache. Better Auth answers these checks from the cookie
cache.

## Invitations and email

`invite-member` stores a pending invitation that expires after `invitation_ttl`, then
emails the invitee through your mailer as `AuthEmail::Plugin` with kind
`"organization-invitation"`. The email carries `url` (the `invitation_url` link) and
`code` (the invitation id), and its default subject is "{inviter} invited you to
{organization}". To send your own template, match on the kind:

```rust
use fastauth::mail::{AuthEmail, MailError, Mailer};

pub struct AcmeMailer;

impl Mailer for AcmeMailer {
    async fn send(&self, email: AuthEmail) -> Result<(), MailError> {
        match email {
            AuthEmail::Plugin(e) if e.kind == "organization-invitation" => {
                let link = e.url.unwrap_or_default();
                send(&e.to, &e.subject, &format!("Join here: {link}")).await
            }
            other => {
                let (subject, text) = other.default_text("Acme");
                send(other.to(), &subject, &text).await
            }
        }
    }
}
```

The page behind the link is yours to build. It signs the invitee in (or up), shows the
invitation with `getInvitation({ query: { id } })` and calls
`acceptInvitation({ invitationId })` or `rejectInvitation(..)`. Only a user signed in with
the invited email can see, accept or reject it; anyone else gets 403
`YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION`. The id is the secret in the link, so treat
it like a token.

Inviting an address that already has a live pending invitation answers 400
`USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION`; pass `resend: true` to extend that
invitation and send the email again. An organization with `invitation_limit` pending
invitations (100 by default) can't invite anyone new until one is accepted, rejected,
canceled or expires: `invite-member` answers 403 `INVITATION_LIMIT_REACHED`.

## Server API

`auth.organization()` comes from the `OrganizationExt` trait and only compiles when
`Organization` is in your plugin list. Four methods act for the server and need no session:

```rust
use axum::http::HeaderMap;
use fastauth::plugins::organization::{
    CreateOrganizationInput, InviteMemberInput, OrganizationExt,
};
use fastauth::prelude::*;

pub async fn provision(auth: &AppAuth, owner: &Id, teammate: &Id) -> Result<Id, AuthError> {
    let api = auth.organization();
    let created = api
        .create(
            owner,
            CreateOrganizationInput {
                name: "Acme".into(),
                slug: "acme".into(),
                ..Default::default()
            },
        )
        .await?;
    let org_id = created.organization.id;
    api.add_member(&org_id, teammate, "admin").await?;
    Ok(org_id)
}

pub async fn can_pay(auth: &AppAuth, org_id: &Id, user_id: &Id) -> Result<bool, AuthError> {
    auth.organization()
        .has_permission(org_id, user_id, &[("invoice", &["pay"])])
        .await
}
```

| Method | Returns | Notes |
|---|---|---|
| `create(&user_id, CreateOrganizationInput)` | `OrganizationWithMembers` | Ignores `allow_user_to_create_organization`, respects `organization_limit`. Doesn't change any session's active organization. Runs hooks on `CreateOrganization`. |
| `add_member(&org_id, &user_id, role)` | `Member` | No invitation. `role` is a name or a comma-separated list; each must exist. Runs hooks on `AddMember`. |
| `has_permission(&org_id, &user_id, &[(resource, &[actions])])` | `bool` | `false` for non-members. |
| `invitations_for_email(email)` | `Vec<InvitationWithOrganization>` | Pending invitations for any address. |
| `roles()` | `&Roles` | The configured roles. |

Every route also has a method that calls it as the session in a request's headers. It
answers what the route would, as an `ApiResponse` with `data` and the `set_cookies` to
forward:

```rust
pub async fn invite(auth: &AppAuth, headers: &HeaderMap, email: &str) -> Result<Id, AuthError> {
    let invitation = auth
        .organization()
        .invite_member(
            headers,
            InviteMemberInput {
                email: email.into(),
                role: "member".into(),
                organization_id: None,
                resend: false,
            },
        )
        .await?;
    Ok(invitation.data.id)
}
```

The names follow the routes: `create_as`, `update`, `delete`, `list`, `get_full`,
`set_active`, `check_slug`, `invite_member`, `accept_invitation`, `reject_invitation`,
`cancel_invitation`, `get_invitation`, `list_invitations`, `list_user_invitations`,
`remove_member`, `update_member_role`, `leave`, `get_active_member`, `list_members` and
`check_permission`. Each takes `&HeaderMap` and the route's input type (`Empty {}` for the
ones without input). [The server API](../../concepts/01-sessions.md#the-server-api) explains how headers
carry the session.

### Hooks

The plugin has no hook options of its own. Use fastauth's endpoint hooks on its endpoint
types ([Hooks](../../reference/01-plugin-authoring.md#hooks)):

```rust
.configure(|app| {
    app.hook::<CreateOrganization>().before(
        |_ctx, mut input: CreateOrganizationInput| async move {
            if input.slug.starts_with("admin") {
                return Err(AuthError::bad_request("SLUG_RESERVED", "pick another slug"));
            }
            input.slug = input.slug.to_lowercase();
            Ok(Before::Continue(input))
        },
    );
})
```

The endpoint types are named after the routes (`CreateOrganization`, `UpdateOrganization`,
`DeleteOrganization`, `InviteMember`, `AcceptInvitation`, `RemoveMember`,
`UpdateMemberRole` and so on), with `...Input` types for their bodies. A hook on
`CreateOrganization` runs for the route, `create_as` and the server-only `create`. For
`create`, `input.user_id` names the creator; over HTTP it's `None` and the creator is the
session's user (a `userId` in a request body is ignored, as in Better Auth). The
server-only calls have their own types to hook: `AddMember` (input `NewMember`) for
`add_member`, `CheckPermission` for `has_permission` and `UserInvitations` for
`invitations_for_email`.

## Axum extractors

Three extractors resolve the signed-in user's membership. Each derefs to `Member`, and
`into_inner()` gives it to you by value. They are the same types in axum and actix-web; the
example below is axum, and [actix-web](../../integrations/03-actix.md#plugin-extractors) shows
the actix routes.

| Extractor | Gives you |
|---|---|
| `ActiveMember<A>` | The membership in the session's active organization. |
| `OrgMember<A, S>` | The membership in the organization `S` names: `Active` (the default) or `FromPath<P>`. |
| `RequirePermission<A, P, S = Active>` | Like `OrgMember`, and the member's role must grant permission `P`. |

```rust
use axum::Router;
use axum::extract::Path;
use axum::routing::{delete, get, post};
use fastauth::plugins::organization::access::MemberDelete;
use fastauth::plugins::organization::extract::{
    ActiveMember, FromPath, OrgMember, RequirePermission,
};
use fastauth::plugins::organization::{Organization, path_param};
use fastauth::prelude::*;

path_param!(pub OrgId = "org_id");

async fn dashboard(member: ActiveMember<AppAuth>) -> String {
    format!("{} in {}", member.role, member.organization_id)
}

async fn org_page(member: OrgMember<AppAuth, FromPath<OrgId>>) -> String {
    format!("member {} of {}", member.id, member.organization_id)
}

async fn remove_member(
    member: RequirePermission<AppAuth, MemberDelete, FromPath<OrgId>>,
    Path((_org_id, member_id)): Path<(String, String)>,
) -> String {
    format!("{} may remove {member_id}", member.user_id)
}

async fn pay_invoice(_: RequirePermission<AppAuth, InvoicePay>) -> &'static str {
    "paid"
}

pub fn app(auth: AppAuth) -> Router {
    Router::new()
        .route("/dashboard", get(dashboard))
        .route("/orgs/{org_id}", get(org_page))
        .route("/orgs/{org_id}/members/{member_id}", delete(remove_member))
        .route("/invoices/pay", post(pay_invoice))
        .merge(auth.router())
        .layer(auth.session_layer())
        .with_state(auth)
}
```

`FromPath` takes a type rather than `"org_id"` because stable Rust has no `&str` const
generics; `path_param!(pub OrgId = "org_id")` declares that type. A route without the named
parameter is a programming error and answers 500. `InvoicePay` is a custom permission
([Permissions as types](#permissions-as-types)).

The extractors reuse the request's session lookup, load the membership with one query, and
check permissions with the same `Roles::allows` the endpoints use. They reject with
`AuthError`, which answers the same JSON as the auth routes:

| Extractor | Rejection |
|---|---|
| `ActiveMember<A>`, `OrgMember<A, S>` | `401 UNAUTHORIZED`, `403 NO_ACTIVE_ORGANIZATION` (with `Active`), `403 YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION` |
| `RequirePermission<A, P, S>` | the same, or `403 PERMISSION_DENIED` |

## Events

| Event | Emitted when | Fields |
|---|---|---|
| `OrganizationCreated` | an organization is created, over HTTP or by the server API | `organization_id`, `user_id` (the owner) |
| `MemberAdded` | any new membership: the creator's, `add_member`'s, an accepted invitation's | `organization_id`, `user_id`, `member_id`, `role` |
| `MemberRemoved` | a member is removed or leaves | `organization_id`, `user_id`, `member_id` |
| `InvitationAccepted` | an invitee accepts (`MemberAdded` fires too) | `invitation_id`, `organization_id`, `user_id`, `member_id` |

Deleting an organization doesn't emit `MemberRemoved` for its members. Updates, role
changes, and new, rejected or canceled invitations emit nothing; hook the endpoint instead.
Handlers run after the change succeeds, and their errors are logged rather than returned
([Events](../../get-started/03-configuration.md#events)):

```rust
.on(|e: MemberAdded, ctx: Ctx<_>| async move {
    let seats = ctx
        .db()
        .count::<Member>(Member::ORGANIZATION_ID.eq(&e.organization_id))
        .await?;
    println!("{} now has {seats} members", e.organization_id);
    Ok(())
})
```

## Roles and permissions

A permission is a resource and the actions on it, such as `member: [delete]`. A role is a
named set of them. `Roles::new()` holds Better Auth's three default roles:

| Role | `organization` | `member` | `invitation` | `team` | `ac` |
|---|---|---|---|---|---|
| `owner` | update, delete | create, update, delete | create, cancel | create, update, delete | create, read, update, delete |
| `admin` | update | create, update, delete | create, cancel | create, update, delete | create, read, update, delete |
| `member` | none | none | none | none | read |

`team` and `ac` are there to match Better Auth's statements; fastauth has no teams or
dynamic access control routes that use them.

The endpoints check these permissions: `organization: [update]` to update,
`organization: [delete]` to delete, `invitation: [create]` to invite and to list
invitations, `invitation: [cancel]` to cancel, `member: [delete]` to remove a member and
`member: [update]` to change roles. On top of that, a few owner rules are fixed: only
owners invite, promote, demote or remove owners, and an organization always keeps at least
one owner.

### Custom roles

`role(name, statements)` defines a role, replacing one with the same name, and
`grant(name, statements)` adds actions to an existing role (or defines it):

```rust
pub fn roles() -> Roles {
    Roles::new()
        .role(
            "billing",
            [("invoice", &["read", "pay"]), ("organization", &["update"])],
        )
        .grant("owner", [("invoice", &["read", "pay", "refund"])])
        .grant("admin", [("invoice", &["read"])])
}
```

Pass them with `Organization::default().roles(roles())`. Owners don't get your resources
automatically, so grant them explicitly as above. Roles that aren't defined can't be
assigned: inviting or assigning one answers 400 `ROLE_NOT_FOUND`.

`Roles::allows(role, permissions)` is the one permission check. `role` can be a
comma-separated list; the answer is yes when one of the roles grants every action on every
resource asked for. An empty request is never allowed:

```rust
let roles = roles();
assert!(roles.allows("billing", &[("invoice", &["pay"])]));
assert!(roles.allows("member,billing", &[("invoice", &["read"])]));
assert!(!roles.allows("admin", &[("invoice", &["pay"])]));
assert!(!roles.allows("owner", &[]));
```

### Permissions as types

For the extractors, a permission is a zero-sized type implementing `Permission`. The
built-in ones are in `fastauth::plugins::organization::access`: `OrganizationUpdate`,
`OrganizationDelete`, `MemberCreate`, `MemberUpdate`, `MemberDelete`, `InvitationCreate` and
`InvitationCancel`. Write your own for your resources:

```rust
pub struct InvoicePay;

impl Permission for InvoicePay {
    const RESOURCE: &'static str = "invoice";
    const ACTIONS: &'static [&'static str] = &["pay"];
}
```

Every action in `ACTIONS` is required. Clients ask the same question with
`authClient.organization.hasPermission({ permissions: { invoice: ["pay"] } })`.

## Error codes

Codes, messages and statuses follow Better Auth, so client code that checks `error.code`
keeps working. `PERMISSION_DENIED` is fastauth's own.

| Code | Status | When |
|---|---|---|
| `YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION` | 403 | `create` with `allow_user_to_create_organization(false)` |
| `YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS` | 403 | `create` past `organization_limit` |
| `ORGANIZATION_ALREADY_EXISTS` | 400 | `create` with a slug that's taken |
| `ORGANIZATION_SLUG_ALREADY_TAKEN` | 400 | `check-slug` or `update` with a slug that's taken |
| `ORGANIZATION_NOT_FOUND` | 400 | the named organization doesn't exist, or `update` and `invite-member` with no organization |
| `USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION` | 400, 403 or 401 | the caller isn't a member: 400 on `update` and `delete`, 403 on `get-full-organization` and `set-active`, 401 on `has-permission` |
| `YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION` | 403 | `update` without `organization: [update]` |
| `YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION` | 403 | `delete` without `organization: [delete]` |
| `NO_ACTIVE_ORGANIZATION` | 400 (403 from extractors) | no `organizationId` given and none active |
| `USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION` | 400 | inviting, adding or accepting for an existing member, including the loser of two adds or accepts at once |
| `MEMBER_NOT_FOUND` | 400 | the caller or the target isn't a member |
| `ROLE_NOT_FOUND` | 400 | a role that isn't defined; the message names it |
| `YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER` | 400 | the last owner leaves, or an owner is removed by a non-owner or as the last one |
| `YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER` | 400 | the last owner changes their own role away from `owner` |
| `YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER` | 401 | `remove-member` without `member: [delete]` |
| `YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION` | 403 | `invite-member` without `invitation: [create]` |
| `YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE` | 403 | a non-owner invites as `owner` |
| `USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION` | 400 | a live pending invitation exists and `resend` isn't set |
| `INVITATION_LIMIT_REACHED` | 403 | `invite-member` when the organization already has `invitation_limit` pending invitations |
| `INVITATION_NOT_FOUND` | 400 | unknown, no longer pending, or (to accept or view) expired |
| `YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION` | 403 | the session's email isn't the invited one |
| `EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION` | 403 | accept or reject with `require_email_verification_on_invitation` and an unverified email |
| `EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION` | 403 | `get-invitation` with that option and an unverified email, and `list-user-invitations` with an unverified email, always |
| `YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION` | 403 | `cancel-invitation` without `invitation: [cancel]` |
| `YOU_ARE_NOT_ALLOWED_TO_LIST_INVITATIONS` | 403 | `list-invitations` without `invitation: [create]` |
| `INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION` | 400 | `get-invitation` after the inviter left |
| `YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER` | 403 | `update-member-role` without the permission, on another organization's member, or a non-owner touching `owner` |
| `YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION` | 403 | `list-members`, `list-invitations` and the extractors, for a non-member |
| `PERMISSION_DENIED` | 403 | `RequirePermission` when the role doesn't grant `P` |

Core codes show up too: 401 `UNAUTHORIZED` without a session, 400 `INVALID_REQUEST_BODY` for an
empty `name`, an empty slug or one over 255 characters, or an unknown `sortBy`, 400
`INVALID_EMAIL` from `invite-member` (also for an address over 254 bytes),
and 400 `USER_NOT_FOUND` when the server API's `create` or `add_member` names an unknown
user.

## Better Auth's client

Use Better Auth's `organizationClient` from `better-auth/client/plugins`, tested with
`better-auth` 1.7.28. [Better Auth's client](../../integrations/02-better-auth-client.md) covers the rest of
the setup:

```ts
import { createAuthClient } from "better-auth/client";
import { organizationClient } from "better-auth/client/plugins";

export const authClient = createAuthClient({
  baseURL: "http://localhost:3000",
  plugins: [organizationClient()],
});
```

`compat/better-auth/run-organization.sh` builds the plugin's `compat_server` example, runs
`compat/better-auth/organization.ts` against it, and passes 30 of 30 checks: `create` (with
metadata and `session.activeOrganizationId`), `checkSlug`, `list`, `inviteMember` (and a
repeated invite's error code), `getInvitation`, `acceptInvitation`, `getFullOrganization`,
`listMembers`, `hasPermission`, `getActiveMember`, `updateMemberRole`, `update` (403 for a
member), `leave` (and the last owner's error), `setActive({ organizationId: null })` and
`delete`. It isn't part of `compat/better-auth/run.sh` yet.

The `compat_server` example turns `require_email_verification_on_invitation` off, because the
script accepts an invitation with an unverified account, which Better Auth allows for its own
random invitation ids. fastauth requires a verified email by default.

Known gaps:

- **Stricter than Better Auth:** accepting, rejecting or viewing an invitation needs a
  verified email by default; `cancel-invitation` refuses invitations that are no longer
  pending; `remove-member` answers `MEMBER_NOT_FOUND` for another organization's member
  before checking roles, where Better Auth may answer an owner or permission error first.
  The database keeps one `member` row per user and organization (Better Auth's schema
  doesn't), slugs are capped at 255 characters and invitation emails at 254 bytes (400
  rather than a database error), and `organization_limit` holds under parallel creates: the
  count runs in the create's transaction after locking the user's row.
- **No teams, dynamic access control or `getActiveMemberRole`.** The client's team, role
  and `getActiveMemberRole` methods get 404 `NOT_FOUND`.
- **`checkRolePermission` runs in the browser** against the client's own role definitions,
  which are Better Auth's defaults. With custom roles, pass the same roles to
  `organizationClient` or ask the server with `hasPermission`.
- **No `additionalFields`** on organizations, members or invitations. Use `metadata` on the
  organization.

## Not built

These parts of Better Auth's organization plugin don't exist in fastauth:

- Teams: the `teams` option, the team routes, `set-active-team` and `teamId` on invitations.
- Dynamic access control: roles stored per organization, and the `create-role`,
  `list-roles`, `get-role`, `update-role` and `delete-role` routes. Roles are fixed at build
  time.
- The `get-organization` and `get-active-member-role` routes.
- The `membershipLimit`, `invitationLimit`, `creatorRole`,
  `cancelPendingInvitationsOnReInvite` and `disableOrganizationDeletion` options, and
  `allowUserToCreateOrganization` or `organizationLimit` as functions.
- `organizationHooks`. Use endpoint [hooks](#hooks) and [events](#events) instead.
- `sendInvitationEmail`. Your mailer gets `AuthEmail::Plugin` instead.
