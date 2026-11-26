# Changelog

## Unreleased

### Security

- **SESS-1:** with the cookie cache on, `/admin/*` and `impersonate-user` authorized from the
  cached session, so a revoked, demoted or banned admin kept admin rights for the cache's max
  age. Admin checks now read the session and user from the database.
- **SESS-2:** `/two-factor/get-totp-uri`, `/two-factor/generate-backup-codes` and
  `/change-password` accepted a cached or API-key session, and `/revoke-session`,
  `/revoke-sessions` and `/revoke-other-sessions` a cached one. The first three now need a
  stored session (`sensitive_session`); the revoke routes read it from the database.
- **SESS-3:** `/api-key/delete` accepted impersonation, API-key and revoked cached sessions. It
  now needs a stored session, as create and update do; so do renaming and deleting a passkey,
  `/unlink-account` and `/delete-anonymous-user`.
- **SESS-4:** a `rememberMe: false` session lived the full `expires_in` (7 days) and slid on
  refresh, and multi-session kept a persistent device cookie for it. It now lives one day at
  most, is never extended, and its device cookie lasts the browser session.
- **SESS-5:** `create_session` set the session cookie before the session hooks ran, so a
  refused sign-in or impersonation left the browser signed in (for impersonation, with an
  unmarked 7-day session for the target). Hooks now run first; on an error the row is deleted
  and no cookie is set. Impersonation writes `impersonatedBy` and its expiry in the same insert.
- **SESS-6:** the cookie cache carried `returned = false` columns to the browser in a signed,
  readable cookie. Those values are now encrypted inside the cache payload.
- **SESS-7:** a JWT from `/token` ran its full `expiration_time` even past the session it came
  from (an impersonation session, for example). `exp` is now capped at the session's expiry.
- **SESS-8:** the sliding refresh ignored the row count of its conditional update, so a
  session revoked mid-request got a refreshed cookie and a fresh cookie-cache cookie. The
  request now answers signed out and clears the cookies.
- Organization role and permission checks on every route that changes something also read
  the session from the database now (the SESS-1 class).

Fixes from the FAST-45 security review. One claim model now covers every path that proves an
email: whoever proves control of an address becomes the only owner of its user
([Claiming an email](docs/concepts/03-security.md#claiming-an-email)).

- **ATO-1 (high):** a sign-in the first registrant left waiting at the two-factor step can no
  longer finish after the owner claims the address; the claim deletes it, and the security
  stamp refuses one already in flight.
- **ATO-2 (high):** `/reset-password` with an emailed link now claims an unverified user, so
  the first registrant's API keys, passkeys, OAuth links and two-factor no longer survive it.
- **ATO-3 (high):** a verification link (`/verify-email`, `/email-otp/verify-email`) opened
  without proof of the password claims the user and deletes the password, instead of
  verifying the first registrant's account and leaving their password working.
- **ATO-4 (high):** a verified social sign-in that claims a user deletes every earlier OAuth
  link, not only the password, so a provider link the first registrant made stops signing in.
- **ATO-5 (medium):** a claim deletes the user's two-factor enrollment (secret, backup codes,
  trusted devices) and clears `twoFactorEnabled`.
- **ATO-6 (medium):** plugin cleanup runs inside the claim's transaction
  (`PluginBuilder::on_claim`) instead of on the post-commit `UserClaimed` event, so a sign-in
  refused after the claim no longer leaves API keys or passkeys behind; a failing cleanup
  fails the whole claim.
- **ATO-7 (medium):** password-reset and email-verification links are bound to the user's
  address and security stamp, so they die when the email changes or the user is claimed.
- **ATO-8 (medium):** a guest whose email gets verified (email OTP change-email) is no longer
  anonymous, so the next sign-in in that browser doesn't delete the account.
- **ATO-10 (low):** username rules run wherever a client writes user fields
  (`PluginBuilder::prepare_user_input`), so email-OTP sign-up validates `username`, and
  `"username": null` no longer clears an immutable username.
- **RACE-1 (medium):** a password sign-in that was in flight while the user was claimed no
  longer keeps a session: every sign-in and account link compares the user's new
  `security_stamp` before it finishes, on Postgres, SQLite and MySQL.

### Behaviour changes

- With the cookie cache on, admin and organization routes that change something,
  `/admin/has-permission`, `/organization/has-permission` and the `/revoke-*` routes cost one
  extra database read, and answer `401` to a session revoked since the cache cookie was set.
- An API key's session and an impersonation session can no longer read the TOTP URI,
  generate backup codes, change the password, delete API keys, rename or delete passkeys,
  unlink accounts or delete an anonymous user (`401` for a key's session,
  `403 NOT_ALLOWED_WHILE_IMPERSONATING` while impersonating). Better Auth allows some of
  these; see [Security](docs/concepts/03-security.md#sessions-that-arent-a-sign-in).
- `rememberMe: false` sessions expire after one day (or `expires_in`, if shorter) and aren't
  refreshed.
- A session hook that returns an error now leaves no session behind: the row is deleted and
  the response sets no session cookie.
- JWTs expire with their session at the latest.
- The cookie-cache format changed, so every existing cache cookie is ignored once (the next
  request reads the database and writes a new one).
- Opening a verification link signed out, in another browser than the one that signed up
  (no session and no `pending_verification` cookie), deletes the user's password with
  everything else from before the proof. The owner signs in with a magic link or code, or sets
  a password with a reset. Better Auth only sets `emailVerified`.
- `/reset-password` and email OTP's reset on an unverified user verify the email and delete
  the user's other accounts, sessions, passkeys, API keys and two-factor, even with
  `revoke_sessions_on_password_reset(false)`.
- A sign-in or social link that was in progress while the user was claimed answers 401
  `UNAUTHORIZED` instead of a session.
- Password-reset and email-verification links sent before the upgrade no longer work; users
  request a new one.
- Sign-up and a sign-in refused with `EMAIL_NOT_VERIFIED` set a signed
  `<prefix>.pending_verification` cookie that lives as long as a verification link.
- A user with a verified email is never anonymous, whatever `is_anonymous` says.

### Upgrading

- **Database:** a new column, `user.security_stamp` (integer, not null, default 0). Run
  `auth.migrator().run()` or `fastauth migrate` (or `fastauth generate` for a SQL file) on
  Postgres, SQLite and MySQL; existing users get 0 and keep signing in.
- **Plugins:** move credential cleanup from `on::<UserClaimed>` to `on_claim`.
  `Internal::claim_unverified_user` is deprecated in favour of `claim_user(user, None)`.

### Core

- `Ctx::authoritative_session()`: the request's session as the database holds it, re-read
  only when the cookie cache answered. For authorization decisions; unlike
  `sensitive_session()` it lets API-key and impersonation sessions through.
- `Ctx::dont_remember()`: whether the session cookie this request sets, or carries, is from a
  `rememberMe: false` sign-in.
- `NewSession` and `Internal::create_session_with(user_id, remember_me, NewSession)`: a session
  with its own expiry and plugin columns in one insert. `create_session` calls it.
- `SessionView` has a new private field, so code outside core can't build one with a struct
  literal any more.
- Claim model: `Internal::claim_user(user, link)`, `prove_email`, `create_user_verification` /
  `consume_user_verification`, `link_account_unless_claimed`, `remember_password_holder` and
  `user_fields`; `PluginBuilder::on_claim` with `Claim` and `prepare_user_input` with
  `UserInput` (all in `plugin_prelude`); `User::SECURITY_STAMP` and
  `UserView::security_stamp()`. `UserClaimed` is for notifications only. No public trait
  changed.

## 0.5.0 (2026-11-26)

### Highlights

- **MySQL.** `fastauth-sqlx` runs on MySQL 8 next to Postgres and SQLite. Use the facade's
  `mysql-tls` feature against a default MySQL 8.
- **actix-web.** The new `fastauth-actix` crate (facade feature `actix`) does for actix-web
  what `fastauth-axum` does for axum, organization and admin extractors included.
- **MIT only.** From 0.5.0 on, fastauth is licensed under MIT alone. 0.4.0 and earlier stay
  MIT OR Apache-2.0.
- **A security fix for passkeys and API keys.** In 0.4 and earlier, whoever registered an
  unverified email first could keep access through passkeys or API keys after the real owner
  claimed it. 0.5.0 deletes them when the owner proves the address. Upgrade if you use the
  passkey or API-key plugin.

### Upgrading from 0.4

Bump `fastauth` (and any `fastauth-*` crate you depend on directly) to `"0.5"`. Most apps
need no other change; check this list.

**New, and off unless you turn it on**

- The facade's `actix`, `mysql` and `mysql-tls` features, and `fastauth-sqlx`'s `mysql`
  and `tls-rustls` features. Defaults are unchanged (`axum`, `postgres`, `macros`).
- `Passkey::sign_up(resolver)`: passkey-first sign-up for signed-out visitors.
- `EmailOtp::change_email(true)` and `verify_current_email(true)`: changing the email with a
  code.
- Core's `actix` feature and `UserClaimed` event, both additive.

**Database**

- No new tables or columns, and the SQL fastauth generates for Postgres and SQLite is
  unchanged, so a 0.4 database needs no migration. Passkey-first sign-up and the email change
  keep their pending state in the existing `verification` table.
- MySQL is new: `auth.migrator().run()` or your `fastauth migrate` binary creates every
  table in an empty MySQL 8 database. fastauth doesn't copy data between databases.

**Code that may not compile**

- `EmailOtpError` has four new variants, `ChangeEmailDisabled`, `EmailIsTheSame`,
  `CurrentEmailOtpRequired` and `EmailAlreadyInUse`, and isn't `#[non_exhaustive]`, so an
  exhaustive `match` on it needs arms for them.
- The passkey plugin's `RegisterOutput` has a new public field, `challenge` (a sign-in
  gate's answer for passkey-first sign-up), so code that builds it or destructures it without
  `..` needs it.
- No public trait changed.

**License**

- 0.5.0 is MIT only; its crates declare `license = "MIT"` and ship one `LICENSE` file
  instead of `LICENSE-MIT` and `LICENSE-APACHE`. If a license allow-list (cargo-deny or
  similar) only admitted fastauth through Apache-2.0, add MIT.

**Behaviour changes**

- When a magic link, an email code or a social account with a verified email claims a user
  whose email wasn't verified, that user's passkeys and API keys are deleted, as its accounts
  and sessions already were. Someone who signed up with an unverified email and added a
  passkey or key loses it once another person proves the address, so have users verify their
  email before they rely on either.
- The email OTP plugin always registers `/email-otp/request-email-change` and
  `/email-otp/change-email` (3 requests a minute per client, like its other routes). With
  `change_email` off they answer `400 CHANGE_EMAIL_WITH_OTP_IS_DISABLED` instead of 404.
- The passkey plugin passes `generate-register-options`' `context` to the `sign_up`
  resolver instead of ignoring it. Without `sign_up`, registering signed out still answers
  `401`, and signed-in registration answers as in 0.4.
- The docs moved into folders (`docs/06-database.md` is now `docs/concepts/02-database.md`,
  and so on), so links into the repository's `docs/` need updating. Docs site URLs are the
  same, except `/docs/open-questions/`, which redirects to `/docs/decisions/`.

### Security

- **Claiming an unverified user now revokes its API keys and passkeys.** A magic link, an
  email code or a verified social account that claims a user whose email wasn't verified
  deleted that user's accounts and sessions, but an API key or passkey the first registrant
  had made kept working, so whoever registered someone else's address first kept access
  after the owner proved it. Both are now deleted on claim (core's new `UserClaimed` event).


### actix-web

- New crate `fastauth-actix`, the facade's `actix` feature (`fastauth::actix`): actix-web 4
  with the same shape as `fastauth-axum`. `auth.scope()` mounts every auth route under
  `base_path`, `Session`, `OptionalSession` and `FreshSession` extract the session with the
  axum extractors' `401` and `403` answers, and `auth.session_middleware()` resolves it once
  per request and writes refreshed cookies. The peer address feeds `ClientIp::Socket`. See
  [actix-web](docs/integrations/03-actix.md).
- The organization plugin's `OrgMember`, `ActiveMember` and `RequirePermission` work in
  actix-web too (`actix` feature), and the admin plugin adds `actix::RequireRole`.
- `fastauth-core` has an `actix` feature: `AuthError` is an actix `ResponseError` and
  `ApiResponse` a `Responder`, like its `axum` feature does for axum.
- `crates/fastauth/examples/actix_sqlite.rs` is the `axum_sqlite` example on actix-web, and
  `SERVER=actix compat/better-auth/run.sh` runs the Better Auth client suite against it.

### MySQL

- `fastauth-sqlx` supports MySQL 8 behind a new `mysql` feature (also on the `fastauth`
  facade): `Sqlx::new(MySqlPool)` gives `Sqlx<MySql>`, and `.schema(..)` picks the database.
  Every core and plugin table migrates and passes the adapter conformance suite. Tables are
  InnoDB, utf8mb4 with the case-sensitive `utf8mb4_0900_bin` collation; UUID ids are
  `binary(16)`, other ids and key text `varchar(768)`, timestamps `datetime(6)` in UTC. See
  [Databases](docs/concepts/02-database.md#mysql) for the column types and how to connect.
- The facade's `mysql-tls` feature is `mysql` plus TLS through sqlx's rustls backend
  (`fastauth-sqlx`'s new `tls-rustls` feature). MySQL 8's default login needs TLS, so this
  is the feature to use against a default MySQL 8.
- The sqlx and plugin SQL tests also run on MySQL when `MYSQL_DATABASE_URL` is set, and the
  Better Auth compat servers for `run.sh`, `run-organization.sh` and `run-passkey.sh` run on
  MySQL when `DATABASE_URL` is set.

### License

- fastauth is now licensed under MIT only. Earlier releases, 0.4.0 included, were dual-licensed
  MIT OR Apache-2.0 and keep that license; every crate's `license` field is now `MIT` and each
  package ships the MIT text as `LICENSE`.

### Plugins

- **Passkey-first sign-up.** `Passkey::sign_up(resolver)`, off by default, lets a signed-out
  visitor register a passkey and become a user with it: Better Auth's
  `registration: { requireSession: false, resolveUser }` with `addPasskey({ context })`. The
  user is created only after the attestation verifies, never gets a passkey added when the
  email is taken (`422`), and `createSession` signs in through the sign-in gates. Signed-in
  registration still needs a fresh session that may mint credentials.
- **Email OTP: change the email with a code.** `EmailOtp::change_email(true)` adds Better
  Auth's `/email-otp/request-email-change` and `/email-otp/change-email`
  (`emailOtp.requestEmailChange` and `emailOtp.changeEmail`): a code sent to the new address
  makes it the user's, verified. `verify_current_email(true)` also asks for a code sent to the
  current address. Both routes need a session that may change credentials.

### Core

- New event `UserClaimed { user_id }`, emitted when proof of an email claims an unverified
  user (`Internal::claim_unverified_user` and social sign-in), so plugins can drop
  credentials of their own.

### Docs and tooling

- The docs are grouped into folders that match the docs site: `docs/get-started`,
  `docs/concepts`, `docs/integrations`, `docs/plugins` (by kind) and `docs/reference`.
  [All plugins](docs/plugins/README.md) lists every plugin with its crate and feature, and the
  plugin authoring guide moved to [its own page](docs/reference/01-plugin-authoring.md). Site
  URLs stay the same except `/docs/open-questions/`, which redirects to `/docs/decisions/`.
- Docs site: the layout is centered with a 1440px frame on wide screens, the header dither
  stays clear of the controls, code blocks scroll instead of wrapping, and code in tables
  only breaks between path segments.

## 0.4.0 (2026-11-26)

### Security

0.4.0 fixes 28 findings from a security review of 0.3.0 (2 high, 9 medium, 8 low, 9 info).
**All versions before 0.4.0 are affected; upgrade.** The two highs:

- **Open redirect and password-reset account takeover (CORE-1).** A callback URL with a tab
  or newline after the first `/` passed the redirect check, and the browser followed it to
  another site. Without signing in, an attacker could request a password reset for any
  user with such a `redirectTo`; the genuine reset email's link then sent the user's
  browser, reset token attached, to the attacker's site, and the attacker could set a new
  password for that account. Every
  `callbackURL`, `newUserCallbackURL`, `errorCallbackURL` and `redirectTo` was an open
  redirect.
- **Banned users kept access through API keys (AUTHZ-1).** With the admin and API-key
  plugins, a banned user's API key still authenticated, and could create more keys. Bans now
  apply to every kind of session, and banning disables the user's keys.

Every finding, by id:

- **CORE-1** (high, also TOKENS-1): a callback URL such as `/<TAB>/evil.example` passed the
  redirect check, and a browser opened it as `//evil.example`: an open redirect on every
  `callbackURL`, `newUserCallbackURL`, `errorCallbackURL` and `redirectTo`, and theft of
  password-reset tokens through a genuine reset email. Redirect targets are now refused with
  control characters, backslashes or encoded `/` and `\`, resolved against `base_url`, and
  required to stay on a trusted origin; `Location` carries the resolved URL.
  ([Security](docs/concepts/03-security.md#redirects))
- **AUTHZ-1** (high): a banned user's API key no longer authenticates. The admin plugin's ban
  check is a session gate, so it applies to every session (API key, bearer, cookie cache),
  and banning disables the user's API keys.
- **CORE-2**: without a client IP, the strict sign-in/sign-up/reset limits no longer put every
  client in one bucket, where three wrong passwords from anyone locked everyone out. Requests
  without an IP are limited per account named in the JSON body (`email` or `username`), the
  first one logs a warning, and the README, quickstart and `admin_server` example now serve
  with `into_make_service_with_connect_info::<SocketAddr>()`.
- **CORE-3**: password reset, verification, sign-up (with `require_email_verification`) and
  email OTP send their emails in the background and do the same database work for unknown
  emails, so response time no longer reveals which emails have accounts.
- **CORE-4**: a password reset (core and email OTP) revokes every session of the user by
  default.
- **CORE-5**: `/change-password` and two-factor's `/enable`, `/disable`, `/get-totp-uri` and
  `/generate-backup-codes` are under the strict limit (3 per 10 seconds).
- **CORE-6**: passkey registration, two-factor enable/disable, `/link-social` and API-key
  create/update use `Ctx::sensitive_session()`, which skips the cookie cache.
- **CORE-7**: `ClientIp::Header` accepts only a value that is a single valid IP, and the new
  `ClientIp::TrustedProxies { header, proxies }` reads `x-forwarded-for` from the right. The
  docs say never to use `ClientIp::Header` with `x-forwarded-for`.
- **CORE-8**: TOTP and backup codes had no per-challenge attempt cap, and the pending
  two-factor cookie could be replayed for its whole max age. The pending sign-in is now a
  server-side `verification` row that allows 5 guesses across all methods and is deleted
  when a code finishes it. ([Security](docs/concepts/03-security.md#two-factor-sign-in))
- **2FA-1**: concurrent wrong guesses on `/two-factor/verify-otp` all counted as one attempt.
  Each guess now claims its attempt with a compare-and-swap before the code is compared.
- **TOKENS-2**: `/link-social` linked any provider identity. It now requires a live starting
  session, a provider-verified email equal to the user's (unless
  `Social::allow_different_emails(true)`), and linking not `AccountLinking::Off`.
- **TOKENS-3**: `JwksVerifier` and `auth.jwt().verify()` never checked `nbf`; they do now.
- **TOKENS-4**: `auth.jwt().verify()` trusted retired keys forever. It now uses only the keys
  `/jwks` publishes, and `rotate()` deletes keys past their grace period.
- **TOKENS-5**: a huge `expires_in` from an OAuth token endpoint panicked the callback; token
  lifetimes are now clamped to 10 years and negative ones ignored.
- **TOKENS-6**: the JWT docs told resource servers to refetch the JWKS on every
  `UnknownKey`, which any client can trigger. They now say to refetch at most once per
  cool-down, and a token without a `kid` is `VerifyError::Invalid` instead of
  `UnknownKey(None)`.
- **TOKENS-7**: documented that the bearer plugin's `set-auth-token` header lets page scripts
  read the session token ([Bearer tokens](docs/plugins/tokens/01-bearer.md#security)).
- **AUTHZ-2**: an API key's session is never fresh, so it can't register a passkey or pass
  `FreshSession`.
- **AUTHZ-3**: an API key's session can't create keys or update them (so it can't lift its own
  expiry or limits).
- **AUTHZ-4**: admins without `user:impersonate-admins` can't set another admin's password,
  email, role or ban, remove them or revoke their sessions (`403 YOU_CANNOT_MANAGE_ADMINS`).
- **AUTHZ-5**: `/api-key/create` and `/api-key/update` read the session from the database, so a
  revoked session in the cookie cache can't mint a key.
- **AUTHZ-6**: session refresh no longer extends an impersonation session past
  `impersonation_session_duration`.
- **AUTHZ-7**: impersonation sessions can't create or update API keys, register passkeys, link
  social accounts or change two-factor (`403 NOT_ALLOWED_WHILE_IMPERSONATING`).
- **AUTHZ-8**: two owners leaving (or removing or demoting each other) at once can no longer
  leave an organization without an owner.
- **AUTHZ-9**: accepting, rejecting or viewing an invitation needs a verified email by default.
- **AUTHZ-10**: documented that API-key `permissions` don't limit a key's session, on
  `ApiKeys::sessions` and in docs/14; key sessions can no longer mint credentials.
- **AUTHZ-11**: `/organization/remove-member` answers `MEMBER_NOT_FOUND` for another
  organization's member before any role check, so it no longer reveals who owns it.
- **AUTHZ-12**: `/organization/cancel-invitation` only cancels pending invitations.

### Upgrading from 0.3

Bump `fastauth` to `"0.4"` and go through this list: some defaults changed, and two public
enums gained variants.

**Code that may not compile**

- `ClientIp` has a new variant, `TrustedProxies { header, proxies }`, so an exhaustive
  `match` on it needs an arm for it.
- `AdminError` has two new variants, `YouCannotManageAdmins` and
  `NotAllowedWhileImpersonating`, so an exhaustive `match` on it needs arms for them.
- No public trait changed; the core additions are listed under Core below.

**Database**

- Core tables are unchanged. Two-factor's pending sign-ins live in the existing
  `verification` table (its `data` column, there since 0.1), so they need no migration.
- The username plugin adds `username` (unique) and `display_username` to `user`, and the
  anonymous plugin adds `is_anonymous`. Run your migrations after registering either.
  Multi-session adds no table or column.
- Two-factor sign-ins that are pending when you deploy must start over: the `two_factor`
  cookie now names a `verification` row, and old cookies don't. A pending sign-in allows 5
  guesses across TOTP, email codes and backup codes; after that the user signs in with their
  password again.

**Changed defaults**

- `EmailPassword::revoke_sessions_on_password_reset` defaults to `true` (was `false`), for
  `/reset-password` and `/email-otp/reset-password`: a reset signs the user out everywhere.
  Better Auth defaults to `false`; set `.revoke_sessions_on_password_reset(false)` to keep
  sessions.
- **Organization:** `require_email_verification_on_invitation` defaults to `true` (was
  `false`). Users must verify their email before they can view, accept or reject an
  invitation. Set it to `false` to keep 0.3 behaviour (Better Auth's default for its random
  ids).

**Redirects**

- Redirects answer with an absolute `Location`: `callbackURL: "/dashboard"` redirects to
  `{base_url}/dashboard`, the same place a browser resolved the relative one to. Better Auth
  sends relative targets back as they came. The JSON `url` of `/sign-in/*` is unchanged.
- Callback URLs with control characters, backslashes or `%2f`/`%5c` in the path are refused
  with 403 `INVALID_CALLBACK_URL`, as Better Auth refuses them.
- `Ctx::redirect` answers 403 `INVALID_CALLBACK_URL` for a URL that fails
  `is_safe_redirect`, so custom plugins can only redirect to the app or a trusted origin.

**Sessions that didn't come from a sign-in**

- An API key's session (`ApiKeys::sessions(true)`) can't mint credentials: it is never
  fresh (`403 SESSION_NOT_FRESH` from `Fresh` endpoints and `FreshSession`), and it gets
  `401` from API-key create and update, passkey registration, `/link-social` and
  two-factor enable and disable.
- An impersonation session gets `403 NOT_ALLOWED_WHILE_IMPERSONATING` from those same
  endpoints, and session refresh no longer extends it past
  `impersonation_session_duration`.
- Those endpoints read the session from the database, so a session revoked while still in
  the cookie cache can't use them either.

**Social sign-in**

- `AccountLinking::Off` now also refuses `/link-social` (`?error=unable_to_link_account`),
  like Better Auth's `accountLinking.enabled: false`.
- `/link-social` needs a live session started by a sign-in, and refuses a provider account
  with a different email (`?error=email_doesn't_match`) unless
  `Social::allow_different_emails(true)`.

**Admin**

- A banned user's requests answer `403 BANNED_USER` whatever the session came from (cookie,
  cookie cache, bearer token, API key).
- Banning a user disables their API keys. They stay disabled when the ban lifts, until the
  owner turns them back on.
- Acting on another admin's account (password, email, role, ban, removal, revoking sessions)
  needs `user:impersonate-admins`, or answers `403 YOU_CANNOT_MANAGE_ADMINS`.

**Client IP and rate limits**

- `ClientIp::Header` accepts only a value that is a single valid IP; a comma-separated list
  counts as no IP. For `x-forwarded-for`, use `ClientIp::TrustedProxies`.
- Requests without a client IP are rate-limited per account named in the JSON body instead
  of sharing one bucket, and the first one logs a warning. With axum, serve with
  `into_make_service_with_connect_info::<SocketAddr>()` so `ClientIp::Socket` sees the
  address.
- `/change-password` and two-factor's `/enable`, `/disable`, `/get-totp-uri` and
  `/generate-backup-codes` are limited to 3 requests per 10 seconds.

**Emails**

- Password reset, verification, sign-up (with `require_email_verification`) and email OTP
  send their emails after the response. A mailer error is logged with `tracing::error!`
  instead of answering 500. `LogMailer` and `MemoryMailer` still send before the response,
  so tests can read `MemoryMailer` as before.

**JWT**

- Tokens with a future `nbf` no longer verify, in `JwksVerifier` and `auth.jwt().verify()`.
- A token without a `kid` is `VerifyError::Invalid` instead of `UnknownKey(None)`.
- `auth.jwt().verify()` only trusts the keys `/jwks` publishes, so a retired key stops
  verifying once its grace period ends, and `rotate()` deletes keys past their grace period.

**Organization**

- `/organization/remove-member` answers `MEMBER_NOT_FOUND` for another organization's
  member before any role check.
- `/organization/cancel-invitation` only cancels pending invitations; an accepted, rejected
  or cancelled one answers `INVITATION_NOT_FOUND`.

### New plugins

- **fastauth-plugin-username** (feature `username`, `fastauth::plugins::username`): `username`
  and `display_username` columns on `user`, set on `/sign-up/email`, `/update-user` and
  `auth.api().create_user`, validated (length, validator), refused when taken and stored
  normalized (lowercase by default). `POST /sign-in/username` (runs the sign-in gates) and
  `POST /is-username-available`. Options for length, username and display username
  validators, normalization, validation order and `immutable_username`. `UsernameExt` for
  server calls. Wire-compatible with `usernameClient` (`compat/better-auth/run-username.sh`).
  ([docs/20](docs/plugins/sign-in/04-username.md))
- **fastauth-plugin-anonymous** (feature `anonymous`, `fastauth::plugins::anonymous`):
  `POST /sign-in/anonymous` creates a user with a placeholder email and `is_anonymous: true`.
  When that browser later signs in or up with any real method, `on_link_account` gets both
  sessions and the anonymous user is deleted (unless `disable_delete_anonymous_user`).
  `POST /delete-anonymous-user`, `email_domain_name`, `generate_name` and
  `generate_random_email`. `AnonymousExt` for server calls. Wire-compatible with
  `anonymousClient` (`compat/better-auth/run-anonymous.sh`). ([docs/21](docs/plugins/sign-in/05-anonymous.md))
- **fastauth-plugin-multi-session** (feature `multi-session`,
  `fastauth::plugins::multi_session`): several signed-in accounts per browser through Better
  Auth's signed `session_token_multi-{token}` cookies, `/multi-session/list-device-sessions`,
  `/multi-session/set-active` and `/multi-session/revoke`, `maximum_sessions` (default 5),
  and `/sign-out` signing every remembered account out. `MultiSessionExt` for server calls.
  Wire-compatible with `multiSessionClient` (`compat/better-auth/run-multi-session.sh`).
  ([docs/22](docs/plugins/access/03-multi-session.md))

### Core

All additive; no public trait changed.

- `PluginBuilder::on_session_created`: an async hook that runs inside the request right
  after a session is created, for every sign-in method. It sees the request's previous
  session cookie, can query the database and set cookies, and its error fails the response
  ([Plugins](docs/reference/01-plugin-authoring.md#after-a-session-is-created)).
- `Internal::find_session_by_token` (an unexpired session and its user, without refreshing
  it) and `Internal::set_session_cookies` (make a token the request's session).
- Read-only getters for plugins: `EmailPassword::requires_email_verification()`,
  `EmailPassword::max_password_len()` and `SessionConfig::lifetime()`.
- Session gates: `PluginBuilder::session_gate(|ctx, session, usage| ..)` runs on every
  session a request uses (cookie, cookie cache, bearer token, a resolver's
  `Resolved::User`) and on every sensitive session; `Err` refuses it. `SessionUse` says
  which (`Request` or `Sensitive`) ([Plugins](docs/reference/01-plugin-authoring.md#session-gates)).
- `Ctx::sensitive_session()`: the request's session read again from the database, skipping
  the cookie cache, refused for ephemeral sessions (401) and checked by the session gates
  with `SessionUse::Sensitive`. For endpoints that create or change a credential.
- `Internal::ephemeral_session(&user_id)`: the request-only session `Resolved::User` builds,
  after the session gates.
- `PluginBuilder::fixed_session_expiry(|session| ..)`: sessions it answers true for are never
  extended by the refresh. Admin marks impersonation sessions with it.
- `Internal::send_email_in_background` (send without waiting for the mailer, logging a
  failure) and `Internal::simulate_verification` (the database work of a verification
  lookup, for the branch that sends nothing). `Internal::send_verification_email` now sends
  in the background.
- `CoreConfig::resolve_redirect(target)`: the URL a redirect to `target` lands on, or `None`
  when it isn't safe; `is_safe_redirect` is built on it.

## 0.3.0 (2026-11-26)

### Upgrading from 0.2

None of these changes break a 0.2 app: bump `fastauth` to `"0.3"` and turn on the features
you want. The `jwt` and `passkey` plugins add a table each (`jwks`, `passkey`), so run your
migrations after registering them; the others add none. One behaviour change for custom
plugins: a session found by a resolver's `Resolved::Token` is now refreshed like a cookie
session (see Core below).

### New plugins

- **fastauth-plugin-magic-link** (feature `magic-link`, `fastauth::plugins::magic_link`):
  `POST /sign-in/magic-link` emails a single-use link through the app's mailer, and
  `GET /magic-link/verify` signs the user in, creating them on first use unless
  `.disable_sign_up(true)`. Redirects to `callbackURL`, `newUserCallbackURL` or
  `errorCallbackURL?error=..` as Better Auth does; links expire after 5 minutes by default
  and only the token's SHA-256 is stored. `MagicLinkExt` for server calls. Wire-compatible
  with `magicLinkClient` (`compat/better-auth/run-magic-link.sh`).
  ([docs/15](docs/plugins/sign-in/01-magic-link.md), #26)
- **fastauth-plugin-email-otp** (feature `email-otp`, `fastauth::plugins::email_otp`):
  one-time codes by email for sign-in (with sign-up), email verification and password reset:
  `/email-otp/send-verification-otp`, `/sign-in/email-otp`, `/email-otp/verify-email`,
  `/email-otp/check-verification-otp`, `/email-otp/request-password-reset` (and
  `/forget-password/email-otp`) and `/email-otp/reset-password`. `otp_length`, `expires_in`
  and `allowed_attempts`; codes are stored as a keyed HMAC, compared in constant time, and
  attempts are claimed atomically before comparing. `EmailOtpExt` for server calls.
  Wire-compatible with `emailOTPClient` (`compat/better-auth/run-email-otp.sh`).
  ([docs/16](docs/plugins/sign-in/02-email-otp.md), #26)
- Both plugins claim an unverified user when a link or code proves the email: the user's
  earlier accounts and sessions are deleted and the email is marked verified, as Better Auth
  does.
- **fastauth-plugin-bearer** (feature `bearer`, `fastauth::plugins::bearer`): sessions from
  `Authorization: Bearer <token>` on every auth route, in server API calls and in the axum
  extractors, signed or raw tokens (`require_signature` to refuse raw ones), and the
  `set-auth-token` header on every response that sets the session cookie. Wire-compatible
  with Better Auth's `bearer` plugin (`compat/better-auth/run-bearer.sh`).
  ([docs/17](docs/plugins/tokens/01-bearer.md), #27)
- **fastauth-plugin-jwt** (feature `jwt`, `fastauth::plugins::jwt`): `GET /token`, `GET /jwks`,
  the `set-auth-jwt` header on `/get-session`, a `jwks` table with private keys encrypted
  with the app secret, EdDSA (default), ES256 and RS256 keys, issuer, audience, expiration
  time, `define_payload`, scheduled and on-demand key rotation with a grace period,
  `JwtExt` (`token`, `sign`, `verify`, `jwks`, `rotate`), and `JwksVerifier` for resource
  servers. Built on `jsonwebtoken` and aws-lc-rs. Wire-compatible with Better Auth's
  `jwtClient` (`compat/better-auth/run-jwt.sh`). ([docs/18](docs/plugins/tokens/02-jwt.md), #27)
- **fastauth-plugin-passkey** (feature `passkey`, `fastauth::plugins::passkey`): passkeys on
  webauthn-rs 0.6. Better Auth's seven routes (`/passkey/generate-register-options`,
  `verify-registration`, `generate-authenticate-options`, `verify-authentication`,
  `list-user-passkeys`, `update-passkey`, `delete-passkey`), its `passkey` table and
  encodings, and `rp_id`, `rp_name` and `origin` options. Challenges live server-side for
  five minutes and work once; the signature counter is checked and advanced with a
  compare-and-swap; sign-in runs the sign-in gates with method `"passkey"`. User
  verification is always required. `PasskeyExt` lists, renames and deletes passkeys.
  Wire-compatible with `passkeyClient`, checked in headless Chrome with a virtual
  authenticator (`compat/better-auth/run-passkey.sh`). ([docs/19](docs/plugins/sign-in/03-passkey.md), #28)

### Core

- `Internal::claim_unverified_user`, the claim above, for plugins with email-primary
  sign-in.
- `routes::normalize_email` and `routes::user_input_fields` are public, so plugins validate
  emails and user fields exactly like sign-up.
- `EmailPassword::revokes_sessions_on_password_reset()` and
  `EmailVerification::auto_signs_in_after_verification()` read those settings.
- `PluginBuilder::on_response`: a hook over the HTTP response of every routed endpoint.
- Sessions found by a resolver's `Resolved::Token` are refreshed like cookie sessions.

### Docs and tooling

- The README, the overview, the plugins page, the docs site and the `use-fastauth` skill list
  the five new plugins; the skill has a reference for each.
- Every compat script in `compat/better-auth/` takes `PORT` (3000 unless set), so two runs
  on one machine don't collide. The `axum_sqlite` and organization `compat_server` examples
  read `PORT` too.

## 0.2.0 (2026-11-26)

### New plugins

- **fastauth-plugin-organization** (feature `organization`, `fastauth::plugins::organization`):
  organizations, members, invitations by email, the active organization on the session,
  owner/admin/member roles with custom roles and typed permissions, `OrganizationExt`, and
  the axum extractors `ActiveMember`, `OrgMember<A, FromPath<P>>` and
  `RequirePermission<A, P, S>`. Wire-compatible with Better Auth's `organizationClient`
  (`compat/better-auth/run-organization.sh`). ([docs/12](docs/plugins/access/01-organization.md), #19)
- **fastauth-plugin-admin** (feature `admin`, `fastauth::plugins::admin`): Better Auth's 15
  `/admin/*` routes, statement-based roles and permissions, bans enforced by a sign-in gate,
  impersonation, case-sensitive user search in SQL, `AdminExt`, and the `RequireRole<A, R>`
  extractor. Wire-compatible with `adminClient` (`compat/better-auth/run-admin.sh`).
  ([docs/13](docs/plugins/access/02-admin.md), #18)
- **fastauth-plugin-api-key** (feature `api-key`, `fastauth::plugins::api_key`): hashed API
  keys with expiry, usage limits and refills, per-key rate limits and permissions,
  server-only verify and cleanup, atomic counters, `ApiKeysExt`, and sessions from
  `x-api-key`, opt-in with `ApiKeys::new().sessions(true)`. Wire-compatible with
  `@better-auth/api-key`'s `apiKeyClient`. ([docs/14](docs/plugins/tokens/03-api-keys.md), #17)
- The facade gains the `organization`, `admin` and `api-key` features; with `axum` on, they
  turn on the plugins' extractors. The `axum_sqlite` example registers all three, and
  `compat/better-auth/run.sh` checks the API key flow. (#21)

### Breaking

- **Ids are ULIDs by default.** `FastAuth::builder().ids(..)` picks the strategy:
  `IdStrategy::Ulid` (default), `UuidV7`, `UuidV4`, or `IdStrategy::custom(|| ..)`. Custom ids
  are checked when generated (non-empty, at most 255 bytes); a bad one fails the request with
  a 500 and a log line.
- **Postgres id columns are `text` for new installs** under the default and custom strategies,
  and `uuid` under the UUID strategies. A database created with 0.1 has `uuid` columns: keep
  it working with `.ids(IdStrategy::UuidV7)`. The migrator never changes column types; it warns
  when the live id columns don't match the configured strategy. SQLite stores ids as `text`
  either way.
- `ctx.new_id()` returns `Result<Id, AuthError>`: use `ctx.new_id()?`.
- `fastauth_core::testing::conformance_schema` and `http_flow` take the `IdStrategy` to
  store ids with, and `run_adapter_conformance` runs every case with text ids and with
  UUID ids.
- **Sign-in gates still run after a challenge.** Finishing a challenged sign-in with
  `ctx.internal().create_session(..)` skipped every other gate, so a banned user who answered
  a TOTP challenge got a session. Gates now belong to the plugin that registered them, and
  `ctx.internal().complete_sign_in(challenger, user, method, remember_me)` runs every gate except
  the challenger's before creating the session. `create_session` stays the low-level,
  gate-free primitive.
- `SignInAttempt::method` is a `Cow<'static, str>`, so a completed sign-in keeps its original
  method; `Internal::sign_in` takes `impl Into<Cow<'static, str>>`.
- `AuthInstance` has a required `try_plugin::<P>()`, implemented for `Auth`.
- `fastauth_core::adapter::Filter` is `#[non_exhaustive]`. Adapters need a fallback arm, which
  should answer `DbError::Unsupported`.
- **two-factor**: the verify endpoints finish a pending sign-in through the other plugins'
  gates. A gate that denies answers its error; a gate that challenges answers its JSON, so
  `VerifyOutput` is an enum (`Verified { token, user }` or `Challenge(json)`). A pending
  sign-in started before the upgrade must start again.

### Added

- `Filter::Contains` and `Filter::EndsWith`, with `Col::contains` and `Col::ends_with` on
  `String` columns. Like `StartsWith`, they are case-sensitive and match literally: `%`, `_`
  and `*` are not wildcards. Implemented in `MemoryAdapter` and fastauth-sqlx (Postgres
  `LIKE .. ESCAPE '\'`, SQLite `GLOB` with bracket escapes) and covered by the adapter
  conformance suite.
- `AuthInstance::try_plugin::<P>()`, for code generic over `AuthInstance` (an axum extractor)
  that can't name the `HasPlugin` index.
- `Api::db()`: typed queries outside a request, for the same kind of code.
- `IdStorage`, with `Schema::id_storage()`, `TableDef::id_storage()` and
  `LiveSchema::id_storage` for adapters that store ids per strategy.
- Docs: every page rewritten to match `main`, new pages for the three plugins, and the
  agent skill updated; every Rust sample compiles.
- `PluginBuilder::server_endpoint::<E>()` declares an endpoint with no HTTP route that hooks
  can still target. Core's `CreateUser`, the organization plugin's `AddMember`,
  `CheckPermission` and `UserInvitations`, and the API key plugin's `VerifyApiKey` and
  `DeleteAllExpiredApiKeys` use it, so hooking them is no longer a `BuildError`.
- Core event `UserDeleted { user_id, email }`, emitted by the admin plugin's `remove-user`.

### Fixed

- Organization: the server API's `create` runs the same `CreateOrganization` endpoint as the
  route (`CreateOrganization::client()` / `::server()`), so hooks on it run for both;
  `CreateOrganizationInput` gains a server-only `user_id`, which a request body can't set.
  `add_member` runs hooks on `AddMember`. `CreateOrganizationFor` and `NewOrganization`
  are gone.
- Admin: `RequireRole<_, role::Admin>` lets in every admin by `Admin::is_admin`, the check
  the endpoints use: any configured admin role, whatever its name, and `admin_user_ids`
  whatever their role. Before, it only knew the role named `admin`. Custom `Role` markers can
  override the new `Role::held_by`.
- Admin: `set-user-password` emits `PasswordChanged`, like core's change and reset.
- Doc comments: `Api::create_user` names `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL`,
  `ListUserInvitations` points at `invitations_for_email`, and the facade's plugin links
  are no longer ambiguous to rustdoc.

## 0.1.0 (2026-11-25)

First release.

- **fastauth-core**: `FastAuth::builder()`, the compile-checked plugin list (`plugins![..]`,
  `Has`, `Requires`), the plugin API (endpoints with `Access`, typed hooks, sign-in gates,
  session resolvers, events), sessions with hashed tokens, sliding expiry and an optional cookie
  cache, HKDF-derived keys with rotation, argon2id, CSRF origin checks, GCRA rate limiting, and
  the Better Auth-compatible core endpoints: email and password, sessions, email verification,
  password reset, user updates.
- **fastauth-axum**: `auth.router()`, `auth.service()`, `auth.session_layer()`, and the
  `Session`, `Option<Session>` and `FreshSession` extractors.
- **fastauth-sqlx**: Postgres and SQLite adapter, additive migrations, generated SQL, and
  shared transactions with per-call savepoints (`auth.api().in_tx(&tx)`).
- **fastauth-macros**: `#[derive(Fields)]`, `#[derive(Model)]`, `#[derive(AuthError)]`.
- **fastauth-oauth**: the `Social` plugin with GitHub and Google, PKCE, state bound to the
  browser, account linking by verified email, profile mapping, per-provider `disable_sign_up`.
- **fastauth-plugin-two-factor**: TOTP, email codes, backup codes, trusted devices.
- **fastauth-cli**: `fastauth secret`, plus `fastauth::cli::run` for schema, status, generate
  and migrate from your own binary.
- Tested against Better Auth's TypeScript client 1.7.28.
