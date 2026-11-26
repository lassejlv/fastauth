# Changelog

## Unreleased

### New plugins

- **fastauth-plugin-magic-link** (feature `magic-link`, `fastauth::plugins::magic_link`):
  `POST /sign-in/magic-link` emails a single-use link through the app's mailer, and
  `GET /magic-link/verify` signs the user in, creating them on first use unless
  `.disable_sign_up(true)`. Redirects to `callbackURL`, `newUserCallbackURL` or
  `errorCallbackURL?error=..` as Better Auth does; links expire after 5 minutes by default
  and only the token's SHA-256 is stored. `MagicLinkExt` for server calls. Wire-compatible
  with `magicLinkClient` (`compat/better-auth/run-magic-link.sh`).
  ([docs/15](docs/15-magic-link.md))
- **fastauth-plugin-email-otp** (feature `email-otp`, `fastauth::plugins::email_otp`):
  one-time codes by email for sign-in (with sign-up), email verification and password reset:
  `/email-otp/send-verification-otp`, `/sign-in/email-otp`, `/email-otp/verify-email`,
  `/email-otp/check-verification-otp`, `/email-otp/request-password-reset` (and
  `/forget-password/email-otp`) and `/email-otp/reset-password`. `otp_length`, `expires_in`
  and `allowed_attempts`; codes are stored as a keyed HMAC, compared in constant time, and
  attempts are claimed atomically before comparing. `EmailOtpExt` for server calls.
  Wire-compatible with `emailOTPClient` (`compat/better-auth/run-email-otp.sh`).
  ([docs/16](docs/16-email-otp.md))
- Both plugins claim an unverified user when a link or code proves the email: the user's
  earlier accounts and sessions are deleted and the email is marked verified, as Better Auth
  does.
- **fastauth-plugin-bearer** (feature `bearer`, `fastauth::plugins::bearer`): sessions from
  `Authorization: Bearer <token>` on every auth route, in server API calls and in the axum
  extractors, signed or raw tokens (`require_signature` to refuse raw ones), and the
  `set-auth-token` header on every response that sets the session cookie. Wire-compatible
  with Better Auth's `bearer` plugin (`compat/better-auth/run-bearer.sh`).
  ([docs/17](docs/17-bearer.md))
- **fastauth-plugin-jwt** (feature `jwt`, `fastauth::plugins::jwt`): `GET /token`, `GET /jwks`,
  the `set-auth-jwt` header on `/get-session`, a `jwks` table with private keys encrypted
  with the app secret, EdDSA (default), ES256 and RS256 keys, issuer, audience, expiration
  time, `define_payload`, scheduled and on-demand key rotation with a grace period,
  `JwtExt` (`token`, `sign`, `verify`, `jwks`, `rotate`), and `JwksVerifier` for resource
  servers. Built on `jsonwebtoken` and aws-lc-rs. Wire-compatible with Better Auth's
  `jwtClient` (`compat/better-auth/run-jwt.sh`). ([docs/18](docs/18-jwt.md))
- **fastauth-plugin-passkey** (feature `passkey`, `fastauth::plugins::passkey`): passkeys on
  webauthn-rs 0.6. Better Auth's seven routes (`/passkey/generate-register-options`,
  `verify-registration`, `generate-authenticate-options`, `verify-authentication`,
  `list-user-passkeys`, `update-passkey`, `delete-passkey`), its `passkey` table and
  encodings, and `rp_id`, `rp_name` and `origin` options. Challenges live server-side for
  five minutes and work once; the signature counter is checked and advanced with a
  compare-and-swap; sign-in runs the sign-in gates with method `"passkey"`. User
  verification is always required. `PasskeyExt` lists, renames and deletes passkeys.
  Wire-compatible with `passkeyClient`, checked in headless Chrome with a virtual
  authenticator (`compat/better-auth/run-passkey.sh`). ([docs/19](docs/19-passkey.md))

### Core

- `Internal::claim_unverified_user`, the claim above, for plugins with email-primary
  sign-in.
- `routes::normalize_email` and `routes::user_input_fields` are public, so plugins validate
  emails and user fields exactly like sign-up.
- `EmailPassword::revokes_sessions_on_password_reset()` and
  `EmailVerification::auto_signs_in_after_verification()` read those settings.
- `PluginBuilder::on_response`: a hook over the HTTP response of every routed endpoint.
- Sessions found by a resolver's `Resolved::Token` are refreshed like cookie sessions.

## 0.2.0 (2026-11-26)

### New plugins

- **fastauth-plugin-organization** (feature `organization`, `fastauth::plugins::organization`):
  organizations, members, invitations by email, the active organization on the session,
  owner/admin/member roles with custom roles and typed permissions, `OrganizationExt`, and
  the axum extractors `ActiveMember`, `OrgMember<A, FromPath<P>>` and
  `RequirePermission<A, P, S>`. Wire-compatible with Better Auth's `organizationClient`
  (`compat/better-auth/run-organization.sh`). ([docs/12](docs/12-organization.md), #19)
- **fastauth-plugin-admin** (feature `admin`, `fastauth::plugins::admin`): Better Auth's 15
  `/admin/*` routes, statement-based roles and permissions, bans enforced by a sign-in gate,
  impersonation, case-sensitive user search in SQL, `AdminExt`, and the `RequireRole<A, R>`
  extractor. Wire-compatible with `adminClient` (`compat/better-auth/run-admin.sh`).
  ([docs/13](docs/13-admin.md), #18)
- **fastauth-plugin-api-key** (feature `api-key`, `fastauth::plugins::api_key`): hashed API
  keys with expiry, usage limits and refills, per-key rate limits and permissions,
  server-only verify and cleanup, atomic counters, `ApiKeysExt`, and sessions from
  `x-api-key`, opt-in with `ApiKeys::new().sessions(true)`. Wire-compatible with
  `@better-auth/api-key`'s `apiKeyClient`. ([docs/14](docs/14-api-keys.md), #17)
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
