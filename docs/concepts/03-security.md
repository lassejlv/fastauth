# Security

Defaults are chosen so an app that configures nothing is safe. Each section says what
fastauth does and what you can change.

## Secrets

One master secret (32 bytes minimum, 64 recommended) is expanded with HKDF-SHA256 into a
separate key per purpose:

| Purpose | Info string | Used for |
|---|---|---|
| Cookie signing | `fastauth/v1/cookie` | HMAC-SHA256 on every cookie fastauth sets |
| Cookie cache | `fastauth/v1/cookie-cache` | HMAC on the cached session payload |
| Field encryption | `fastauth/v1/encrypt` | XChaCha20-Poly1305 for encrypted columns (OAuth tokens, two-factor secrets) |
| Plugin keys | `fastauth/v1/plugin/{id}` | `ctx.keys().derive_key(ID)` inside a plugin |

So a bug that leaks one derived key doesn't expose the others, and plugins can't reach
core's keys.

**Rotation.** `.secrets([new, old])`: the first signs and encrypts, all verify and
decrypt. Encrypted values carry a one-byte key id, so values encrypted under an old secret
still decrypt. Cookies signed with the old secret expire within one session lifetime (7
days by default), but encrypted columns (OAuth tokens, two-factor secrets) keep needing it:
there is no re-encryption command yet, so keep the old secret in the list until those rows
are rewritten.

## Session tokens

- 32 bytes from the OS CSPRNG, base64url (43 characters).
- The database stores `SHA-256(token)`, not the token. A read-only database leak (a backup,
  a SQL injection elsewhere in the app) can't be turned into live sessions. A plain hash
  is enough because the token has 256 bits of entropy, so nobody can brute-force it.
- The cookie holds `token.signature`. Checking the HMAC first rejects forged or mangled
  cookies without a database query.

This differs from Better Auth, which stores tokens as they are. See
[Decisions](../reference/03-decisions.md#3-hashed-session-tokens) for the migration impact.

The same rule covers every other secret value fastauth stores: verification values,
OAuth state and [API keys](../plugins/tokens/03-api-keys.md) are stored as hashes.

## Cookies

| Attribute | Default |
|---|---|
| `HttpOnly` | always |
| `Secure` and `__Secure-` prefix | when `base_url` is https |
| `SameSite` | `Lax` |
| `Path` | `/` |
| `Max-Age` | session expiry; refreshed with the session |

## Sessions that aren't a sign-in

Some sessions don't come from someone typing a password: an API key's request-only session
([API keys](../plugins/tokens/03-api-keys.md#sessions-from-api-keys)), an admin's impersonation session, and a
session answered from the cookie cache after it was revoked. fastauth limits what they can do:

- **Bans and other session gates apply to every session.** Plugins register
  [session gates](../reference/01-plugin-authoring.md#session-gates) that run on every session a request uses
  (cookie, cookie cache, bearer token, API key). The admin plugin refuses banned users there,
  so a ban stops a user's API keys and cached sessions too, and banning disables their keys.
- **Ephemeral sessions are never fresh.** An API key's session fails `Fresh` endpoints and
  `FreshSession` with `403 SESSION_NOT_FRESH`.
- **Credentials need a stored, authoritative session.** Creating, updating or deleting an API
  key, registering, renaming or deleting a passkey, `/link-social`, `/unlink-account`,
  `/change-password`, `/delete-anonymous-user`, turning two-factor on or off, reading the TOTP
  URI and generating backup codes use `ctx.sensitive_session()`: the session is read again
  from the database, skipping the cookie cache, so a revoked session gets `401`; an API key's
  session has nothing stored and gets `401`; and the admin plugin refuses impersonation
  sessions with `403 NOT_ALLOWED_WHILE_IMPERSONATING`. So a leaked key, a support agent or a
  stolen cookie can't turn into a lasting credential.
- **Authorization reads the session from the database.** Admin permission checks
  (`/admin/*`, impersonation, `/admin/has-permission`), organization role and permission
  checks on every endpoint that changes something, and `/revoke-session`,
  `/revoke-sessions` and `/revoke-other-sessions` use `ctx.authoritative_session()`. When
  the cookie cache answered the request, the session and user are read again and the session
  gates run on the stored rows, so a revoked session gets `401` and a demotion or a ban
  counts at once instead of after the cache's max age. Without the cookie cache the session
  was already read from the database and nothing is queried twice. Unlike
  `sensitive_session()`, it lets API-key and impersonation sessions through, as any request
  does. Read-only lists (organizations, members) still answer from the cache.
- **Sessions end when they should.** A `rememberMe: false` sign-in gets a session that
  lives one day at most (or `expires_in`, if that's shorter) and is never extended by the
  sliding refresh; with multi-session, its device cookie has no `Max-Age` either. A session
  revoked while a request is refreshing it gets no refreshed cookie: the request answers
  signed out and clears the cookies. When a session hook refuses a new session, the row is
  deleted and the response sets none of its cookies.
- **The cookie cache hides hidden columns.** Columns marked `returned = false` are left out
  of the readable cache payload and stored encrypted (field-encryption key) inside it, so
  they never reach the browser in clear.
- **Impersonation stays short.** The admin plugin marks impersonation sessions with
  `PluginBuilder::fixed_session_expiry`, so the refresh never extends them and they end after
  `impersonation_session_duration`.
- **Admins can't take each other over.** Acting on another admin's account (password, email,
  role, ban, removal, sessions) needs `user:impersonate-admins`
  ([Admin](../plugins/access/02-admin.md#endpoints)).

Better Auth checks bans only when a session is created, lets a key's session create keys,
and doesn't stop impersonation sessions from minting credentials, so fastauth is stricter
here. Its passkey registration, API-key creation, admin checks, `/change-password`,
`/revoke-*` and backup-code generation also read the session from the database. Better Auth
lets a cached session read the TOTP URI, unlink an account and rename or delete a passkey, an
API key's session generate backup codes, and impersonation or API-key sessions delete API
keys, and it answers organization role checks from the cookie cache; fastauth refuses or
re-reads in those cases, so it is stricter there too.

API-key `permissions` still don't limit the key's session: it can do what its owner can on
every route that takes a session. Check permissions with `auth.api_keys().verify(..)`, or
leave `.sessions` off.

## CSRF

`SameSite=Lax` already blocks cross-site `POST`s from carrying the cookie in current
browsers. On top of that, every non-`GET` request that carries a session cookie must send an
`Origin` (or, failing that, `Referer`) matching `base_url` or a trusted origin: 403
`INVALID_ORIGIN` for an untrusted one, 403 `MISSING_OR_NULL_ORIGIN` when it's missing or
`null`, as in Better Auth.

## Redirects

Every URL a request names as a place to send the browser (`callbackURL`,
`newUserCallbackURL`, `errorCallbackURL`, `redirectTo`) goes through
`CoreConfig::resolve_redirect`, on core routes, social sign-in and linking, magic links and
username sign-in. It refuses ASCII control characters and backslashes anywhere, since
browsers drop or reinterpret them (`/<TAB>/evil.example` opens `//evil.example`). A relative
URL must start with a single `/`, have no `%2f` or `%5c` in its path, and still be on
`base_url`'s origin once resolved against it; an absolute URL must be on `base_url`'s origin
or a trusted origin. Anything else answers 403 `INVALID_CALLBACK_URL`.

A redirect's `Location` is the resolved, serialized URL (`http://localhost:3000/dashboard`
for `callbackURL: "/dashboard"`), never the string the request sent, and a redirect that
fails the check answers 403 instead. Better Auth runs the same checks
(`isSafeRelativeURL`) but sends relative targets back as they came; a browser lands in the
same place either way.

## Passwords

- **argon2id**, OWASP parameters (19 MiB, t=2, p=1), PHC string format so parameters can
  be raised later; hashes with old parameters are upgraded on the next successful sign-in.
- Hashing runs on a blocking pool **behind a semaphore** (default: number of CPUs).
  Without it, a burst of sign-in attempts would allocate 19 MiB each and could run the
  server out of memory.
- Unknown emails still hash a dummy password, so response time doesn't reveal which emails
  have accounts. When `require_email_verification` is on, sign-up for an existing email
  answers like a successful sign-up (no session, a user that isn't stored) and sends no
  email, so sign-up can't be used to discover accounts either. Without it, sign-up answers
  422 `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL`, as Better Auth does.
- Length: 8 to 128 by default. The maximum bounds the work per request.
- A password reset signs the user out everywhere by default
  (`revoke_sessions_on_password_reset`, also used by email OTP's reset), because a reset is
  how an owner recovers from a compromise and must end the attacker's sessions too. Better
  Auth leaves them signed in unless `revokeSessionsOnPasswordReset` is set;
  `.revoke_sessions_on_password_reset(false)` gets that behaviour back.
- `PasswordHasher` is a trait, set with `EmailPassword::hasher(..)`. Verifying scrypt hashes
  imported from a Better Auth database is [planned](../get-started/01-overview.md#planned).

## Verification values

Email verification, password reset and two-factor OTP values are random, single use,
short-lived (default 1 hour, 15 minutes for OTP), and stored hashed in `verification`.
Codes are compared in constant time (`subtle`). OTPs allow 5 attempts before the code is
burned. Each guess claims an attempt with a compare-and-swap on the stored counter before
the code is compared, and a guess that loses the swap tries again, so concurrent guesses
are counted one by one and can't try more than 5 codes.

## Two-factor sign-in

A sign-in that two-factor challenges is stored server-side as a `verification` row, and the
`two_factor` cookie only names it (signed, as every cookie). The row allows 5 guesses in all
across TOTP, emailed and backup codes, counted the same way as OTP attempts; after that it
is deleted, the cookie is cleared, and the next guess answers 400
`TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE`, so the user signs in with their password again. A
correct code deletes the row before the session is created, so a copy of the cookie can't
finish the sign-in a second time. The row expires with `two_factor_cookie_max_age` (10
minutes by default). Better Auth also caps attempts per challenge; it doesn't cap TOTP
guesses for a signed-in user, and neither does fastauth beyond the rate limit.

A user has at most one `two_factor` row: `two_factor.user_id` is unique, and
`/two-factor/enable` replaces the old secret in a transaction that locks the user's row
first. Without that, two enables at once could leave two secrets, and the one the user's app
was set up with might not be the one sign-in checks. Better Auth has no such constraint.

## Account enumeration

Routes that take an email and must not reveal whether it has an account answer the same
way either way: `/request-password-reset` (and `/forget-password`),
`/send-verification-email`, `/sign-up/email` with `require_email_verification`, and email
OTP's `send-verification-otp` and `request-password-reset`. They also take the same time:

- The email is sent in the background (tokio's blocking pool), so the response never waits
  for the mailer. A real SMTP or HTTP mail API call takes 100 ms or more, enough to tell a
  known email from an unknown one in a single request if the route waited for it, as it
  did before 0.4. Like Better Auth's `runInBackgroundOrAwait`, except that fastauth always
  sends in the background. A send that fails is logged with `tracing::error!`, since the
  client already has its answer; emails still in flight when the process exits are lost.
- The branch that sends nothing does the database work of the branch that does: a
  verification-table lookup for an unknown email on reset and verification, as Better Auth
  does, and email OTP issues and discards a code.

`LogMailer` and `MemoryMailer` do no I/O, so they still send before the response.

## Claiming an email

Anyone can sign up with an address they don't own: nothing proves the mailbox until a link or
code sent to it comes back. So whoever proves control of an email becomes the only owner of
its user, on every path that proves one:

- a magic link, and an email code that signs in or resets a password;
- `/reset-password` with a link from `/request-password-reset` (the link was mailed to the
  address, so it proves the mailbox like a magic link does);
- a social sign-in or link where the provider verified the email;
- `/verify-email` and `/email-otp/verify-email`, unless the request also proves it holds the
  password (below).

When one of these lands on a user whose email isn't verified, core claims the user in **one
database transaction**. It changes the user's security stamp, marks the email verified, and
deletes every account (the password and every OAuth link), every session, the user's
verification and reset links, and whatever each plugin registered with
[`on_claim`](../reference/01-plugin-authoring.md#claiming-a-user): passkeys, API keys, the
two-factor enrollment (TOTP secret, backup codes, so trusted-device cookies stop matching)
and a sign-in waiting at the two-factor step. If any of it fails, nothing is committed and the
request fails, so the next proof claims the user again. The `UserClaimed` event is sent after
the commit, for notifications only.

**The security stamp.** `user.security_stamp` is a random number, never sent to clients,
that every claim changes. A sign-in reads it with the user before checking the password, code
or passkey, and the session is only kept if the stamp is still the same once it exists
(a locking check that waits for a claim in progress). The same holds for a pending two-factor
sign-in, an OAuth callback, and links to reset a password or verify an email, which carry the
stamp and the address they were sent to. So a sign-in that started before a claim can't finish
after it, and a reset or verification link dies when the user is claimed or changes email.

**Verification links.** A verification link proves the mailbox, but not that the person who
opens it set the password. When the request also carries the user's session, or the signed
`pending_verification` cookie that sign-up (and a sign-in refused with `EMAIL_NOT_VERIFIED`)
leaves in the browser that knew the password, the email is just marked verified. Otherwise
the link claims the user: the password is deleted with everything else, and the owner signs
in with a magic link or code, or sets a password with a reset. Without this, someone who signed
up with your address first would sign in to your account with their password as soon as you
verified it.

**Stricter than Better Auth.** Better Auth 1.7.28 marks the email verified on these paths and
keeps everything else: the first registrant's password (verify-email), their passkeys, API
keys, two-factor and OAuth links (reset-password, verify-email), and a sign-in that is in
flight. fastauth's claim covers all of them. What an app notices:

- Opening a verification link in another browser than the one that signed up, while signed
  out, deletes the password. The owner then uses a magic link, an email code, or a reset.
- `/reset-password` on an unverified user verifies the email, deletes the user's other
  accounts, passkeys, API keys and two-factor, and signs them out everywhere, even with
  `revoke_sessions_on_password_reset(false)`.
- A sign-in that was checking the password while the user was claimed answers 401
  `UNAUTHORIZED` instead of a session.

**Not covered.** JWTs issued before a claim stay valid until they expire (15 minutes by
default), and organization memberships and invitations of the claimed user are kept.

## OAuth

- `state` and PKCE (S256) on every provider, including ones that don't require PKCE.
- State is stored hashed in `verification` with a 10-minute TTL and bound to a signed
  cookie, so a callback only completes in the browser that started it.
- Profiles come from the provider's API over TLS with the fresh access token (Google's
  OpenID Connect userinfo endpoint, GitHub's `/user` and `/user/emails`), so no `id_token`
  is trusted yet. Verifying `id_token`s against the provider's JWKS (cached, refreshed on
  unknown `kid`, checking `nonce`, `aud`, `iss` and expiry) arrives with the generic OIDC
  provider.
- Provider access and refresh tokens are stored encrypted (XChaCha20-Poly1305).
- Accounts link by email only when the provider reports the email as verified and linking
  isn't turned off (`AccountLinking::Off`).
- `/link-social` links a provider account to the signed-in user only when the session that
  started the link is still live when the provider sends the browser back, linking isn't
  `AccountLinking::Off`, and the provider verified the email (else
  `?error=unable_to_link_account`), and when the provider's email is the user's, ignoring
  case (else `?error=email_doesn't_match`, unless `Social::allow_different_emails(true)`).
  These are Better Auth's `linkOAuthAccount` checks. Better Auth also links an unverified
  email from a provider on its `trustedProviders` list; fastauth has no such list.
- A token response's `expires_in` and `refresh_token_expires_in` are clamped to 10 years,
  and negative values are ignored, so a broken or hostile token endpoint can't crash the
  callback.
- Linking to a user whose email was never verified claims it ([Claiming an email](#claiming-an-email)):
  the social account is linked in the same transaction that deletes the user's other accounts,
  sessions and plugin credentials, so the person who proved the email through the provider is
  the only one who can sign in. A legitimate owner who never verified their email loses their
  password and can set a new one with a password reset.

## Bearer tokens and JWTs

- With the [bearer plugin](../plugins/tokens/01-bearer.md), every response that sets the session cookie also
  returns the signed session token in `set-auth-token`, readable by page scripts. The cookie
  stays `HttpOnly`, but an XSS on your origin (or on an origin your CORS config allows with
  credentials) can read the token from that header. Register `Bearer` only for apps whose
  clients need it. Better Auth behaves the same.
- [JWTs](../plugins/tokens/02-jwt.md): `JwksVerifier` and `auth.jwt().verify()` check `nbf` as well as `exp`,
  `iss` and `aud`. Server-side `verify` uses only the keys `/jwks` publishes, so a retired
  key stops verifying when its grace period ends, and `rotate()` deletes keys past it.
  Better Auth's `verifyJWT` trusts every stored key.
- `VerifyError::UnknownKey` comes from the token's unauthenticated header, so anyone can
  trigger it. A resource server that refetches the JWKS on it should do so at most once per
  cool-down (30 seconds or more). A token without a `kid` is `Invalid`.

## Rate limiting

On by default: 100 requests per 10 seconds per IP and path, and 3 per 10 seconds on
`/sign-in/*`, `/sign-up/*`, `/forget-password`, `/request-password-reset`,
`/send-verification-email` and `/change-password`. Two-factor adds 5 a minute on
`/two-factor/verify-*`, and 3 per 10 seconds on the routes that confirm the password
(`/two-factor/enable`, `/disable`, `/get-totp-uri`, `/generate-backup-codes`), so a stolen
session can't guess the password faster than sign-in allows. The
limiter is GCRA (one timestamp per key, no sliding-window bookkeeping) in a sharded
in-memory map, so each process counts on its own; a shared store is
[planned](../get-started/01-overview.md#planned). Exceeding a limit returns `429 TOO_MANY_REQUESTS`.

**The client IP** decides whose limit a request counts against, so it must be one the
client can't choose ([Configuration](../get-started/03-configuration.md#rate-limits)):

- `ClientIp::Socket` (the default) needs the integration to pass the socket address; in
  axum, serve with `into_make_service_with_connect_info::<SocketAddr>()`.
- Behind a proxy, `ClientIp::Header` for a header holding one address that the proxy
  overwrites, or `ClientIp::TrustedProxies { header, proxies }` for `x-forwarded-for`, which
  takes the `proxies`-th address from the right. **Never `ClientIp::Header("x-forwarded-for")`**:
  its first value is whatever the client sent. A header value that isn't a valid IP counts
  as no IP, so a client can't invent one.
- A request without a client IP is logged once (`tracing::warn!`). It is limited per account
  when its JSON body names one (`email` or `username`), and otherwise shares one bucket with
  every other request without an IP. Better Auth puts all of them in one shared bucket, where
  three wrong passwords from anyone lock everyone out of sign-in; fastauth keeps the limit on
  each account instead, so only guesses at the same account count against it.

## The database

Uniqueness that matters for security is a database constraint, not only a check before an
insert, so two requests at once can't both pass the check:

- `user.email` (stored lowercased), `user.username` (normalized, username plugin),
  `organization.slug`, `passkey.credential_id`, and every token, code and key hash.
- `account (provider_id, account_id)`: one provider account belongs to one user. A second
  link answers 409 `SOCIAL_ACCOUNT_ALREADY_LINKED`.
- `member (organization_id, user_id)`: one membership per user and organization. Two
  accepts or adds at once leave one row, and the other answers
  `USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION`. Removing a member removes them.
- `two_factor.user_id`: one TOTP secret per user.

Better Auth enforces none of the last three in its schema. A database made by fastauth 0.5
or earlier gets them on its next migration, which refuses to run while duplicates exist and
names them; [Unique constraints on an existing database](02-database.md#unique-constraints-on-an-existing-database)
has the queries that fix them.

Limits counted before an insert are counted inside a transaction that first locks the
user's row: the organization plugin's `organization_limit`, so parallel creates can't each
see room for one more. On Postgres and MySQL the second request waits for the first; SQLite
runs one write transaction at a time anyway.

In production:

- **Use TLS to the database, and check the certificate.** sqlx's default for MySQL is
  `ssl-mode=preferred` and for Postgres `sslmode=prefer`: TLS when the server offers it, no
  certificate check, and plain text when it doesn't. Put `ssl-mode=verify_identity` (MySQL)
  or `sslmode=verify-full` (Postgres) in `DATABASE_URL` unless the database is on the
  same host. [MySQL](02-database.md#mysql) has examples.
- **MySQL 8 only.** MariaDB isn't supported (it lacks `utf8mb4_0900_bin`); the first
  migration fails on it rather than running with different comparison rules.
- **Keep MySQL's `sql_mode` strict** (the default), so a value too long for a key column is
  an error and not cut short into another value's key.
- **UUID ids compare as UUIDs on Postgres and MySQL.** Under a UUID id strategy, other
  spellings of the same UUID (uppercase, no hyphens, braces) find the same row there, while
  SQLite stores ids as text and compares them exactly. The admin plugin's "not yourself"
  checks (banning or removing your own user) compare the requested id with the caller's as
  strings, so on Postgres and MySQL an admin can get past them by spelling their own id
  differently; that only reaches their own account. If your own code compares an id from a
  client with an `Id`, compare the id the database returned instead.

## What fastauth doesn't do for you

- **TLS.** Terminate it in front of the app; set `base_url` to https so cookies get `Secure`.
- **Account enumeration via other routes.** If your own `/users/:email` endpoint answers
  differently for unknown emails, the sign-in timing work above doesn't help.
- **Bot protection.** There's no CAPTCHA plugin yet; a [sign-in gate](../reference/01-plugin-authoring.md#sign-in-gates)
  or a before hook on sign-up is where one would go.
