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

**Rotation.** `.secrets([new, old])`: the first secret signs, verifies and encrypts.
Every secret in the list still decrypts, and still verifies a signed session token
(`Keys::verify_token`). A session token only points to a session row, so a retired secret
can't forge one, and a rotation signs nobody out.

A retired secret verifies nothing else. Values that carry their own meaning are accepted
only when the current secret signed them: the cookie cache, two-factor trusted-device
cookies, and any other cookie a plugin reads with `Ctx::signed_cookie` (a plugin cookie
that holds a session token uses `Ctx::signed_token_cookie` instead). Right after a
rotation:

- cookie caches signed with the old secret are ignored, so the next request reads the
  session from the database and caches it again;
- trusted devices ask for the second factor once more;
- a sign-in in flight that holds a short-lived signed cookie (OAuth state, a passkey
  challenge, a pending two-factor sign-in, minutes at most) has to start again.

So a leaked secret, once rotated out, can no longer sign a cookie cache, which would
otherwise let its holder act as any user without a session row.

Encrypted values carry a one-byte key id, so values encrypted under an old secret still
decrypt. Encrypted columns (OAuth tokens, two-factor secrets) keep needing the old secret:
there is no re-encryption command yet, so keep it in the list until those rows are
rewritten. A leaked secret still decrypts the values written under it.

## Checks at build time

`.build()` refuses configuration that is unsafe in production:

- **Always:** a `base_url` with credentials (`https://user:pw@..`), a query or a fragment.
  Emailed links are built from `base_url`, so each of these would break them.
- **When `base_url` isn't local:** an `http://` `base_url`, since cookies would go out
  without `Secure`, and a secret with less than `Secret::MIN_ENTROPY_BITS` (120) bits of
  estimated entropy. The estimate (`Secret::entropy_bits`) is the length times log2 of the
  number of distinct bytes: a secret from `fastauth secret` scores about 370, 32 zero bytes
  score 0.

Local means `localhost`, `*.localhost` or a loopback address; there both problems are only
logged as warnings. `Builder::allow_insecure_config(true)` does the same for any host, for
local development, CI and staging on a private network. Never set it in production. Better
Auth only warns about a weak secret and doesn't check an `http://` `base_url`, so fastauth
is stricter here.

A wrong client IP setting can't be caught here: the socket address only exists per
request. fastauth logs the first request without a client IP instead, as an error when
`base_url` isn't local and `allow_insecure_config` is off ([Rate limiting](#rate-limiting)).

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

Every response from the auth routes carries `Cache-Control: no-store` unless the endpoint
set its own, so a shared cache or CDN never stores `/get-session` or a response holding a
session token. Better Auth sets it on `/get-session`.

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
- **Credentials need a stored, authoritative session.** Creating or updating an API key,
  registering a passkey, `/link-social` and turning two-factor on or off use
  `ctx.sensitive_session()`: the session is read again from the database, skipping the cookie
  cache, so a revoked session gets `401`; an API key's session has nothing stored and gets
  `401`; and the admin plugin refuses impersonation sessions with
  `403 NOT_ALLOWED_WHILE_IMPERSONATING`. So a leaked key, a support agent or a stolen cookie
  can't turn into a lasting credential.
- **Impersonation stays short.** The admin plugin marks impersonation sessions with
  `PluginBuilder::fixed_session_expiry`, so the refresh never extends them and they end after
  `impersonation_session_duration`.
- **Admins can't take each other over.** Acting on another admin's account (password, email,
  role, ban, removal, sessions) needs `user:impersonate-admins`
  ([Admin](../plugins/access/02-admin.md#endpoints)).

Better Auth checks bans only when a session is created, lets a key's session create keys,
and doesn't stop impersonation sessions from minting credentials, so fastauth is stricter
here. Its passkey registration and API-key creation also read the session from the database.

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

## Email addresses

Every route that takes an email (core, admin, organization invitations, and plugins that
call `routes::normalize_email`) trims and lowercases it, then accepts only one plain
address, with the rules of Better Auth's `z.email()`:

- a local part of letters, digits and `_'+-.`, not starting with a dot, without `..`, and
  not ending in `.` or `'`;
- a domain of labels made of letters, digits and `-`, ending in a top-level domain of two
  or more letters.

So address lists, spaces, control characters, quotes, a second `@` and non-ASCII addresses
answer `400 INVALID_EMAIL`, and a mailer never gets a `To` it could split into several
recipients.

## Verification values

Email verification, password reset and two-factor OTP values are random, single use,
short-lived (default 1 hour, 15 minutes for OTP), and stored hashed in `verification`.
Codes are compared in constant time (`subtle`). OTPs allow 5 attempts before the code is
burned. Each guess claims an attempt with a compare-and-swap on the stored counter before
the code is compared, and a guess that loses the swap tries again, so concurrent guesses
are counted one by one and can't try more than 5 codes.

Storing a new verification value first deletes every expired one, so the rows anyone can
create (OAuth states, passkey challenges, magic links) don't pile up. Better Auth cleans up
the same way when it looks one up.

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
- Background sends are bounded, because password hashing runs on the same blocking pool:
  at most 8 run at once per process, up to 10,000 more wait, and past that an email is
  dropped and logged. A send that takes longer than 60 seconds is abandoned and logged;
  the timeout fires when the mailer's future yields, so a mailer that blocks its thread
  isn't cut off. A slow SMTP server delays email but can't starve sign-in.
- The branch that sends nothing does the database work of the branch that does: a
  verification-table lookup for an unknown email on reset and verification, as Better Auth
  does, and email OTP issues and discards a code.

`LogMailer` and `MemoryMailer` do no I/O, so they still send before the response.

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
- Linking to a user whose email was never verified closes the pre-registration attack (someone
  signs up with your email and a password before you first sign in with Google). In one
  transaction, the user's `credential` account is deleted, all of the user's sessions are
  revoked, the email is marked verified, and the social account is linked. The person who
  proved the email through the provider ends up as the only one who can sign in. A legitimate
  owner who never verified their email loses their password and can set a new one with a
  password reset.

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

- **IPv6 clients are limited per /64** by default, as Better Auth's `ipv6Subnet` does: a
  home connection or a cloud VM gets a whole /64, so per-address limits wouldn't limit it.
  `RateLimit::ipv6_prefix(bits)` changes the prefix; 128 limits each address on its own.
  IPv4-mapped IPv6 addresses count as IPv4.
- **Each account has a limit too.** On every route with a rule of its own (core's strict
  routes, the plugins' rules and yours, not the default limit), each account the JSON body
  names, its `email` and its `username`, gets 30 requests per 10 minutes per rule,
  whatever the client IP. So guesses at one password spread over many addresses still
  stop. `RateLimit::account_limit(Some(Limit::per(..)))` changes it and `None` turns it
  off. Better Auth has no per-account limit, so fastauth is stricter here.
- **Memory is bounded.** The limiter keeps at most `RateLimit::max_keys(n)` keys (100,000
  by default). Each shard drops its expired keys every 1024 checks and when it's full, and
  if it's still full, the half of its keys closest to expiry. Account names are kept as a keyed 64-bit
  hash, never the value from the body, so a long `email` costs no memory.

**The client IP** decides whose limit a request counts against, so it must be one the
client can't choose ([Configuration](../get-started/03-configuration.md#rate-limits)):

- `ClientIp::Socket` (the default) needs the integration to pass the socket address; in
  axum, serve with `into_make_service_with_connect_info::<SocketAddr>()`.
- Behind a proxy, `ClientIp::Header` for a header holding one address that the proxy
  overwrites, or `ClientIp::TrustedProxies { header, proxies }` for `x-forwarded-for`, which
  takes the `proxies`-th address from the right. **Never `ClientIp::Header("x-forwarded-for")`**:
  its first value is whatever the client sent. A header value that isn't a valid IP counts
  as no IP, so a client can't invent one.
- A request without a client IP is logged once: with `tracing::error!` when `base_url`
  isn't local and `allow_insecure_config` is off, else with `tracing::warn!`. `.build()`
  can't check the setting, because the socket address only exists per request. The request
  is limited per account when its JSON body names one, on its `email` and on its
  `username` when it has both, so a junk `email` doesn't buy a fresh bucket for username
  guesses. Without either it shares one bucket with every other request without an IP.
  Better Auth puts all of them in one shared bucket, where three wrong passwords from anyone
  lock everyone out of sign-in; fastauth keeps the limit on each account instead, so only
  guesses at the same account count against it.

## Logs

`Debug` output never shows a secret value: `VerifyEmail` and `ResetPassword` print
`[redacted]` for the link and token, `PluginEmail` for the text, link and code, and
`SessionView` for the session token. Logging request bodies or cookie headers yourself
still puts passwords and tokens in your logs.

## What fastauth doesn't do for you

[Production checklist](../reference/04-production-checklist.md) lists what to set before real
users.

- **TLS.** Terminate it in front of the app; set `base_url` to https so cookies get `Secure`.
  Connect to the database over TLS that checks the certificate as well
  ([Databases](02-database.md#mysql)).
- **Account enumeration via other routes.** If your own `/users/:email` endpoint answers
  differently for unknown emails, the sign-in timing work above doesn't help.
- **Bot protection.** There's no CAPTCHA plugin yet; a [sign-in gate](../reference/01-plugin-authoring.md#sign-in-gates)
  or a before hook on sign-up is where one would go.
