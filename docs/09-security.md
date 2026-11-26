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
[Decisions](10-open-questions.md#3-hashed-session-tokens) for the migration impact.

The same rule covers every other secret value fastauth stores: verification values,
OAuth state and [API keys](14-api-keys.md) are stored as hashes.

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
([API keys](14-api-keys.md#sessions-from-api-keys)), an admin's impersonation session, and a
session answered from the cookie cache after it was revoked. fastauth limits what they can do:

- **Bans and other session gates apply to every session.** Plugins register
  [session gates](05-plugins.md#session-gates) that run on every session a request uses
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
- **Impersonation stays short.** Session refresh only extends sessions created with the full
  `expires_in`, so an impersonation session ends after `impersonation_session_duration`.
- **Admins can't take each other over.** Acting on another admin's account (password, email,
  role, ban, removal, sessions) needs `user:impersonate-admins`
  ([Admin](13-admin.md#endpoints)).

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
`null`, as in Better Auth. Callback URLs
(`callbackURL`, `redirectTo`) are checked against the same list, which closes open redirects.

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
- `PasswordHasher` is a trait, set with `EmailPassword::hasher(..)`. Verifying scrypt hashes
  imported from a Better Auth database is [planned](01-overview.md#planned).

## Verification values

Email verification, password reset and two-factor OTP values are random, single use,
short-lived (default 1 hour, 15 minutes for OTP), and stored hashed in `verification`.
Codes are compared in constant time (`subtle`). OTPs allow 5 attempts before the code is
burned.

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
- Linking to a user whose email was never verified closes the pre-registration attack (someone
  signs up with your email and a password before you first sign in with Google). In one
  transaction, the user's `credential` account is deleted, all of the user's sessions are
  revoked, the email is marked verified, and the social account is linked. The person who
  proved the email through the provider ends up as the only one who can sign in. A legitimate
  owner who never verified their email loses their password and can set a new one with a
  password reset.

## Rate limiting

On by default: 100 requests per 10 seconds per IP and path, and 3 per 10 seconds on
`/sign-in/*`, `/sign-up/*`, `/forget-password`, `/request-password-reset` and
`/send-verification-email`. Two-factor adds 5 a minute on `/two-factor/verify-*`. The
limiter is GCRA (one timestamp per key, no sliding-window bookkeeping) in a sharded
in-memory map, so each process counts on its own; a shared store is
[planned](01-overview.md#planned). Exceeding a limit returns `429 TOO_MANY_REQUESTS`.

## What fastauth doesn't do for you

- **TLS.** Terminate it in front of the app; set `base_url` to https so cookies get `Secure`.
- **Account enumeration via other routes.** If your own `/users/:email` endpoint answers
  differently for unknown emails, the sign-in timing work above doesn't help.
- **Bot protection.** There's no CAPTCHA plugin yet; a [sign-in gate](05-plugins.md#sign-in-gates)
  or a before hook on sign-up is where one would go.
