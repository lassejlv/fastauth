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
| Field encryption | `fastauth/v1/encrypt` | XChaCha20-Poly1305 for `Encrypted<T>` columns |
| Plugin keys | `fastauth/v1/plugin/{id}` | `ctx.derive_key()` inside a plugin |

So a bug that leaks one derived key doesn't expose the others, and plugins can't reach
core's keys.

**Rotation.** `.secrets([new, old])`: the first signs and encrypts, all verify and
decrypt. Encrypted values carry a one-byte key id, so `fastauth reencrypt` can rewrite old
rows in the background. After one session lifetime (7 days by default), drop the old secret.

## Session tokens

- 32 bytes from the OS CSPRNG, base64url (43 characters).
- The database stores `SHA-256(token)`, not the token. A read-only database leak (a backup,
  a SQL injection elsewhere in the app) can't be turned into live sessions. A plain hash
  is enough because the token has 256 bits of entropy, so nobody can brute-force it.
- The cookie holds `token.signature`. Checking the HMAC first rejects forged or mangled
  cookies without a database query.

This differs from Better Auth, which stores tokens as they are. See
[Open questions](10-open-questions.md#3-hashed-session-tokens) for the migration impact.

## Cookies

| Attribute | Default |
|---|---|
| `HttpOnly` | always |
| `Secure` and `__Secure-` prefix | when `base_url` is https |
| `SameSite` | `Lax` |
| `Path` | `/` |
| `Max-Age` | session expiry; refreshed with the session |

## CSRF

`SameSite=Lax` already blocks cross-site `POST`s from carrying the cookie in current
browsers. On top of that, every non-`GET` request that carries a session cookie must send an
`Origin` (or, failing that, `Referer`) matching `base_url` or a trusted origin. Callback URLs
(`callbackURL`, `redirectTo`) are checked against the same list, which closes open redirects.

## Passwords

- **argon2id**, OWASP parameters (19 MiB, t=2, p=1), PHC string format so parameters can
  be raised later; hashes with old parameters are upgraded on the next successful sign-in.
- Hashing runs on a blocking pool **behind a semaphore** (default: number of CPUs).
  Without it, a burst of sign-in attempts would allocate 19 MiB each and could run the
  server out of memory.
- Unknown emails still hash a dummy password, so response time doesn't reveal which emails
  have accounts. Sign-up for an existing email returns the same response as success when
  `require_email_verification` is on, and emails the owner instead.
- Length: 8 to 128 by default. The maximum bounds the work per request.
- `PasswordHasher` is a trait. `Scrypt::better_auth_compat()` (feature `scrypt`) verifies
  hashes imported from a Better Auth database and rehashes them with argon2id on sign-in.

## Verification values

Email verification, password reset, magic link and OTP values are random, single use,
short-lived (default 1 hour, 15 minutes for OTP), and stored hashed in `verification`.
Codes are compared in constant time (`subtle`). OTPs allow 5 attempts before the code is
burned.

## OAuth

- `state` and PKCE (S256) on every provider, including ones that don't require PKCE.
- State is stored hashed in `verification` with a 10-minute TTL and bound to a signed
  cookie, so a callback only completes in the browser that started it.
- OIDC `id_token`s are verified against the provider's JWKS (cached, refreshed on unknown
  `kid`), including `nonce`, `aud`, `iss` and expiry.
- Provider access and refresh tokens are stored as `Encrypted<String>`.
- Accounts link by email only when the provider reports the email as verified and linking
  is allowed for that provider.

## Rate limiting

On by default: 100 requests per 10 seconds per IP and path, and 3 per 10 seconds on
`/sign-in/*`, `/sign-up/*`, `/forget-password` and `/request-password-reset`. The limiter is
GCRA (one timestamp per key, no sliding-window bookkeeping) in a sharded in-memory map, or in
secondary storage when you run more than one instance. Exceeding a limit returns `429` with
`Retry-After`.

## What fastauth doesn't do for you

- **TLS.** Terminate it in front of the app; set `base_url` to https so cookies get `Secure`.
- **Account enumeration via other routes.** If your own `/users/:email` endpoint answers
  differently for unknown emails, the sign-in timing work above doesn't help.
- **Bot protection.** A CAPTCHA plugin (Turnstile, hCaptcha) gates sign-up and sign-in, but
  isn't on by default.
