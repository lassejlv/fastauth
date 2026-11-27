# Migrating from Better Auth

fastauth can run next to a Better Auth app on the same database while you move traffic over in
phases. Both apps accept each other's sign-ins: a user who signs in on one is signed in on the
other, a sign-out or password change on one counts on both, and either app can extend a
session. This page covers the part that makes sign-ins portable: cookies, session refresh and
password hashes.

Everything here is opt-in. Without it fastauth keeps its own cookie format, refresh rule and
argon2id hashes. The mode relaxes some of fastauth's defaults on purpose, for the migration
window only; [Trade-offs](#trade-offs) lists each one.

Tested against the code Better Auth 1.7.8 runs:

| Package | Version | Used for |
|---|---|---|
| `better-auth` | 1.7.8 | session lookup and refresh, cookie names, secrets |
| `better-call` | 1.4.2 | signing, parsing and verifying cookies |
| `@better-auth/utils` | 0.5.0 | `hashPassword` and `verifyPassword` (`/password`) |

## Turning it on

`.better_auth_compat(..)` sets everything at once:

```rust
pub fn build(pool: PgPool) -> Result<Auth<Sqlx<Postgres>>, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://api.example.com")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .better_auth_compat(BetterAuthCompat::from_env("BETTER_AUTH_SECRET")?.cookie_prefix("vt"))
        .build()
}
```

- `BetterAuthCompat::from_env("BETTER_AUTH_SECRET")` (or `::new(secret)`) takes the Better
  Auth app's secret as the app has it. Use the same value in both apps.
- `.cookie_prefix(..)` is the Better Auth app's `advanced.cookiePrefix` (default
  `"better-auth"`).
- `.expires_in(..)` and `.update_age(..)` are its `session.expiresIn` and
  `session.updateAge` (14 days and one day unless set).
- `.max_concurrent_hashes(n)` caps scrypt hashes running at once (8 unless set).

fastauth still needs its own `.secret(..)`: it keys everything that isn't a cookie (encrypted
columns, plugin keys, rate-limit buckets), through HKDF as always.

The preset is applied at `.build()` and overrides the cookie prefix, cookie signing, session
expiry and refresh, and the password hasher. Each piece is also a knob of its own:

| Knob | Does |
|---|---|
| `CookieConfig::signing(CookieSigning::better_auth(secret))` | [Cookies](#cookies) in Better Auth's format |
| `SessionConfig::sliding_refresh(SlidingRefresh::ExpiresAt)` | [Better Auth's refresh rule](#session-refresh) |
| `EmailPassword::hasher(BetterAuthScrypt)` | [Better Auth's password hashes](#passwords) |
| `EmailPassword::max_concurrent_hashes(n)` | at most `n` hashes at once |

## Cookies

With `CookieSigning::BetterAuth`, fastauth signs and reads cookies exactly as better-call 1.4.2
does:

- **Name:** `{prefix}.session_token`, with `__Secure-` in front when `base_url` is https,
  which is also when Better Auth adds it. `HttpOnly`, `SameSite=Lax`, `Path=/`, and `Secure`
  on https, as in Better Auth.
- **Value:** `encodeURIComponent(token + "." + signature)`, where the signature is
  HMAC-SHA256 of the token in standard base64 with padding (44 characters). The HMAC key is
  the secret's UTF-8 bytes, with no key derivation.
- **Reading:** surrounding whitespace and one pair of quotes are dropped, a value holding a
  `%` is percent-decoded (and kept as it came when it isn't valid percent-encoding), and the
  value before the last `.` counts when it isn't empty, the signature after it is 44
  characters ending in `=`, and the HMAC matches. The HMAC is compared in constant time. So
  a cookie is accepted percent-encoded or not, and when a request carries the same cookie
  twice, the first one counts.

The same format covers every cookie fastauth signs: the `dont_remember` marker of a
`rememberMe: false` sign-in and the multi-session device cookies, which Better Auth reads too,
and plugin cookies such as the two-factor and impersonation ones.

**The secret is used as it is.** `BetterAuthCompat::from_env` reads the variable's bytes.
Don't load it with `Secret::from_env`: that decodes a value that happens to be valid base64url
(a 64-character hex secret is), so the key would differ from Better Auth's. `.build()` refuses
an empty Better Auth secret, and, when `base_url` isn't local, one shorter than 32 bytes or
with less than about 120 bits of estimated entropy, as for fastauth's own secret
([Security](../concepts/03-security.md#checks-at-build-time)). Better Auth only warns.

**Rotation.** Better Auth 1.7.8 signs and verifies cookies with its current secret alone
(`BETTER_AUTH_SECRET`, or the first entry of `secrets` / `BETTER_AUTH_SECRETS`); the versioned
`secrets` list only keys its encryption. fastauth matches that: one secret signs and verifies
cookies, so rotating it signs everyone out of both apps. Change it in both at once.
`.secrets([new, old])` still rotates fastauth's own keys.

**The cookie cache.** fastauth never reads or writes Better Auth's `session_data` cookie, and
`.build()` refuses `SessionConfig::cookie_cache` together with Better Auth cookies. The two
caches share a name but not a format; reading Better Auth's means trusting a payload signed
with the shared raw secret and rebuilding the session from a JSON copy of the rows, which
fastauth's cache doesn't do, and a cache cookie in fastauth's format would only be deleted by
Better Auth. When Better Auth's own cache is on:

- fastauth's sign-out deletes `session_data` with the session cookies, as Better Auth's does;
- Better Auth binds its cache to the session token and drops it when the token changes, so a
  sign-in on fastauth doesn't leave a stale cache;
- a session that fastauth revokes elsewhere (a password change, `/revoke-sessions`) keeps
  working in the Better Auth app wherever a cache is set, until the cache's `maxAge` (5
  minutes by default). Keep Better Auth's `session.cookieCache` off or short during the
  migration.

## Session refresh

Both apps extend a session to its full lifetime from now once it's older than `update_age`
since its last extension, and set the cookie's `Max-Age` again:

- **Numbers.** `BetterAuthCompat` uses a 14-day lifetime and a one-day `update_age`. Better
  Auth's own defaults are 7 days and one day, so set `.expires_in(..)` to the Better Auth
  app's `session.expiresIn`. When they differ, each app extends sessions to its own lifetime.
- **Rule.** `SlidingRefresh::ExpiresAt` is Better Auth's: a session is due when
  `expires_at - expires_in + update_age <= now`. fastauth's default counts from
  `updated_at`, but Better Auth moves `updatedAt` on every change to a session row (an
  active organization, say), so on a shared database it doesn't say when the session was last
  extended. Concurrent refreshes still extend a session once: the update is conditional on the
  `expires_at` it read.
- **`rememberMe: false`.** Neither app extends a session the user asked not to remember.
  Better Auth tells by the `dont_remember` cookie; fastauth reads that cookie too, and also
  treats a session that was created to last a day or less (`expires_at - created_at`) as one,
  so a request without the marker (a bearer token) can't extend it either.

Finding a Better Auth session by the token in its cookie also needs fastauth to store and
look up session tokens the way Better Auth does (the plain token in `session.token`). That's
a database setting; without it the cookie verifies but fastauth finds no session.

## Passwords

`BetterAuthScrypt` verifies and writes Better Auth's hashes, stored in `account.password` on the
`credential` account:

- **Format:** `"<salt>:<key>"`. The salt is 16 random bytes as 32 lowercase hex characters,
  the key 64 bytes as lowercase hex.
- **Key:** scrypt with N = 16384, r = 16, p = 1 and a 64-byte output, of the password after
  NFKC normalization (so `ﬁ` and `fi`, or a full-width and an ASCII password, are the same
  password), salted with the salt's hex string as UTF-8, not the 16 bytes it encodes.
- **Checking:** like Better Auth, the first two `:`-separated parts are the salt and the key
  (anything after them is ignored), the key must equal the derived key's lowercase hex, and a
  hash without both parts is an error. The comparison is constant-time.
- **New hashes** use the same format, and `needs_rehash` is always false, so a rollback to
  Better Auth loses nobody's password.

Each hash takes 32 MiB of memory (128 · N · r), against argon2id's 19 MiB, and runs on
fastauth's bounded hashing pool ([Security](../concepts/03-security.md#passwords)): a burst
of sign-ins waits for a permit instead of allocating more. `BetterAuthCompat` allows 8 hashes
at once, or fewer on a machine with fewer CPUs, so at most 256 MiB. A hash keeps its permit
until it finishes, even when the request is dropped. With `EmailPassword::hasher(BetterAuthScrypt)`
on its own, set `.max_concurrent_hashes(n)` yourself; the default is one per CPU. The
parameters are fixed, so a stored hash can't ask for more work, and the password length limit
(128 by default, as in Better Auth) bounds the rest.

## Trade-offs

The mode gives up some of fastauth's defaults so a Better Auth app can share sessions and
passwords. Each is meant for the migration window only:

| fastauth by default | With Better Auth compatibility | What it costs |
|---|---|---|
| Cookies signed with a key derived from the secret by HKDF (`fastauth/v1/cookie`) | HMAC keyed with the raw Better Auth secret | The cookie key is the secret itself, and the Better Auth app holds it too: a leak from either app lets its holder sign session cookies (they still need a session token from the database to sign in). |
| Every configured secret verifies a session token, so rotating signs nobody out | One secret signs and verifies cookies | Rotating the Better Auth secret signs everyone out of both apps. |
| argon2id (19 MiB, t=2), upgraded when parameters rise | scrypt (32 MiB, N=16384, r=16), never rehashed | No upgrade path while Better Auth reads the database; scrypt with these parameters is weaker against GPU guessing than argon2id, and each hash takes more memory. |
| An optional signed cookie cache | Refused | One database read per request that resolves a session. |

Storing session tokens as they are, instead of their SHA-256, is a trade-off of the database
settings: with it, a read-only leak of the database yields live sessions.

## After the cutover

Once the Better Auth app is gone, the cookie settings can go back to fastauth's: removing
`CookieSigning::BetterAuth` (or the preset) changes the cookie format, so everyone signs in
again once. Keep `BetterAuthScrypt` until every password is in another format: argon2id can't
verify the scrypt hashes, and a hasher that verifies them and rehashes on the next sign-in
isn't built yet.

## Golden vectors

`compat/better-auth/run-vectors.sh` (part of `scripts/ci.sh --only compat`) checks both
directions:

- `compat/better-auth/vectors/better-auth.json` holds cookies signed by better-call 1.4.2 under
  three secrets (base64, hex and non-ASCII), for values that need percent-encoding, plus
  requests better-call accepts or refuses (unencoded, quoted, duplicated, tampered, wrong
  padding), and password hashes from `@better-auth/utils/password` 0.5.0, including NFKC
  cases (`ﬁ`, combining marks, full-width, half-width katakana), empty and long passwords.
  fastauth's tests verify every one and sign and hash each to the same bytes.
- `check.mjs` verifies fastauth's own values with Better Auth's code: the checked-in
  `vectors/fastauth.json` and a set the run makes fresh.

Regenerate the Better Auth side with `cd compat/better-auth/vectors && npm ci && node generate.mjs`.
