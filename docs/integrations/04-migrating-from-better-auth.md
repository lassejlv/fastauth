# Migrating from Better Auth

fastauth can run next to a Better Auth app on the same database while you move traffic over in
phases. Both apps accept each other's sign-ins: a user who signs in on one is signed in on the
other, a sign-out or password change on one counts on both, and either app can extend a
session. This page covers what makes sign-ins portable (cookies, session refresh and password
hashes) and the database settings that let both apps use the same tables (column names,
session storage, accounts another app owns, migrations and verification rows).

Everything here is opt-in. Without it fastauth keeps its own cookie format, refresh rule and
argon2id hashes. The mode relaxes some of fastauth's defaults on purpose, for the migration
window only; [Trade-offs](#trade-offs) lists each one.

Tested against the code Better Auth 1.7.8 runs:

| Package | Version | Used for |
|---|---|---|
| `better-auth` | 1.7.8 | session lookup and refresh, cookie names, secrets |
| `better-call` | 1.4.2 | signing, parsing and verifying cookies |
| `@better-auth/utils` | 0.5.0 | `hashPassword` and `verifyPassword` (`/password`) |
| `auth` (Better Auth's CLI) | 1.7.8 | the schema on Postgres, MySQL and SQLite (`crates/fastauth-sqlx/tests/better-auth/`) |

## Turning it on

`.better_auth_compat(..)` sets everything at once:

```rust
pub fn build(pool: PgPool) -> Result<Auth<Sqlx<Postgres>>, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://api.example.com")
        .database(Sqlx::new(pool).rename("verification", "fastauth_verification"))
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

- `.rename("verification", "fastauth_verification")` on the adapter gives fastauth's
  verification rows a table of their own ([Verification rows](#verification-rows)); the
  preset can't set it, since table names belong to the adapter.

fastauth still needs its own `.secret(..)`: it keys everything that isn't a cookie (encrypted
columns, plugin keys, rate-limit buckets), through HKDF as always.

The preset is applied at `.build()` and overrides the cookie prefix, cookie signing, session
expiry and refresh, the password hasher and the [database settings](#database-settings).
Each piece is also a knob of its own:

| Knob | Does |
|---|---|
| `CookieConfig::signing(CookieSigning::better_auth(secret))` | [Cookies](#cookies) in Better Auth's format |
| `SessionConfig::sliding_refresh(SlidingRefresh::ExpiresAt)` | [Better Auth's refresh rule](#session-refresh) |
| `EmailPassword::hasher(BetterAuthScrypt)` | [Better Auth's password hashes](#passwords) |
| `EmailPassword::max_concurrent_hashes(n)` | at most `n` hashes at once |
| `Builder::column_naming`, `rename_column`, `bytes_as_hex_text` | [Better Auth's column names](#database-settings) |
| `Builder::session_tokens(SessionTokens::Raw)` | [raw session tokens](#database-settings) |
| `Builder::only_owned_accounts(true)` | [accounts another app owns](#accounts-another-app-owns) |
| `Builder::migrations(Migrations::ReviewOnly)` | [review-only migrations](#the-schema) |

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
look up session tokens the way Better Auth does, the plain token in `session.token`:
`SessionTokens::Raw`, which the preset sets ([Database settings](#database-settings)).

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

## Database settings

The preset sets these; without it, set them one by one:

```rust
use fastauth::config::SessionTokens;
use fastauth::migrate::Migrations;
use fastauth::prelude::*;
use fastauth::schema::ColumnNaming;
use serde::{Deserialize, Serialize};

/// The app's own Better Auth field, `customerId`.
#[derive(Fields, Serialize, Deserialize, Clone, Debug)]
pub struct Customer {
    pub customer_id: Option<String>,
}

pub fn build(pool: PgPool) -> anyhow::Result<Auth<Sqlx<Postgres>, Customer>> {
    Ok(FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        // fastauth's verification rows get a table of their own; see below.
        .database(Sqlx::new(pool).rename("verification", "fastauth_verification"))
        .user_fields::<Customer>()
        .column_naming(ColumnNaming::CamelCase)
        .rename_column("account", "password_hash", "password")
        .bytes_as_hex_text("account", "access_token")
        .bytes_as_hex_text("account", "refresh_token")
        .session_tokens(SessionTokens::Raw)
        .only_owned_accounts(true)
        .migrations(Migrations::ReviewOnly)
        .email_password(EmailPassword::default())
        .build()?)
}
```

| Setting | What it does |
|---|---|
| `.column_naming(ColumnNaming::CamelCase)` | Stores every column, core's, the plugins' and the app's, under its camelCase name: `email_verified` as `"emailVerified"`, `customer_id` as `"customerId"`. Code keeps the declared names (`User::EMAIL_VERIFIED`, the `Fields` field names); only the SQL changes. |
| `.rename_column(table, column, to)` | Stores one column under another name, over the strategy. Better Auth keeps the password hash in `account.password`. Use it for any custom field whose name doesn't follow the strategy. |
| `.bytes_as_hex_text(table, column)` | Stores a byte column as lowercase hex in a text column. Better Auth's `accessToken` and `refreshToken` are text; fastauth keeps writing its encrypted bytes there. |
| `.session_tokens(SessionTokens::Raw)` | Stores the session token itself in `session.token` and looks it up there, as Better Auth does, instead of its SHA-256 in `token_hash`. |
| `.only_owned_accounts(true)` | Leaves `account` rows of providers fastauth doesn't own alone (below). |
| `.migrations(Migrations::ReviewOnly)` | `fastauth migrate` and `auth.migrator().run()` refuse; `fastauth generate` writes the SQL for you to review. |
| `Sqlx::rename("verification", ..)` | Keeps fastauth's verification rows out of Better Auth's table. |

## The schema

Better Auth's migrations own the tables during the cutover, so fastauth never changes them
itself. Run `fastauth generate` against the shared database: with
`Migrations::ReviewOnly` it writes one file per change, each for you to review and apply
with your own migrations, in order. On a database Better Auth 1.7.8 created, there are four:

1. `add_user_securityStamp`: `ALTER TABLE "user" ADD COLUMN "securityStamp" bigint NOT NULL DEFAULT 0`.
   fastauth changes the stamp whenever proof of the email claims a user, so a sign-in or link
   that started before the claim can't finish after it
   ([Claiming an email](../concepts/03-security.md#claiming-an-email)). Better Auth doesn't
   know the column and inserts users with the default.
2. `index_account_accountId`: an index on `account."accountId"`.
3. `unique_account_providerId_accountId`: `CREATE UNIQUE INDEX
   "account_providerId_accountId_key" ON "account" ("providerId", "accountId")`, so one
   provider account can't be linked to two users. The file starts with a comment holding a
   query that lists the rows the index would refuse; run it first, it must return no rows.
4. `create_verification`: `CREATE TABLE "fastauth_verification"` with its identifier index.

Afterwards `fastauth status` reports nothing pending and no warnings. fastauth recognises
Better Auth's own indexes (`session_userId_idx`, `account_userId_idx`) and its unique
constraints, so it plans nothing for them. Tables of Better Auth plugins that fastauth doesn't
have stay untouched.

## Accounts another app owns

With `only_owned_accounts(true)`, fastauth owns the `credential` rows and the rows of each
social provider a plugin registers (`Social`'s providers). Rows of any other provider, such
as the `oidc` rows an SSO integration writes, are never read as a way to sign in, listed by
`/list-accounts`, unlinked, changed or deleted:

- a claim (a magic link, an email code, a verification link without the password, a verified
  social profile) deletes the user's sessions, tokens and owned accounts and leaves the
  foreign rows, which belong to identities the other app vouches for;
- `/unlink-account` answers `ACCOUNT_NOT_FOUND` for them, and they don't count as the user's
  last account;
- deleting a user (the admin plugin's `/admin/remove-user`, an anonymous user's cleanup)
  answers `409 USER_HAS_FOREIGN_ACCOUNTS` instead, since the foreign key would delete the
  rows with the user. Remove them in the app that owns them first.

Plugins that write their own provider ids declare them with
`PluginBuilder::account_provider`.

## Verification rows

fastauth stores the hash of each emailed token and data Better Auth's `verification` table
has no column for, so it keeps its rows in a table of its own (`fastauth_verification`
above) and never reads Better Auth's. A link Better Auth mailed before the cutover (a
password reset, a magic link, an email code, minutes to an hour old) doesn't work once
fastauth serves that route; the user asks for a new one.

fastauth deletes expired rows before it stores a new one. To keep the table small when few
new ones arrive, prune it yourself with `auth.prune_verifications()`, or start
`auth.prune_verifications_every(interval)` once at startup; the task stops when the
`Auth` is dropped.

## Trade-offs

The mode gives up some of fastauth's defaults so a Better Auth app can share sessions and
passwords. Each is meant for the migration window only:

| fastauth by default | With Better Auth compatibility | What it costs |
|---|---|---|
| Cookies signed with a key derived from the secret by HKDF (`fastauth/v1/cookie`) | HMAC keyed with the raw Better Auth secret | The cookie key is the secret itself, and the Better Auth app holds it too: a leak from either app lets its holder sign session cookies (they still need a session token from the database to sign in). |
| Every configured secret verifies a session token, so rotating signs nobody out | One secret signs and verifies cookies | Rotating the Better Auth secret signs everyone out of both apps. |
| argon2id (19 MiB, t=2), upgraded when parameters rise | scrypt (32 MiB, N=16384, r=16), never rehashed | No upgrade path while Better Auth reads the database; scrypt with these parameters is weaker against GPU guessing than argon2id, and each hash takes more memory. |
| An optional signed cookie cache | Refused | One database read per request that resolves a session. |
| `session` holds each token's SHA-256 | It holds the tokens themselves (`SessionTokens::Raw`) | A read-only leak of the database (a backup, an injection elsewhere) yields every live session, and the lookup compares the token itself in the database. The signed cookie is still checked first, and the security stamp, claim locks, sensitive and authoritative sessions, session gates and expiry rules work the same. |
| OAuth tokens in `bytea` columns | Hex in Better Auth's text columns | Nothing for fastauth's own tokens, which stay encrypted. Tokens Better Auth stored for a provider both apps configure are plain text, which fastauth reads as bytes and can't decrypt; they are replaced on the user's next sign-in with that provider through fastauth. The other way round, after a sign-in through fastauth Better Auth's `/get-access-token` (and app code reading `account.accessToken`) gets fastauth's ciphertext instead of a token the provider accepts, until the user signs in with that provider through Better Auth again. |
| The migrator adds what's missing at startup | Review-only | Every fastauth upgrade that adds a column goes through `fastauth generate` and review, so nothing changes Better Auth's tables behind its back. |
| A claim deletes all of a user's accounts | Only the accounts fastauth owns | A foreign row (`oidc`) survives a claim, which is right when the other app vouches for that identity; deleting a user with one is refused. |

## Cutover checklist

In order:

1. **Turn Better Auth's cookie cache off first.** Set `session.cookieCache` to off (or leave it
   at Better Auth's default, off), deploy, and wait for its `maxAge` to pass so no
   `session_data` cookie is left. With it on, a sign-out, password change or revocation in
   fastauth keeps working in the Better Auth app until the cache expires
   ([The cookie cache](#cookies)); the suite shows both.
2. **Secrets.** fastauth gets the Better Auth app's `BETTER_AUTH_SECRET` as it is, through
   `BetterAuthCompat::from_env` (never `Secret::from_env`, which decodes a hex or base64 value
   into other bytes), and its own new random `FASTAUTH_SECRET` for everything else. Keep both
   in your secret manager, at least 32 random bytes each. Don't rotate `BETTER_AUTH_SECRET`
   during the cutover: it signs everyone out of both apps.
3. **Match the configs.** The same cookie prefix, `session.expiresIn` as `.expires_in(..)`
   (Better Auth's default is 7 days, the preset's 14), `updateAge` as `.update_age(..)`, the
   app's user fields as `Fields` with the same column names, and each social provider under
   the same provider id. Put `app.config.ts` from your real `auth.ts` in
   `compat/better-auth-dual/better-auth/`, mirror it in `compat/better-auth-dual/fastauth/src/auth.rs`
   and run `compat/better-auth-dual/run-dual.sh` ([Verified against Better Auth 1.7.8](#verified-against-better-auth-178)).
4. **The schema.** Take a backup, run `fastauth generate` against the production database (or a
   fresh copy), review the four files, run the duplicate check at the top of the unique index
   one (it must return no rows), and apply them with your own migration tool. Afterwards
   `fastauth status` reports nothing pending and `npx auth migrate` reports
   `No migrations needed.`
5. **Deploy fastauth without traffic, then move routes over** behind one site, so both apps
   see the same cookies. Links Better Auth mailed before a route moved (a reset link, a magic
   link) stop working on that route ([Verification rows](#verification-rows)).
6. **During the window.** SSO stays in the Better Auth app, and so does deleting a user who has
   an `oidc` row (fastauth answers 409). Every fastauth upgrade that adds columns goes through
   `fastauth generate` and review. App code in the Better Auth app that reads a provider's
   access token sees fastauth's ciphertext after a sign-in through fastauth ([Trade-offs](#trade-offs)).
7. **Rolling back** is moving the routes back: sessions and passwords fastauth wrote keep
   working in Better Auth.
8. **Remove compat mode only once the Better Auth app is gone:** no traffic, no code reading
   the tables, and the SSO accounts moved or handled. [After the cutover](#after-the-cutover)
   says which settings can go and what each costs.

## After the cutover

Switching `SessionTokens::Raw` back to `Hashed` needs a `token_hash` column and signs
everyone out; a hashed mode that keeps working next to Better Auth isn't built yet. The other
database settings can stay as long as the tables keep Better Auth's names, and
`Migrations::ReviewOnly` can go once fastauth owns the schema.


Once the Better Auth app is gone, the cookie settings can go back to fastauth's: removing
`CookieSigning::BetterAuth` (or the preset) changes the cookie format, so everyone signs in
again once. Keep `BetterAuthScrypt` until every password is in another format: argon2id can't
verify the scrypt hashes, and a hasher that verifies them and rehashes on the next sign-in
isn't built yet.

## Verified against Better Auth 1.7.8

`compat/better-auth-dual/run-dual.sh` (part of `scripts/ci.sh --only compat`) runs a real
Better Auth 1.7.8 app (Node, `better-auth/node`) and a fastauth app (axum) against one
Postgres 17, with `BetterAuthCompat`, `only_owned_accounts` and `fastauth_verification` as on
this page. The Better Auth app's config is one file,
`compat/better-auth-dual/better-auth/app.config.ts`: cookie prefix `vt`, 14-day sessions
refreshed after a day, email and password, a `customerId` field and no cookie cache. Swap in
your own and keep `compat/better-auth-dual/fastauth/src/auth.rs` in step. The run proves:

- **The schema.** Better Auth's `npx auth migrate` creates it; users and sessions are created
  through Better Auth before fastauth's columns exist. `fastauth migrate` refuses,
  `fastauth generate` writes exactly the four migrations above, the duplicate check finds
  nothing, they apply, and `fastauth status` is clean. Afterwards Better Auth's `npx auth
  migrate` reports `No migrations needed.`, its old sessions and users keep working, the old
  rows have `securityStamp` 0 from the default, and its new sign-ups get it too. Adding the
  admin plugin later writes five more migrations (nullable columns or columns with a
  default) that Better Auth also accepts.
- **Sign-up and sign-in** in one app and sign-in with the other, both ways, with the email in
  any case; a user from before fastauth signs in to it.
- **Cookies.** Each app resolves the other's `vt.session_token` to the same user and session,
  including a session from before fastauth and fastauth's 43-character base64url tokens in
  Better Auth (Better Auth's are 32 alphanumeric characters), and the app's own routes see it.
  Both refuse a changed token and a token without its signature. On https both set and read
  `__Secure-vt.session_token` (Secure, HttpOnly, SameSite=Lax, Path=/) and ignore the name
  without the prefix. `/list-sessions` lists the sessions of both apps.
- **Sign-out and revocation.** A sign-out in either app deletes the row and clears the cookie,
  and the other app signs the user out; `/revoke-session` works across apps.
- **Passwords.** `/change-password` with `revokeOtherSessions` in either app signs out the
  other app's sessions and keeps the current one; without it the other app's sessions keep
  working. Either way the old password fails in the other app and the new one works.
  fastauth's password reset signs Better Auth out; Better Auth's reset keeps fastauth's
  sessions, as its `revokeSessionsOnPasswordReset` (off here) says.
- **Refresh**, both ways: sessions last 14 days, a session extended 23 hours ago isn't extended
  and gets no cookie, one extended more than a day ago is extended to 14 days with
  `Max-Age=1209600`, the other app reads it afterwards, neither resolves an expired session,
  and neither extends the other's `rememberMe: false` session.
- **`customerId`** written by either app's own code is read by the other's code and returned
  by its `/get-session`; a client can't set it at sign-up in either.
- **scrypt.** Hashes Better Auth wrote verify in fastauth; hashes fastauth wrote verify in
  Better Auth with fastauth stopped (a rollback), NFKC included.
- **`oidc` rows** stay byte for byte through a magic-link sign-in, magic-link, email-code and
  verified-social claims (which delete the owned credential account and Better Auth's old
  sessions and change the security stamp), `/update-user` and `/revoke-sessions`.
  fastauth's `/list-accounts` leaves them out, `/unlink-account` answers
  `ACCOUNT_NOT_FOUND`, and `/admin/remove-user` answers `409 USER_HAS_FOREIGN_ACCOUNTS` and
  leaves the user and row alone, while a user without one is removed. fastauth never touches
  Better Auth's `verification` rows, expired ones included (Better Auth deletes its own
  expired rows whenever it looks one up).
- **Social sign-in** through a mock OAuth provider both apps configure (Better Auth's
  `genericOAuth`, a custom `OAuthProvider` in fastauth, provider id `mock`): a user created in
  either app signs in to the other on the same account row. fastauth reads the row Better Auth
  wrote with plain-text tokens without an error and replaces them with its own, and Better
  Auth writes plain ones back on its next sign-in. In between, Better Auth's
  `/get-access-token` returns fastauth's ciphertext ([Trade-offs](#trade-offs)).
- **The cookie cache.** With it off, a revocation in fastauth signs the user out of Better Auth
  at once. With it on (`maxAge` 5 minutes) Better Auth keeps answering with the revoked
  session from `vt.session_data`; `?disableCookieCache=true` and the instance with it off
  don't. fastauth's sign-out deletes `vt.session_data`.

Not covered by the run:

- the production `auth.ts` itself, and any Better Auth plugin it has beyond the above
  (their tables, columns and session fields);
- Better Auth's SSO plugin: the `oidc` rows are seeded directly, so its own sign-in isn't run;
- real social providers (Google, GitHub): only the mock, so whether both apps store the same
  `accountId` for a real provider isn't checked;
- MySQL and SQLite; Better Auth's secondary storage;
- email verification, email change, two-factor and multi-session across the apps;
- Better Auth's `revokeSessionsOnPasswordReset: true`, secret rotation, and refreshes racing
  in both apps at once;
- a real browser over TLS: the https instances have an https base URL but are served over
  plain HTTP, so cookie names and attributes are checked, not how a browser treats them.

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
