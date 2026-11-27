# Changelog

## Unreleased

### Added

- **Better Auth database compatibility: cookies, password hashes and session refresh.** A
  fastauth app can now share sign-ins with a Better Auth app on the same database during a
  migration. Everything is opt-in and the defaults don't change.
  `FastAuth::builder().better_auth_compat(BetterAuthCompat::new(secret).cookie_prefix("vt"))`
  sets it all; each piece is also a knob of its own:
  - `CookieConfig::signing(CookieSigning::better_auth(secret))`: cookies named
    `{prefix}.session_token` (`__Secure-` on https) whose value is
    `encodeURIComponent(token + "." + base64(HMAC-SHA256(raw secret, token)))`, signed and
    verified byte for byte like better-call 1.4.2, percent-encoded or not, in constant time.
  - `BetterAuthScrypt`: verifies and writes Better Auth's `"<saltHex>:<keyHex>"` scrypt hashes
    (N = 16384, r = 16, p = 1, 64 bytes, NFKC), never rehashed, so a rollback keeps working.
  - `SessionConfig::sliding_refresh(SlidingRefresh::ExpiresAt)`: Better Auth's refresh rule,
    counted from `expires_at` because Better Auth moves `updatedAt` on every session update.
    The preset uses a 14-day lifetime and a one-day `update_age`.
  - `EmailPassword::max_concurrent_hashes(n)` bounds the hashing pool (scrypt takes 32 MiB per
    hash); the preset allows 8.
  - Golden vectors from better-call 1.4.2 and `@better-auth/utils` 0.5.0 in
    `compat/better-auth/vectors`, checked in both directions by `run-vectors.sh`.

  The mode relaxes fastauth's defaults on purpose for the migration window: the cookie key is
  the raw shared secret without HKDF and only it verifies cookies, passwords are scrypt instead
  of argon2id, and the cookie cache is refused. See
  [Migrating from Better Auth](docs/integrations/04-migrating-from-better-auth.md#trade-offs).
- `Keys::decode_cookie` and `Passwords::with_concurrency`, used by the above.

### Better Auth database compatibility: schema and storage

fastauth can now run on the tables of a Better Auth app and share them with it during a
phased cutover ([Migrating from Better Auth](docs/integrations/04-migrating-from-better-auth.md)).
Every setting is opt-in: an app that sets none of them keeps 0.7's schema, SQL and security
defaults exactly. `BetterAuthCompat` sets all of them but the verification table, which
the adapter names (`Sqlx::rename("verification", "fastauth_verification")`).

- **Column names.** `Builder::column_naming(ColumnNaming::CamelCase)` stores every column of
  core, the plugins and the app's `Fields` under its camelCase name (`"emailVerified"`,
  `"userId"`), and `Builder::rename_column(table, column, to)` overrides one column, such
  as `account.password_hash` as Better Auth's `password`. Code, filters and sorts keep the
  declared names; the sqlx adapter uses the stored names in every query, index, constraint
  and migration on Postgres, SQLite and MySQL, and recognises Better Auth's index names.
  `Builder::bytes_as_hex_text(table, column)` stores a byte column as hex in a text column
  (Better Auth's `accessToken` and `refreshToken`).
- **Raw session tokens.** `Builder::session_tokens(SessionTokens::Raw)` stores and looks up
  the token itself in `session.token`, as Better Auth does, so both apps resolve each other's
  sessions. It gives up the protection hashed tokens give a leaked table; hashing stays the
  default. `CoreConfig::session_token_eq(token)` filters by a token under either setting.
- **Accounts another app owns.** `Builder::only_owned_accounts(true)` limits fastauth to
  `credential` rows and the providers plugins register (`PluginBuilder::account_provider`,
  which `Social` calls for each provider). Claims, `/list-accounts`, `/unlink-account` and
  the admin and anonymous user deletions leave other rows (an `oidc` provider) alone, and
  deleting a user that has one answers `409 USER_HAS_FOREIGN_ACCOUNTS`.
- **Review-only migrations.** `Builder::migrations(Migrations::ReviewOnly)` makes
  `Migrator::run` and `apply` (and `fastauth migrate`) refuse with `ReviewOnly`;
  `fastauth generate` writes one file per change from the new `Migrator::sql_steps`, with a
  duplicate check above each unique constraint on an existing table. On Better Auth 1.7.8's
  schema the changes are an additive `"securityStamp" bigint NOT NULL DEFAULT 0`, an index on
  `account."accountId"`, the unique `("providerId", "accountId")` index and fastauth's own
  verification table.
- **Verification pruning.** `Auth::prune_verifications()` deletes expired verification rows,
  and `Auth::prune_verifications_every(interval)` runs it on a Tokio task until the `Auth`
  is dropped.
- **Tests.** `testing::run_adapter_conformance_renamed` runs the adapter suite with renamed
  columns (MemoryAdapter and all three sqlx databases pass), and `fastauth-sqlx`'s
  `better_auth_schema` tests run on the schema Better Auth 1.7.8's CLI generates for each
  database (`crates/fastauth-sqlx/tests/better-auth/generate.sh`).

### Provider tokens Better Auth can read

- **`Builder::store_oauth_tokens_in_plaintext(true)`** stores the access and refresh tokens a
  provider returns as plain text instead of encrypting them, as Better Auth 1.7.8 does unless
  its `account.encryptOAuthTokens` is on. A Better Auth app on the same database then gets
  working tokens from its `/get-access-token` (and from `account.accessToken`) after a
  sign-in through fastauth, instead of fastauth's ciphertext. In Better Auth's text columns
  the token is stored as the text itself (`BytesText::Utf8`), not as hex. It's off by
  default and `BetterAuthCompat` doesn't turn it on: anyone who can read the table or a
  backup can call the provider as each user. Rows already stored aren't rewritten.
- **`Account::read_access_token(keys)` and `read_refresh_token(keys)`** read a stored token
  whichever way it's stored: fastauth's ciphertext (bytes, or hex in a text column) or plain
  text written by fastauth or Better Auth. `Auth::keys()` gives app code the keys.

### Better Auth cross-app suite

`compat/better-auth-dual/run-dual.sh` (in `scripts/ci.sh --only compat`) runs a real Better
Auth 1.7.8 app and a fastauth app on axum against one Postgres 17, as during a phased cutover:
Better Auth's migration creates the schema, fastauth's four review-only migrations go on top,
and each app accepts the other's sign-ups, cookies (`__Secure-` on https), sign-outs, password
changes and resets, refreshes, `customerId`, scrypt hashes and social accounts, with SSO
(`oidc`) rows left alone and Better Auth's cookie cache on and off. The fastauth app stores
provider tokens in plain text, so Better Auth's `/get-access-token` returns tokens the
provider accepts; a second instance with encrypted tokens shows the gap that leaves. The
Better Auth app's config is one file, `compat/better-auth-dual/better-auth/app.config.ts`, to swap for a real one.
[Verified against Better Auth 1.7.8](docs/integrations/04-migrating-from-better-auth.md#verified-against-better-auth-178)
lists what it proves.

### Core changes

All additive: `ColumnNaming`, `TableDef::stored_name` / `stored_column` /
`column_stored_as` / `is_hex_text` / `stored_reference`;
`SessionTokens`, `Session::TOKEN` and `CoreConfig::{session_tokens, session_token_eq,
owns_account_provider, owned_account_providers}`; `Migrations`, `ReviewOnly`,
`MigrationSql`, `Migrator::{mode, sql_steps}`; two `Adapter` methods with defaults,
`session_with_user_by_token` (with `SessionWithUserByToken`) and `duplicates_query`;
`Internal::{accounts_of, refuse_foreign_accounts}`; `PluginBuilder::account_provider`; the
`USER_HAS_FOREIGN_ACCOUNTS` code; `Builder::store_oauth_tokens_in_plaintext`,
`CoreConfig::oauth_tokens_in_plaintext`, `Ctx::oauth_token_bytes`, `BytesText` and
`TableDef::bytes_text`, `Account::{read_access_token, read_refresh_token}` and `Auth::keys`.
`LiveSchema` now holds stored column names, which are the declared names unless a naming
setting changes them.

## 0.7.0 (2026-11-27)

### Highlights

- **Several instances, with Redis or Valkey.** An app can now run as several processes,
  containers or machines behind a load balancer and still enforce one set of rate limits.
  Give the builder a store every instance shares with `.secondary_storage(..)`; the new
  `fastauth-redis` crate (facade features `redis` and `redis-tls`) provides one for Redis and
  Valkey. Sessions, tokens and code attempts already lived in the database, so a revoked
  session or a ban already reached every instance; the rate limiter was the only thing each
  process kept to itself. See [Running several instances](docs/concepts/04-multiple-instances.md).
- **A security fix (F61-1).** A request a squatter had in flight could restore access after
  the real owner reclaimed the email; **all versions before 0.7.0 are affected**. Someone who
  signs up with an address they don't own could start a password change, a passkey
  registration, an API key, a two-factor enrollment or an email change, and if the owner
  proved the address while that request was running, the request still landed on the
  owner's account. Each of these writes now locks the user and stores nothing when the
  account was claimed since the request was authorised. Upgrade every app on 0.6 or earlier.

0.7.0 also fixes eleven lower-severity findings of the same review (F61-2 to F61-11 and
F61-16), listed under [Security](#security).

### Upgrading from 0.6

Bump `fastauth` (and any `fastauth-*` crate you depend on directly) to `"0.7"`, then go
through this list.

- **No database migration.** 0.7.0 adds no table, column, index or constraint, so a database
  migrated for 0.6 is already right and `fastauth status` passes on it. The migrator only
  reads two things more carefully:
  - On Postgres, a unique index that a failed `CREATE UNIQUE INDEX CONCURRENTLY` left invalid
    no longer counts as the constraint (F61-8). If you have one, `fastauth status` now exits 1
    and the migrator plans the constraint again; drop the invalid index (`DROP INDEX
    CONCURRENTLY ..`) after fixing the duplicates, then migrate.
  - On MySQL, the duplicate check compares values by the prefix the index keys on (F61-9), so
    a 0.5 database with values that differ only after 384 characters is now refused before any
    DDL, naming the rows, instead of failing half-way.
- **Plugin authors: `Internal::set_password` takes `&UserView`** instead of `&Id`. This
  breaks plugins that set passwords, and there's no deprecated `&Id` version on purpose. The
  fix for F61-1 needs the security stamp the user had when the request was authorised; a
  version that took an id would have to read the user again and would see the stamp after
  the claim, so the race would be back. Pass the user the request authorised:
  `ctx.session().user` on a session route, or the `UserView` a sign-in or token was read
  for. It answers `401` and stores nothing when the user was claimed since. For your own
  credential writes, use the new `Internal::lock_user_unless_claimed(&user)`, which returns a
  transaction holding the user row (write through `ctx.db_on(&tx)`, then commit), and
  `Internal::create_session_unless_claimed(&user, remember_me)` for a session that a
  session-authorised request creates ([Plugin authoring](docs/reference/01-plugin-authoring.md)).
- **The rate limiter is async.** Core now awaits each rate-limit check so that it can call
  secondary storage. No public API changed: `RateLimit`, its rules and plugins' rate rules
  work as before, and without secondary storage the limiter is the same in-memory GCRA. With
  secondary storage:
  - each bucket is a fixed window, so a client can send `max` requests at the end of one
    window and `max` more at the start of the next;
  - a limited request makes one round trip to the store per bucket (the client's, then one
    for each account the body names);
  - when the store fails, each instance falls back to its own memory and logs an error at most
    once a minute. A store that doesn't answer costs a request at most one
    `secondary_storage_timeout` (100 ms by default), and after 5 failures in a row the store
    is skipped for 5 seconds (F61-16).
- **Account rate-limit buckets reset when the first secret rotates.** The per-account buckets
  (`RateLimit::account_limit`, 30 requests per 10 minutes by default) are now keyed by an
  HMAC of the email or username under a key derived from the first secret, so instances agree
  on them and the store never sees the address. Rotating with `.secrets([new, old])` gives
  every account a fresh allowance once, and during a rolling rotation instances on different
  first secrets count separately until all run the new one. Client-IP buckets aren't
  affected. The upgrade itself also starts account buckets afresh, as a restart always did.
- **No new enum variants.** No public enum gained a variant and no public struct gained a
  field, so exhaustive matches and struct literals that compiled against 0.6 still compile.
  Everything else new is additive: `fastauth_core::storage` (`SecondaryStorage`,
  `StorageError`, `DEFAULT_STORAGE_TIMEOUT`), `Builder::secondary_storage`,
  `Builder::secondary_storage_timeout` and `Builder::multi_instance`,
  `Internal::lock_user_unless_claimed` and `create_session_unless_claimed`,
  `testing::run_storage_conformance`, `Transaction` in `plugin_prelude`, an associated
  const `BEGIN` with a default on `fastauth_sqlx::Driver`, and the `fastauth-redis` crate
  (with its `CONNECTION_TIMEOUT` and `RESPONSE_TIMEOUT`).
- **Behaviour changes.**
  - Change-password, the password rehash at sign-in, password reset (core and email OTP),
    passkey registration, API key create, two-factor enable and the first verify-totp,
    linking a social account, email OTP change-email, `/update-user`, and admin
    set-user-password and update-user on the admin's own account answer
    `401 UNAUTHORIZED` when the user was claimed after the request was authorised. Each holds
    a lock on the user row for its write, so two such writes for one user run one after the
    other. The message of this `401`, also sent to a sign-in a claim overtook, is now "the
    account changed meanwhile; sign in again".
  - MySQL: transactions fastauth begins itself run at READ COMMITTED, as Postgres does by
    default (F61-7). Keep `binlog_format` at `ROW` (MySQL's default) or `MIXED`; under
    `STATEMENT`, InnoDB refuses writes at that level. Transactions you pass with `in_tx`
    keep the level you began them at.
  - Secrets: `Secret::entropy_bits` estimates differently (F61-10). Placeholders repeated to
    length, counting runs and secrets drawn from a few characters now score low, so a secret
    that 0.6 accepted can make `.build()` fail on a production host; generated secrets
    (`fastauth secret`, `openssl rand -hex 32`) pass. Only the first secret is checked; a weak
    retired secret logs a warning instead of failing the build (F61-6).
  - Sessions: a session whose stored lifetime is at most a day and shorter than `expires_in`
    is never extended (F61-3). That covers `rememberMe: false` sessions used without their
    marker cookie, and sessions a plugin created with a short expiry through
    `create_session_with`.
  - A username sign-in refused with `EMAIL_NOT_VERIFIED` now sets the
    `pending_verification` cookie, as the email sign-in does (F61-4), and that cookie is
    accepted under any configured secret (F61-5).
  - A request dropped while hashing a password keeps its hashing slot until the hash finishes
    (F61-2), so clients that disconnect can't run more hashes than the CPU-count cap.
  - With `.multi_instance(true)`, `.build()` logs a warning when rate limiting is on and no
    secondary storage is set.
  - Secondary storage calls time out after 100 ms (F61-16). A call that takes longer counts
    the request in the instance's memory instead, so an app on a store with high latency
    should raise it with `.secondary_storage_timeout(..)`. `RedisStorage::connect` sets a
    1 s connection timeout and a 250 ms response timeout; a `ConnectionManager` passed to
    `RedisStorage::new` keeps its own.

### Several instances

- **`.secondary_storage(..)`**, Better Auth's `secondaryStorage`: a key-value store every
  instance of an app shares. Rate limit counters live there, so a limit holds across every
  instance instead of once per instance. Each bucket is a fixed-window counter, as in Better
  Auth's secondary-storage limiter; without secondary storage the in-memory GCRA limiter
  stays. When the storage fails, the instance falls back to its in-memory limiter and logs
  an error at most once a minute.
- **New crate `fastauth-redis`** (facade features `redis` and `redis-tls`): `RedisStorage`
  on Redis or Valkey through a reconnecting connection manager. A rate-limit step is one Lua
  script (`INCR`, then `PEXPIRE` on a new counter), so instances never both take the last
  request. Tested against Redis 7 and Valkey 8, including two `Auth` instances on one
  Postgres and one Redis.
- **`.multi_instance(true)`** says the app runs several instances; `.build()` then warns
  when rate limiting is on without secondary storage.
- Sessions, verification values and code attempts stay in the database, which instances
  already share and which consumes tokens atomically; nothing on the wire changes. New page:
  [Running several instances](docs/concepts/04-multiple-instances.md). The Production
  checklist now says multi-instance apps need secondary storage.

### Security

Fixes for the FAST-61 review of 0.6.0, one line per finding.

- **F61-1 (medium):** a password change (or the rehash at sign-in), passkey registration, API
  key, two-factor enrollment or email change that the first registrant had in flight when the
  owner claimed the address landed on the claimed account. Every session-authorised write of a
  credential or identity now runs under a lock on the user row that holds only while the
  security stamp is unchanged, and answers 401 and stores nothing after a claim.
- **F61-2 (medium):** a request dropped mid-hash (a client disconnect, a timeout layer) gave
  its hashing permit back while argon2 kept running, so disconnecting clients could run far
  more hashes at once than the CPU-count cap. The permit now moves into the blocking task and
  is held until the hash finishes.
- **F61-3 (low):** a `rememberMe: false` session used without its `dont_remember` marker
  (as a bearer token, or from a cookie jar that dropped the marker) slid to the full
  `expires_in`. The refresh now also skips a session whose stored lifetime is shorter than
  `expires_in` and at most a day.
- **F61-4 (low):** a username sign-in refused with `EMAIL_NOT_VERIFIED` mailed a link but left
  no `pending_verification` cookie, so the owner opening it in that browser was claimed and
  lost the password. It now leaves the cookie, as the email sign-in does.
- **F61-5 (low):** `pending_verification` was read with the current secret only, so a secret
  rotation between sign-up and the click claimed the owner and deleted the password. It is now
  accepted under any configured secret, like a session token.
- **F61-6 (low):** `.build()` refused a weak *retired* secret too, so rotating off a weak 0.5
  secret forced `allow_insecure_config(true)` in production. Only the current secret is
  refused now; a weak retired one logs a warning.
- **F61-7 (low):** first-time `/two-factor/enable` calls for *different* users deadlocked on
  MySQL (a gap lock from deleting a missing row, then inserts into the gap), and one answered
  500. fastauth's own MySQL transactions now begin at READ COMMITTED, as Postgres runs by
  default; keep `binlog_format` at ROW or MIXED.
- **F61-8 (low):** on Postgres, a unique index left invalid by a failed `CREATE UNIQUE INDEX
  CONCURRENTLY` counted as the unique constraint, so the migrator planned nothing and
  duplicates went in. Introspection now counts only valid, ready indexes.
- **F61-9 (info):** on MySQL the duplicate check compared whole values but a unique index
  over two text columns keys on a 384-character prefix of each, so values that differed only
  after it passed the check and the migration failed half-way. The check now groups by the
  indexed prefix and refuses before any DDL.
- **F61-10 (info):** the secret entropy estimate (length × log2 of distinct bytes) passed
  placeholders repeated to length (`"changeme"` × 6) and refused about a third of
  `openssl rand -hex 16` secrets. `Secret::entropy_bits` now counts repeated and counting
  stretches once and uses the secret's alphabet (hex, alphanumeric, base64, printable, any
  byte): placeholders score below 25 bits, and 0.08% of 128-bit hex secrets are refused.
- **F61-11 (info):** the first unknown-email sign-in after a start ran the hasher twice (it
  made the dummy hash, then verified against it), so it took about twice as long as a wrong
  password for a known email. It now runs it once.
- **F61-16 (info):** secondary storage calls had no timeout, so a slow or partitioned Redis
  stalled every rate-limited request, sign-in included. Each call now times out after 100 ms
  (`.secondary_storage_timeout(..)`) and falls back to the in-memory limiter, a request waits
  for at most one timeout, and a circuit breaker skips the storage for 5 seconds after 5
  failures in a row, then probes it again. `RedisStorage::connect` sets a 1 s connection
  timeout and a 250 ms response timeout.

### Core

- **Breaking for plugins:** `Internal::set_password` takes the `&UserView` the request
  authorised instead of a user id, and answers 401 when that user was claimed since.
- Additive: `Internal::lock_user_unless_claimed(&user)`, a transaction holding the user row
  locked at the security stamp `user` was read with (401 when a claim moved it), and
  `Internal::create_session_unless_claimed(&user, remember_me)`. `link_account_unless_claimed`
  now inserts under that lock instead of inserting and checking afterwards.
  `plugin_prelude` exports `Transaction`.
- Additive: `fastauth_core::storage` with the `SecondaryStorage` trait (`get`, `set` with a
  TTL, `delete`, atomic `increment` with a TTL set on creation) and `StorageError`, and
  `testing::run_storage_conformance` behind the `testing` feature.
- Account rate-limit buckets are keyed by an HMAC under a key derived from the first secret
  instead of a per-process hash, so instances agree on them and storage never sees the
  email or username. Rotating the first secret starts account buckets afresh.

## 0.6.0 (2026-11-27)

### Highlights and security

0.6.0 is a security release, and **every version before 0.6.0 is affected**. It fixes all 41
findings of a second, independent security review of 0.5.0 (4 high, 10 medium, 22 low and 5
info) and two more that fuzzing found. Upgrade every app on 0.5 or earlier, and read
[Upgrading from 0.5](#upgrading-from-05) first: there is a database migration, and some
behaviour is deliberately stricter.

- **Account takeover by squatting an email (ATO-1 to ATO-4, high).** Anyone can sign up with
  an address they don't own; that needs no access to the mailbox. Until now, things the
  squatter left on that unverified account survived the real owner proving the address, and
  each one was a way into the owner's account: a two-factor sign-in parked half-way that
  finished after the owner's proof (ATO-1); API keys, passkeys, OAuth links and two-factor
  that a password reset kept (ATO-2); the squatter's password, which a verification link
  activated (ATO-3); and a link to a second social provider (ATO-4). In 0.6.0 every proof of
  an email works the same way: whoever proves the address becomes the only owner of its
  user, and everything from before the proof is deleted in one transaction
  ([Claiming an email](docs/concepts/03-security.md#claiming-an-email)).
- **Revoked admins kept admin rights (SESS-1, medium).** With the cookie cache on, the admin
  routes and impersonation trusted the cached session, so an admin whose session was
  revoked, whose role was removed or who was banned kept admin rights until the cache cookie
  expired, which was long enough to create a new admin. Admin and organization checks now
  read the session and the user from the database. If you can't upgrade at once, turn the
  cookie cache off in apps with the admin plugin.
- **Safer by default.** `.build()` refuses an `http://` `base_url` or a guessable secret
  for a production host, unique constraints in the database close the races the review
  found, rate limits cover IPv6 clients and each account, a retired secret no longer signs
  anything self-contained, and request text with a NUL byte answers `400`. The new
  [Production checklist](docs/reference/04-production-checklist.md) lists what an app must
  set before real users.

### Upgrading from 0.5

Bump `fastauth` (and any `fastauth-*` crate you depend on directly) to `"0.6"`, then go
through this list.

- **Migrate the database: a new column.** `user.security_stamp` (integer, not null, default
  0) lets a claim stop sign-ins that started before it. Run `auth.migrator().run()` or your
  `fastauth migrate` binary, or `fastauth generate` for a SQL file, on Postgres, SQLite or
  MySQL. Existing users get 0 and keep signing in, and rows a 0.5 server writes get the
  default, so you can migrate before you deploy.
- **Migrate the database: three new unique constraints**, on `account (provider_id,
  account_id)`, on `member (organization_id, user_id)` with the organization plugin, and on
  `two_factor (user_id)` with two-factor. Before it runs any statement, the migrator
  (`migrator().apply(..)`, `run()`, `fastauth migrate`) looks for rows that would break a
  new constraint; if it finds some, it changes nothing and fails with `DbError::Schema`,
  naming the table, the columns and up to 10 of the rows. SQL from `generate` or
  `migrator().sql()` has no such check, and the database refuses the `CREATE UNIQUE INDEX`
  itself. Either way, find and fix the duplicates with the queries in [Unique constraints on
  an existing database](docs/concepts/02-database.md#unique-constraints-on-an-existing-database),
  then migrate again. `fastauth status` exits 1 until the constraints exist. On MySQL,
  multi-column unique constraints index a 384-character prefix of each text column, and new
  tables store `account.provider_id` as `varchar(768)` instead of `longtext`.
- **`.build()` fails on unsafe production settings.** When `base_url`'s host isn't local
  (`localhost`, `*.localhost` or a loopback address), `.build()` returns `BuildError`
  for an `http://` `base_url` and for a secret with less than about 120 bits of estimated
  entropy (`Secret::entropy_bits`). A `base_url` with credentials, a query or a fragment
  fails on every host. On a local host the first two only log warnings. For development, CI
  and staging on a private network, `Builder::allow_insecure_config(true)` turns them into
  warnings for any host; set it from an environment variable production doesn't have. Secrets
  from `fastauth secret` or `Secret::generate()` pass; a test fixture that pairs an
  `https` `base_url` with a fixed short secret needs `Secret::generate()`. A request
  without a client IP is now logged with `tracing::error!` on a production host.
- **Secret rotation.** With `.secrets([new, old])`, a secret that is no longer first still
  verifies session tokens and decrypts encrypted columns, so nobody is signed out, but it no
  longer verifies anything self-contained (CRYPTO-1). After a rotation, cookie caches signed
  with the old secret are ignored once, trusted devices ask for the second factor again, and
  sign-ins in flight that hold a short-lived signed cookie (OAuth state, passkey challenge,
  pending two-factor) start over. In code, `Keys::verify` and `Ctx::signed_cookie` now
  accept only the current secret. A plugin that keeps a session token in a signed cookie of
  its own must read it with the new `Ctx::signed_token_cookie` (or `Keys::verify_token`),
  which accepts every configured secret, or its users lose that cookie at each rotation.
- **Proving an email now claims the user.** A magic link, an email code, a password reset, a
  verification link and a verified social profile all claim an unverified user the same way.
  What your users will notice:
  - A verification link (`/verify-email`, `/email-otp/verify-email`) opened without proof
    of the password deletes the user's password with everything else from before the proof.
    Proof is a live session of that user, or the signed `<prefix>.pending_verification`
    cookie that sign-up, or a sign-in refused with `EMAIL_NOT_VERIFIED`, sets in the
    browser that knew the password. So someone who signs up on a laptop and opens the link on
    a phone signs in with a magic link or code, or sets a password with a reset. Say so on
    your verification page. Better Auth only sets `emailVerified`.
  - `/reset-password` and email OTP's reset on an unverified user verify the email and
    delete the user's other accounts, sessions, passkeys, API keys and two-factor, even with
    `revoke_sessions_on_password_reset(false)`.
  - Password-reset and verification links sent before the upgrade stop working, and so does
    one sent before the user's email changed. Users request a new one.
  - A sign-in or social link that was in progress while the user was claimed answers
    `401 UNAUTHORIZED` instead of a session.
  - A user with a verified email is never anonymous, whatever `is_anonymous` says.
- **Sessions are checked where it matters.**
  - API-key and impersonation sessions can no longer read the TOTP URI, generate backup
    codes, change the password, delete API keys, rename or delete passkeys, unlink accounts
    or delete an anonymous user: `401` for a key's session and
    `403 NOT_ALLOWED_WHILE_IMPERSONATING` while impersonating. Better Auth allows some of
    these ([Security](docs/concepts/03-security.md#sessions-that-arent-a-sign-in)).
  - With the cookie cache on, admin and organization routes that change something,
    `/admin/has-permission`, `/organization/has-permission` and the `/revoke-*` routes
    cost one more database read and answer `401` to a session revoked since the cache
    cookie was set.
  - The cookie-cache format changed, so every existing cache cookie is ignored once.
  - A `rememberMe: false` session lives one day at most (or `expires_in`, if shorter) and
    isn't refreshed.
  - A session hook that returns an error leaves no session: the row is deleted and no
    cookie is set.
  - JWTs expire with their session at the latest.
- **Stricter limits and input checks.**
  - Rate limits: IPv6 clients share one bucket per /64 (`RateLimit::ipv6_prefix`), and every
    route with a rule of its own (sign-in, sign-up, password reset, the plugins' mail and
    code routes) also allows each account 30 requests per 10 minutes, whatever the client IP
    (`RateLimit::account_limit`).
  - Email addresses must be one plain address. Spaces, quotes, non-ASCII characters and
    address lists that `normalize_email` used to accept answer `400 INVALID_EMAIL`.
  - Admin roles without `user:set-email` can't set `emailVerified` on `create-user`;
    columns another plugin owns (such as `twoFactorEnabled`) answer `400 INVALID_FIELD` on
    `create-user` and `update-user`; `list-users` without `limit` returns at most 100
    users.
  - An organization can have 100 pending invitations by default
    (`Organization::invitation_limit`); past that, `invite-member` answers
    `403 INVITATION_LIMIT_REACHED`. Slugs over 255 characters answer
    `400 INVALID_REQUEST_BODY` and invitation emails over 254 bytes `400 INVALID_EMAIL`.
    Better Auth has none of these caps.
  - Emails are sent at most 8 at once per process; past 10,000 waiting they are dropped and
    logged, and a send is abandoned after 60 seconds.
  - A second link of a provider account that's already linked answers
    `409 SOCIAL_ACCOUNT_ALREADY_LINKED` (Better Auth's code) instead of 500. Parallel adds
    or accepts of one member answer `USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION` for the
    loser, and two password sets at once for a user without one leave one credential account.
- **NUL bytes are refused.** Every core and plugin endpoint answers
  `400 INVALID_REQUEST_BODY` to a JSON body with `\u0000` in a string or a query with
  `%00`, before it reads any field. On SQLite, `contains`, `starts_with` and
  `ends_with` filters now match bytes exactly (`instr`/`substr` on `BLOB` casts instead
  of `GLOB`); on Postgres a needle with a NUL matches nothing.
- **Plugin authors.** Move credential cleanup from `on::<UserClaimed>` to
  `PluginBuilder::on_claim`, which runs inside the claim's transaction; `UserClaimed` is for
  notifications only. `Internal::claim_unverified_user` is deprecated in favour of
  `claim_user(user, None)`. Validate user columns a client writes with
  `PluginBuilder::prepare_user_input`.
- **Code that may not compile.** No public trait changed, but:
  - `SessionView` has a new private field, so code outside core can't build one with a
    struct literal. Get one from the API (`get_session_by_token`, for example).
  - `migrate::Step` has a new variant, `AddUnique { table, columns }`, and isn't
    `#[non_exhaustive]`. Adapters must handle it, and refuse it with
    `migrate::duplicates_error` when the table holds duplicates.
  - `LiveSchema` has a new public field, `uniques`. Code that builds it without
    `..Default::default()` needs it; leave it `None` if your adapter can't read unique
    constraints.
  - `OrganizationError` has a new variant, `InvitationLimitReached`, and isn't
    `#[non_exhaustive]`, so an exhaustive `match` on it needs an arm.
  - `plugin_prelude` also exports `Claim`, `NewSession`, `UserInput` and `BoxFuture`.

### Security

Fixes for the FAST-45 review of 0.5.0 and for the two findings of the fuzzing campaign.

**Claiming an email.** One claim model now covers every path that proves an email.

- **ATO-1 (high):** a two-factor sign-in the first registrant left pending can't finish after
  the owner claims the address: the claim deletes it, and the security stamp refuses one
  already in flight.
- **ATO-2 (high):** `/reset-password` with an emailed link claims an unverified user, so the
  first registrant's API keys, passkeys, OAuth links and two-factor don't survive it.
- **ATO-3 (high):** a verification link opened without proof of the password claims the user
  and deletes the password, instead of verifying the first registrant's account and leaving
  their password working.
- **ATO-4 (high):** a verified social sign-in that claims a user deletes every earlier OAuth
  link, not only the password.
- **ATO-5 (medium):** a claim deletes the user's two-factor enrollment (secret, backup codes,
  trusted devices) and clears `twoFactorEnabled`.
- **ATO-6 (medium):** plugin cleanup runs inside the claim's transaction
  (`PluginBuilder::on_claim`) instead of on the post-commit `UserClaimed` event, so a
  sign-in refused after the claim leaves no API keys or passkeys behind, and a failing
  cleanup fails the whole claim.
- **ATO-7 (medium):** password-reset and verification links are bound to the user's address
  and security stamp, so they die when the email changes or the user is claimed.
- **ATO-8 (medium):** a guest whose email gets verified (email OTP change-email) is no longer
  anonymous, so the next sign-in in that browser doesn't delete the account.
- **ATO-10 (low):** username rules run wherever a client writes user fields
  (`PluginBuilder::prepare_user_input`), so email-OTP sign-up validates `username`, and
  `"username": null` no longer clears an immutable username.
- **RACE-1 (medium):** a password sign-in in flight while the user was claimed keeps no
  session: every sign-in and account link checks the user's `security_stamp` before it
  finishes, on Postgres, SQLite and MySQL.

**Sessions.**

- **SESS-1 (medium):** with the cookie cache on, `/admin/*` and `impersonate-user` decided
  on the cached session, so a revoked, demoted or banned admin kept admin rights for the
  cache's max age. Admin checks, and organization role and permission checks on every route
  that changes something, now read the session and user from the database.
- **SESS-2:** `/two-factor/get-totp-uri`, `/two-factor/generate-backup-codes` and
  `/change-password` need a stored session (`sensitive_session`); `/revoke-session`,
  `/revoke-sessions` and `/revoke-other-sessions` read it from the database.
- **SESS-3:** `/api-key/delete`, renaming and deleting a passkey, `/unlink-account` and
  `/delete-anonymous-user` need a stored session, as API-key create and update do.
- **SESS-4:** a `rememberMe: false` session lives one day at most, is never extended, and its
  multi-session device cookie lasts the browser session.
- **SESS-5:** session hooks run before the session cookie is set; on an error the row is
  deleted and no cookie is set. Impersonation writes `impersonatedBy` and its expiry in the
  same insert.
- **SESS-6:** `returned = false` columns are encrypted inside the cookie-cache payload
  instead of readable in the signed cookie.
- **SESS-7:** a JWT's `exp` is capped at its session's expiry.
- **SESS-8:** a sliding refresh that finds the session revoked mid-request answers signed out
  and clears the cookies instead of refreshing them.

**Admin and input.**

- **ATO-9 (medium):** admin `create-user` needs `user:set-email` to set `emailVerified`,
  and `create-user` and `update-user` refuse columns another plugin owns unless clients may
  set them, so a delegated `user:update` role can't turn off another user's two-factor.
- **ATO-11 (also reported as CFG-1):** an email address must be one plain address (Better
  Auth's `z.email()` rules), so address lists, whitespace, control characters and a second
  `@` answer `400 INVALID_EMAIL` instead of reaching the mailer.
- **SQLX-1 (low, fuzzing):** on SQLite, a NUL in a `contains`, `starts_with` or
  `ends_with` needle matched every row, and a stored value with a NUL hid from needles
  matching after it; on Postgres a NUL needle was a query error. SQLite text filters match
  byte by byte now, and on Postgres such a needle matches nothing.
- **SQLX-2 (low, fuzzing):** request text with a NUL answered an unauthenticated 500 on
  Postgres. Every endpoint refuses it with `400 INVALID_REQUEST_BODY`.

**Database.**

- **RACE-2:** `organization_limit` counts memberships inside the create's transaction after
  locking the user's row, so parallel creates can't all get through.
- **RACE-3:** `member` is unique on `(organization_id, user_id)`, so parallel adds or
  accepts can't leave a user in an organization twice.
- **RACE-4:** `two_factor.user_id` is unique, and enable replaces the row in a transaction
  that locks the user's row first, so parallel enables can't leave two TOTP secrets.
- **Account links:** `account` is unique on `(provider_id, account_id)`, so one provider
  account can't be linked to two users by requests at once.
- **DB-1:** on MySQL, a migration stopped between `ADD COLUMN` and its `UNIQUE` left the
  constraint missing for good. The migrator now reads unique constraints back on every
  database and plans the missing ones, and on MySQL a new column's foreign key goes in the
  same `ALTER TABLE` as the column.
- **DB-2:** on MySQL, an organization slug or invitation email longer than its key column
  answered 500 (or was cut into another value's key). Slugs are capped at 255 characters and
  invitation emails at 254 bytes.
- **DB-3, DB-4, DB-5 (info):** documented that sqlx's default database TLS mode checks no
  certificate, that UUID spellings match differently on Postgres and MySQL than on SQLite,
  and that MariaDB is unsupported.

**Configuration and keys.**

- **CFG-2:** every auth route response carries `Cache-Control: no-store` unless the
  endpoint set its own, `/get-session` included.
- **CFG-3:** `.build()` refuses a secret under about 120 bits of estimated entropy when
  `base_url` isn't local.
- **CFG-4:** `.build()` refuses a `base_url` with credentials, a query or a fragment, and
  an `http://` `base_url` on a host that isn't local.
- **CFG-5:** `Debug` of `VerifyEmail`, `ResetPassword`, `PluginEmail` and `SessionView`
  redacts links, tokens, codes and the email body.
- **CRYPTO-1:** a secret that is no longer first in `.secrets([..])` stops verifying the
  cookie cache, trusted-device cookies and other self-contained signed cookies; it still
  verifies session tokens and decrypts.

**Denial of service.**

- **DOS-1:** IPv6 clients are rate limited per /64 by default, as in Better Auth.
- **DOS-2:** the limiter keys accounts by a keyed hash instead of the raw body value and keeps
  at most 100,000 keys, evicting expired ones first.
- **DOS-3:** expired verification rows are deleted before a new one is stored.
- **DOS-4:** background emails run at most 8 at once per process, with up to 10,000 queued and
  a 60-second timeout, so a slow mailer can't starve password hashing.
- **DOS-5:** `/admin/list-users` answers at most 100 users when the request gives no
  `limit`, as in Better Auth.
- **DOS-6:** routes with a rate-limit rule of their own also limit each account the body
  names to 30 requests per 10 minutes, whatever the client IP.
- **DOS-7:** an organization can have at most 100 pending invitations by default.
- **DOS-8:** without a client IP, a request is limited on its `username` as well as its
  `email`, so a junk `email` doesn't give username guesses a fresh bucket.

### Core

All additive; no public trait changed.

- `Ctx::authoritative_session()`: the request's session as the database holds it, re-read
  only when the cookie cache answered. For authorization decisions; unlike
  `sensitive_session()` it lets API-key and impersonation sessions through.
- `Ctx::dont_remember()`: whether the session cookie this request sets, or carries, is from a
  `rememberMe: false` sign-in.
- `NewSession` and `Internal::create_session_with(user_id, remember_me, NewSession)`: a
  session with its own expiry and plugin columns in one insert.
- Claim model: `Internal::claim_user(user, link)`, `prove_email`,
  `create_user_verification` / `consume_user_verification`, `link_account_unless_claimed`,
  `remember_password_holder` and `user_fields`; `PluginBuilder::on_claim` with `Claim` and
  `prepare_user_input` with `UserInput` (all in `plugin_prelude`); `User::SECURITY_STAMP`
  and `UserView::security_stamp()`.
- `SchemaBuilder::unique(table, &[columns])` declares a unique constraint over several
  columns (`TableDef::uniques`, `UniqueDef`, `TableDef::unique_sets()`). Adapters report a
  violation as `DbError::UniqueViolation { table, column: None }`. `migrate::unique_key`
  and `migrate::duplicates_error` help adapters read and refuse them.
- `Builder::allow_insecure_config`, `Secret::entropy_bits`, `Secret::MIN_ENTROPY_BITS`,
  `Keys::verify_token`, `Ctx::signed_token_cookie`, and `RateLimit::ipv6_prefix`,
  `account_limit` and `max_keys`.
- `Organization::invitation_limit` and `codes::SOCIAL_ACCOUNT_ALREADY_LINKED`.

### Docs and tooling

- New [Production checklist](docs/reference/04-production-checklist.md), and a [Claiming an
  email](docs/concepts/03-security.md#claiming-an-email) section on the security page that
  says where fastauth is stricter than Better Auth.
- `examples/fullstack`: an axum, Postgres and React app on Better Auth's client, with a
  Playwright suite (`examples/fullstack/e2e.sh`). It isn't published.
- `scripts/ci.sh` runs every check the project has locally (fmt, clippy, tests on Postgres
  and MySQL, the Better Auth compat suites, audit, deny, docs, the website build and fuzzing);
  `--quick` runs fmt, clippy, the tests, audit and deny. Property tests cover core and the
  sqlx adapter, and `fuzz/` has 15 cargo-fuzz targets with minimised corpora.

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
