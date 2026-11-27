# Production checklist

The settings an app must get right before real users. Each item says what to set and why.
The IDs in parentheses are the findings of the security review of 0.5.0 that the item
covers.

## 1. Client IP

Rate limits are kept per client IP, so fastauth must see the real one (DOS-1, DOS-2, DOS-8).

- axum: serve with `app.into_make_service_with_connect_info::<SocketAddr>()`.
- actix-web: nothing to do; `auth.scope()` reads the peer address.
- Behind a proxy or load balancer the socket address is the proxy's. Set
  `.client_ip(ClientIp::Header(..))` for a header holding one address that the proxy
  overwrites (`fly-client-ip`, `cf-connecting-ip`, `x-real-ip` from your own nginx), or
  `ClientIp::TrustedProxies { header: "x-forwarded-for".into(), proxies: n }` with `n` the
  number of proxies that append to it.
- Never `ClientIp::Header("x-forwarded-for")`: its first value is whatever the client sent.
- `.build()` can't check this, because the socket address only exists per request. Watch
  the logs instead: the first request without a client IP logs an error (a warning when
  `base_url` is local). One such line means requests are limited per account or in one
  shared bucket, not per client.

See [Configuration](../get-started/03-configuration.md#rate-limits).

## 2. An https `base_url`

Set `base_url` to the public https origin (CFG-4). Cookies get `Secure` and the `__Secure-`
prefix from it, and emailed links are built from it.

- `.build()` always refuses a `base_url` with credentials (`https://user:pw@..`), a query or
  a fragment.
- It refuses an `http://` `base_url` unless the host is local (`localhost`, `*.localhost`
  or a loopback address), since cookies would go out without `Secure`.
- Terminate TLS in front of the app; fastauth doesn't serve it.

## 3. A generated secret

- Generate it with `fastauth secret` (from `cargo install fastauth-cli`) or
  `Secret::generate()`. Both give 64 random bytes as base64url. Load it with
  `Secret::from_env("FASTAUTH_SECRET")`, never from source.
- `.build()` refuses a secret with less than about 120 bits of estimated entropy when
  `base_url` isn't local (CFG-3): 32 zero bytes, `"a"` repeated, a short phrase.
- Only the first secret has to pass that check. A weak secret further down the list (one you
  are rotating off) logs a warning at `.build()` and isn't refused, so rotating needs no
  `allow_insecure_config`. Drop it once nothing encrypted under it is left.
- Rotate with `.secrets([new, old])`. Nobody is signed out, and a secret that is no longer
  first stops verifying the cookie cache and plugin cookies, so a leaked secret can't forge
  sessions once it's rotated out (CRYPTO-1). Keep the old secret in the list while columns
  encrypted under it (OAuth tokens, two-factor secrets) exist; there is no re-encryption
  command yet. [Security](../concepts/03-security.md#secrets) has the details.

## 4. No `allow_insecure_config` in production

`.allow_insecure_config(true)` turns the refusals in 2 and 3 into warnings. It's for local
development, CI and staging on a private network. Don't set it in production, or set it
from an environment variable that production doesn't have. It also turns the missing
client IP error from 1 into a warning.

## 5. A mailer that answers quickly or queues

Emails are sent in the background on tokio's blocking pool, at most 8 at once per process
(DOS-4).

- Up to 10,000 more wait their turn; past that, emails are dropped and logged with
  `tracing::error!`.
- A send is abandoned and logged after 60 seconds, but only when the mailer's future
  yields; a mailer that blocks its thread isn't cut off.
- So a slow SMTP server delays email without slowing sign-in, but a burst can still drop
  mail. Use an HTTP mail API with a short timeout, or hand emails to your own queue and
  return.
- Watch the logs for "fastauth could not send", "fastauth dropped" and "fastauth gave up".

## 6. The cookie cache, if you turn it on

`SessionConfig::cookie_cache(..)` is off by default. It saves a database read per request
and costs this:

- A revoked session keeps working wherever the cached session is enough, your own routes
  included, until the cache cookie expires. Admin and organization routes that change
  something, the `has-permission` routes and the `/revoke-*` routes read the session from
  the database, so a revoked, demoted or banned admin loses admin rights at once (SESS-1).
  Keep the max age to a few minutes.
- The cache cookie is signed and carries the user row, which the browser can read. Columns
  marked `#[field(returned = false)]` are encrypted inside it (SESS-6).
- Whoever holds the current secret can sign a cache cookie for any user (CRYPTO-1). Rotate a
  leaked secret out at once (item 3).

## 7. Rate limits

On by default; keep them on (DOS-1, DOS-2, DOS-6, DOS-8).

- 100 requests per 10 seconds per client and path, and 3 per 10 seconds on sign-in,
  sign-up, password reset, verification email and change-password. Plugins add their own
  rules.
- IPv6 clients are limited per /64, because one subscriber or cloud VM holds a whole /64.
  `RateLimit::ipv6_prefix(bits)` changes it.
- On every route with a rule of its own, each account the JSON body names (`email`,
  `username`) also has a limit of 30 requests per 10 minutes, whatever the client IP.
  `RateLimit::account_limit(None)` turns it off; you shouldn't need to.
- The limiter keeps at most 100,000 keys in memory (`RateLimit::max_keys(n)`).
- Counters are per process unless you set secondary storage. **An app that runs more than
  one instance needs `.secondary_storage(..)`** (the facade's `redis` feature): otherwise a
  client gets every limit once per instance it reaches. Set `.multi_instance(true)` too, and
  `.build()` warns when the storage is missing.
  [Running several instances](../concepts/04-multiple-instances.md) has the details.

## 8. Shared caches and CDNs

Every response from the auth routes carries `Cache-Control: no-store` unless the endpoint
set its own, so a shared cache never stores `/get-session` or a response holding a token
(CFG-2). Don't override it for the auth path in your CDN or proxy, and don't cache
`/api/auth/*` at all.

## 9. Database TLS

Connect with TLS that checks the server's certificate and host name (DB-3).

- MySQL: build with the facade's `mysql-tls` feature and add `ssl-mode=verify_identity` to
  `DATABASE_URL` (plus `ssl-ca=..` for a private CA). sqlx's default, `preferred`, checks
  no certificate and falls back to plaintext without saying so.
- Postgres: add `sslmode=verify-full` (plus `sslrootcert=..` for a private CA). The default
  `postgres` feature builds no TLS, so turn on a TLS backend for sqlx: `mysql-tls` does it,
  or add `features = ["tls-rustls"]` to your own `sqlx` dependency.

See [Databases](../concepts/02-database.md#mysql).

## 10. MySQL, not MariaDB

`Sqlx<MySql>` needs MySQL 8.0.17 or later. MariaDB isn't supported and fails at the first
`CREATE TABLE` (DB-5).

fastauth runs its transactions at READ COMMITTED on MySQL (F61-7), so keep `binlog_format` at
`ROW`, the default, or `MIXED`: under `STATEMENT`, InnoDB refuses writes at that level. If
you pass your own transaction with `in_tx`, begin it at READ COMMITTED too.

## 11. Migrations run to completion

- Generate migrations with `cargo run --bin fastauth -- generate`, review them, and apply
  them before the new version serves traffic.
- Run `cargo run --bin fastauth -- status` in CI; it exits 1 when a migration is missing.
- MySQL commits each DDL statement on its own, so a migration that fails can stop half-way.
  Run the migrator again: it reads the unique constraints back and adds any that are
  missing (DB-1).
- On Postgres, a unique index left invalid by a failed `CREATE UNIQUE INDEX CONCURRENTLY`
  doesn't count as the constraint (F61-8): the migrator plans the constraint again. Drop the
  invalid index (`DROP INDEX CONCURRENTLY ..`) once you've fixed the duplicates.
- The migrator refuses to add a unique constraint to a table that holds duplicates and
  names the rows. [Unique constraints on an existing
  database](../concepts/02-database.md#unique-constraints-on-an-existing-database) has a
  query to fix each table.

[Databases](../concepts/02-database.md#migrations) has the commands.

## 12. Logs

`Debug` output of `VerifyEmail`, `ResetPassword` and `PluginEmail` prints `[redacted]`
for the link, token, code and body, and `SessionView` for the session token (CFG-5). Your
own logging still has to keep secrets out:

- Don't log request bodies of the auth routes: they hold passwords, codes and tokens.
- Don't log the `Cookie`, `Set-Cookie`, `Authorization` or `set-auth-token` headers.
- Don't log the messages your mailer builds; they hold sign-in links and codes.

## 13. Organization and admin limits

- `Organization::invitation_limit(n)` caps pending invitations per organization (100 by
  default). Each invitation emails an address the inviter picks, so lower it when your
  organizations are small (DOS-7).
- `/admin/list-users` answers at most 100 users when the request gives no `limit` (DOS-5).
  Page with `limit` and `offset` in your admin UI.
