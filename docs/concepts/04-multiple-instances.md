# Running several instances

Most of what fastauth knows lives in the database, so two instances of an app behind a load
balancer already agree on it. The exception is the rate limiter, which counts in each
process's memory unless you give fastauth **secondary storage**: a key-value store every
instance shares, such as Redis or Valkey. This page says what each instance keeps, how to turn
secondary storage on, and how it compares with Better Auth's `secondaryStorage`.

## What instances share

| State | Where it lives | With several instances |
|---|---|---|
| Sessions | the database | Shared. A revoked session is refused by every instance on its next database read. |
| The cookie cache | a signed cookie in the client | Every instance trusts it the same way until it expires (see [below](#sessions-and-the-cookie-cache)). |
| Verification tokens, email OTPs, two-factor attempts | the database, consumed with a conditional delete or a compare-and-swap on the attempt counter | Shared and single-use: two instances can't both accept one token or one guess. |
| Rate limit counters | each process's memory, or secondary storage | Shared only with secondary storage. Without it, each instance allows the full limit, so a client that reaches n instances gets n times every limit. |
| The email queue | each process | Each instance sends its own emails, at most 8 at once ([Production checklist](../reference/04-production-checklist.md#5-a-mailer-that-answers-quickly-or-queues)). |

So an app with more than one instance needs secondary storage for its rate limits, and
nothing else.

## Turning on secondary storage

Add the `redis` feature (`redis-tls` for `rediss://` URLs), connect, and pass the storage to
the builder:

```toml
fastauth = { version = "0.8", features = ["redis"] }
```

```rust
use fastauth::prelude::*;
use fastauth::redis::RedisStorage;

pub async fn build(pool: PgPool) -> anyhow::Result<Auth<Sqlx<Postgres>>> {
    let storage = RedisStorage::connect(&std::env::var("REDIS_URL")?).await?;
    let auth = FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .secondary_storage(storage)
        .multi_instance(true)
        .build()?;
    Ok(auth)
}
```

- `RedisStorage::connect` takes `redis://[user:password@]host[:port][/db]`, `unix:///path`,
  or `rediss://` with `redis-tls` (rustls, checked against the platform's root
  certificates). It fails when the server doesn't answer, so a wrong URL shows at start-up.
  `RedisStorage::new(manager)` takes a `redis::aio::ConnectionManager` you configured
  yourself.
- The connection is one multiplexed connection that reconnects on its own. `RedisStorage` is
  cheap to clone.
- Redis 7 and Valkey 8 are tested. Redis Cluster isn't supported; use one primary.
- Every instance must use the same secret (they already must, to read each other's cookies)
  and the same Redis database.

`.multi_instance(true)` only feeds a check: `.build()` logs a warning when the app says it
runs several instances, rate limiting is on, and no secondary storage is set. It changes
nothing else.

## Rate limits in secondary storage

With secondary storage, each bucket is a counter at
`fastauth:rate-limit:<client>|<rule>|<path>`. The first request of a window creates it with
a TTL of the rule's period, and the window allows the rule's `max` requests. `RedisStorage`
does the increment and the TTL in one Lua script, so two instances can't both take the last
request. This is Better Auth's secondary-storage limiter.

- **Fixed windows, not GCRA.** The in-memory limiter refills gradually (3 per 10 seconds is
  one every 3.3 seconds). A fixed window resets at once at its end, so a client can send
  `max` requests at the end of one window and `max` more at the start of the next. Every
  limit still holds per window.
- **Account limits are shared too.** An account bucket is keyed by an HMAC of the email or
  username under a key derived from your secret, so instances agree on it and Redis never
  sees the address. Client IPs do appear in keys.
- **Keys expire on their own.** A counter lives one period. `RateLimit::max_keys` only bounds
  the in-memory limiter.
- **When Redis fails or is slow**, the instance falls back to its in-memory limiter, so
  limits still hold per instance, and logs `fastauth: secondary storage failed` with
  `tracing::error!` at most once a minute. Sign-in keeps working; see below for how long it
  waits.

## When the storage is slow or down

A Redis that stops answering (a network partition, a paused or overloaded server) would
otherwise hold every rate-limited request, sign-in included, until the connection gave up.
fastauth bounds that wait:

- **Every storage call has a timeout**, 100 ms by default. Change it with
  `.secondary_storage_timeout(Duration::from_millis(..))`. A call that fails or times out
  counts the request in the instance's memory instead. A request waits for at most one
  timeout: once one of its buckets fails, its other buckets (the account limit on sign-in)
  stay in memory.
- **A circuit breaker** stops calling the storage after 5 failed or timed-out calls in a
  row. For the next 5 seconds every request uses the in-memory limiter and doesn't wait at
  all. Then one request probes the storage: if it answers, the shared counters decide again;
  if not, the breaker stays open another 5 seconds. During an outage, one request per
  instance every 5 seconds waits for the timeout.
- **`RedisStorage::connect`** also sets timeouts on its connection: 1 second per connection
  attempt and 250 ms per command, so calls your own code makes can't hang either. A
  `ConnectionManager` you pass to `RedisStorage::new` keeps its own settings; fastauth's
  timeout still applies to its calls.

Pick a timeout well above your store's normal latency: a call that is merely slow also falls
back, and five of them in a row open the breaker. 100 ms is about a hundred round trips to a
Redis on the same network. While the storage is out, each instance allows the full limit, as
it does without secondary storage.

## Sessions and the cookie cache

Sessions live in the database, which every instance reads. Without the cookie cache, every
request reads the session and the user from the database, so a session revoked through one
instance, or a user banned through it, is refused by every other instance on the next
request.

With `SessionConfig::cookie_cache(max_age)`, a request that carries a valid cache cookie
doesn't read the database. A revoked session then keeps working wherever the cached session
is enough, on every instance alike, until the cache cookie expires. Admin and organization
routes that change something read the database anyway, so a banned or demoted admin loses
admin rights at once on every instance ([Production checklist](../reference/04-production-checklist.md#6-the-cookie-cache-if-you-turn-it-on)).
Better Auth behaves the same: its cookie cache is checked before secondary storage. Keep the
max age to a few minutes, or leave the cache off.

## Better Auth's `secondaryStorage`, compared

Better Auth 1.7.28 sends three things through `secondaryStorage`: sessions (with
`session.storeSessionInDatabase` off by default, so they live only there), verification
values, and rate limits. fastauth sends only rate limits:

| | Better Auth with `secondaryStorage` | fastauth with `.secondary_storage(..)` |
|---|---|---|
| Rate limits | `increment` per bucket, fixed window | the same |
| Sessions | in secondary storage, plus an `active-sessions-<userId>` list | in the database; the cookie cache saves the reads |
| Verification values | in secondary storage, consumed with `getAndDelete` | in the database, consumed with a conditional delete |
| `getAndDelete` | required | not part of the trait |

Moving sessions and verification values out of the database is a speed-up, not a fix: the
database is already shared and already consumes tokens atomically. Nothing on the wire
changes, so Better Auth's client works the same with or without secondary storage.

## Your own storage

`RedisStorage` implements `fastauth::storage::SecondaryStorage`, which you can implement for
another store:

```rust
pub trait SecondaryStorage: Send + Sync + 'static {
    fn get(&self, key: &str) -> impl Future<Output = Result<Option<String>, StorageError>> + Send;
    fn set(
        &self,
        key: &str,
        value: &str,
        ttl: Option<Duration>,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
    fn delete(&self, key: &str) -> impl Future<Output = Result<(), StorageError>> + Send;
    fn increment(
        &self,
        key: &str,
        ttl: Duration,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;
}
```

`Duration` is `std::time::Duration`. `increment` must be atomic across instances, start a
missing key at 1 with the TTL, and never extend the TTL afterwards. A TTL of zero means the
shortest one the store has, never "no expiry". The conformance suite checks all of it,
concurrent increments included; `fastauth-redis` runs it against Redis 7 and Valkey 8:

```rust
// [dev-dependencies] fastauth-core = { version = "0.8", features = ["testing"] }
#[tokio::test]
async fn conformance() {
    let storage = fastauth::redis::RedisStorage::connect("redis://127.0.0.1:6379")
        .await
        .unwrap();
    fastauth_core::testing::run_storage_conformance(storage).await;
}
```

`fastauth-redis` also has a two-instance test: two `Auth` instances on one Postgres database
and one Redis show that the sign-in limit is global, that a session revoked through one is
refused by the other (at once without the cookie cache, after the window with it), and that
an admin banned through one is refused admin routes and sign-in on the other.
