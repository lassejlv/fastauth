//! Redis and Valkey [secondary storage](fastauth_core::storage) for
//! [fastauth](https://github.com/lassejlv/fastauth): with it, every instance of an app counts
//! rate limits in one place, so two instances behind a load balancer don't allow twice the
//! limit.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use fastauth_core::prelude::*;
//! use fastauth_redis::RedisStorage;
//!
//! let storage = RedisStorage::connect("redis://127.0.0.1:6379").await?;
//! let auth = FastAuth::builder()
//!     .secret(Secret::from_env("FASTAUTH_SECRET")?)
//!     .base_url("https://acme.dk")
//!     .database(MemoryAdapter::new())
//!     .secondary_storage(storage)
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! Tested with Redis 7 and Valkey 8. A rate limit is one atomic Lua script per
//! bucket (`INCR`, and `PEXPIRE` on the first request of a window), so concurrent requests on
//! different instances never both take the last request. Redis Cluster isn't supported; use a
//! single primary (with replicas or Sentinel in front if you like).

use std::fmt;
use std::time::Duration;

use fastauth_core::storage::{SecondaryStorage, StorageError};
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::{AsyncCommands, Script};

/// Increments `KEYS[1]` and sets its TTL to `ARGV[1]` milliseconds when the increment created
/// it. A counter that somehow has no TTL gets one too, so it can't block a client for good.
const INCREMENT: &str = r"
local count = redis.call('INCR', KEYS[1])
if count == 1 or redis.call('PTTL', KEYS[1]) == -1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return count
";

/// How long [`RedisStorage::connect`] waits for each connection attempt, at start-up and on
/// every reconnect.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(1);

/// How long [`RedisStorage::connect`] waits for the answer to each command.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_millis(250);

/// [`SecondaryStorage`] on Redis or Valkey, through a [`ConnectionManager`]: one multiplexed
/// connection that reconnects on its own after a dropped connection. Cheap to clone; clones
/// share the connection.
#[derive(Clone)]
pub struct RedisStorage {
    conn: ConnectionManager,
    increment: Script,
}

impl fmt::Debug for RedisStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisStorage").finish_non_exhaustive()
    }
}

impl RedisStorage {
    /// Connects to `url`: `redis://[user:password@]host[:port][/db]`, `unix:///path`, or
    /// `rediss://` with the `tls` feature. Fails when the server doesn't answer, so a wrong URL
    /// shows up at start-up rather than on the first sign-in.
    ///
    /// Each connection attempt gives up after [`CONNECTION_TIMEOUT`] and each command after
    /// [`RESPONSE_TIMEOUT`]. fastauth's rate limiter puts its own, shorter timeout on every
    /// call ([`secondary_storage_timeout`](fastauth_core::Builder::secondary_storage_timeout));
    /// these bound the calls an app makes itself.
    pub async fn connect(url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(url)?;
        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(CONNECTION_TIMEOUT))
            .set_response_timeout(Some(RESPONSE_TIMEOUT));
        Ok(Self::new(
            ConnectionManager::new_with_config(client, config).await?,
        ))
    }

    /// Uses a connection manager the app already has, with its own configuration (timeouts,
    /// retries). fastauth's rate limiter still bounds each of its calls with
    /// [`secondary_storage_timeout`](fastauth_core::Builder::secondary_storage_timeout).
    pub fn new(conn: ConnectionManager) -> Self {
        Self {
            conn,
            increment: Script::new(INCREMENT),
        }
    }
}

/// A TTL in milliseconds; zero becomes one, the shortest TTL Redis has.
fn millis(ttl: Duration) -> u64 {
    u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX).max(1)
}

impl SecondaryStorage for RedisStorage {
    async fn get(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.conn.clone().get(key).await.map_err(StorageError::new)
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), StorageError> {
        let mut conn = self.conn.clone();
        let result: redis::RedisResult<()> = match ttl {
            Some(ttl) => conn.pset_ex(key, value, millis(ttl)).await,
            None => conn.set(key, value).await,
        };
        result.map_err(StorageError::new)
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let deleted: redis::RedisResult<u64> = self.conn.clone().del(key).await;
        deleted.map(drop).map_err(StorageError::new)
    }

    async fn increment(&self, key: &str, ttl: Duration) -> Result<u64, StorageError> {
        self.increment
            .key(key)
            .arg(millis(ttl))
            .invoke_async(&mut self.conn.clone())
            .await
            .map_err(StorageError::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttls_are_whole_milliseconds_and_never_zero() {
        assert_eq!(millis(Duration::ZERO), 1);
        assert_eq!(millis(Duration::from_micros(10)), 1);
        assert_eq!(millis(Duration::from_secs(10)), 10_000);
    }
}
