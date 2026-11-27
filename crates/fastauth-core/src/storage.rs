//! Secondary storage: a key-value store every instance of an app shares, such as Redis or
//! Valkey, for state that must agree across instances. Better Auth's `secondaryStorage`.
//!
//! fastauth keeps sessions, verification tokens and code attempts in the database, which
//! instances already share, and the cookie cache in the client's cookie. The one piece of
//! state each process keeps on its own is the rate limiter: with `.secondary_storage(..)` its
//! counters live here, so a limit holds across every instance instead of once per instance.
//! Without it, the limiter stays in memory.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// A key-value store with expiring keys, shared by every instance of the app. `fastauth-redis`
/// implements it for Redis and Valkey.
///
/// Keys fastauth writes start with `fastauth:`. A TTL of zero counts as the shortest TTL the
/// store has (one millisecond in Redis), never as "no expiry".
pub trait SecondaryStorage: Send + Sync + 'static {
    /// The value at `key`, or `None` when it doesn't exist or has expired.
    fn get(&self, key: &str) -> impl Future<Output = Result<Option<String>, StorageError>> + Send;

    /// Stores `value` at `key`, replacing any value and TTL it had. Without a `ttl` it never
    /// expires.
    fn set(
        &self,
        key: &str,
        value: &str,
        ttl: Option<Duration>,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Deletes `key`. Deleting a key that doesn't exist succeeds.
    fn delete(&self, key: &str) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Adds one to the counter at `key` and returns the new value, in one atomic step: two
    /// instances incrementing at once get different values. A key that doesn't exist starts at
    /// 1 and expires `ttl` later. Later increments don't extend the TTL, so the counter covers
    /// a fixed window from its first increment. Rate limits rely on both properties.
    fn increment(
        &self,
        key: &str,
        ttl: Duration,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;
}

/// A secondary storage call that failed, such as a lost connection.
#[derive(Debug, thiserror::Error)]
#[error("secondary storage: {0}")]
pub struct StorageError(#[source] Box<dyn std::error::Error + Send + Sync>);

impl StorageError {
    pub fn new(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(err))
    }
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The object-safe face of [`SecondaryStorage`], for the parts of core that hold one.
pub(crate) trait DynStorage: Send + Sync {
    fn increment<'a>(
        &'a self,
        key: &'a str,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<u64, StorageError>>;
}

impl<S: SecondaryStorage> DynStorage for S {
    fn increment<'a>(
        &'a self,
        key: &'a str,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<u64, StorageError>> {
        Box::pin(SecondaryStorage::increment(self, key, ttl))
    }
}

/// An in-memory [`SecondaryStorage`] for core's own tests, which can be made to fail.
#[cfg(test)]
pub(crate) mod fake {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{Duration, Instant};

    use super::{SecondaryStorage, StorageError};

    type Entries = HashMap<String, (String, Option<Instant>)>;

    #[derive(Clone, Default)]
    pub(crate) struct FakeStorage {
        entries: Arc<Mutex<Entries>>,
        down: Arc<AtomicBool>,
    }

    impl FakeStorage {
        /// Every call fails while `down` is true, like a store that lost its connection.
        pub(crate) fn set_down(&self, down: bool) {
            self.down.store(down, Ordering::SeqCst);
        }

        pub(crate) fn keys(&self) -> Vec<String> {
            self.entries.lock().unwrap().keys().cloned().collect()
        }

        fn live(&self) -> Result<MutexGuard<'_, Entries>, StorageError> {
            if self.down.load(Ordering::SeqCst) {
                return Err(StorageError::new(std::io::Error::other(
                    "connection refused",
                )));
            }
            let mut entries = self.entries.lock().unwrap();
            let now = Instant::now();
            entries.retain(|_, (_, expires)| expires.is_none_or(|at| at > now));
            Ok(entries)
        }
    }

    fn expiry(ttl: Duration) -> Instant {
        Instant::now() + ttl.max(Duration::from_millis(1))
    }

    impl SecondaryStorage for FakeStorage {
        async fn get(&self, key: &str) -> Result<Option<String>, StorageError> {
            Ok(self.live()?.get(key).map(|(value, _)| value.clone()))
        }

        async fn set(
            &self,
            key: &str,
            value: &str,
            ttl: Option<Duration>,
        ) -> Result<(), StorageError> {
            self.live()?
                .insert(key.to_owned(), (value.to_owned(), ttl.map(expiry)));
            Ok(())
        }

        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.live()?.remove(key);
            Ok(())
        }

        async fn increment(&self, key: &str, ttl: Duration) -> Result<u64, StorageError> {
            let mut entries = self.live()?;
            let (value, _) = entries
                .entry(key.to_owned())
                .or_insert_with(|| ("0".into(), Some(expiry(ttl))));
            let next = value
                .parse::<u64>()
                .map_err(|_| StorageError::new(std::io::Error::other("not a counter")))?
                + 1;
            *value = next.to_string();
            Ok(next)
        }
    }

    #[tokio::test]
    async fn fake_storage_passes_the_conformance_suite() {
        crate::testing::run_storage_conformance(FakeStorage::default()).await;
    }
}
