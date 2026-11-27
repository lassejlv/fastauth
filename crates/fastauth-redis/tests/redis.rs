//! `RedisStorage` against a real server at `REDIS_URL` (Redis 7 or Valkey; `scripts/ci.sh`
//! runs it against both). Skipped when `REDIS_URL` isn't set.

use std::time::Duration;

use fastauth_core::storage::SecondaryStorage;
use fastauth_redis::RedisStorage;
use redis::AsyncCommands;

async fn storage() -> Option<(RedisStorage, redis::aio::MultiplexedConnection)> {
    let Ok(url) = std::env::var("REDIS_URL") else {
        eprintln!("REDIS_URL is not set; skipping the Redis test");
        return None;
    };
    let raw = redis::Client::open(url.as_str())
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .expect("connect to REDIS_URL");
    Some((RedisStorage::connect(&url).await.unwrap(), raw))
}

#[tokio::test]
async fn conformance() {
    let Some((storage, _)) = storage().await else {
        return;
    };
    fastauth_core::testing::run_storage_conformance(storage).await;
}

#[tokio::test]
async fn counters_expire_in_milliseconds_and_never_live_forever() {
    let Some((storage, mut raw)) = storage().await else {
        return;
    };
    let key = format!("fastauth:test:{}", fastauth_core::crypto::random_token());
    storage
        .increment(&key, Duration::from_millis(1500))
        .await
        .unwrap();
    let ttl: i64 = raw.pttl(&key).await.unwrap();
    assert!((1..=1500).contains(&ttl), "PTTL {ttl}");

    let () = raw.set(&key, "41").await.unwrap();
    assert_eq!(raw.pttl::<_, i64>(&key).await.unwrap(), -1);
    assert_eq!(
        storage
            .increment(&key, Duration::from_secs(5))
            .await
            .unwrap(),
        42
    );
    let ttl: i64 = raw.pttl(&key).await.unwrap();
    assert!(
        (1..=5000).contains(&ttl),
        "a counter without a TTL gets one: PTTL {ttl}"
    );

    storage.set(&key, "x", Some(Duration::ZERO)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        storage.get(&key).await.unwrap(),
        None,
        "a zero TTL is the shortest one"
    );
}

#[tokio::test]
async fn errors_are_storage_errors() {
    let Some((storage, mut raw)) = storage().await else {
        return;
    };
    let key = format!("fastauth:test:{}", fastauth_core::crypto::random_token());
    let () = raw.set(&key, "not a number").await.unwrap();
    let err = storage
        .increment(&key, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(err.to_string().starts_with("secondary storage:"), "{err}");
    let () = raw.del(&key).await.unwrap();
}

#[tokio::test]
async fn connect_fails_on_a_server_that_is_not_there() {
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        RedisStorage::connect("redis://127.0.0.1:1"),
    )
    .await
    .expect("connect gives up");
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(30));
}

/// `rediss://` with the `tls` feature, when `REDIS_TLS_URL` points at a TLS server whose
/// certificate the platform trusts (`SSL_CERT_FILE` works for a test CA).
#[cfg(feature = "tls")]
#[tokio::test]
async fn tls() {
    let Ok(url) = std::env::var("REDIS_TLS_URL") else {
        eprintln!("REDIS_TLS_URL is not set; skipping the TLS test");
        return;
    };
    let storage = RedisStorage::connect(&url).await.expect("connect over TLS");
    let key = format!("fastauth:test:{}", fastauth_core::crypto::random_token());
    assert_eq!(
        storage
            .increment(&key, Duration::from_secs(5))
            .await
            .unwrap(),
        1
    );
    storage.delete(&key).await.unwrap();
}
