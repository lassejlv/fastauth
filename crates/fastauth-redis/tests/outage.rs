//! A Redis that stops answering mid-run (`docker pause`): sign-in stays fast and rate limits
//! still hold in the instance's memory, and the shared counters take over again once Redis
//! is back. Needs `REDIS_URL` and `REDIS_CONTAINER`, the name of the Docker container behind
//! it, which the test pauses and unpauses (`scripts/ci.sh` sets both); skipped without them.
//! In its own test binary, so pausing Redis can't stall another test.

use std::net::IpAddr;
use std::process::Command;
use std::time::{Duration, Instant};

use bytes::Bytes;
use fastauth_core::ClientAddr;
use fastauth_core::crypto::{Argon2id, random_string};
use fastauth_core::prelude::*;
use fastauth_redis::RedisStorage;
use http::{Method, Request, StatusCode, header};
use redis::AsyncCommands;
use serde_json::json;

const TIMEOUT: Duration = Duration::from_millis(200);

/// Unpauses the container when dropped, so a failing assertion leaves Redis running.
struct Paused<'a>(&'a str);

impl<'a> Paused<'a> {
    fn new(container: &'a str) -> Self {
        docker("pause", container);
        Self(container)
    }
}

impl Drop for Paused<'_> {
    fn drop(&mut self) {
        docker("unpause", self.0);
    }
}

fn docker(command: &str, container: &str) {
    let output = Command::new("docker")
        .args([command, container])
        .output()
        .expect("run docker");
    assert!(
        output.status.success(),
        "docker {command} {container}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn client() -> IpAddr {
    let n = u32::from_str_radix(&random_string(4, b"0123456789abcdef"), 16).unwrap();
    IpAddr::from([198, 19, (n >> 8) as u8, n as u8])
}

/// A sign-in from `ip` for an account that doesn't exist: 401, or 429 once rate limited.
async fn sign_in(auth: &Auth<MemoryAdapter>, ip: IpAddr) -> (StatusCode, Duration) {
    let body = json!({ "email": "nobody@acme.dk", "password": "wrong password" });
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/sign-in/email")
        .header(header::ORIGIN, "http://localhost:3000")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Bytes::from(body.to_string()))
        .unwrap();
    request.extensions_mut().insert(ClientAddr(ip));
    let started = Instant::now();
    let status = auth.handle(request).await.status();
    (status, started.elapsed())
}

#[tokio::test]
async fn a_paused_redis_costs_a_bounded_wait_then_none() {
    let (Ok(url), Ok(container)) = (std::env::var("REDIS_URL"), std::env::var("REDIS_CONTAINER"))
    else {
        eprintln!("REDIS_URL or REDIS_CONTAINER is not set; skipping the Redis outage test");
        return;
    };
    let auth = FastAuth::builder()
        .secret(Secret::from_bytes(
            b"a paused redis, and 32 bytes or more".to_vec(),
        ))
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .secondary_storage(RedisStorage::connect(&url).await.unwrap())
        .secondary_storage_timeout(TIMEOUT)
        .build()
        .expect("valid config");
    let mut raw = redis::Client::open(url.as_str())
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();

    let ip = client();
    assert_eq!(sign_in(&auth, ip).await.0, StatusCode::UNAUTHORIZED);
    let counter = format!("fastauth:rate-limit:{ip}|/sign-in/*|");
    assert_eq!(
        raw.get::<_, Option<String>>(&counter)
            .await
            .unwrap()
            .as_deref(),
        Some("1")
    );

    let paused = Paused::new(&container);
    let mut statuses = Vec::new();
    for _ in 0..5 {
        let (status, took) = sign_in(&auth, ip).await;
        assert!(
            took >= TIMEOUT && took < TIMEOUT + Duration::from_millis(300),
            "a request waits for one timeout while the breaker is closed: {took:?}"
        );
        statuses.push(status);
    }
    assert_eq!(
        statuses,
        [StatusCode::UNAUTHORIZED; 3]
            .into_iter()
            .chain([StatusCode::TOO_MANY_REQUESTS; 2])
            .collect::<Vec<_>>(),
        "the sign-in limit (3 per 10 s) holds in memory"
    );
    let (status, took) = sign_in(&auth, ip).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(took < TIMEOUT, "five failures open the breaker: {took:?}");
    let (status, took) = sign_in(&auth, client()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(took < TIMEOUT, "{took:?}");
    drop(paused);

    tokio::time::sleep(Duration::from_millis(5_100)).await;
    let other = client();
    assert_eq!(sign_in(&auth, other).await.0, StatusCode::UNAUTHORIZED);
    let counter = format!("fastauth:rate-limit:{other}|/sign-in/*|");
    assert_eq!(
        raw.get::<_, Option<String>>(&counter)
            .await
            .unwrap()
            .as_deref(),
        Some("1"),
        "after the cool-down a probe reaches Redis, which counts again"
    );
}
