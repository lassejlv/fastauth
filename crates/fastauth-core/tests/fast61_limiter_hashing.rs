//! FAST-61 adversarial review of the 0.6.0 fixes in #47: the IPv6 prefix rate limiter and the
//! password hashing pool. Tests named `sec_*` assert the secure or correct behaviour and fail
//! on main e1c00a33 on purpose; tests named `guard_*` pass and pin behaviour that was checked.
//!
//! Run: cargo test -p fastauth-core --test fast61_limiter_hashing -- --nocapture --test-threads=1

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration as StdDuration, Instant};

use bytes::Bytes;
use common::{Client, ORIGIN, secret};
use fastauth_core::crypto::{Argon2id, PasswordHasher};
use fastauth_core::prelude::*;
use http::{Method, Request, StatusCode, header};
use serde_json::json;

fn fast_hasher() -> EmailPassword {
    EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1))
}

fn limited_auth(source: ClientIp, limit: RateLimit) -> Auth<MemoryAdapter> {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(fast_hasher())
        .client_ip(source)
        .rate_limit(limit)
        .build()
        .expect("valid config")
}

/// A sign-in guess for a fresh email each time (so the per-account limit stays out of the
/// way) with `header: value`, answering whether it was rate limited.
async fn limited(auth: &Auth<MemoryAdapter>, header_name: &str, value: &str, email: &str) -> bool {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/sign-in/email")
        .header(header::ORIGIN, ORIGIN)
        .header(header_name, value)
        .body(Bytes::from(
            json!({ "email": email, "password": "guess" }).to_string(),
        ))
        .unwrap();
    auth.handle(request).await.status() == StatusCode::TOO_MANY_REQUESTS
}

fn header_ip() -> ClientIp {
    ClientIp::Header("x-client-ip".into())
}

// ---------------------------------------------------------------------- IPv6 limiter

/// guard: the IPv4-mapped spelling of an IPv4 client (what a dual-stack socket reports) is
/// the same bucket as the IPv4 address, and an IPv4 bucket never collides with an IPv6 one.
#[tokio::test]
async fn guard_ipv4_mapped_ipv6_shares_the_ipv4_bucket() {
    let auth = limited_auth(header_ip(), RateLimit::default());
    for n in 0..3 {
        assert!(
            !limited(
                &auth,
                "x-client-ip",
                "203.0.113.9",
                &format!("a{n}@acme.dk")
            )
            .await
        );
    }
    assert!(limited(&auth, "x-client-ip", "::ffff:203.0.113.9", "b@acme.dk").await);
    assert!(limited(&auth, "x-client-ip", "::FFFF:cb00:7109", "c@acme.dk").await);
    assert!(!limited(&auth, "x-client-ip", "2001:db8::203.0.113.9", "d@acme.dk").await);
    assert!(!limited(&auth, "x-client-ip", "203.0.113.10", "e@acme.dk").await);
}

/// guard: through `TrustedProxies`, IPv6 clients in X-Forwarded-For are grouped by /64, the
/// spoofed left part is ignored, and the next /64 is a different client.
#[tokio::test]
async fn guard_trusted_proxies_group_ipv6_clients_by_prefix() {
    let auth = limited_auth(
        ClientIp::TrustedProxies {
            header: "x-forwarded-for".into(),
            proxies: 1,
        },
        RateLimit::default(),
    );
    let mut statuses = Vec::new();
    for n in 1..=6u16 {
        let spoofed = format!("{n}.{n}.{n}.{n}, 2001:db8:1:2:{n:x}::{n:x}");
        statuses.push(limited(&auth, "x-forwarded-for", &spoofed, &format!("a{n}@acme.dk")).await);
    }
    assert_eq!(statuses, [false, false, false, true, true, true]);
    assert!(
        !limited(
            &auth,
            "x-forwarded-for",
            "6.6.6.6, 2001:db8:1:3::1",
            "b@acme.dk"
        )
        .await
    );
}

/// guard: `ipv6_prefix` edges. 56 groups a /56 (a home subscriber's delegation), 128 keeps
/// every address apart, 0 puts every IPv6 client in one bucket and leaves IPv4 apart.
#[tokio::test]
async fn guard_ipv6_prefix_edges() {
    let wide = limited_auth(header_ip(), RateLimit::default().ipv6_prefix(56));
    for n in 0..3u16 {
        let ip = format!("2001:db8:1:2{n:02x}::1");
        assert!(!limited(&wide, "x-client-ip", &ip, &format!("a{n}@acme.dk")).await);
    }
    assert!(limited(&wide, "x-client-ip", "2001:db8:1:2ff:ffff::1", "b@acme.dk").await);
    assert!(!limited(&wide, "x-client-ip", "2001:db8:1:300::1", "c@acme.dk").await);

    let each = limited_auth(header_ip(), RateLimit::default().ipv6_prefix(128));
    for n in 1..=6u16 {
        let ip = format!("2001:db8:1:2::{n:x}");
        assert!(!limited(&each, "x-client-ip", &ip, &format!("a{n}@acme.dk")).await);
    }

    let all = limited_auth(header_ip(), RateLimit::default().ipv6_prefix(0));
    for n in 1..=3u16 {
        let ip = format!("{n:x}::1");
        assert!(!limited(&all, "x-client-ip", &ip, &format!("a{n}@acme.dk")).await);
    }
    assert!(limited(&all, "x-client-ip", "fe80::1", "b@acme.dk").await);
    assert!(!limited(&all, "x-client-ip", "203.0.113.9", "c@acme.dk").await);
}

/// guard: client IP spellings that don't parse (a port, brackets, a zone id, a list in a
/// single-address header) count as no client IP. Varying them doesn't buy fresh buckets for
/// one account: the request falls back to the per-account bucket.
#[tokio::test]
async fn guard_unparseable_client_ips_fall_back_to_the_account_bucket() {
    let auth = limited_auth(header_ip(), RateLimit::default());
    let forms = [
        "203.0.113.9:443",
        "[2001:db8::1]:443",
        "fe80::1%eth0",
        "1.2.3.4, 5.6.7.8",
        "2001:db8::1/64",
    ];
    let mut statuses = Vec::new();
    for form in forms {
        statuses.push(limited(&auth, "x-client-ip", form, "victim@acme.dk").await);
    }
    assert_eq!(statuses, [false, false, false, true, true]);
}

// ---------------------------------------------------------------------- hashing pool

/// A hasher that records how many calls run at once and, while `open` is false, holds each
/// call (and its blocking-pool thread) until it is set.
#[derive(Default)]
struct Gate {
    open: AtomicBool,
    in_flight: AtomicUsize,
    most: AtomicUsize,
    calls: AtomicUsize,
}

struct GatedHasher(Arc<Gate>);

impl GatedHasher {
    fn enter(&self) {
        let gate = &self.0;
        gate.calls.fetch_add(1, Ordering::SeqCst);
        let now = gate.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        gate.most.fetch_max(now, Ordering::SeqCst);
        let started = Instant::now();
        while !gate.open.load(Ordering::SeqCst) && started.elapsed() < StdDuration::from_secs(30) {
            std::thread::sleep(StdDuration::from_millis(2));
        }
        gate.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl PasswordHasher for GatedHasher {
    fn hash(&self, password: &str) -> Result<String, String> {
        self.enter();
        Ok(format!("plain:{password}"))
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, String> {
        self.enter();
        Ok(hash == format!("plain:{password}"))
    }
}

/// Opens the gate when dropped, so a failing assertion doesn't leave blocked threads.
struct OpenOnDrop(Arc<Gate>);

impl Drop for OpenOnDrop {
    fn drop(&mut self) {
        self.0.open.store(true, Ordering::SeqCst);
    }
}

fn gated_auth(gate: &Arc<Gate>) -> Auth<MemoryAdapter> {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(GatedHasher(gate.clone())))
        .rate_limit(RateLimit::disabled())
        .build()
        .expect("valid config")
}

fn sign_in_request(email: &str) -> Request<Bytes> {
    Request::builder()
        .method(Method::POST)
        .uri("/api/auth/sign-in/email")
        .header(header::ORIGIN, ORIGIN)
        .body(Bytes::from(
            json!({ "email": email, "password": "wrong guess" }).to_string(),
        ))
        .unwrap()
}

fn cpus() -> usize {
    std::thread::available_parallelism().map_or(2, |n| n.get())
}

async fn wait_until(condition: impl Fn() -> bool) {
    let started = Instant::now();
    while !condition() && started.elapsed() < StdDuration::from_secs(5) {
        tokio::time::sleep(StdDuration::from_millis(5)).await;
    }
}

/// FAST61-H1: `Passwords::run` (crypto.rs:376-393) holds the semaphore permit in the request
/// future and moves only the hasher into `spawn_blocking`. When the request future is dropped
/// while the hash runs (a client that disconnects, a tower `TimeoutLayer`, a proxy timeout),
/// the permit goes back at once but argon2 keeps running on its blocking-pool thread. The
/// next requests take the freed permits and start more. Repeating it, a client runs as many
/// hashes at once as tokio has blocking threads (512 by default, 19 MiB each with the OWASP
/// parameters, about 9.5 GiB), which is what the CPU-count cap was meant to stop.
///
/// Here each sign-in runs under `tokio::time::timeout` (what `TimeoutLayer` does) and the
/// hasher is held so the hashes overlap; three rounds of timed-out sign-ins.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_requests_dropped_mid_hash_do_not_lift_the_hashing_cap() {
    let gate = Arc::new(Gate::default());
    gate.open.store(true, Ordering::SeqCst);
    let auth = gated_auth(&gate);
    let mut owner = Client::new(auth.clone());
    owner.sign_up("ada@acme.dk", "correct horse").await;
    gate.open.store(false, Ordering::SeqCst);
    gate.most.store(0, Ordering::SeqCst);
    let release = OpenOnDrop(gate.clone());
    let cap = cpus();

    for _round in 0..3 {
        let tasks: Vec<_> = (0..cap * 2)
            .map(|_| {
                let auth = auth.clone();
                tokio::spawn(async move {
                    tokio::time::timeout(
                        StdDuration::from_millis(300),
                        auth.handle(sign_in_request("ada@acme.dk")),
                    )
                    .await
                    .is_err()
                })
            })
            .collect();
        for task in tasks {
            assert!(task.await.unwrap(), "the gated sign-in should time out");
        }
    }
    let most = gate.most.load(Ordering::SeqCst);
    let running = gate.in_flight.load(Ordering::SeqCst);
    drop(release);
    wait_until(|| gate.in_flight.load(Ordering::SeqCst) == 0).await;
    println!(
        "[3 rounds of {} sign-ins timed out mid-hash] cap={cap} most at once={most} still running after the requests ended={running}",
        cap * 2
    );
    assert!(
        most <= cap,
        "{most} password hashes ran at once with a cap of {cap}: requests dropped mid-hash \
         gave their permits back while their hashes kept running"
    );
}

/// guard: without dropped requests, a burst of sign-ins hashes at most CPU-count at once, the
/// rest wait in line, and all of them finish.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn guard_concurrent_sign_ins_hash_at_most_cpu_count_at_once() {
    let gate = Arc::new(Gate::default());
    gate.open.store(true, Ordering::SeqCst);
    let auth = gated_auth(&gate);
    Client::new(auth.clone())
        .sign_up("ada@acme.dk", "correct horse")
        .await;
    gate.open.store(false, Ordering::SeqCst);
    gate.most.store(0, Ordering::SeqCst);
    let release = OpenOnDrop(gate.clone());
    let cap = cpus();
    let tasks: Vec<_> = (0..cap * 3)
        .map(|_| {
            let auth = auth.clone();
            tokio::spawn(async move { auth.handle(sign_in_request("ada@acme.dk")).await.status() })
        })
        .collect();
    wait_until(|| gate.in_flight.load(Ordering::SeqCst) >= cap).await;
    tokio::time::sleep(StdDuration::from_millis(200)).await;
    let most = gate.most.load(Ordering::SeqCst);
    drop(release);
    for task in tasks {
        assert_eq!(task.await.unwrap(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(most, cap);
}

/// FAST61-H2 (info): `verify_dummy` (crypto.rs:409-421) computes its dummy hash on first use,
/// so the first sign-in for an unknown email after a start runs the hasher twice (hash, then
/// verify) where a known email with a wrong password runs it once. On a fresh instance (a
/// deploy, a serverless cold start) that one request takes about twice as long.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sec_first_unknown_email_sign_in_costs_one_hash() {
    let gate = Arc::new(Gate::default());
    gate.open.store(true, Ordering::SeqCst);
    let auth = gated_auth(&gate);
    let before = gate.calls.load(Ordering::SeqCst);
    let status = auth
        .handle(sign_in_request("nobody@acme.dk"))
        .await
        .status();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let unknown = gate.calls.load(Ordering::SeqCst) - before;

    Client::new(auth.clone())
        .sign_up("ada@acme.dk", "correct horse")
        .await;
    let before = gate.calls.load(Ordering::SeqCst);
    auth.handle(sign_in_request("ada@acme.dk")).await;
    let known = gate.calls.load(Ordering::SeqCst) - before;
    println!("[hasher calls] first unknown email={unknown} known email, wrong password={known}");
    assert_eq!(
        unknown, known,
        "the first unknown-email sign-in runs the hasher {unknown} times, a known email {known}"
    );
}
