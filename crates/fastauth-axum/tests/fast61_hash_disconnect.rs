//! FAST-61 review of #47's hashing pool, over a real socket: does a client that disconnects
//! while its password is being hashed give the hashing permit back early?
//!
//! Run: cargo test -p fastauth-axum --test fast61_hash_disconnect -- --nocapture --test-threads=1

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration as StdDuration, Instant};

use bytes::Bytes;
use fastauth_axum::AuthRouter;
use fastauth_core::crypto::{PasswordHasher, Secret};
use fastauth_core::prelude::*;
use http::{Method, Request, StatusCode, header};
use std::io::Write;

use tokio::net::TcpListener;

type AppAuth = Auth<MemoryAdapter>;

const ORIGIN: &str = "http://localhost:3000";

#[derive(Default)]
struct Gate {
    open: AtomicBool,
    in_flight: AtomicUsize,
    most: AtomicUsize,
}

struct GatedHasher(Arc<Gate>);

impl GatedHasher {
    fn enter(&self) {
        let gate = &self.0;
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

struct OpenOnDrop(Arc<Gate>);

impl Drop for OpenOnDrop {
    fn drop(&mut self) {
        self.0.open.store(true, Ordering::SeqCst);
    }
}

/// FAST61-H1 over HTTP/1.1 with axum::serve: each round opens 2 × CPU-count connections that
/// send a sign-in, waits while the first CPU-count of them hash, then closes every
/// connection. If hyper drops the handler future on the closed connection, the permits come
/// back while the hashes run and the next round starts more hashes than the cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_http1_disconnects_mid_hash_do_not_lift_the_hashing_cap() {
    let gate = Arc::new(Gate::default());
    gate.open.store(true, Ordering::SeqCst);
    let auth: AppAuth = FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(ORIGIN)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(GatedHasher(gate.clone())))
        .rate_limit(RateLimit::disabled())
        .build()
        .expect("valid config");
    let signed_up = auth
        .handle(
            Request::builder()
                .method(Method::POST)
                .uri("/api/auth/sign-up/email")
                .header(header::ORIGIN, ORIGIN)
                .body(Bytes::from(
                    r#"{"email":"ada@acme.dk","password":"correct horse","name":"Ada"}"#,
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(signed_up.status(), StatusCode::OK);

    let app = auth.router::<AppAuth>().with_state(auth.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    gate.open.store(false, Ordering::SeqCst);
    gate.most.store(0, Ordering::SeqCst);
    let release = OpenOnDrop(gate.clone());
    let cap = std::thread::available_parallelism().map_or(2, |n| n.get());
    let body = r#"{"email":"ada@acme.dk","password":"wrong guess"}"#;
    let request = format!(
        "POST /api/auth/sign-in/email HTTP/1.1\r\nHost: localhost\r\nOrigin: {ORIGIN}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    for _round in 0..3 {
        let mut connections = Vec::new();
        for _ in 0..cap * 2 {
            let mut stream = std::net::TcpStream::connect(addr).unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            connections.push(stream);
        }
        tokio::time::sleep(StdDuration::from_millis(300)).await;
        drop(connections);
        tokio::time::sleep(StdDuration::from_millis(300)).await;
    }
    let most = gate.most.load(Ordering::SeqCst);
    let running = gate.in_flight.load(Ordering::SeqCst);
    drop(release);
    println!(
        "[3 rounds of {} HTTP/1.1 sign-ins closed mid-hash] cap={cap} most at once={most} still running={running}",
        cap * 2
    );
    assert!(
        most <= cap,
        "{most} password hashes ran at once with a cap of {cap} after clients disconnected mid-hash"
    );
}
