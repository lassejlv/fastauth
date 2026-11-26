//! FAST-45 security review evidence for fastauth-core 0.5.0 (7cd9718): configuration, crypto
//! and denial-of-service findings. Every sec_ test asserts the secure behaviour and fails on
//! 7cd9718 on purpose; guard_ tests pass and pin behaviour that is already right.
//!
//! Run: cargo test -p fastauth-core --test security_fast45_config -- --nocapture --test-threads=1

mod common;

use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration as StdDuration, Instant};

use bytes::Bytes;
use common::{Client, ORIGIN, secret};
use fastauth_core::ClientAddr;
use fastauth_core::crypto::Argon2id;
use fastauth_core::mail::{AuthEmail, MailError, Mailer, MemoryMailer, ResetPassword};
use fastauth_core::model::Model;
use fastauth_core::plugin_prelude::Where;
use fastauth_core::prelude::*;
use fastauth_core::session::{SessionView, UserView};
use http::{Method, Request, StatusCode, header};
use serde_json::json;

fn fast_hasher() -> EmailPassword {
    EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1))
}

fn build(url: &str, secret: Secret) -> Result<Auth<MemoryAdapter>, BuildError> {
    FastAuth::builder()
        .base_url(url)
        .secret(secret)
        .database(MemoryAdapter::new())
        .email_password(fast_hasher())
        .build()
}

fn generated() -> Secret {
    Secret::from_base64(&Secret::generate())
}

async fn post_from(
    auth: &Auth<MemoryAdapter>,
    ip: Option<IpAddr>,
    path: &str,
    body: serde_json::Value,
) -> StatusCode {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/auth{path}"))
        .header(header::ORIGIN, ORIGIN)
        .body(Bytes::from(body.to_string()))
        .unwrap();
    if let Some(ip) = ip {
        request.extensions_mut().insert(ClientAddr(ip));
    }
    auth.handle(request).await.status()
}

/// DOS-1: rate limits are kept per full IPv6 address. One client with a /64 (every home
/// connection, every cloud VM) has 2^64 addresses, so the strict 3-per-10-seconds limit on
/// sign-in never applies to it. Better Auth masks IPv6 to /64 by default.
#[tokio::test]
async fn sec_rate_limit_groups_ipv6_clients_by_prefix() {
    let auth = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(fast_hasher())
        .build()
        .unwrap();
    let mut statuses = Vec::new();
    for host in 1..=30u16 {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, host));
        statuses.push(
            post_from(
                &auth,
                Some(ip),
                "/sign-in/email",
                json!({ "email": "victim@acme.dk", "password": format!("guess {host}") }),
            )
            .await,
        );
    }
    let limited = statuses
        .iter()
        .filter(|s| **s == StatusCode::TOO_MANY_REQUESTS)
        .count();
    println!(
        "[30 sign-in guesses from one IPv6 /64] 429s={limited} of {}",
        statuses.len()
    );
    assert!(
        limited > 0,
        "30 password guesses in a row from one /64 were never rate limited"
    );
}

/// DOS-6: when the client IP is known, nothing limits guesses per account. A botnet, a proxy
/// pool or the /64 above guesses one user's password (or their TOTP code after it) without
/// ever meeting a limit: the only per-account limiter is the no-client-IP fallback.
#[tokio::test]
async fn sec_password_guesses_at_one_account_are_limited_across_clients() {
    let auth = build("http://localhost:3000", secret()).unwrap();
    let mut victim = Client::new(auth.clone());
    victim.sign_up("victim@acme.dk", "correct horse").await;
    let mut limited = 0;
    for host in 1..=60u8 {
        let ip: IpAddr = format!("198.51.100.{host}").parse().unwrap();
        let status = post_from(
            &auth,
            Some(ip),
            "/sign-in/email",
            json!({ "email": "victim@acme.dk", "password": format!("guess {host}") }),
        )
        .await;
        limited += usize::from(status == StatusCode::TOO_MANY_REQUESTS);
    }
    println!("[60 wrong passwords for one account from 60 addresses] 429s={limited}");
    assert!(
        limited > 0,
        "60 wrong passwords for one account in a row, none limited"
    );
}

/// guard: the same guesses from one IPv4 address are limited after three.
#[tokio::test]
async fn guard_rate_limit_applies_per_ipv4_address() {
    let auth = build("http://localhost:3000", secret()).unwrap();
    let ip: IpAddr = "203.0.113.9".parse().unwrap();
    let mut limited = 0;
    for n in 0..6 {
        let status = post_from(
            &auth,
            Some(ip),
            "/sign-in/email",
            json!({ "email": "victim@acme.dk", "password": format!("guess {n}") }),
        )
        .await;
        limited += usize::from(status == StatusCode::TOO_MANY_REQUESTS);
    }
    assert_eq!(limited, 3);
}

#[cfg(target_os = "linux")]
fn resident_bytes() -> usize {
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap();
    statm
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<usize>()
        .unwrap()
        * 4096
}

/// DOS-2: without a client IP the limiter keys on the email the JSON body names, before any
/// validation, so the key is as long as the body allows (64 KiB). Entries are only dropped
/// once a shard holds 50,000 of them, never by age. An unauthenticated client makes the
/// process hold about 60 KB per request: 3 GB per shard before the first prune.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn sec_limiter_without_client_ip_does_not_keep_request_bodies() {
    let auth = build("http://localhost:3000", secret()).unwrap();
    let before = resident_bytes();
    let requests = 1500;
    for n in 0..requests {
        let email = format!("{n}-{}@x.example", "a".repeat(60_000));
        let status = post_from(
            &auth,
            None,
            "/sign-in/email",
            json!({ "email": email, "password": "x" }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an over-long email is refused"
        );
    }
    let grown = resident_bytes().saturating_sub(before);
    println!(
        "[{requests} refused sign-ins without a client IP] resident memory grew by {} MiB",
        grown / (1024 * 1024)
    );
    assert!(
        grown < 16 * 1024 * 1024,
        "{requests} refused requests left {} MiB in the rate limiter",
        grown / (1024 * 1024)
    );
}

/// DOS-3: nothing ever deletes an expired verification row unless its own token comes back.
/// Reset links, email-verification links, magic links, OAuth states and passkey challenges
/// (the last three can be requested by anyone) pile up for good. Better Auth purges expired
/// verifications on lookup (db/internal-adapter, verification.disableCleanup).
#[tokio::test]
async fn sec_expired_verifications_are_purged() {
    let db = MemoryAdapter::new();
    let auth = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(db.clone())
        .email_password(fast_hasher().reset_password_ttl(Duration::milliseconds(1)))
        .mailer(MemoryMailer::new())
        .rate_limit(RateLimit::disabled())
        .build()
        .unwrap();
    let mut client = Client::new(auth);
    client.sign_up("ada@acme.dk", "correct horse").await;
    for _ in 0..20 {
        client
            .post("/request-password-reset", json!({ "email": "ada@acme.dk" }))
            .await;
    }
    tokio::time::sleep(StdDuration::from_millis(20)).await;
    // Ordinary traffic afterwards: another request, a wrong token, a sign-in.
    client
        .post("/request-password-reset", json!({ "email": "ada@acme.dk" }))
        .await;
    client
        .post(
            "/reset-password",
            json!({ "token": "nope", "newPassword": "another horse" }),
        )
        .await;
    client
        .post(
            "/sign-in/email",
            json!({ "email": "ada@acme.dk", "password": "correct horse" }),
        )
        .await;
    let rows = db.dump("verification").len();
    println!("[verification rows left after 21 expired reset requests] {rows}");
    assert!(
        rows <= 2,
        "{rows} verification rows remain; the expired ones are never deleted"
    );
}

/// A mailer that takes as long as a slow SMTP server.
#[derive(Clone)]
struct StuckMailer;

impl Mailer for StuckMailer {
    async fn send(&self, _: AuthEmail) -> Result<(), MailError> {
        std::thread::sleep(StdDuration::from_secs(4));
        Ok(())
    }
}

/// DOS-4: every background email parks one thread of tokio's blocking pool for as long as the
/// mailer takes (spawn_blocking + block_on), with no cap. Password hashing runs on the same
/// pool. 512 pending sends (the pool's default size) and every password sign-in waits for a
/// mailer to finish.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_slow_mailer_does_not_stall_password_sign_in() {
    let auth = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(fast_hasher())
        .mailer(StuckMailer)
        .email_verification(EmailVerification::default().send_on_sign_up(false))
        .rate_limit(RateLimit::disabled())
        .build()
        .unwrap();
    let mut client = Client::new(auth.clone());
    client.sign_up("ada@acme.dk", "correct horse").await;
    for _ in 0..600 {
        let status = post_from(
            &auth,
            None,
            "/request-password-reset",
            json!({ "email": "ada@acme.dk" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    let started = Instant::now();
    let res = client
        .post(
            "/sign-in/email",
            json!({ "email": "ada@acme.dk", "password": "correct horse" }),
        )
        .await;
    let waited = started.elapsed();
    println!(
        "[sign-in behind 600 pending emails] status={} waited={waited:?}",
        res.status
    );
    assert_eq!(res.status, StatusCode::OK);
    assert!(
        waited < StdDuration::from_millis(1500),
        "a correct sign-in waited {waited:?} for the mailer's threads"
    );
}

/// CFG-2: /get-session answers the session token and the user with no Cache-Control, so a
/// shared cache or CDN in front of the app may store one user's session for the next.
/// Better Auth sets cache-control: no-store and pragma: no-cache (api/routes/session.mjs:34).
#[tokio::test]
async fn sec_get_session_response_is_not_cacheable() {
    let auth = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(fast_hasher())
        .rate_limit(RateLimit::disabled())
        .build()
        .unwrap();
    let mut client = Client::new(auth);
    client.sign_up("ada@acme.dk", "correct horse").await;
    let res = client.get("/get-session").await;
    assert!(res.json["session"]["token"].is_string(), "{}", res.json);
    let cache_control = res
        .headers
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    println!("[/get-session] cache-control={cache_control:?}");
    assert!(
        cache_control.contains("no-store"),
        "/get-session returned a session token without Cache-Control: no-store"
    );
}

/// CFG-3: any 32 bytes pass as the master secret, including one repeated byte or a keyboard
/// phrase. Better Auth refuses its default secret in production and warns below 120 bits of
/// estimated entropy (context/create-context.mjs:36-45).
#[test]
fn sec_build_refuses_a_secret_without_entropy() {
    let accepted: Vec<&str> = [
        ("32 zero bytes", Secret::from_bytes(vec![0u8; 32])),
        ("32 x 'a'", Secret::from_base64(&"a".repeat(32))),
        (
            "a keyboard phrase",
            Secret::from_base64("password password password pass!"),
        ),
    ]
    .into_iter()
    .filter(|(_, secret)| build("https://app.example", secret.clone()).is_ok())
    .map(|(name, _)| name)
    .collect();
    assert!(
        accepted.is_empty(),
        "build() accepted these secrets: {accepted:?}"
    );
}

/// guard: a generated secret and a secret shorter than 32 bytes behave as documented.
#[test]
fn guard_build_checks_secret_length() {
    assert!(build("https://app.example", generated()).is_ok());
    assert!(build("https://app.example", Secret::from_bytes(vec![7u8; 31])).is_err());
}

/// CFG-4: base_url is only checked for an http(s) scheme. A URL with credentials, a query or
/// a fragment builds, and every emailed link is made by string concatenation from it.
#[tokio::test]
async fn sec_build_refuses_a_base_url_with_userinfo_query_or_fragment() {
    let accepted: Vec<&str> = [
        "https://user:pw@app.example",
        "https://app.example/?tenant=1",
        "https://app.example/#home",
    ]
    .into_iter()
    .filter(|url| build(url, generated()).is_ok())
    .collect();
    for url in &accepted {
        let auth = build(url, generated()).unwrap();
        println!("[base_url {url}] auth_url={}", auth.config().auth_url());
    }
    assert!(
        accepted.is_empty(),
        "build() accepted these base URLs: {accepted:?}"
    );
}

/// CFG-4: with Secure::Auto, an http:// base_url on a public host silently drops the Secure
/// attribute and the __Secure- prefix from the session cookie. Nothing fails or warns.
#[tokio::test]
async fn sec_public_http_base_url_does_not_silently_drop_secure_cookies() {
    let built = FastAuth::builder()
        .base_url("http://app.example.com")
        .secret(generated())
        .database(MemoryAdapter::new())
        .email_password(fast_hasher())
        .rate_limit(RateLimit::disabled())
        .build();
    let Ok(auth) = built else {
        return; // refusing the configuration is the secure behaviour
    };
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/sign-up/email")
        .header(header::ORIGIN, "http://app.example.com")
        .body(Bytes::from(
            json!({ "email": "ada@acme.dk", "password": "correct horse", "name": "Ada" })
                .to_string(),
        ))
        .unwrap();
    let response = auth.handle(request).await;
    let cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.contains("session_token"))
        .unwrap_or_default()
        .to_owned();
    println!(
        "[http://app.example.com] {}",
        cookie.split('=').next().unwrap_or_default()
    );
    assert!(
        cookie.contains("; Secure"),
        "a public http:// base_url built without complaint and set a session cookie without Secure"
    );
}

/// guard: localhost over http is the development setup and keeps working without Secure.
#[test]
fn guard_localhost_http_base_url_builds() {
    assert!(build("http://localhost:3000", generated()).is_ok());
}

/// CFG-5: the types that carry live credentials derive Debug. One {:?} in an app's mailer,
/// hook or error log writes a reset token or a session token to the logs.
#[tokio::test]
async fn sec_debug_output_redacts_tokens() {
    let marker = "synthetic-reset-token-marker";
    let email = AuthEmail::ResetPassword(ResetPassword {
        to: "ada@acme.dk".into(),
        name: "Ada".into(),
        url: format!("https://app.example/api/auth/reset-password/{marker}"),
        token: marker.into(),
    });
    let email_debug = format!("{email:?}");

    let auth = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(fast_hasher())
        .rate_limit(RateLimit::disabled())
        .build()
        .unwrap();
    let mut client = Client::new(auth.clone());
    let res = client.sign_up("ada@acme.dk", "correct horse").await;
    let token = res.json["token"].as_str().unwrap().to_owned();
    let api = auth.api();
    let row = api
        .db()
        .find::<Session>(Where::all())
        .one_row()
        .await
        .unwrap()
        .unwrap();
    let user = api
        .db()
        .find::<User>(Where::all())
        .one_row()
        .await
        .unwrap()
        .unwrap();
    let view = SessionView {
        session: Session::decode(&row).unwrap(),
        row,
        user: UserView::from_row(user).unwrap(),
        token: Some(token.clone()),
        ephemeral: false,
    };
    let view_debug = format!("{view:?}");

    let mut leaks = Vec::new();
    if email_debug.contains(marker) {
        leaks.push("AuthEmail (reset token and link)");
    }
    if view_debug.contains(&token) {
        leaks.push("SessionView (raw session token)");
    }
    assert!(leaks.is_empty(), "Debug prints live credentials: {leaks:?}");
}
