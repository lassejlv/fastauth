//! FAST-31 security review evidence for fastauth-core 0.3.0: CORE-2, CORE-3, CORE-4 and
//! CORE-5. Every test asserts the secure behaviour; each failed on 0.3.0.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration as StdDuration;

use common::{Client, secret};
use fastauth_core::crypto::{Argon2id, PasswordHasher};
use fastauth_core::mail::{AuthEmail, MailError, Mailer, MemoryMailer};
use fastauth_core::prelude::*;
use http::StatusCode;
use serde_json::json;
use tokio::sync::Semaphore;

fn fast_hasher() -> EmailPassword {
    EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1))
}

fn auth_with(
    email_password: EmailPassword,
    mailer: impl Mailer,
    rate_limit: RateLimit,
) -> Auth<MemoryAdapter> {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(email_password)
        .mailer(mailer)
        .rate_limit(rate_limit)
        .build()
        .expect("valid config")
}

/// CORE-2: without ClientAddr (README's axum::serve(listener, app), or any proxy) every
/// client shares the "unknown" bucket: three wrong passwords from anyone lock everyone
/// out of sign-in.
#[tokio::test]
async fn sec_rate_limit_without_client_ip_does_not_lock_out_everyone() {
    let auth = auth_with(fast_hasher(), MemoryMailer::new(), RateLimit::default());
    let mut victim = Client::new(auth.clone());
    victim.sign_up("victim@acme.dk", "correct horse").await;
    let mut attacker = Client::new(auth.clone());
    for _ in 0..3 {
        attacker
            .post(
                "/sign-in/email",
                json!({ "email": "someone@else.dk", "password": "wrong password" }),
            )
            .await;
    }
    let res = victim
        .post(
            "/sign-in/email",
            json!({ "email": "victim@acme.dk", "password": "correct horse" }),
        )
        .await;
    assert_ne!(
        res.status,
        StatusCode::TOO_MANY_REQUESTS,
        "the victim's correct sign-in was throttled by another client's requests: {}",
        res.json
    );
}

/// A mailer that holds every send until the test opens the gate, like an SMTP server that
/// hasn't answered yet. A route that waits for the mailer can't answer while the gate is shut.
#[derive(Clone)]
struct GatedMailer {
    gate: Arc<Semaphore>,
    sent: MemoryMailer,
}

impl GatedMailer {
    fn new() -> Self {
        Self {
            gate: Arc::new(Semaphore::new(0)),
            sent: MemoryMailer::new(),
        }
    }

    fn open(&self) {
        self.gate.close();
    }

    /// The emails delivered once the gate is open: waits until `expected` have arrived, then
    /// a little longer, so a send that shouldn't happen has time to show up.
    async fn delivered(&self, expected: usize) -> Vec<AuthEmail> {
        for _ in 0..200 {
            if self.sent.sent().len() >= expected {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(50)).await;
        }
        tokio::time::sleep(StdDuration::from_millis(200)).await;
        self.sent.sent()
    }
}

impl Mailer for GatedMailer {
    async fn send(&self, email: AuthEmail) -> Result<(), MailError> {
        let _ = self.gate.acquire().await;
        self.sent.send(email).await
    }
}

/// Counts password hasher runs, so both branches of a route can be shown to spend one.
#[derive(Clone, Default)]
struct CountingHasher(Arc<AtomicUsize>);

impl PasswordHasher for CountingHasher {
    fn hash(&self, password: &str) -> Result<String, String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Argon2id::with_params(1024, 1, 1).hash(password)
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Argon2id::with_params(1024, 1, 1).verify(password, hash)
    }
}

/// Answers `path` with the mail gate shut. A route that waits for the mailer never answers,
/// so the timeout only catches a hang; nothing compares durations.
async fn answered_without_the_mailer(
    client: &mut Client<MemoryAdapter, (), fastauth_core::Nil>,
    path: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    let res = tokio::time::timeout(StdDuration::from_secs(30), client.post(path, body))
        .await
        .unwrap_or_else(|_| panic!("{path} waited for the mailer before answering"));
    assert!(
        res.status.is_success(),
        "{path}: {} {}",
        res.status,
        res.json
    );
    res.json
}

/// CORE-3: routes that promise not to reveal accounts answer at once for unknown emails but
/// only after the mailer returns for known ones. With a slow mailer the difference is the
/// mailer's latency, measurable from one request. Asserted without a clock: every route
/// answers known and unknown emails alike while the mailer is still blocked, the known ones
/// do get their email once it unblocks, and sign-up spends one password hash either way.
#[tokio::test]
async fn sec_email_routes_take_the_same_time_for_known_and_unknown_emails() {
    let mailer = GatedMailer::new();
    let hasher = CountingHasher::default();
    let auth = auth_with(
        EmailPassword::default()
            .hasher(hasher.clone())
            .require_email_verification(true),
        mailer.clone(),
        RateLimit::disabled(),
    );
    let mut client = Client::new(auth);
    answered_without_the_mailer(
        &mut client,
        "/sign-up/email",
        json!({ "email": "known@acme.dk", "password": "correct horse", "name": "Known" }),
    )
    .await;

    let mut expected = 1;
    for (path, known, unknown) in [
        (
            "/request-password-reset",
            json!({ "email": "known@acme.dk" }),
            json!({ "email": "unknown@acme.dk" }),
        ),
        (
            "/send-verification-email",
            json!({ "email": "known@acme.dk" }),
            json!({ "email": "unknown@acme.dk" }),
        ),
    ] {
        let k = answered_without_the_mailer(&mut client, path, known).await;
        let u = answered_without_the_mailer(&mut client, path, unknown).await;
        assert_eq!(k, u, "{path} answers known and unknown emails alike");
        expected += 1;
    }

    let mut hashes = Vec::new();
    for (i, email) in ["fresh@acme.dk", "known@acme.dk", "known@acme.dk"]
        .into_iter()
        .enumerate()
    {
        let before = hasher.0.load(Ordering::SeqCst);
        answered_without_the_mailer(
            &mut client,
            "/sign-up/email",
            json!({ "email": email, "password": "correct horse", "name": "Ada" }),
        )
        .await;
        hashes.push((i, email, hasher.0.load(Ordering::SeqCst) - before));
    }
    expected += 1;
    println!("/sign-up/email (requireEmailVerification) hasher runs: {hashes:?}");
    assert_eq!(hashes[0].2, 1, "a new sign-up hashes the password once");
    assert_eq!(
        hashes[2].2, 1,
        "a sign-up for an existing email spends one password hash too"
    );

    mailer.open();
    let delivered: Vec<(&str, String)> = mailer
        .delivered(expected)
        .await
        .iter()
        .map(|email| {
            let kind = match email {
                AuthEmail::VerifyEmail(_) => "verify",
                AuthEmail::ResetPassword(_) => "reset",
                _ => "other",
            };
            (kind, email.to().to_owned())
        })
        .collect();
    println!("delivered once the mailer answered: {delivered:?}");
    let count = |kind: &str, to: &str| {
        delivered
            .iter()
            .filter(|d| d.0 == kind && d.1 == to)
            .count()
    };
    assert_eq!(count("reset", "known@acme.dk"), 1, "{delivered:?}");
    assert!(count("verify", "known@acme.dk") >= 2, "{delivered:?}");
    assert_eq!(count("verify", "fresh@acme.dk"), 1, "{delivered:?}");
    assert!(
        !delivered.iter().any(|d| d.1 == "unknown@acme.dk"),
        "nothing is mailed to an address without an account: {delivered:?}"
    );
}

/// CORE-4: a password reset (the recovery path after a compromise) leaves every existing
/// session, the attacker's included, signed in by default.
#[tokio::test]
async fn sec_password_reset_revokes_existing_sessions_by_default() {
    let mailer = MemoryMailer::new();
    let auth = auth_with(fast_hasher(), mailer.clone(), RateLimit::disabled());
    let mut attacker = Client::new(auth.clone());
    attacker.sign_up("victim@acme.dk", "stolen password").await;
    assert!(!attacker.get("/get-session").await.json.is_null());

    let mut owner = Client::new(auth);
    owner
        .post(
            "/request-password-reset",
            json!({ "email": "victim@acme.dk" }),
        )
        .await;
    let Some(AuthEmail::ResetPassword(email)) = mailer.last() else {
        panic!("no reset email")
    };
    let reset = owner
        .post(
            "/reset-password",
            json!({ "token": email.token, "newPassword": "new strong password" }),
        )
        .await;
    assert_eq!(reset.status, StatusCode::OK, "{}", reset.json);
    let still = attacker.get("/get-session").await;
    assert!(
        still.json.is_null(),
        "the pre-reset session still works after the reset: {}",
        still.json
    );
}

/// CORE-5: /change-password checks the current password but falls under the default limit
/// (100 per 10 s), so a stolen session can guess the password far faster than sign-in allows.
#[tokio::test]
async fn sec_change_password_is_rate_limited_like_sign_in() {
    let auth = auth_with(fast_hasher(), MemoryMailer::new(), RateLimit::default());
    let mut thief = Client::new(auth);
    thief.sign_up("victim@acme.dk", "correct horse").await;
    let mut statuses = Vec::new();
    for i in 0..10 {
        let res = thief
            .post(
                "/change-password",
                json!({ "currentPassword": format!("guess {i}"), "newPassword": "attacker pass" }),
            )
            .await;
        statuses.push(res.status.as_u16());
    }
    assert!(
        statuses.contains(&429),
        "10 password guesses in a row, none throttled: {statuses:?}"
    );
}
