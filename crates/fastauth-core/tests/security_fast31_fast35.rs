//! FAST-31 security review evidence for fastauth-core 0.3.0: CORE-2, CORE-3, CORE-4 and
//! CORE-5. Every test asserts the secure behaviour; each failed on 0.3.0.

mod common;

use std::time::{Duration as StdDuration, Instant};

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::mail::{AuthEmail, MailError, Mailer, MemoryMailer};
use fastauth_core::prelude::*;
use http::StatusCode;
use serde_json::json;

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

/// A mailer that takes as long as a real SMTP or HTTP mail API call.
#[derive(Clone)]
struct SlowMailer(MemoryMailer);

const MAIL_LATENCY: StdDuration = StdDuration::from_millis(150);

impl Mailer for SlowMailer {
    async fn send(&self, email: AuthEmail) -> Result<(), MailError> {
        std::thread::sleep(MAIL_LATENCY);
        self.0.send(email).await
    }
}

async fn median_ms(
    client: &mut Client<MemoryAdapter, (), fastauth_core::Nil>,
    path: &str,
    body: serde_json::Value,
) -> u128 {
    let mut samples = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let res = client.post(path, body.clone()).await;
        samples.push(start.elapsed().as_millis());
        assert!(
            res.status.is_success(),
            "{path}: {} {}",
            res.status,
            res.json
        );
    }
    samples.sort();
    samples[2]
}

/// CORE-3: routes that promise not to reveal accounts answer at once for unknown emails but
/// only after the mailer returns for known ones. With a 150 ms mailer the difference is
/// the mailer's latency, measurable from one request.
#[tokio::test]
async fn sec_email_routes_take_the_same_time_for_known_and_unknown_emails() {
    let mailer = SlowMailer(MemoryMailer::new());
    let auth = auth_with(
        fast_hasher().require_email_verification(true),
        mailer,
        RateLimit::disabled(),
    );
    let mut client = Client::new(auth);
    client.sign_up("known@acme.dk", "correct horse").await;

    let mut leaks = Vec::new();
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
        let k = median_ms(&mut client, path, known).await;
        let u = median_ms(&mut client, path, unknown).await;
        println!("{path}: known {k} ms, unknown {u} ms");
        if k.abs_diff(u) > 50 {
            leaks.push(format!("{path}: known {k} ms vs unknown {u} ms"));
        }
    }

    let mut signups = Vec::new();
    for i in 0..5 {
        let start = Instant::now();
        client
            .sign_up(&format!("fresh{i}@acme.dk"), "correct horse")
            .await;
        let new = start.elapsed().as_millis();
        let start = Instant::now();
        client.sign_up("known@acme.dk", "correct horse").await;
        let existing = start.elapsed().as_millis();
        signups.push((new, existing));
    }
    signups.sort();
    let (new, existing) = signups[2];
    println!("/sign-up/email (requireEmailVerification): new {new} ms, existing {existing} ms");
    if new.abs_diff(existing) > 50 {
        leaks.push(format!(
            "/sign-up/email with requireEmailVerification: new {new} ms vs existing {existing} ms"
        ));
    }
    assert!(
        leaks.is_empty(),
        "timing reveals accounts:\n{}",
        leaks.join("\n")
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
