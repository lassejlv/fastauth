//! FAST-31 security review evidence for fastauth-plugin-email-otp 0.3.0. Asserts the secure
//! behaviour; fails on 0.3.0.

mod common;

use std::time::{Duration as StdDuration, Instant};

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::mail::{AuthEmail, MailError, Mailer, MemoryMailer};
use fastauth_core::prelude::*;
use fastauth_plugin_email_otp::EmailOtp;
use serde_json::json;

#[derive(Clone)]
struct SlowMailer(MemoryMailer);

impl Mailer for SlowMailer {
    async fn send(&self, email: AuthEmail) -> Result<(), MailError> {
        std::thread::sleep(StdDuration::from_millis(150));
        self.0.send(email).await
    }
}

/// EOTP-1: send-verification-otp answers {"success": true} either way, but only sends (and
/// waits for the mailer) when the email has a user, so response time reveals accounts for
/// the forget-password and email-verification types, and for sign-in with disable_sign_up.
#[tokio::test]
async fn sec_send_otp_takes_the_same_time_for_known_and_unknown_emails() {
    let mut leaks = Vec::new();
    for (disable_sign_up, kind) in [
        (false, "forget-password"),
        (false, "email-verification"),
        (true, "sign-in"),
    ] {
        let auth: Auth<MemoryAdapter, (), plugins![EmailOtp]> = FastAuth::builder()
            .secret(secret())
            .base_url("http://localhost:3000")
            .database(MemoryAdapter::new())
            .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
            .email_verification(EmailVerification::default().send_on_sign_up(false))
            .mailer(SlowMailer(MemoryMailer::new()))
            .rate_limit(RateLimit::disabled())
            .plugin(EmailOtp::new().disable_sign_up(disable_sign_up))
            .build()
            .unwrap();
        let mut client = Client::new(auth);
        client.sign_up("known@acme.dk", "correct horse").await;
        let known = median(&mut client, "known@acme.dk", kind).await;
        let unknown = median(&mut client, "unknown@acme.dk", kind).await;
        println!(
            "type {kind} (disable_sign_up {disable_sign_up}): known {known} ms, unknown {unknown} ms"
        );
        if known.abs_diff(unknown) > 50 {
            leaks.push(format!(
                "type {kind}: known {known} ms vs unknown {unknown} ms"
            ));
        }
    }
    assert!(
        leaks.is_empty(),
        "timing reveals accounts:\n{}",
        leaks.join("\n")
    );
}

async fn median(
    client: &mut Client<MemoryAdapter, (), plugins![EmailOtp]>,
    email: &str,
    kind: &str,
) -> u128 {
    let body = json!({ "email": email, "type": kind });
    let mut samples = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let res = client
            .post("/email-otp/send-verification-otp", body.clone())
            .await;
        assert_eq!(res.json, json!({ "success": true }));
        samples.push(start.elapsed().as_millis());
    }
    samples.sort();
    samples[2]
}
