//! FAST-31 security review evidence for fastauth-plugin-email-otp 0.3.0. Asserts the secure
//! behaviour; fails on 0.3.0.

mod common;

use std::sync::Arc;
use std::time::Duration as StdDuration;

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::mail::{AuthEmail, MailError, Mailer, MemoryMailer};
use fastauth_core::prelude::*;
use fastauth_plugin_email_otp::EmailOtp;
use serde_json::json;
use tokio::sync::Semaphore;

/// A mailer that holds every send until the test opens the gate, like an SMTP server that
/// hasn't answered yet. A route that waits for the mailer can't answer while the gate is shut.
#[derive(Clone)]
struct GatedMailer {
    gate: Arc<Semaphore>,
    sent: MemoryMailer,
}

impl Mailer for GatedMailer {
    async fn send(&self, email: AuthEmail) -> Result<(), MailError> {
        let _ = self.gate.acquire().await;
        self.sent.send(email).await
    }
}

/// EOTP-1: send-verification-otp answers {"success": true} either way, but only sends (and
/// waits for the mailer) when the email has a user, so response time reveals accounts for
/// the forget-password and email-verification types, and for sign-in with disable_sign_up.
/// Asserted without a clock: known and unknown emails both get their answer while the
/// mailer is still blocked, and only the known one gets a code once it unblocks.
#[tokio::test]
async fn sec_send_otp_takes_the_same_time_for_known_and_unknown_emails() {
    for (disable_sign_up, kind) in [
        (false, "forget-password"),
        (false, "email-verification"),
        (true, "sign-in"),
    ] {
        let mailer = GatedMailer {
            gate: Arc::new(Semaphore::new(0)),
            sent: MemoryMailer::new(),
        };
        let auth: Auth<MemoryAdapter, (), plugins![EmailOtp]> = FastAuth::builder()
            .secret(secret())
            .base_url("http://localhost:3000")
            .database(MemoryAdapter::new())
            .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
            .email_verification(EmailVerification::default().send_on_sign_up(false))
            .mailer(mailer.clone())
            .rate_limit(RateLimit::disabled())
            .plugin(EmailOtp::new().disable_sign_up(disable_sign_up))
            .build()
            .unwrap();
        let mut client = Client::new(auth);
        client.sign_up("known@acme.dk", "correct horse").await;
        for email in ["known@acme.dk", "unknown@acme.dk"] {
            let body = json!({ "email": email, "type": kind });
            let res = tokio::time::timeout(
                StdDuration::from_secs(30),
                client.post("/email-otp/send-verification-otp", body),
            )
            .await
            .unwrap_or_else(|_| panic!("type {kind}: {email} waited for the mailer"));
            assert_eq!(res.json, json!({ "success": true }), "type {kind}: {email}");
        }
        mailer.gate.close();
        for _ in 0..200 {
            if !mailer.sent.sent().is_empty() {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(50)).await;
        }
        tokio::time::sleep(StdDuration::from_millis(200)).await;
        let delivered: Vec<String> = mailer
            .sent
            .sent()
            .iter()
            .map(|email| email.to().to_owned())
            .collect();
        println!("type {kind} (disable_sign_up {disable_sign_up}): delivered {delivered:?}");
        assert_eq!(delivered, ["known@acme.dk"], "type {kind}");
    }
}
