//! Secret rotation: what a session signed before the rotation keeps.

mod common;

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::mail::AuthEmail;
use fastauth_core::prelude::*;
use http::StatusCode;
use serde_json::json;

fn build(db: MemoryAdapter, mailer: MemoryMailer, secrets: Vec<Secret>) -> Auth<MemoryAdapter> {
    FastAuth::builder()
        .secrets(secrets)
        .base_url("http://localhost:3000")
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .session(SessionConfig::default().update_age(Duration::ZERO))
        .mailer(mailer)
        .rate_limit(RateLimit::disabled())
        .build()
        .expect("valid config")
}

fn rotated() -> Vec<Secret> {
    vec![Secret::from_bytes(vec![99u8; 32]), secret()]
}

#[tokio::test]
async fn a_session_from_before_a_rotation_still_proves_the_password_on_a_verification_link() {
    let db = MemoryAdapter::new();
    let mailer = MemoryMailer::new();
    let mut client = Client::new(build(db.clone(), mailer.clone(), vec![secret()]));
    let res = client.sign_up("owner@acme.dk", "correct horse").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    client.jar.remove("fastauth.pending_verification");
    let sent = client
        .post(
            "/send-verification-email",
            json!({ "email": "owner@acme.dk" }),
        )
        .await;
    assert_eq!(sent.status, StatusCode::OK, "{}", sent.json);
    let Some(AuthEmail::VerifyEmail(email)) = mailer.last() else {
        panic!("no verification email")
    };

    client.auth = build(db, mailer, rotated());
    let verified = client
        .get(&format!("/verify-email?token={}", email.token))
        .await;
    assert!(verified.status.is_success() || verified.status.is_redirection());

    let signed_in = client
        .post(
            "/sign-in/email",
            json!({ "email": "owner@acme.dk", "password": "correct horse" }),
        )
        .await;
    assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.json);
}

#[tokio::test]
async fn a_remember_me_false_session_is_not_extended_after_a_rotation() {
    let db = MemoryAdapter::new();
    let mailer = MemoryMailer::new();
    let mut client = Client::new(build(db.clone(), mailer.clone(), vec![secret()]));
    client.sign_up("short@acme.dk", "correct horse").await;
    client.jar.clear();
    let res = client
        .post(
            "/sign-in/email",
            json!({ "email": "short@acme.dk", "password": "correct horse", "rememberMe": false }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let before = client.get("/get-session").await.json["session"]["expiresAt"].clone();

    client.auth = build(db, mailer, rotated());
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let after = client.get("/get-session").await.json["session"]["expiresAt"].clone();
    assert!(before.is_string(), "{before}");
    assert_eq!(before, after);
}
