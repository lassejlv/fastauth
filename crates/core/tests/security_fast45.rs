//! FAST-45 security review (area: identity, prefix ATO): core email handling. Each `sec_*`
//! test asserts the secure behaviour and fails on fastauth 0.5.0 (7cd9718).
//!
//! Run: cargo +stable test -p fastauth-core --all-features --test security_fast45 -- --nocapture --test-threads=1

mod common;

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::mail::{AuthEmail, MemoryMailer};
use fastauth_core::prelude::*;
use fastauth_core::routes::normalize_email;
use http::StatusCode;
use serde_json::json;

/// ATO-11: `normalize_email` only asks for a non-empty local part and a dot in the domain,
/// so address lists, inner whitespace, control characters and a second `@` all pass as one
/// "email".
#[test]
fn sec_normalize_email_rejects_lists_whitespace_and_control_characters() {
    let accepted: Vec<&str> = [
        "mallory@evil.example, ceo@acme.dk",
        "mallory@evil.example,ceo@acme.dk",
        "mallory@evil.example;ceo@acme.dk",
        "mallory@evil.example ceo@acme.dk",
        "ada@acme.dk\r\nBcc: mallory@evil.example",
        "ada@acme.dk\u{0}.evil.example",
        "mallory@evil.example@acme.dk",
        "\"ada\" <mallory@evil.example>, x@acme.dk",
    ]
    .into_iter()
    .filter(|email| normalize_email(email).is_ok())
    .collect();
    println!("[accepted as one email address] {accepted:#?}");
    assert!(accepted.is_empty(), "normalize_email accepted {accepted:?}");
}

/// ATO-11, end to end: signing up as `mallory@evil.example, ceo@acme.dk` mails the
/// verification link to that whole string. A mailer that treats it as two recipients
/// delivers to Mallory, and she ends up with a verified user whose email ends in
/// `@acme.dk`, the suffix apps key domain rules on.
#[tokio::test]
async fn sec_sign_up_refuses_an_address_list_as_the_email() {
    let mailer = MemoryMailer::new();
    let auth: Auth<MemoryAdapter, (), plugins![]> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(
            EmailPassword::default()
                .hasher(Argon2id::with_params(1024, 1, 1))
                .require_email_verification(true),
        )
        .rate_limit(RateLimit::disabled())
        .mailer(mailer.clone())
        .build()
        .expect("valid config");
    let mut mallory = Client::new(auth.clone());
    let email = "mallory@evil.example, ceo@acme.dk";
    let res = mallory.sign_up(email, "correct horse").await;
    println!(
        "[sign-up as {email:?}] status={} body={}",
        res.status, res.json
    );
    let sent: Vec<(String, String)> = mailer
        .sent()
        .into_iter()
        .filter_map(|mail| match mail {
            AuthEmail::VerifyEmail(e) => Some((e.to, e.token)),
            _ => None,
        })
        .collect();
    println!(
        "[verification emails] to={:?}",
        sent.iter().map(|(to, _)| to).collect::<Vec<_>>()
    );
    if let Some((_, token)) = sent.last() {
        let res = mallory.get(&format!("/verify-email?token={token}")).await;
        let signed_in = mallory
            .post(
                "/sign-in/email",
                json!({ "email": email, "password": "correct horse" }),
            )
            .await;
        println!(
            "[after the link] verify={} sign-in={} user={}",
            res.status, signed_in.status, signed_in.json["user"]
        );
    }
    assert_eq!(
        res.status,
        StatusCode::BAD_REQUEST,
        "sign-up took an address list as one email and mailed the verification link to {:?}",
        sent.first().map(|(to, _)| to)
    );
}
