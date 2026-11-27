//! FAST-45 security review evidence (7cd9718), organization plugin: invitation limits.
//! sec_ tests assert the secure behaviour and fail on 7cd9718 on purpose.
//!
//! Run: cargo test -p fastauth-plugin-organization --test security_fast45_config -- --nocapture --test-threads=1

mod common;

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::mail::{AuthEmail, MemoryMailer};
use fastauth_core::prelude::*;
use fastauth_plugin_organization::Organization;
use http::StatusCode;
use serde_json::json;

/// DOS-7: any signed-in user can create an organization and invite any number of addresses.
/// Each invitation is an email from the app's own domain to an address of the sender's
/// choosing, whose subject and body carry the sender's name and the organization's name
/// verbatim ("{name} invited you to {org}"). Nothing caps pending invitations per
/// organization (Better Auth: invitationLimit, default 100 pending, crud-invites.mjs:171-176)
/// or members (membershipLimit, default 100), so the app becomes a spam and phishing relay,
/// limited only by the per-IP request limit.
#[tokio::test]
async fn sec_pending_invitations_per_organization_are_capped() {
    let mailer = MemoryMailer::new();
    let auth: Auth<MemoryAdapter, (), plugins![Organization]> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .email_verification(EmailVerification::default().send_on_sign_up(false))
        .mailer(mailer.clone())
        .rate_limit(RateLimit::disabled())
        .plugin(Organization::default())
        .build()
        .expect("valid config");
    let mut spammer = Client::new(auth);
    let res = spammer
        .post(
            "/sign-up/email",
            json!({ "email": "x@spam.example", "password": "correct horse", "name": "Your bank: verify at https://evil.example" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let res = spammer
        .post(
            "/organization/create",
            json!({ "name": "Account suspended", "slug": "s" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let mut accepted = 0;
    for n in 0..150 {
        let res = spammer
            .post(
                "/organization/invite-member",
                json!({ "email": format!("victim{n}@corp.example"), "role": "member" }),
            )
            .await;
        accepted += usize::from(res.status == StatusCode::OK);
    }
    let sent = mailer.sent();
    let subject = match sent.last() {
        Some(AuthEmail::Plugin(email)) => email.subject.clone(),
        _ => String::new(),
    };
    println!(
        "[150 invitations from a fresh account] accepted={accepted} emails={} last subject={subject:?}",
        sent.len()
    );
    assert!(
        accepted <= 100,
        "one fresh account sent {accepted} invitation emails from the app's domain"
    );
}
