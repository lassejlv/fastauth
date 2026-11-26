//! FAST-45 security review evidence (7cd9718), username plugin: the no-client-IP rate limit.
//! sec_ tests assert the secure behaviour and fail on 7cd9718 on purpose.
//!
//! Run: cargo test -p fastauth-plugin-username --test security_fast45_config -- --nocapture --test-threads=1

mod common;

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_plugin_username::Username;
use http::StatusCode;
use serde_json::json;

type Plugins = plugins![Username];

/// DOS-2: without a client IP, sign-in is limited per account the JSON body names. The
/// limiter reads email first and username second (rate_limit.rs:122-131), but
/// /sign-in/username signs in by username and ignores an extra email key. A different junk
/// email on every request gives every guess a fresh bucket, so the per-account limit that
/// replaced the shared bucket (FAST-31 CORE-2) does not limit username sign-in at all.
#[tokio::test]
async fn sec_username_sign_in_limit_follows_the_username_without_a_client_ip() {
    let auth: Auth<MemoryAdapter, (), Plugins> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .plugin(Username::new())
        .build()
        .expect("valid config");
    let mut victim = Client::new(auth.clone());
    let res = victim
        .post(
            "/sign-up/email",
            json!({ "email": "ada@acme.dk", "password": "correct horse", "name": "Ada", "username": "ada" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);

    let mut attacker = Client::new(auth);
    let mut statuses = Vec::new();
    for n in 0..20 {
        let res = attacker
            .post(
                "/sign-in/username",
                json!({ "username": "ada", "password": format!("guess {n}"), "email": format!("junk{n}@x.example") }),
            )
            .await;
        statuses.push(res.status.as_u16());
    }
    println!("[20 guesses at username ada, each with a different junk email] {statuses:?}");
    assert!(
        statuses.contains(&429),
        "20 password guesses at one username were never rate limited: {statuses:?}"
    );
}
