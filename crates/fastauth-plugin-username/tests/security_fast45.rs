//! FAST-45 security review (area: identity, prefix ATO): the username plugin alone. Each
//! `sec_*` test asserts the secure behaviour and fails on fastauth 0.5.0 (7cd9718).
//!
//! Run: cargo +stable test -p fastauth-plugin-username --all-features --test security_fast45 -- --nocapture --test-threads=1

mod common;

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_plugin_username::Username;
use http::StatusCode;
use serde_json::json;

type Plugins = plugins![Username];

fn build(plugin: Username) -> Auth<MemoryAdapter, (), Plugins> {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(plugin)
        .build()
        .expect("valid config")
}

/// ATO-10: with `immutable_username(true)`, `/update-user` refuses a new username but accepts
/// `"username": null`, which the immutability check never sees. With the username cleared, the
/// next update sets any free name, and the old handle is free for someone else to take.
#[tokio::test]
async fn sec_immutable_username_cannot_be_cleared_and_replaced() {
    let auth = build(Username::new().immutable_username(true));
    let mut ada = Client::new(auth.clone());
    let res = ada
        .post(
            "/sign-up/email",
            json!({ "email": "ada@acme.dk", "password": "correct horse", "name": "Ada", "username": "ada" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let res = ada
        .post("/update-user", json!({ "username": "grace" }))
        .await;
    assert_eq!(res.json["code"], "USERNAME_IS_IMMUTABLE", "{}", res.json);

    let cleared = ada.post("/update-user", json!({ "username": null })).await;
    let renamed = ada
        .post("/update-user", json!({ "username": "grace" }))
        .await;
    let now = ada.get("/get-session").await.json["user"]["username"].clone();
    println!(
        "[update-user username:null] status={} body={}",
        cleared.status, cleared.json
    );
    println!(
        "[update-user username:grace after it] status={} body={}",
        renamed.status, renamed.json
    );
    println!("[username now] {now}");

    let mut mallory = Client::new(auth.clone());
    let taken = mallory
        .post(
            "/sign-up/email",
            json!({ "email": "mallory@evil.example", "password": "correct horse", "name": "M", "username": "ada" }),
        )
        .await;
    println!(
        "[someone else signs up as \"ada\"] status={} username={}",
        taken.status, taken.json["user"]["username"]
    );
    assert_eq!(
        now, "ada",
        "an immutable username was cleared ({}) and replaced ({}); the old handle went to another user: {}",
        cleared.status, renamed.status, taken.status
    );
}
