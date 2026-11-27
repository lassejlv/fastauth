//! FAST-58 (SQLX-1, SQLX-2): request text holding a NUL character is refused with 400
//! `INVALID_REQUEST_BODY` before any endpoint reads it, so it never reaches a database that
//! can't store it (Postgres) or cuts text at it (SQLite).

mod common;

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use http::StatusCode;
use serde_json::json;

fn auth() -> Auth<MemoryAdapter> {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(256, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .build()
        .expect("valid config")
}

fn assert_refused(res: &common::Res, label: &str) {
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{label}: {}", res.json);
    assert_eq!(
        res.json["code"], "INVALID_REQUEST_BODY",
        "{label}: {}",
        res.json
    );
}

#[tokio::test]
async fn a_nul_in_sign_up_text_is_a_400() {
    let mut client = Client::new(auth());
    for (label, body) in [
        (
            "name",
            json!({ "email": "nul@acme.dk", "password": "correct horse", "name": "a\0b" }),
        ),
        (
            "email",
            json!({ "email": "n\0ul@acme.dk", "password": "correct horse", "name": "Nul" }),
        ),
        (
            "password",
            json!({ "email": "nul@acme.dk", "password": "correct\0horse", "name": "Nul" }),
        ),
        (
            "an extra field",
            json!({ "email": "nul@acme.dk", "password": "correct horse", "name": "Nul", "x\0": 1 }),
        ),
        (
            "after an escaped backslash",
            json!({ "email": "nul@acme.dk", "password": "correct horse", "name": "a\\\0b" }),
        ),
    ] {
        let res = client.post("/sign-up/email", body).await;
        assert_refused(&res, label);
    }
}

#[tokio::test]
async fn a_nul_in_update_user_text_is_a_400() {
    let mut client = Client::new(auth());
    let res = client.sign_up("ada@acme.dk", "correct horse").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let res = client
        .post("/update-user", json!({ "name": "Ada\0" }))
        .await;
    assert_refused(&res, "name");
    let res = client.post("/update-user", json!({ "image": "\0" })).await;
    assert_refused(&res, "image");
}

#[tokio::test]
async fn a_nul_in_the_query_is_a_400() {
    let mut client = Client::new(auth());
    let res = client.get("/get-session?disableCookieCache=%00").await;
    assert_refused(&res, "query");
}

#[tokio::test]
async fn the_text_backslash_u0000_is_not_a_nul() {
    let mut client = Client::new(auth());
    let res = client
        .post(
            "/sign-up/email",
            json!({ "email": "ada@acme.dk", "password": "correct horse", "name": "a\\u0000b" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["user"]["name"], "a\\u0000b");
}
