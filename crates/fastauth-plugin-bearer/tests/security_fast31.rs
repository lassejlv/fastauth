//! FAST-31 security review (area: tokens / bearer). No bearer finding failed; these `guard_*`
//! tests pin the behaviour the review verified.

mod common;

use common::{bearer, secret, send};
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_plugin_bearer::{Bearer, SET_AUTH_TOKEN};
use http::{Method, StatusCode};
use serde_json::{Value, json};

type BearerAuth = Auth<MemoryAdapter, (), plugins![Bearer]>;

fn build() -> BearerAuth {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Bearer::new())
        .build()
        .expect("valid config")
}

async fn sign_up(auth: &BearerAuth, email: &str) -> String {
    let res = send(
        auth,
        Method::POST,
        "/sign-up/email",
        &[],
        Some(json!({ "email": email, "password": "correct horse", "name": "Ada" })),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    res.header(SET_AUTH_TOKEN).unwrap().to_owned()
}

async fn who(auth: &BearerAuth, headers: &[(&str, &str)]) -> Value {
    let res = send(auth, Method::GET, "/get-session", headers, None).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    res.json["user"]["email"].clone()
}

/// A valid session cookie wins over a valid bearer token for another user, and an invalid
/// cookie is not rescued by a valid bearer token: the request is signed out (fail closed).
/// Better Auth instead lets the bearer token replace the cookie.
#[tokio::test]
async fn guard_cookie_precedence_fails_closed() {
    let auth = build();
    let ada = sign_up(&auth, "ada@acme.dk").await;
    let bob = sign_up(&auth, "bob@acme.dk").await;
    let ada_cookie = format!("fastauth.session_token={ada}");
    let bob_bearer = bearer(&bob);

    let both = who(
        &auth,
        &[("cookie", &ada_cookie), ("authorization", &bob_bearer)],
    )
    .await;
    assert_eq!(both, "ada@acme.dk");

    let forged_cookie = format!("fastauth.session_token={}x", &ada[..ada.len() - 1]);
    let res = send(
        &auth,
        Method::GET,
        "/get-session",
        &[("cookie", &forged_cookie), ("authorization", &bob_bearer)],
        None,
    )
    .await;
    println!(
        "invalid cookie + valid bearer -> {} {}",
        res.status, res.json
    );
    assert_eq!(res.json, Value::Null);
}

/// Odd `Authorization` values neither panic nor sign anyone in.
#[tokio::test]
async fn guard_malformed_bearer_values_are_ignored() {
    let auth = build();
    let ada = sign_up(&auth, "ada@acme.dk").await;
    let (raw, signature) = ada.rsplit_once('.').unwrap();
    let long = "a".repeat(64 * 1024);
    for value in [
        "Bearer".to_owned(),
        "Bearer  ".to_owned(),
        "Bearer .".to_owned(),
        "Bearer ....".to_owned(),
        "Bearer %".to_owned(),
        "Bearer %ZZ.x".to_owned(),
        "Bearer %FF%FE.x".to_owned(),
        format!("Bearer {raw}."),
        format!("Bearer .{signature}"),
        format!("Bearer {raw}.{signature}.{signature}"),
        format!("Bearer {raw}x.{signature}"),
        format!("Bearer {long}"),
        format!("Bearer {long}.{signature}"),
        format!("Token {ada}"),
    ] {
        let res = send(
            &auth,
            Method::GET,
            "/get-session",
            &[("authorization", &value)],
            None,
        )
        .await;
        assert_eq!(res.status, StatusCode::OK, "{value:.40}");
        assert_eq!(res.json, Value::Null, "{value:.40}");
    }
}
