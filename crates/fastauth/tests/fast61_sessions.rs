//! FAST-61 review of the 0.6.0 authoritative sessions (#45), SESS-4: "a `rememberMe: false`
//! session lives one day at most and is never refreshed". The stored session is created with
//! the short lifetime, but whether a request refreshes it is decided by the client's signed
//! `dont_remember` marker cookie (session.rs `dont_remember` / `refresh`). The marker isn't bound
//! to the session and isn't stored, so a request that carries the token without the marker (a
//! bearer token, or a cookie jar that dropped the marker) extends the session to the full
//! `expires_in` and gets a persistent cookie back.
//!
//! It needs an `update_age` below one day: with the default (one day), the short session expires
//! at the moment a refresh would become due.
//!
//! Run: cargo test -p fastauth --all-features --test fast61_sessions -- --nocapture
#![cfg(feature = "bearer")]

use std::time::Duration as StdDuration;

use axum::body::Bytes;
use axum::http::{Request, header};
use fastauth::crypto::{Argon2id, Secret};
use fastauth::plugins::bearer::Bearer;
use fastauth::prelude::*;
use serde_json::{Value, json};
use time::OffsetDateTime;

const ORIGIN: &str = "http://localhost:3000";

type AppAuth = Auth<MemoryAdapter, (), plugins![Bearer]>;

fn build() -> AppAuth {
    FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(ORIGIN)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .session(SessionConfig::default().update_age(Duration::seconds(1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Bearer::new())
        .build()
        .expect("valid config")
}

async fn send(
    auth: &AppAuth,
    method: &str,
    path: &str,
    body: Option<Value>,
    headers: &[(&str, String)],
) -> (u16, Vec<String>, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("/api/auth{path}"))
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let body = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
    let response = auth.handle(builder.body(body).unwrap()).await;
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|c| c.to_str().unwrap().to_owned())
        .collect();
    let json = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
    (response.status().as_u16(), cookies, json)
}

/// Signs up and signs in with `rememberMe: false`. Answers the token and the session cookie
/// (name=value) the sign-in set.
async fn sign_in_dont_remember(auth: &AppAuth) -> (String, String) {
    let (status, _, json) = send(
        auth,
        "POST",
        "/sign-up/email",
        Some(json!({ "email": "ada@acme.dk", "password": "correct horse battery", "name": "Ada" })),
        &[],
    )
    .await;
    assert_eq!(status, 200, "{json}");
    let (status, cookies, json) = send(
        auth,
        "POST",
        "/sign-in/email",
        Some(json!({ "email": "ada@acme.dk", "password": "correct horse battery", "rememberMe": false })),
        &[],
    )
    .await;
    assert_eq!(status, 200, "{json}");
    let session_cookie = cookies
        .iter()
        .find(|c| c.split('=').next().unwrap().ends_with(".session_token"))
        .expect("a session cookie")
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    (json["token"].as_str().unwrap().to_owned(), session_cookie)
}

fn days_left(session: &Value) -> f64 {
    let expires = OffsetDateTime::parse(
        session["session"]["expiresAt"].as_str().expect("expiresAt"),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    (expires - OffsetDateTime::now_utc()).as_seconds_f64() / 86_400.0
}

#[tokio::test]
async fn sec_bearer_use_does_not_extend_a_dont_remember_session() {
    let auth = build();
    let (token, _) = sign_in_dont_remember(&auth).await;
    tokio::time::sleep(StdDuration::from_millis(1100)).await;
    let bearer = [("authorization", format!("Bearer {token}"))];
    send(&auth, "GET", "/get-session", None, &bearer).await;
    let (status, _, session) = send(&auth, "GET", "/get-session", None, &bearer).await;
    assert_eq!(status, 200, "{session}");
    let left = days_left(&session);
    assert!(
        left <= 1.0,
        "a rememberMe: false session used with its bearer token now expires in {left:.2} days"
    );
}

#[tokio::test]
async fn sec_dropping_the_marker_cookie_does_not_extend_a_dont_remember_session() {
    let auth = build();
    let (_, session_cookie) = sign_in_dont_remember(&auth).await;
    tokio::time::sleep(StdDuration::from_millis(1100)).await;
    let only_token = [("cookie", session_cookie)];
    let (_, cookies, _) = send(&auth, "GET", "/get-session", None, &only_token).await;
    let (status, _, session) = send(&auth, "GET", "/get-session", None, &only_token).await;
    assert_eq!(status, 200, "{session}");
    let left = days_left(&session);
    let persistent = cookies.iter().any(|c| {
        c.split('=').next().unwrap().ends_with(".session_token") && c.contains("Max-Age=")
    });
    assert!(
        left <= 1.0 && !persistent,
        "without the dont_remember marker the session now expires in {left:.2} days and the \
         refresh set a persistent cookie: {persistent}"
    );
}

#[tokio::test]
async fn guard_a_dont_remember_session_with_its_marker_is_not_extended() {
    let auth = build();
    let (status, _, json) = send(
        &auth,
        "POST",
        "/sign-up/email",
        Some(json!({ "email": "ada@acme.dk", "password": "correct horse battery", "name": "Ada" })),
        &[],
    )
    .await;
    assert_eq!(status, 200, "{json}");
    let (_, cookies, _) = send(
        &auth,
        "POST",
        "/sign-in/email",
        Some(json!({ "email": "ada@acme.dk", "password": "correct horse battery", "rememberMe": false })),
        &[],
    )
    .await;
    let jar = cookies
        .iter()
        .filter(|c| !c.contains("Max-Age=0"))
        .map(|c| c.split(';').next().unwrap().to_owned())
        .collect::<Vec<_>>()
        .join("; ");
    tokio::time::sleep(StdDuration::from_millis(1100)).await;
    let (status, _, session) = send(&auth, "GET", "/get-session", None, &[("cookie", jar)]).await;
    assert_eq!(status, 200, "{session}");
    assert!(days_left(&session) <= 1.0);
}
