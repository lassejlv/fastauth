//! FAST-61 adversarial review of the 0.6.0 fix in #50: NUL characters refused at
//! `decode_input`. Every test here is a `guard_*`: it passes on main e1c00a33 and pins a
//! bypass that was tried and is closed.
//!
//! Run: cargo test -p fastauth-core --test fast61_nul -- --nocapture --test-threads=1

mod common;

use std::time::{Duration as StdDuration, Instant};

use bytes::Bytes;
use common::{ORIGIN, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use http::{Method, Request, StatusCode, header};
use serde_json::Value;

fn auth() -> Auth<MemoryAdapter> {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .build()
        .expect("valid config")
}

async fn send(
    auth: &Auth<MemoryAdapter>,
    method: Method,
    uri: &str,
    body: &[u8],
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Bytes::copy_from_slice(body))
        .unwrap();
    let response = auth.handle(request).await;
    let json = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
    (response.status(), json)
}

fn is_nul_refusal(status: StatusCode, json: &Value) -> bool {
    status == StatusCode::BAD_REQUEST
        && json["code"] == "INVALID_REQUEST_BODY"
        && json["message"].as_str().is_some_and(|m| m.contains("NUL"))
}

fn users(auth: &Auth<MemoryAdapter>) -> usize {
    auth.adapter().dump("user").len()
}

/// guard: a `\u0000` escape is refused wherever it sits in the JSON body: a field the
/// endpoint reads, a key, a field it ignores, a nested value, right after an escaped
/// backslash, or as the low half of a surrogate escape. No user is created.
#[tokio::test]
async fn guard_nul_escapes_anywhere_in_the_body_are_refused() {
    let auth = auth();
    for body in [
        r#"{"email":"a@acme.dk","password":"correct horse","name":"Ada\u0000Admin"}"#,
        r#"{"email":"a@acme.dk","password":"correct horse","name":"Ada","na\u0000me":"x"}"#,
        r#"{"email":"a@acme.dk","password":"correct horse","name":"Ada","ignored":"\u0000"}"#,
        r#"{"email":"a@acme.dk","password":"correct horse","name":"Ada","x":{"y":["\u0000"]}}"#,
        r#"{"email":"a@acme.dk","password":"correct horse","name":"Ada\\\u0000"}"#,
        r#"{"email":"a@acme.dk","password":"correct horse","name":"\uD800\u0000"}"#,
        r#"{"email":"a@acme.dk\u0000","password":"correct horse","name":"Ada"}"#,
        r#"{"email":"a@acme.dk","password":"correct\u0000horse","name":"Ada"}"#,
    ] {
        let (status, json) = send(
            &auth,
            Method::POST,
            "/api/auth/sign-up/email",
            body.as_bytes(),
        )
        .await;
        assert!(is_nul_refusal(status, &json), "{body}: {status} {json}");
    }
    assert_eq!(users(&auth), 0);
}

/// guard: escapes that look like a NUL but aren't one pass: `\\u0000` (an escaped backslash,
/// then text) and `\u005cu0000` (an escaped backslash spelled as \u005c, then text).
#[tokio::test]
async fn guard_text_that_only_looks_like_a_nul_escape_passes() {
    let auth = auth();
    for (n, name) in [r#"Ada\\u0000"#, r#"Ada\u005cu0000"#, r#"Ada\u0001"#]
        .iter()
        .enumerate()
    {
        let body =
            format!(r#"{{"email":"a{n}@acme.dk","password":"correct horse","name":"{name}"}}"#);
        let (status, json) = send(
            &auth,
            Method::POST,
            "/api/auth/sign-up/email",
            body.as_bytes(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}: {json}");
    }
}

/// guard: raw bytes that would decode to NUL in a lax decoder (a raw NUL inside a string,
/// overlong UTF-8 `C0 80`, a three-byte overlong `E0 80 80`, CESU `ED A0 80`) are refused by
/// the JSON parser as a client error, never a 500 or a stored value.
#[tokio::test]
async fn guard_raw_and_overlong_nul_bytes_are_client_errors() {
    let auth = auth();
    for bad in [&b"\x00"[..], b"\xC0\x80", b"\xE0\x80\x80", b"\xED\xA0\x80"] {
        let mut body = br#"{"email":"a@acme.dk","password":"correct horse","name":"Ada"#.to_vec();
        body.extend_from_slice(bad);
        body.extend_from_slice(br#""}"#);
        let (status, json) = send(&auth, Method::POST, "/api/auth/sign-up/email", &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad:?}: {json}");
    }
    assert_eq!(users(&auth), 0);
}

/// guard: in a GET query, `%00` is refused anywhere, also next to other escapes; `%2500` (the
/// text "%00") and `+` are not NULs and get the endpoint's own answer.
#[tokio::test]
async fn guard_query_nul_forms() {
    let auth = auth();
    for query in [
        "token=%00",
        "token=a%00b",
        "to%00ken=x",
        "token=%C0%80%00",
        "token=x&x=%00",
    ] {
        let (status, json) = send(
            &auth,
            Method::GET,
            &format!("/api/auth/verify-email?{query}"),
            b"",
        )
        .await;
        assert!(is_nul_refusal(status, &json), "{query}: {status} {json}");
    }
    for query in ["token=%2500", "token=%25%30%30", "token=+", "token=%u0000"] {
        let (status, json) = send(
            &auth,
            Method::GET,
            &format!("/api/auth/verify-email?{query}"),
            b"",
        )
        .await;
        assert!(!is_nul_refusal(status, &json), "{query}: {status} {json}");
        assert!(status.as_u16() < 500, "{query}: {status} {json}");
    }
}

/// guard: a path parameter is never percent-decoded, so `/reset-password/%00` looks up the
/// text "%00" (hashed) and answers the invalid-token redirect; no NUL reaches the database.
#[tokio::test]
async fn guard_path_token_cannot_carry_a_nul() {
    let auth = auth();
    for token in ["%00", "a%00b", "%2500"] {
        let (status, json) = send(
            &auth,
            Method::GET,
            &format!("/api/auth/reset-password/{token}?callbackURL=http://localhost:3000/reset"),
            b"",
        )
        .await;
        assert_eq!(status, StatusCode::FOUND, "{token}: {json}");
    }
}

/// guard: the NUL scan is linear. A 64 KiB body of escaped backslashes (the scanner's
/// two-byte skip) or of `\u0001` escapes, ending in a NUL, is refused in well under the time
/// a quadratic scan would take (`2^32 steps).
#[tokio::test]
async fn guard_nul_scan_on_a_64_kib_body_is_linear() {
    let auth = auth();
    for unit in [r"\\", r"\u0001", "\\", "u0000"] {
        let name = unit.repeat((60 * 1024) / unit.len() / 2 * 2);
        let body =
            format!(r#"{{"email":"a@acme.dk","password":"correct horse","name":"{name}\u0000"}}"#);
        assert!(body.len() <= 64 * 1024);
        let started = Instant::now();
        let (status, json) = send(
            &auth,
            Method::POST,
            "/api/auth/sign-up/email",
            body.as_bytes(),
        )
        .await;
        let took = started.elapsed();
        println!("[64 KiB body of {unit:?}] {status} in {took:?}");
        assert!(status.is_client_error(), "{json}");
        assert!(took < StdDuration::from_millis(500), "{took:?}");
    }
}
