//! The API-key header (`x-api-key`) through the session resolver, and `/api-key/verify`. A
//! session or a valid answer may only come back for the exact key the server issued.

#![no_main]

use std::sync::LazyLock;

use arbitrary::Arbitrary;
use bytes::Bytes;
use fastauth_core::crypto::{Argon2id, Secret};
use fastauth_core::prelude::*;
use fastauth_fuzz::client::Client;
use fastauth_fuzz::{BASE_URL, RUNTIME, SECRET};
use fastauth_plugin_api_key::ApiKeys;
use http::{HeaderValue, Request, header};
use libfuzzer_sys::fuzz_target;
use serde_json::json;

type KeyAuth = Auth<MemoryAdapter, (), plugins![ApiKeys]>;

struct Fixture {
    auth: KeyAuth,
    key: String,
}

static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
    let auth: KeyAuth = FastAuth::builder()
        .secret(Secret::from_bytes(SECRET.to_vec()))
        .base_url(BASE_URL)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(256, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(ApiKeys::new().sessions(true).disable_rate_limit())
        .build()
        .expect("valid config");
    let mut client = Client::new(&auth);
    client.sign_up("key@acme.dk");
    let created = client.post("/api-key/create", &json!({ "name": "fuzz" }));
    let key = created.json["key"].as_str().expect("a key").to_owned();
    Fixture { auth, key }
});

#[derive(Arbitrary, Debug)]
struct Input {
    mode: u8,
    junk: String,
    index: u16,
}

fn candidate(key: &str, input: &Input) -> String {
    let junk = &input.junk;
    match input.mode % 6 {
        0 => junk.clone(),
        1 => format!("{key}{junk}"),
        2 => format!("{junk}{key}"),
        3 => {
            let mut chars: Vec<char> = key.chars().collect();
            let i = usize::from(input.index) % chars.len();
            chars[i] = if chars[i].is_ascii_lowercase() {
                chars[i].to_ascii_uppercase()
            } else {
                chars[i].to_ascii_lowercase()
            };
            chars.into_iter().collect()
        }
        4 => key
            .chars()
            .take(usize::from(input.index) % key.len())
            .collect(),
        _ => format!(" {key} "),
    }
}

fuzz_target!(|input: Input| {
    let fixture = &*FIXTURE;
    let value = candidate(&fixture.key, &input);
    if let Ok(header_value) = HeaderValue::from_str(&value) {
        let request = Request::get("/api/auth/get-session")
            .header("x-api-key", header_value)
            .body(Bytes::new())
            .unwrap();
        let response = send_any(&fixture.auth, request);
        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap_or_default();
        assert_ne!(response.status(), 500, "500 for x-api-key {value:?}");
        if response.status() == 200 && !body.is_null() {
            assert_eq!(value, fixture.key, "a session for x-api-key {value:?}");
        }
    }
    let request = Request::post("/api/auth/api-key/verify")
        .header(header::ORIGIN, BASE_URL)
        .body(Bytes::from(json!({ "key": value }).to_string()))
        .unwrap();
    let response = send_any(&fixture.auth, request);
    assert_ne!(response.status(), 500, "500 verifying {value:?}");
    let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap_or_default();
    if body["valid"] == true {
        assert_eq!(value, fixture.key, "/api-key/verify accepted {value:?}");
    }
});

fn send_any(auth: &KeyAuth, request: Request<Bytes>) -> fastauth_core::endpoint::Response {
    RUNTIME.block_on(auth.handle(request))
}
