//! The session cookie cache (`session_data`) behind a valid signature. The fuzzer holds the
//! secret, so it can sign any payload: this reaches the JSON, row and session decoding that
//! a forged signature never gets to. A cache entry may only stand in for the session whose
//! token, schema fingerprint and lifetime it was written for; otherwise the request must fall
//! back to the database and resolve to the cookie's real user.

#![no_main]

use arbitrary::Arbitrary;
use fastauth_core::crypto::{base64url, base64url_decode};
use fastauth_fuzz::json::ArbJson;
use fastauth_fuzz::{FIXTURE, session_user, sign_cache};
use http::{HeaderMap, HeaderValue, header};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};
use std::sync::LazyLock;

#[derive(Arbitrary, Debug)]
enum Forge {
    /// Any bytes as the payload.
    Raw(Vec<u8>),
    /// The genuine payload with one top-level field replaced.
    Field(u8, ArbJson),
    /// The genuine payload with one session (`s`) or user (`u`) column replaced.
    Column(bool, u8, ArbJson),
    /// The genuine payload with `s` or `u` cut or padded to `len` columns.
    Resize(bool, u8),
    /// A signed-looking value that isn't signed.
    Unsigned(String),
}

/// The genuine cache payload the fixture's sign-in wrote.
static GENUINE: LazyLock<Value> = LazyLock::new(|| {
    let cookie = FIXTURE
        .cache_cookie
        .as_deref()
        .expect("the fixture has a cache cookie");
    let value = cookie.split_once('=').unwrap().1;
    let (encoded, _) = value.rsplit_once('.').unwrap();
    serde_json::from_slice(&base64url_decode(encoded).unwrap()).unwrap()
});

const FIELDS: [&str; 5] = ["s", "u", "t", "e", "f"];

fn forge(input: &Forge) -> String {
    let mut payload = GENUINE.clone();
    match input {
        Forge::Raw(bytes) => return sign_cache(&base64url(bytes)),
        Forge::Unsigned(value) => return value.clone(),
        Forge::Field(field, value) => {
            payload[FIELDS[usize::from(*field) % FIELDS.len()]] = value.to_json();
        }
        Forge::Column(user, index, value) => {
            let columns = payload[if *user { "u" } else { "s" }]
                .as_array_mut()
                .unwrap();
            let len = columns.len();
            columns[usize::from(*index) % len] = value.to_json();
        }
        Forge::Resize(user, len) => {
            let columns = payload[if *user { "u" } else { "s" }]
                .as_array_mut()
                .unwrap();
            columns.resize(usize::from(*len), json!("Null"));
        }
    }
    sign_cache(&base64url(payload.to_string().as_bytes()))
}

/// Whether the server may use this payload instead of the database.
fn applies(payload: &Value) -> bool {
    let genuine = &*GENUINE;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    payload["t"] == genuine["t"]
        && payload["f"] == genuine["f"]
        && payload["e"].as_i64().is_some_and(|e| e >= now)
        && payload["s"].as_array().map(Vec::len) == genuine["s"].as_array().map(Vec::len)
        && payload["u"].as_array().map(Vec::len) == genuine["u"].as_array().map(Vec::len)
}

fuzz_target!(|input: Forge| {
    let fixture = &*FIXTURE;
    let cache = forge(&input);
    if !cache.is_ascii() {
        return;
    }
    let Ok(value) = HeaderValue::from_str(&format!(
        "{}; fastauth.session_data={cache}",
        fixture.session_cookie
    )) else {
        return;
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, value);
    let user = session_user(&headers);
    let payload = cache
        .rsplit_once('.')
        .and_then(|(encoded, _)| base64url_decode(encoded))
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    if !payload.as_ref().is_some_and(applies) {
        assert_eq!(
            user.as_deref(),
            Some("fuzz@acme.dk"),
            "a cache entry that doesn't apply changed who the session is: {input:?}"
        );
    }
});
