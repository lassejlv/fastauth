//! Multi-session device cookies (`*_multi-*`): a Cookie header mixing genuine device cookies,
//! forged ones, genuine values under other names and tampered values, then any of
//! `list-device-sessions`, `set-active`, `revoke` and `/sign-out`. A browser may only see,
//! switch to or revoke sessions whose signed cookies it actually holds, and never a 500.

#![no_main]

use arbitrary::Arbitrary;
use fastauth_core::crypto::{Argon2id, Secret};
use fastauth_core::prelude::*;
use fastauth_fuzz::client::Client;
use fastauth_fuzz::{BASE_URL, SECRET};
use fastauth_plugin_multi_session::MultiSession;
use http::{Method, StatusCode};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

type MultiAuth = Auth<MemoryAdapter, (), plugins![MultiSession]>;

fn build() -> MultiAuth {
    FastAuth::builder()
        .secret(Secret::from_bytes(SECRET.to_vec()))
        .base_url(BASE_URL)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(256, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(MultiSession::new())
        .build()
        .expect("valid config")
}

#[derive(Arbitrary, Debug)]
enum Pick {
    /// The jar's nth cookie as the browser holds it.
    Genuine(u8),
    /// A device-session cookie the server never set.
    Forged(String, String),
    /// The jar's nth value under another name.
    Renamed(u8, String),
    /// The jar's nth cookie with junk after its value.
    Tampered(u8, String),
}

#[derive(Arbitrary, Debug)]
enum Token {
    Real(bool),
    Upper(bool),
    Fuzz(String),
}

#[derive(Arbitrary, Debug)]
enum Op {
    List,
    SetActive(Token),
    Revoke(Token),
    SignOut,
}

#[derive(Arbitrary, Debug)]
struct Input {
    cookies: Vec<Pick>,
    ops: Vec<Op>,
}

fuzz_target!(|input: Input| {
    let auth = build();
    let mut browser = Client::new(&auth);
    let tokens = [browser.sign_up("a@acme.dk"), browser.sign_up("b@acme.dk")];
    let jar: Vec<(String, String)> = browser.jar.clone().into_iter().collect();
    let signed: Vec<&str> = jar
        .iter()
        .filter(|(name, _)| name.contains("_multi-"))
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(signed.len(), 2, "both sign-ups are remembered: {jar:?}");

    let mut cookies = Vec::new();
    for pick in input.cookies.iter().take(6) {
        let nth = |i: &u8| &jar[usize::from(*i) % jar.len()];
        cookies.push(match pick {
            Pick::Genuine(i) => format!("{}={}", nth(i).0, nth(i).1),
            Pick::Forged(name, value) => format!("fastauth.session_token_multi-{name}={value}"),
            Pick::Renamed(i, name) => format!("{name}={}", nth(i).1),
            Pick::Tampered(i, junk) => format!("{}={}{junk}", nth(i).0, nth(i).1),
        });
    }
    let header = cookies.join("; ");
    if http::HeaderValue::from_str(&header).is_err() {
        return;
    }
    // A token is held when the header carries its genuine signed device cookie value.
    let held = |token: &str| {
        jar.iter().any(|(name, value)| {
            name.contains("_multi-")
                && name.ends_with(&token.to_lowercase())
                && header.contains(value.as_str())
        })
    };
    let alive = |token: &str| {
        let session_cookie = jar
            .iter()
            .find(|(name, value)| {
                name.contains("_multi-")
                    && name.ends_with(&token.to_lowercase())
                    && !value.is_empty()
            })
            .map(|(_, value)| value.clone())
            .unwrap();
        let mut probe = Client::new(&auth);
        probe
            .jar
            .insert("fastauth.session_token".into(), session_cookie);
        !probe.get("/get-session").json.is_null()
    };

    for op in input.ops.iter().take(4) {
        let mut client = Client::new(&auth);
        let token_of = |t: &Token| match t {
            Token::Real(b) => tokens[usize::from(*b)].clone(),
            Token::Upper(b) => tokens[usize::from(*b)].to_uppercase(),
            Token::Fuzz(s) => s.clone(),
        };
        let request =
            |client: &mut Client<'_, _, _, _>, method: Method, path: &str, body: Option<&Value>| {
                let mut builder = http::Request::builder()
                    .method(method)
                    .uri(format!("/api/auth{path}"))
                    .header(http::header::ORIGIN, BASE_URL)
                    .header(http::header::COOKIE, header.as_str());
                let body =
                    body.map_or_else(bytes::Bytes::new, |b| bytes::Bytes::from(b.to_string()));
                if !body.is_empty() {
                    builder = builder.header(http::header::CONTENT_TYPE, "application/json");
                }
                client.send_raw(builder.body(body).unwrap())
            };
        let reply = match op {
            Op::List => request(
                &mut client,
                Method::GET,
                "/multi-session/list-device-sessions",
                None,
            ),
            Op::SetActive(t) => request(
                &mut client,
                Method::POST,
                "/multi-session/set-active",
                Some(&json!({ "sessionToken": token_of(t) })),
            ),
            Op::Revoke(t) => request(
                &mut client,
                Method::POST,
                "/multi-session/revoke",
                Some(&json!({ "sessionToken": token_of(t) })),
            ),
            Op::SignOut => request(&mut client, Method::POST, "/sign-out", Some(&json!({}))),
        };
        assert_ne!(
            reply.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{op:?}: {}",
            reply.json
        );
        if reply.status == StatusCode::OK {
            match op {
                Op::List => {
                    for item in reply.json.as_array().into_iter().flatten() {
                        let token = item["session"]["token"].as_str().unwrap_or_default();
                        assert!(
                            tokens.iter().any(|t| t == token),
                            "listed an unknown session: {item}"
                        );
                        assert!(
                            held(token),
                            "listed a session the header doesn't hold: {header:?}"
                        );
                    }
                }
                Op::SetActive(_) => {
                    let token = reply.json["session"]["token"].as_str().unwrap_or_default();
                    assert!(
                        held(token),
                        "set-active switched to a session the header doesn't hold: {header:?}"
                    );
                }
                _ => {}
            }
        }
        for token in &tokens {
            if !held(token) {
                assert!(
                    alive(token),
                    "{op:?} with {header:?} revoked a session the browser doesn't hold"
                );
            }
        }
    }
});
