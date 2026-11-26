//! The username plugin's normalizer and validator, directly and through
//! `/sign-in/username` and `/is-username-available`. What `validate` accepts must meet the
//! configured length and the default character set, and a username sign-in may only succeed
//! for the stored username.

#![no_main]

use arbitrary::Arbitrary;
use fastauth_core::crypto::{Argon2id, Secret};
use fastauth_core::prelude::*;
use fastauth_fuzz::client::{Client, PASSWORD};
use fastauth_fuzz::{BASE_URL, Rotating, SECRET};
use fastauth_plugin_username::{Username, ValidationOrder};
use http::StatusCode;
use libfuzzer_sys::fuzz_target;
use serde_json::json;

type NameAuth = Auth<MemoryAdapter, (), plugins![Username]>;

const STORED: &str = "fuzz_user";

/// Rebuilt now and then: every matching sign-in adds a session.
static AUTH: Rotating<NameAuth> = Rotating::new(
    || {
        let auth: NameAuth = FastAuth::builder()
            .secret(Secret::from_bytes(SECRET.to_vec()))
            .base_url(BASE_URL)
            .database(MemoryAdapter::new())
            .email_password(EmailPassword::default().hasher(Argon2id::with_params(256, 1, 1)))
            .rate_limit(RateLimit::disabled())
            .plugin(Username::new())
            .build()
            .expect("valid config");
        let reply = Client::new(&auth).post(
            "/sign-up/email",
            &json!({ "email": "name@acme.dk", "password": PASSWORD, "name": "Fuzz", "username": "Fuzz_User" }),
        );
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.json);
        auth
    },
    20_000,
);

#[derive(Arbitrary, Debug)]
struct Input {
    min: u8,
    max: u8,
    post_normalization: bool,
    normalize: bool,
    candidate: String,
}

fuzz_target!(|input: Input| {
    let (min, max) = (usize::from(input.min % 8), usize::from(input.max % 40));
    let mut plugin = Username::new()
        .min_username_length(min)
        .max_username_length(max);
    if input.post_normalization {
        plugin = plugin.username_validation_order(ValidationOrder::PostNormalization);
    }
    if !input.normalize {
        plugin = plugin.disable_username_normalization();
    }
    let candidate = &input.candidate;
    let normalized = plugin.normalize(candidate);
    if plugin.validate(candidate).is_ok() {
        let checked = if input.post_normalization {
            &normalized
        } else {
            candidate
        };
        let length = checked.chars().count();
        assert!(
            (min..=max).contains(&length),
            "{checked:?} passed with {length} chars outside {min}..={max}"
        );
        assert!(
            !checked.is_empty()
                && checked
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.'),
            "{checked:?} passed the default validator"
        );
    }

    let auth = AUTH.get();
    let mut client = Client::new(&*auth);
    let reply = client.post(
        "/sign-in/username",
        &json!({ "username": candidate, "password": PASSWORD }),
    );
    assert_ne!(
        reply.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{candidate:?}: {}",
        reply.json
    );
    if reply.status == StatusCode::OK {
        assert_eq!(
            candidate.to_lowercase(),
            STORED,
            "{candidate:?} signed in as {STORED}"
        );
    }
    let reply = client.post("/is-username-available", &json!({ "username": candidate }));
    assert_ne!(
        reply.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{candidate:?}: {}",
        reply.json
    );
    if reply.json["available"] == false {
        assert_eq!(
            candidate.to_lowercase(),
            STORED,
            "{candidate:?} reported taken"
        );
    }
});
