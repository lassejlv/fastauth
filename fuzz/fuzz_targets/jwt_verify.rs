//! Full JWT verification, on both sides: the plugin's own `verify` and the resource
//! server's `JwksVerifier` with the plugin's JWKS. Arbitrary tokens never verify; tokens the
//! server signs with fuzzed claims verify only when `exp`, `nbf`, `iss`, `aud` (and, for
//! `JwksVerifier`, `sub`) all hold; and a genuine token with a byte changed verifies only
//! if it still carries the same claims.

#![no_main]

use std::sync::LazyLock;

use arbitrary::Arbitrary;
use fastauth_core::crypto::{Argon2id, Secret};
use fastauth_core::prelude::*;
use fastauth_fuzz::json::ArbJson;
use fastauth_fuzz::{BASE_URL, RUNTIME, SECRET};
use fastauth_plugin_jwt::{JwksVerifier, Jwt, JwtExt};
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value, json};

type JwtAuth = Auth<MemoryAdapter, (), plugins![Jwt]>;

struct Fixture {
    auth: JwtAuth,
    verifier: JwksVerifier,
}

static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
    let auth: JwtAuth = FastAuth::builder()
        .secret(Secret::from_bytes(SECRET.to_vec()))
        .base_url(BASE_URL)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(256, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Jwt::new())
        .build()
        .expect("valid config");
    let jwks = RUNTIME.block_on(auth.jwt().jwks()).expect("jwks");
    let jwks = serde_json::to_string(&jwks).unwrap();
    let verifier = JwksVerifier::from_json(&jwks, BASE_URL, BASE_URL).expect("valid JWKS");
    Fixture { auth, verifier }
});

/// A claim value: plausible ones that sit near the edges, or anything.
#[derive(Arbitrary, Debug)]
enum Claim {
    /// Now plus this many seconds.
    Time(i16),
    /// Now plus this many seconds, as a float.
    FloatTime(i16, u8),
    BaseUrl,
    BaseUrlIn(Vec<String>),
    Text(String),
    Any(ArbJson),
}

#[derive(Arbitrary, Debug)]
enum Input {
    Raw(String),
    Claims(Vec<(u8, Claim)>),
    Mutate(Vec<(u8, Claim)>, u16, u8),
}

const KEYS: [&str; 7] = ["exp", "nbf", "iat", "iss", "aud", "sub", "jti"];

fn claims(input: &[(u8, Claim)], now: i64) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("sub".into(), json!("user-1"));
    for (key, claim) in input.iter().take(8) {
        let value = match claim {
            Claim::Time(delta) => json!(now + i64::from(*delta)),
            Claim::FloatTime(delta, frac) => {
                json!(now as f64 + f64::from(*delta) + f64::from(*frac) / 256.0)
            }
            Claim::BaseUrl => json!(BASE_URL),
            Claim::BaseUrlIn(others) => {
                let mut list: Vec<Value> = others.iter().take(3).map(|o| json!(o)).collect();
                list.push(json!(BASE_URL));
                Value::Array(list)
            }
            Claim::Text(text) => json!(text),
            Claim::Any(value) => value.to_json(),
        };
        map.insert(KEYS[usize::from(*key) % KEYS.len()].into(), value);
    }
    map
}

fn number(value: Option<&Value>) -> Option<f64> {
    value.and_then(Value::as_f64)
}

/// What both verifiers must have checked on claims they accept.
fn assert_valid(claims: &Map<String, Value>, now: i64, who: &str) {
    let exp = number(claims.get("exp"));
    assert!(
        exp.is_some_and(|exp| exp >= (now - 2) as f64),
        "{who} accepted exp {:?} at {now}: {claims:?}",
        claims.get("exp")
    );
    if let Some(nbf) = claims.get("nbf") {
        assert!(
            number(Some(nbf)).is_some_and(|nbf| nbf <= (now + 2) as f64),
            "{who} accepted nbf {nbf:?} at {now}"
        );
    }
    // jsonwebtoken also takes `iss` as an array holding the issuer (see the README).
    let iss_ok = match claims.get("iss") {
        Some(Value::String(iss)) => iss == BASE_URL,
        Some(Value::Array(isss)) => isss.contains(&json!(BASE_URL)),
        _ => false,
    };
    assert!(iss_ok, "{who} accepted iss {:?}", claims.get("iss"));
    let aud_ok = match claims.get("aud") {
        Some(Value::String(aud)) => aud == BASE_URL,
        Some(Value::Array(auds)) => auds.contains(&json!(BASE_URL)),
        _ => false,
    };
    assert!(aud_ok, "{who} accepted aud {:?}", claims.get("aud"));
}

fuzz_target!(|input: Input| {
    let fixture = &*FIXTURE;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let jwt = fixture.auth.jwt();
    let (token, signed) = match &input {
        Input::Raw(token) => (token.clone(), None),
        Input::Claims(c) | Input::Mutate(c, ..) => {
            let Ok(token) = RUNTIME.block_on(jwt.sign(claims(c, now))) else {
                return;
            };
            let Some(signed) = RUNTIME.block_on(jwt.verify(&token)).ok().flatten() else {
                return_or_check(fixture, &token, now);
                return;
            };
            (token, Some(signed))
        }
    };
    let token = match &input {
        Input::Mutate(_, pos, byte) => {
            let mut bytes = token.into_bytes();
            let i = usize::from(*pos) % bytes.len();
            bytes[i] = *byte;
            match String::from_utf8(bytes) {
                Ok(token) => token,
                Err(_) => return,
            }
        }
        _ => token,
    };
    let plugin = RUNTIME.block_on(jwt.verify(&token)).ok().flatten();
    let resource = fixture.verifier.verify::<Map<String, Value>>(&token).ok();
    match &input {
        Input::Raw(_) => {
            assert!(
                plugin.is_none(),
                "the plugin verified a raw token: {token:?}"
            );
            assert!(
                resource.is_none(),
                "JwksVerifier verified a raw token: {token:?}"
            );
        }
        Input::Claims(_) => {
            for (who, claims) in [("the plugin", &plugin), ("JwksVerifier", &resource)] {
                if let Some(claims) = claims {
                    assert_valid(claims, now, who);
                }
            }
            if let Some(claims) = &resource {
                assert!(claims.contains_key("sub"), "JwksVerifier accepted no sub");
            }
        }
        Input::Mutate(..) => {
            for claims in [&plugin, &resource].into_iter().flatten() {
                assert_eq!(
                    Some(claims),
                    signed.as_ref(),
                    "a changed token verified with other claims: {token:?}"
                );
            }
        }
    }
});

/// A token the plugin rejects right after signing must be rejected by `JwksVerifier` too,
/// unless it only lacks `sub`.
fn return_or_check(fixture: &Fixture, token: &str, now: i64) {
    if let Ok(claims) = fixture.verifier.verify::<Map<String, Value>>(token) {
        assert_valid(&claims, now, "JwksVerifier (rejected by the plugin)");
    }
}
