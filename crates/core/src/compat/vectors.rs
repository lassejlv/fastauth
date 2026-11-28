//! The golden vectors in `tests/compat/better-auth/vectors`: better-auth.json, made by Better Auth's
//! own code, must verify here byte for byte, and fastauth.json, made here, is what
//! `check.mjs` verifies with Better Auth's code. `FASTAUTH_VECTORS_OUT=path` writes a fresh
//! fastauth.json there (`run-vectors.sh` does).

use http::HeaderMap;
use http::header::COOKIE;
use serde_json::{Value, json};

use super::*;
use crate::config::CookieSigning;
use crate::cookies;
use crate::crypto::{Keys, SignPurpose};

fn load(name: &str) -> Value {
    let path = format!(
        "{}/../../tests/compat/better-auth/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap()
}

fn keys(secret: &str) -> Keys {
    Keys::new(vec![Secret::from_bytes(vec![7u8; 32])])
        .with_cookie_signing(&CookieSigning::better_auth(secret))
}

fn str_of(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("{v} is not a string"))
}

fn array(v: &Value) -> &Vec<Value> {
    v.as_array()
        .unwrap_or_else(|| panic!("{v} is not an array"))
}

/// What fastauth reads from a request with this Cookie header, the way the session lookup does.
fn read_signed(keys: &Keys, header: &str, name: &str) -> Option<String> {
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, header.parse().unwrap());
    let raw = cookies::read(&headers, name)?;
    keys.verify_token(&keys.decode_cookie(raw))
        .map(str::to_owned)
}

#[test]
fn better_auth_cookies_verify_and_sign_identically() {
    let vectors = load("better-auth.json");
    let mut checked = 0;
    for set in array(&vectors["cookies"]) {
        let name = str_of(&set["name"]);
        let keys = keys(str_of(&set["secret"]));
        for signed in array(&set["signed"]) {
            let (value, cookie) = (str_of(&signed["value"]), str_of(&signed["cookie"]));
            assert_eq!(keys.sign(SignPurpose::Cookie, value), cookie, "{value:?}");
            assert_eq!(
                read_signed(&keys, &format!("{name}={cookie}"), name).as_deref(),
                Some(value)
            );
            checked += 1;
        }
        for case in array(&set["parse"]) {
            let header = str_of(&case["header"]);
            assert_eq!(
                read_signed(&keys, header, name).as_deref(),
                case["result"].as_str(),
                "{}: {header}",
                case["label"]
            );
            checked += 1;
        }
    }
    assert!(checked > 90, "{checked}");
}

#[test]
fn better_auth_password_hashes_verify_and_hash_identically() {
    let vectors = load("better-auth.json");
    for case in array(&vectors["scrypt"]) {
        let hash = str_of(&case["hash"]);
        let (salt, _) = hash.split_once(':').unwrap();
        assert_eq!(
            BetterAuthScrypt::hash_with_salt(str_of(&case["password"]), salt),
            hash,
            "{}",
            case["label"]
        );
        for check in array(&case["checks"]) {
            assert_eq!(
                BetterAuthScrypt.verify(str_of(&check["password"]), hash),
                Ok(check["result"].as_bool().unwrap()),
                "{}: {}",
                case["label"],
                check["password"]
            );
        }
    }
    for case in array(&vectors["malformed"]) {
        let got = BetterAuthScrypt.verify(str_of(&case["password"]), str_of(&case["hash"]));
        match case["result"].as_bool() {
            Some(expected) => assert_eq!(got, Ok(expected), "{}", case["label"]),
            None => assert!(got.is_err(), "{}: {got:?}", case["label"]),
        }
    }
}

/// The secrets, values and passwords of better-auth.json, signed and hashed by fastauth.
fn fastauth_vectors() -> Value {
    let vectors = load("better-auth.json");
    let cookies: Vec<Value> = array(&vectors["cookies"])
        .iter()
        .map(|set| {
            let keys = keys(str_of(&set["secret"]));
            let signed: Vec<Value> = array(&set["signed"])
                .iter()
                .map(|s| {
                    let value = str_of(&s["value"]);
                    json!({ "value": value, "cookie": keys.sign(SignPurpose::Cookie, value) })
                })
                .collect();
            json!({ "secret": set["secret"], "name": set["name"], "signed": signed })
        })
        .collect();
    let scrypt: Vec<Value> = array(&vectors["scrypt"])
        .iter()
        .map(|case| {
            let password = str_of(&case["password"]);
            let hash = BetterAuthScrypt.hash(password).unwrap();
            json!({ "label": case["label"], "password": password, "hash": hash })
        })
        .collect();
    json!({ "generator": "fastauth-core compat::vectors", "cookies": cookies, "scrypt": scrypt })
}

#[test]
fn fastauth_vectors_for_better_auth() {
    let checked_in = load("fastauth.json");
    for set in array(&checked_in["cookies"]) {
        let keys = keys(str_of(&set["secret"]));
        let name = str_of(&set["name"]);
        for signed in array(&set["signed"]) {
            let cookie = str_of(&signed["cookie"]);
            assert_eq!(
                read_signed(&keys, &format!("{name}={cookie}"), name).as_deref(),
                Some(str_of(&signed["value"]))
            );
        }
    }
    for case in array(&checked_in["scrypt"]) {
        assert_eq!(
            BetterAuthScrypt.verify(str_of(&case["password"]), str_of(&case["hash"])),
            Ok(true)
        );
    }
    if let Some(path) = std::env::var_os("FASTAUTH_VECTORS_OUT") {
        let text = serde_json::to_string_pretty(&fastauth_vectors()).unwrap() + "\n";
        std::fs::write(&path, text).unwrap();
    }
}
