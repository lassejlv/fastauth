//! FAST-45 security review evidence (7cd9718): secret rotation cannot retire a leaked secret.
//! sec_ tests assert the secure behaviour and fail on 7cd9718 on purpose.
//!
//! Run: cargo test -p fastauth-core --test security_fast45_rotation -- --nocapture --test-threads=1

mod common;

use common::{Client, secret};
use fastauth_core::crypto::{Argon2id, base64url, base64url_decode};
use fastauth_core::prelude::*;
use hmac::{Hmac, KeyInit, Mac};
use http::StatusCode;
use sha2::Sha256;

fn retired() -> Secret {
    secret()
}

fn current() -> Secret {
    Secret::from_bytes(vec![99u8; 32])
}

fn build(db: MemoryAdapter, secrets: Vec<Secret>) -> Auth<MemoryAdapter> {
    FastAuth::builder()
        .secrets(secrets)
        .base_url("http://localhost:3000")
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .session(SessionConfig::default().cookie_cache(Duration::minutes(5)))
        .rate_limit(RateLimit::disabled())
        .build()
        .expect("valid config")
}

/// What a holder of the raw secret computes: HKDF-SHA256(salt "fastauth", info
/// "fastauth/v1/cookie-cache"), then HMAC-SHA256 over the value (crypto.rs:56-62, 181-194).
fn sign_cache(raw_secret: &[u8], value: &str) -> String {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(b"fastauth"), raw_secret);
    let mut key = [0u8; 32];
    hk.expand(b"fastauth/v1/cookie-cache", &mut key).unwrap();
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
    mac.update(value.as_bytes());
    format!("{value}.{}", base64url(&mac.finalize().into_bytes()))
}

/// CRYPTO-1: .secrets([new, old]) makes every secret verify every signature as well as
/// decrypt (crypto.rs:156-204). The docs say to keep the old secret in the list for as long
/// as encrypted columns (two-factor secrets, OAuth tokens, JWT private keys) still need it,
/// and nothing re-encrypts them (docs/concepts/03-security.md:21-26). So a leaked secret
/// can't be retired: after the app "rotates" to a new one, whoever holds the leaked secret
/// still signs a cookie-cache payload for any user and is that user, with no session row.
/// The same holds for two-factor trusted-device cookies and the admin plugin's cookies.
#[tokio::test]
async fn sec_a_rotated_out_secret_can_no_longer_sign_cookies() {
    let db = MemoryAdapter::new();
    let before = build(db.clone(), vec![retired()]);
    let mut victim = Client::new(before.clone());
    let res = victim.sign_up("ceo@acme.dk", "correct horse").await;
    let victim_id = res.json["user"]["id"].as_str().unwrap().to_owned();
    let mut attacker = Client::new(before);
    let res = attacker
        .sign_up("attacker@evil.example", "correct horse")
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let attacker_id = res.json["user"]["id"].as_str().unwrap().to_owned();
    attacker.get("/get-session").await;

    // The secret leaks; the operator rotates: new secret first, the old one kept for
    // decryption as documented. The attacker keeps their own session cookie.
    let after = build(db, vec![current(), retired()]);
    attacker.auth = after;
    let cache_name = "fastauth.session_data";
    let cached = attacker
        .jar
        .get(cache_name)
        .cloned()
        .expect("a cookie cache was set");
    let (encoded, _) = cached.rsplit_once('.').unwrap();
    let json = String::from_utf8(base64url_decode(encoded).unwrap()).unwrap();
    let forged = json
        .replace(&attacker_id, &victim_id)
        .replace("attacker@evil.example", "ceo@acme.dk");
    let leaked = vec![42u8; 32];
    attacker.jar.insert(
        cache_name.into(),
        sign_cache(&leaked, &base64url(forged.as_bytes())),
    );

    let res = attacker.get("/get-session").await;
    let email = res.json["user"]["email"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    println!(
        "[get-session after rotation, cache signed with the old secret] status={} user={email:?}",
        res.status
    );
    assert_ne!(
        email, "ceo@acme.dk",
        "after rotating to a new secret, a cookie signed with the leaked one still signs in as the victim"
    );
}
