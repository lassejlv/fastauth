//! FAST-61 adversarial review of the 0.6.0 fixes in #47: secret rotation and the build-time
//! configuration checks (`Builder::build`, `allow_insecure_config`). Tests named `sec_*` assert
//! the secure or correct behaviour and fail on main e1c00a33 on purpose; tests named `guard_*`
//! pass and pin behaviour that was checked and is right.
//!
//! Run: cargo test -p fastauth-core --test fast61_rotation_config -- --nocapture --test-threads=1

mod common;

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::mail::AuthEmail;
use fastauth_core::prelude::*;
use http::StatusCode;
use serde_json::json;

fn fast_hasher() -> EmailPassword {
    EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1))
}

fn generated() -> Secret {
    Secret::from_base64(&Secret::generate())
}

fn build_with(
    url: &str,
    secrets: Vec<Secret>,
    insecure: bool,
) -> Result<Auth<MemoryAdapter>, BuildError> {
    FastAuth::builder()
        .secrets(secrets)
        .base_url(url)
        .database(MemoryAdapter::new())
        .email_password(fast_hasher())
        .allow_insecure_config(insecure)
        .build()
}

fn problems(result: Result<Auth<MemoryAdapter>, BuildError>) -> Option<String> {
    result.err().map(|e| e.to_string())
}

fn session_cookie<D, U, P>(client: &Client<D, U, P>) -> (String, String) {
    client
        .jar
        .iter()
        .find(|(k, _)| k.ends_with("session_token"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .expect("session cookie")
}

// ---------------------------------------------------------------------- rotation

fn verifying_auth(
    db: MemoryAdapter,
    mailer: MemoryMailer,
    secrets: Vec<Secret>,
) -> Auth<MemoryAdapter> {
    FastAuth::builder()
        .secrets(secrets)
        .base_url("http://localhost:3000")
        .database(db)
        .email_password(fast_hasher().require_email_verification(true))
        .mailer(mailer)
        .rate_limit(RateLimit::disabled())
        .build()
        .expect("valid config")
}

/// FAST61-R1: the pending-verification cookie that sign-up leaves in the browser that knows
/// the password is read with `Ctx::signed_cookie`, which accepts only the current secret
/// (internal.rs:900). FAST-56 moved the session half of `holds_credentials_of` to
/// `signed_token_cookie` but not this half. So when the operator rotates the secret between
/// a user's sign-up and their click on the verification link, the owner's own browser no
/// longer proves it holds the password, `prove_email` claims the account and deletes the
/// password the owner just chose.
#[tokio::test]
async fn sec_a_rotation_between_sign_up_and_verification_keeps_the_owners_password() {
    let db = MemoryAdapter::new();
    let mailer = MemoryMailer::new();
    let mut owner = Client::new(verifying_auth(db.clone(), mailer.clone(), vec![secret()]));
    let res = owner.sign_up("owner@acme.dk", "correct horse").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert!(
        owner.jar.contains_key("fastauth.pending_verification"),
        "baseline: sign-up leaves the pending-verification cookie: {:?}",
        owner.jar.keys()
    );
    assert!(
        !owner.jar.contains_key("fastauth.session_token"),
        "baseline: with require_email_verification sign-up signs nobody in"
    );
    let Some(AuthEmail::VerifyEmail(email)) = mailer.last() else {
        panic!("no verification email")
    };

    owner.auth = verifying_auth(db, mailer, vec![generated(), secret()]);
    let verified = owner
        .get(&format!("/verify-email?token={}", email.token))
        .await;
    assert!(
        verified.status.is_success() || verified.status.is_redirection(),
        "{} {}",
        verified.status,
        verified.json
    );
    owner.jar.clear();
    let signed_in = owner
        .post(
            "/sign-in/email",
            json!({ "email": "owner@acme.dk", "password": "correct horse" }),
        )
        .await;
    println!(
        "[owner signs in after verifying across a rotation] status={} {}",
        signed_in.status, signed_in.json
    );
    assert_eq!(
        signed_in.status,
        StatusCode::OK,
        "the owner verified their email from the browser they signed up in, one rotation \
         later, and lost the password they chose: {}",
        signed_in.json
    );
}

/// guard: without a rotation, the same flow keeps the password (the cookie proves it).
#[tokio::test]
async fn guard_verification_from_the_sign_up_browser_keeps_the_password() {
    let mailer = MemoryMailer::new();
    let mut owner = Client::new(verifying_auth(
        MemoryAdapter::new(),
        mailer.clone(),
        vec![secret()],
    ));
    owner.sign_up("owner@acme.dk", "correct horse").await;
    let Some(AuthEmail::VerifyEmail(email)) = mailer.last() else {
        panic!("no verification email")
    };
    owner
        .get(&format!("/verify-email?token={}", email.token))
        .await;
    owner.jar.clear();
    let signed_in = owner
        .post(
            "/sign-in/email",
            json!({ "email": "owner@acme.dk", "password": "correct horse" }),
        )
        .await;
    assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.json);
}

/// FAST61-R2: the entropy refusal takes the minimum over every secret in the list
/// (auth.rs:325-330), retired ones included. A retired secret only decrypts old columns and
/// verifies session tokens (pointers to rows), so a weak one adds nothing that keeping it as
/// the current secret didn't already give away. But an app upgrading from 0.5 with a secret
/// that 0.6 calls weak (CFG-3) can't rotate to a strong secret while keeping the old one to
/// decrypt its two-factor secrets, OAuth tokens and JWKS keys: the only way to build is
/// `allow_insecure_config(true)` in production, which also turns the http:// refusal off.
#[test]
fn sec_a_weak_retired_secret_does_not_block_rotating_to_a_strong_one() {
    let weak_0_5_secret = Secret::from_bytes(b"password password password pass!".to_vec());
    assert!(weak_0_5_secret.entropy_bits() < Secret::MIN_ENTROPY_BITS);
    let refused = problems(build_with(
        "https://acme.dk",
        vec![generated(), weak_0_5_secret],
        false,
    ));
    println!("[https build with secrets([strong, weak retired])] {refused:?}");
    assert!(
        refused.is_none(),
        "rotating to a strong secret while keeping the weak old one to decrypt is refused; \
         the only way out is allow_insecure_config(true): {refused:?}"
    );
}

/// guard: a weak *current* secret is still refused on a production host.
#[test]
fn guard_a_weak_current_secret_is_refused() {
    let refused = problems(build_with(
        "https://acme.dk",
        vec![Secret::from_bytes(vec![42u8; 32]), generated()],
        false,
    ));
    assert!(refused.is_some_and(|p| p.contains("entropy")));
}

/// guard: an empty secret list is refused; a duplicated secret (a retired secret equal to
/// the current one) builds and works; reordering keeps sessions signed by either secret,
/// since session tokens verify with any listed secret; a session cookie signed by a secret
/// that left the list is refused.
#[tokio::test]
async fn guard_secret_lists_empty_duplicate_and_reordered() {
    assert!(problems(build_with("https://acme.dk", Vec::new(), false)).is_some());

    let a = generated();
    let b = generated();
    let db = MemoryAdapter::new();
    let auth = |secrets: Vec<Secret>| {
        FastAuth::builder()
            .secrets(secrets)
            .base_url("http://localhost:3000")
            .database(db.clone())
            .email_password(fast_hasher())
            .rate_limit(RateLimit::disabled())
            .build()
            .expect("valid config")
    };
    let mut client = Client::new(auth(vec![a.clone(), a.clone()]));
    let res = client.sign_up("ada@acme.dk", "correct horse").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let (name, signed_by_a) = session_cookie(&client);

    client.auth = auth(vec![b.clone(), a.clone()]);
    let res = client.get("/get-session").await;
    assert_eq!(res.json["user"]["email"], "ada@acme.dk", "{}", res.json);

    client.auth = auth(vec![a.clone(), b.clone()]);
    client.jar.insert(name.clone(), signed_by_a.clone());
    let res = client.get("/get-session").await;
    assert_eq!(res.json["user"]["email"], "ada@acme.dk", "{}", res.json);

    client.auth = auth(vec![b.clone()]);
    client.jar.insert(name, signed_by_a);
    let res = client.get("/get-session").await;
    assert!(
        res.json.is_null(),
        "a session cookie signed by a secret that left the list is refused: {}",
        res.json
    );
}

/// guard: a session cookie whose signature is cut short, emptied, removed or extended is
/// refused (HMAC tags are compared at full length).
#[tokio::test]
async fn guard_a_truncated_or_empty_cookie_signature_is_refused() {
    let auth = FastAuth::builder()
        .secret(generated())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(fast_hasher())
        .rate_limit(RateLimit::disabled())
        .build()
        .unwrap();
    let mut client = Client::new(auth);
    client.sign_up("ada@acme.dk", "correct horse").await;
    let (name, value) = session_cookie(&client);
    let res = client.get("/get-session").await;
    assert_eq!(
        res.json["user"]["email"], "ada@acme.dk",
        "baseline: {}",
        res.json
    );
    let (token, sig) = value.rsplit_once('.').unwrap();
    for forged in [
        format!("{token}."),
        format!("{token}.{}", &sig[..sig.len() / 2]),
        format!("{token}.{}", &sig[..4]),
        token.to_owned(),
        format!("{token}.{sig}AA"),
    ] {
        client.jar.insert(name.clone(), forged.clone());
        let res = client.get("/get-session").await;
        assert!(res.json.is_null(), "{forged} was accepted: {}", res.json);
    }
}

// ---------------------------------------------------------------------- build checks

/// guard: base URLs that only look like localhost are not local, so an http:// one is
/// refused on a production build. Spellings checked: subdomain tricks, wildcard DNS,
/// percent-encoded dots, backslash, userinfo, fragment and query tricks, the IPv4-mapped
/// loopback, 0.0.0.0, a trailing dot, a lookalike punycode host and uppercase.
#[test]
fn guard_base_urls_that_only_look_local_are_refused_over_http() {
    for url in [
        "http://localhost.evil.com",
        "http://LOCALHOST.evil.com",
        "http://127.0.0.1.nip.io",
        "http://localhost%2eevil.com",
        "http://evil.com\\@localhost",
        "http://localhost@evil.com",
        "http://localhost:3000@evil.com",
        "http://evil.com#@localhost",
        "http://evil.com?@localhost",
        "http://[::ffff:127.0.0.1]",
        "http://0.0.0.0:3000",
        "http://localhost.",
        "http://evillocalhost",
        "http://lоcalhost",
        "http://acme.dk",
    ] {
        let refused = problems(build_with(url, vec![generated()], false));
        println!("[{url}] refused={}", refused.is_some());
        assert!(
            refused.is_some(),
            "{url} builds over http with a strong secret, as if it were localhost"
        );
    }
}

/// guard: spellings that really are this machine count as local (and are lenient).
#[test]
fn guard_loopback_spellings_count_as_local() {
    for url in [
        "http://localhost:3000",
        "http://LOCALHOST:3000",
        "http://app.localhost",
        "http://127.0.0.1:8080",
        "http://127.1",
        "http://2130706433",
        "http://0x7f000001",
        "http://[::1]:3000",
        "http://[0:0:0:0:0:0:0:1]",
    ] {
        let refused = problems(build_with(url, vec![secret()], false));
        assert!(refused.is_none(), "{url}: {refused:?}");
    }
}

/// guard: `allow_insecure_config(true)` turns only the two production refusals (entropy,
/// public http://) into warnings; the always-on checks still refuse. Nothing else enables it:
/// no environment variable, no `cfg!(debug_assertions)`, a `false` default, and no example,
/// template, facade or CLI path sets it (checked by grep on e1c00a33).
#[test]
fn guard_allow_insecure_config_keeps_the_always_on_checks() {
    assert!(build_with("http://acme.dk", vec![secret()], true).is_ok());
    for url in [
        "http://user:pw@acme.dk",
        "https://acme.dk/?next=x",
        "https://acme.dk/#x",
        "ftp://acme.dk",
    ] {
        assert!(
            problems(build_with(url, vec![generated()], true)).is_some(),
            "{url} built with allow_insecure_config(true)"
        );
    }
    assert!(
        problems(build_with(
            "http://acme.dk",
            vec![Secret::from_bytes(vec![1u8; 31])],
            true
        ))
        .is_some()
    );
}

/// FAST61-C1 (info): the entropy estimate is length × log2(distinct bytes), as in Better
/// Auth (which only warns). Repeating a word until the length makes up for it passes, so
/// common placeholder shapes build on a production host.
#[test]
fn sec_build_refuses_a_repeated_placeholder_secret() {
    let mut accepted = Vec::new();
    for placeholder in [
        "changeme".repeat(6),
        "secret".repeat(9),
        "0123456789abcdef".repeat(2),
        "abcdefghijklmnopqrstuvwxyz012345".to_owned(),
        "a".repeat(120) + "b",
    ] {
        let estimate = Secret::from_base64(&placeholder).entropy_bits();
        let refused = problems(build_with(
            "https://acme.dk",
            vec![Secret::from_base64(&placeholder)],
            false,
        ));
        println!(
            "[{placeholder}] estimate={estimate:.0} bits refused={}",
            refused.is_some()
        );
        if refused.is_none() {
            accepted.push(placeholder);
        }
    }
    assert!(
        accepted.is_empty(),
        "placeholder secrets build on https: {accepted:?}"
    );
}

/// FAST61-C2 (info): `openssl rand -hex 16` gives 32 hex characters, 128 random bits and the
/// 32-byte minimum. The estimate is 32 × log2(distinct hex digits seen), under 120 whenever
/// 13 or fewer of the 16 digits occur: about a third of such secrets are refused (32% of
/// 100,000 samples). This one is a real `secrets.token_hex(16)` output.
#[test]
fn sec_build_accepts_a_128_bit_hex_secret() {
    let hex = "2f708df355380d3c13310abbfbb4327b";
    let estimate = Secret::from_base64(hex).entropy_bits();
    let refused = problems(build_with(
        "https://acme.dk",
        vec![Secret::from_base64(hex)],
        false,
    ));
    println!("[openssl rand -hex 16 style secret] estimate={estimate:.0} bits refused={refused:?}");
    assert!(
        refused.is_none(),
        "a 128-bit random hex secret of the minimum length is refused: {refused:?}"
    );
}
