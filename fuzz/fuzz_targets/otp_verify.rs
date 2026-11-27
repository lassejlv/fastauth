//! The one-time-code state machines: two-factor TOTP, emailed two-factor codes and backup
//! codes during a pending sign-in, and email-OTP sign-in. A sequence of fuzzed steps runs on
//! a fresh instance next to a model of which codes are live. A verify only succeeds for a code
//! that is live right then (a TOTP step not used before, the latest unspent emailed code, an
//! unused backup code, an email OTP with guesses left), and nothing answers 500.

#![no_main]

use arbitrary::Arbitrary;
use fastauth_core::crypto::{Argon2id, Secret};
use fastauth_core::mail::{AuthEmail, MemoryMailer};
use fastauth_core::prelude::*;
use fastauth_fuzz::client::{Client, PASSWORD};
use fastauth_fuzz::{BASE_URL, SECRET};
use fastauth_plugin_email_otp::EmailOtp;
use fastauth_plugin_two_factor::TwoFactor;
use fastauth_plugin_two_factor::totp::hotp;
use http::StatusCode;
use libfuzzer_sys::fuzz_target;
use serde_json::json;

type OtpAuth = Auth<MemoryAdapter, (), plugins![TwoFactor, EmailOtp]>;

const EMAIL: &str = "otp@acme.dk";
const EMAIL_ATTEMPTS: u32 = 3;

#[derive(Arbitrary, Debug)]
enum Code {
    /// The live code (TOTP: at this step offset from now).
    Live(i8),
    /// The live code with text around it.
    Padded(i8, String, String),
    Raw(String),
}

#[derive(Arbitrary, Debug)]
enum Op {
    SignIn,
    Totp(Code),
    SendOtp,
    Otp(Code),
    Backup(u8, Code),
    EmailSend,
    EmailSignIn(Code),
    EmailCheck(Code),
}

fn base32_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut bits, mut acc, mut out) = (0u32, 0u64, Vec::new());
    for c in text.bytes() {
        let Some(v) = ALPHABET.iter().position(|&a| a == c) else {
            continue;
        };
        acc = (acc << 5) | v as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn now_step() -> u64 {
    time::OffsetDateTime::now_utc().unix_timestamp() as u64 / 30
}

fn code(code: &Code, live: &str) -> String {
    match code {
        Code::Live(_) => live.to_owned(),
        Code::Padded(_, pre, post) => format!("{pre}{live}{post}"),
        Code::Raw(raw) => raw.clone(),
    }
}

fn last_code(mailer: &MemoryMailer, kind: &str) -> Option<String> {
    mailer
        .sent()
        .into_iter()
        .rev()
        .find_map(|email| match email {
            AuthEmail::Plugin(p) if p.kind == kind => p.code,
            _ => None,
        })
}

fuzz_target!(|ops: Vec<Op>| {
    let mailer = MemoryMailer::new();
    let auth: OtpAuth = FastAuth::builder()
        .secret(Secret::from_bytes(SECRET.to_vec()))
        .base_url(BASE_URL)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(256, 1, 1)))
        .mailer(mailer.clone())
        .rate_limit(RateLimit::disabled())
        .plugin(TwoFactor::new())
        .plugin(EmailOtp::new())
        .build()
        .expect("valid config");

    let mut owner = Client::new(&auth);
    owner.sign_up(EMAIL);
    let enabled = owner.post("/two-factor/enable", &json!({ "password": PASSWORD }));
    assert_eq!(enabled.status, StatusCode::OK, "{}", enabled.json);
    let uri = url::Url::parse(enabled.json["totpURI"].as_str().expect("totpURI")).unwrap();
    let secret = base32_decode(&uri.query_pairs().find(|(k, _)| k == "secret").unwrap().1);
    let mut backup: Vec<String> =
        serde_json::from_value(enabled.json["backupCodes"].clone()).unwrap();
    let step = now_step();
    let confirm = owner.post(
        "/two-factor/verify-totp",
        &json!({ "code": hotp(&secret, step, 6) }),
    );
    if confirm.status != StatusCode::OK {
        return;
    }
    let mut last_step = step;
    let mut otp: Option<String> = None;
    let mut email_code: Option<(String, u32)> = None;

    let mut browser = Client::new(&auth);
    for op in ops.iter().take(10) {
        let reply = match op {
            Op::SignIn => browser.post(
                "/sign-in/email",
                &json!({ "email": EMAIL, "password": PASSWORD }),
            ),
            Op::Totp(c) => {
                let delta = match c {
                    Code::Live(d) | Code::Padded(d, ..) => i64::from(*d % 3),
                    Code::Raw(_) => 0,
                };
                let step = (now_step() as i64 + delta).max(0) as u64;
                let given = code(c, &hotp(&secret, step, 6));
                let reply = browser.post("/two-factor/verify-totp", &json!({ "code": given }));
                if reply.status == StatusCode::OK {
                    let now = now_step();
                    let matched = (now.saturating_sub(2)..=now + 2)
                        .filter(|s| *s > last_step && hotp(&secret, *s, 6) == given.trim())
                        .max();
                    let Some(matched) = matched else {
                        panic!("TOTP {given:?} accepted at step {now}, last used {last_step}");
                    };
                    last_step = matched;
                }
                reply
            }
            Op::SendOtp => {
                let reply = browser.post("/two-factor/send-otp", &json!({}));
                if reply.status == StatusCode::OK {
                    otp = last_code(&mailer, "two-factor-otp");
                }
                reply
            }
            Op::Otp(c) => {
                let given = code(c, otp.as_deref().unwrap_or("000000"));
                let reply = browser.post("/two-factor/verify-otp", &json!({ "code": given }));
                if reply.status == StatusCode::OK {
                    assert_eq!(
                        Some(given.trim()),
                        otp.as_deref(),
                        "two-factor OTP {given:?} accepted"
                    );
                    otp = None;
                }
                reply
            }
            Op::Backup(i, c) => {
                let live = backup
                    .get(usize::from(*i) % backup.len().max(1))
                    .cloned()
                    .unwrap_or_default();
                let given = code(c, &live);
                let reply =
                    browser.post("/two-factor/verify-backup-code", &json!({ "code": given }));
                if reply.status == StatusCode::OK {
                    let used = backup.iter().position(|b| b == given.trim());
                    let Some(used) = used else {
                        panic!("backup code {given:?} accepted; unused: {backup:?}");
                    };
                    backup.remove(used);
                }
                reply
            }
            Op::EmailSend => {
                let reply = browser.post(
                    "/email-otp/send-verification-otp",
                    &json!({ "email": EMAIL, "type": "sign-in" }),
                );
                if reply.status == StatusCode::OK {
                    email_code = last_code(&mailer, "email-otp-sign-in").map(|c| (c, 0));
                }
                reply
            }
            Op::EmailSignIn(c) | Op::EmailCheck(c) => {
                let live = email_code
                    .as_ref()
                    .map_or("000000", |(c, _)| c.as_str())
                    .to_owned();
                let given = code(c, &live);
                let check = matches!(op, Op::EmailCheck(_));
                let reply = if check {
                    browser.post(
                        "/email-otp/check-verification-otp",
                        &json!({ "email": EMAIL, "type": "sign-in", "otp": given }),
                    )
                } else {
                    browser.post(
                        "/sign-in/email-otp",
                        &json!({ "email": EMAIL, "otp": given }),
                    )
                };
                let before = email_code.clone();
                email_code = match before.clone() {
                    None => None,
                    Some((_, tries)) if tries >= EMAIL_ATTEMPTS => None,
                    Some((live, _)) if given.trim() == live && !check => None,
                    Some((live, tries)) if given.trim() == live => Some((live, tries)),
                    Some((live, tries)) => Some((live, tries + 1)),
                };
                if reply.status == StatusCode::OK {
                    let Some((live, tries)) = before else {
                        panic!("email OTP {given:?} accepted with no live code");
                    };
                    assert!(
                        tries < EMAIL_ATTEMPTS,
                        "email OTP accepted after {tries} wrong guesses"
                    );
                    assert_eq!(given.trim(), live, "email OTP {given:?} accepted");
                }
                reply
            }
        };
        assert_ne!(
            reply.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{op:?}: {}",
            reply.json
        );
    }
});
