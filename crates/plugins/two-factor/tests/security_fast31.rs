//! FAST-31 security review evidence for fastauth-plugin-two-factor 0.3.0. Each test asserts
//! the secure behaviour and fails on 0.3.0. The CORE-8 tests were added with the fix.

mod common;

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::mail::{AuthEmail, MemoryMailer};
use fastauth_core::prelude::*;
use fastauth_plugin_two_factor::TwoFactor;
use fastauth_sqlx::Sqlx;
use fastauth_sqlx::sqlx::sqlite::SqlitePoolOptions;
use http::StatusCode;
use serde_json::json;

const EMAIL: &str = "ada@acme.dk";
const PASSWORD: &str = "correct horse";

/// 2FA-1: /two-factor/verify-otp reads the attempt counter, checks the code, then writes
/// counter+1, with no compare-and-swap. Concurrent wrong guesses all read the same count,
/// so a burst of guesses costs one attempt and the five-attempt limit doesn't hold. Runs on
/// SQLite, where each query yields, as on any real database.
#[tokio::test]
async fn sec_verify_otp_attempt_limit_holds_under_concurrency() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mailer = MemoryMailer::new();
    let auth: Auth<Sqlx<fastauth_sqlx::sqlx::Sqlite>, (), plugins![TwoFactor]> =
        FastAuth::builder()
            .secret(secret())
            .base_url("http://localhost:3000")
            .database(Sqlx::new(pool))
            .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
            .mailer(mailer.clone())
            .rate_limit(RateLimit::disabled())
            .plugin(TwoFactor::new().skip_verification_on_enable(true))
            .build()
            .unwrap();
    auth.migrator().run().await.unwrap();

    let mut ada = Client::new(auth.clone());
    ada.sign_up(EMAIL, PASSWORD).await;
    let enabled = ada
        .post("/two-factor/enable", json!({ "password": PASSWORD }))
        .await;
    assert_eq!(enabled.status, StatusCode::OK, "{}", enabled.json);
    ada.post("/sign-out", json!({})).await;

    // The attacker knows the password and holds the pending two-factor cookie.
    let mut attacker = Client::new(auth.clone());
    let challenged = attacker
        .post(
            "/sign-in/email",
            json!({ "email": EMAIL, "password": PASSWORD }),
        )
        .await;
    assert_eq!(challenged.json["twoFactorRedirect"], true);
    attacker.post("/two-factor/send-otp", json!({})).await;
    let Some(AuthEmail::Plugin(email)) = mailer.last() else {
        panic!("no OTP email")
    };
    let code = email.code.unwrap();

    let guesses = 40;
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..guesses {
        let mut guesser = Client::new(auth.clone());
        guesser.jar = attacker.jar.clone();
        let guess = format!("{:06}", (code.parse::<u32>().unwrap() + 1 + i) % 1_000_000);
        tasks.spawn(async move {
            guesser
                .post("/two-factor/verify-otp", json!({ "code": guess }))
                .await
                .json["code"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        });
    }
    let answers: Vec<String> = tasks.join_all().await;
    let wrong = answers.iter().filter(|c| *c == "INVALID_CODE").count();
    let right = attacker
        .post("/two-factor/verify-otp", json!({ "code": code }))
        .await;
    assert_ne!(
        right.status,
        StatusCode::OK,
        "{wrong} wrong guesses answered INVALID_CODE (limit is 5), yet the real code still \
         signed in afterwards: {}",
        right.json
    );
}

async fn sqlite_app() -> (
    Auth<Sqlx<fastauth_sqlx::sqlx::Sqlite>, (), plugins![TwoFactor]>,
    Vec<String>,
) {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let auth: Auth<Sqlx<fastauth_sqlx::sqlx::Sqlite>, (), plugins![TwoFactor]> =
        FastAuth::builder()
            .secret(secret())
            .base_url("http://localhost:3000")
            .database(Sqlx::new(pool))
            .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
            .rate_limit(RateLimit::disabled())
            .plugin(TwoFactor::new().skip_verification_on_enable(true))
            .build()
            .unwrap();
    auth.migrator().run().await.unwrap();
    let mut ada = Client::new(auth.clone());
    ada.sign_up(EMAIL, PASSWORD).await;
    let enabled = ada
        .post("/two-factor/enable", json!({ "password": PASSWORD }))
        .await;
    assert_eq!(enabled.status, StatusCode::OK, "{}", enabled.json);
    let backup_codes = enabled.json["backupCodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    ada.post("/sign-out", json!({})).await;
    (auth, backup_codes)
}

/// CORE-8: a pending two-factor sign-in allows five guesses in all, across TOTP and backup
/// codes, also when they arrive at once. Before, only the per-IP rate limit counted them.
#[tokio::test]
async fn sec_pending_sign_in_allows_five_guesses() {
    let (auth, backup_codes) = sqlite_app().await;
    let mut attacker = Client::new(auth.clone());
    let challenged = attacker
        .post(
            "/sign-in/email",
            json!({ "email": EMAIL, "password": PASSWORD }),
        )
        .await;
    assert_eq!(challenged.json["twoFactorRedirect"], true);

    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..40 {
        let mut guesser = Client::new(auth.clone());
        guesser.jar = attacker.jar.clone();
        let (path, code) = if i % 2 == 0 {
            ("/two-factor/verify-totp", "not-a-code".to_owned())
        } else {
            ("/two-factor/verify-backup-code", format!("wrong-{i:05}"))
        };
        tasks.spawn(async move { guesser.post(path, json!({ "code": code })).await.status });
    }
    let statuses = tasks.join_all().await;
    assert!(
        statuses.iter().all(|s| *s != StatusCode::OK),
        "{statuses:?}"
    );

    let right = attacker
        .post(
            "/two-factor/verify-backup-code",
            json!({ "code": backup_codes[0] }),
        )
        .await;
    assert_ne!(
        right.status,
        StatusCode::OK,
        "40 wrong guesses on one pending sign-in, yet a real backup code still signed in: {}",
        right.json
    );
}

/// CORE-8: the pending sign-in lives server-side and finishes once. Before, the pending
/// cookie was signed data that could be replayed for its whole max age, even after the
/// sign-in it started had finished.
#[tokio::test]
async fn sec_pending_sign_in_cookie_works_once() {
    let (auth, backup_codes) = sqlite_app().await;
    let mut browser = Client::new(auth.clone());
    browser
        .post(
            "/sign-in/email",
            json!({ "email": EMAIL, "password": PASSWORD }),
        )
        .await;
    let mut replay = Client::new(auth.clone());
    replay.jar = browser.jar.clone();

    let first = browser
        .post(
            "/two-factor/verify-backup-code",
            json!({ "code": backup_codes[0] }),
        )
        .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.json);

    let again = replay
        .post(
            "/two-factor/verify-backup-code",
            json!({ "code": backup_codes[1] }),
        )
        .await;
    assert_ne!(
        again.status,
        StatusCode::OK,
        "a copy of the pending cookie signed in a second time: {}",
        again.json
    );
    assert_eq!(again.json["code"], "INVALID_TWO_FACTOR_COOKIE");
}
