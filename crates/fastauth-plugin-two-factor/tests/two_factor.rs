mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use common::{Client, Res, secret};
use fastauth_core::PluginSet;
use fastauth_core::crypto::Argon2id;
use fastauth_core::mail::AuthEmail;
use fastauth_core::model::Model;
use fastauth_core::plugin_prelude::{Adapter, Gate, Plugin, PluginBuilder};
use fastauth_core::prelude::*;
use fastauth_plugin_two_factor::{
    EnableInput, PasswordInput, TwoFactor, TwoFactorExt, TwoFactorRow, VerifyInput, VerifyOutput,
    totp,
};
use http::{HeaderMap, StatusCode, header};
use serde_json::{Value, json};

type AppAuth = Auth<MemoryAdapter, (), plugins![TwoFactor]>;

const EMAIL: &str = "ada@acme.dk";
const PASSWORD: &str = "correct horse";

fn build(plugin: TwoFactor, rate_limit: RateLimit) -> (AppAuth, MemoryMailer) {
    let mailer = MemoryMailer::new();
    let auth = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .mailer(mailer.clone())
        .rate_limit(rate_limit)
        .plugin(plugin)
        .build()
        .expect("valid config");
    (auth, mailer)
}

fn app() -> Client<MemoryAdapter, (), plugins![TwoFactor]> {
    Client::new(build(TwoFactor::new().issuer("Acme"), RateLimit::disabled()).0)
}

/// An authenticator app: reads the secret from the URI and never reuses a time step.
struct Authenticator {
    secret: Vec<u8>,
    last_step: Option<u64>,
}

impl Authenticator {
    fn from_uri(uri: &str) -> Self {
        let secret = uri
            .split(['?', '&'])
            .find_map(|p| p.strip_prefix("secret="))
            .expect("secret in the TOTP URI");
        Self {
            secret: base32_decode(secret),
            last_step: None,
        }
    }

    /// A valid code for a step no earlier code used: up to three per 30 seconds.
    fn code(&mut self) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 30;
        let step = self
            .last_step
            .map_or(now - 1, |last| (last + 1).max(now - 1));
        assert!(step <= now + 1, "test used more than three codes in a step");
        self.last_step = Some(step);
        totp::hotp(&self.secret, step, 6)
    }
}

fn base32_decode(input: &str) -> Vec<u8> {
    let mut bits = 0u64;
    let mut count = 0;
    let mut out = Vec::new();
    for c in input.bytes() {
        let value = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            .iter()
            .position(|&a| a == c)
            .expect("base32 character");
        bits = (bits << 5) | value as u64;
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    out
}

fn wrong(code: &str) -> String {
    code.chars()
        .map(|c| char::from(b'0' + (c as u8 - b'0' + 1) % 10))
        .collect()
}

trait TwoFactorClient {
    async fn sign_in_as(&mut self, email: &str) -> Res;
    async fn sign_out(&mut self) -> Res;
    async fn enable_as(&mut self, email: &str) -> (Authenticator, Vec<String>);

    async fn sign_in(&mut self) -> Res {
        self.sign_in_as(EMAIL).await
    }

    async fn enable(&mut self) -> (Authenticator, Vec<String>) {
        self.enable_as(EMAIL).await
    }

    async fn verify(&mut self, path: &str, code: &str) -> Res;
    fn has_cookie(&self, name: &str) -> bool;
    async fn two_factor_enabled(&mut self) -> Value;
}

impl<P: PluginSet> TwoFactorClient for Client<MemoryAdapter, (), P> {
    async fn sign_in_as(&mut self, email: &str) -> Res {
        self.post(
            "/sign-in/email",
            json!({ "email": email, "password": PASSWORD }),
        )
        .await
    }

    async fn sign_out(&mut self) -> Res {
        self.post("/sign-out", json!({})).await
    }

    /// Signs up, enables two-factor and confirms it with a first code.
    async fn enable_as(&mut self, email: &str) -> (Authenticator, Vec<String>) {
        self.sign_up(email, PASSWORD).await;
        let res = self
            .post("/two-factor/enable", json!({ "password": PASSWORD }))
            .await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.json);
        let codes = serde_json::from_value(res.json["backupCodes"].clone()).unwrap();
        let mut app = Authenticator::from_uri(res.json["totpURI"].as_str().unwrap());
        let res = self.verify("/two-factor/verify-totp", &app.code()).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.json);
        (app, codes)
    }

    async fn verify(&mut self, path: &str, code: &str) -> Res {
        self.post(path, json!({ "code": code })).await
    }

    fn has_cookie(&self, name: &str) -> bool {
        self.jar.contains_key(&format!("fastauth.{name}"))
    }

    async fn two_factor_enabled(&mut self) -> Value {
        self.get("/get-session").await.json["user"]["twoFactorEnabled"].clone()
    }
}

#[tokio::test]
async fn enable_verify_then_sign_in_through_the_challenge() {
    let mut client = app();
    client.sign_up(EMAIL, PASSWORD).await;
    let res = client
        .post("/two-factor/enable", json!({ "password": PASSWORD }))
        .await;
    let uri = res.json["totpURI"].as_str().unwrap().to_owned();
    assert!(
        uri.starts_with("otpauth://totp/Acme:ada%40acme.dk?secret="),
        "{uri}"
    );
    assert!(uri.ends_with("&issuer=Acme&digits=6&period=30"), "{uri}");
    assert_eq!(res.json["backupCodes"].as_array().unwrap().len(), 10);
    assert_eq!(
        client.two_factor_enabled().await,
        false,
        "off until the first code"
    );

    let mut app = Authenticator::from_uri(&uri);
    let res = client.verify("/two-factor/verify-totp", &app.code()).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["user"]["twoFactorEnabled"], true);
    assert_eq!(client.two_factor_enabled().await, true);

    client.sign_out().await;
    let res = client.sign_in().await;
    assert_eq!(
        res.json,
        json!({ "twoFactorRedirect": true, "twoFactorMethods": ["totp", "otp"] })
    );
    assert!(client.has_cookie("two_factor"));
    assert!(!client.has_cookie("session_token"));
    assert_eq!(client.get("/get-session").await.json, Value::Null);

    let res = client.verify("/two-factor/verify-totp", &app.code()).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert!(!res.json["token"].as_str().unwrap().is_empty());
    assert_eq!(res.json["user"]["email"], EMAIL);
    assert!(client.has_cookie("session_token"));
    assert!(!client.has_cookie("two_factor"), "pending cookie cleared");
    assert_eq!(
        client.get("/get-session").await.json["user"]["email"],
        EMAIL
    );
}

#[tokio::test]
async fn secrets_are_encrypted_at_rest() {
    let mut client = app();
    let (app, codes) = client.enable().await;
    let rows = client.auth.adapter().dump(TwoFactorRow::TABLE);
    assert_eq!(rows.len(), 1);
    let stored = format!("{:?}", rows[0]);
    assert!(!stored.contains(&format!("{:?}", app.secret)));
    assert!(codes.iter().all(|c| !stored.contains(c.as_str())));
}

#[tokio::test]
async fn sign_in_is_not_challenged_before_the_first_code() {
    let mut client = app();
    client.sign_up(EMAIL, PASSWORD).await;
    client
        .post("/two-factor/enable", json!({ "password": PASSWORD }))
        .await;
    client.sign_out().await;
    assert!(client.sign_in().await.json["token"].is_string());
}

#[tokio::test]
async fn skip_verification_on_enable_turns_it_on_at_once() {
    let (auth, _) = build(
        TwoFactor::new().skip_verification_on_enable(true),
        RateLimit::disabled(),
    );
    let mut client = Client::new(auth);
    client.sign_up(EMAIL, PASSWORD).await;
    let res = client
        .post("/two-factor/enable", json!({ "password": PASSWORD }))
        .await;
    assert!(res.json["totpURI"].as_str().unwrap().contains("fastauth:"));
    assert_eq!(client.two_factor_enabled().await, true);
}

#[tokio::test]
async fn enable_needs_the_password() {
    let mut client = app();
    client.sign_up(EMAIL, PASSWORD).await;
    let res = client
        .post("/two-factor/enable", json!({ "password": "wrong" }))
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json["code"], "INVALID_PASSWORD");
    client.jar.clear();
    let res = client
        .post("/two-factor/enable", json!({ "password": PASSWORD }))
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_code_is_rejected() {
    let mut client = app();
    let (mut app, _) = client.enable().await;
    client.sign_out().await;
    client.sign_in().await;
    let code = app.code();
    let res = client
        .verify("/two-factor/verify-totp", &wrong(&code))
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json["code"], "INVALID_CODE");
    assert!(!client.has_cookie("session_token"));
    let res = client.verify("/two-factor/verify-totp", &code).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
}

#[tokio::test]
async fn a_code_is_accepted_once() {
    let mut client = app();
    client.sign_up(EMAIL, PASSWORD).await;
    let res = client
        .post("/two-factor/enable", json!({ "password": PASSWORD }))
        .await;
    let mut app = Authenticator::from_uri(res.json["totpURI"].as_str().unwrap());
    let code = app.code();
    let first = client.verify("/two-factor/verify-totp", &code).await;
    assert_eq!(first.status, StatusCode::OK);

    client.sign_out().await;
    client.sign_in().await;
    let replay = client.verify("/two-factor/verify-totp", &code).await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
    assert_eq!(replay.json["code"], "INVALID_CODE");
    let next = client.verify("/two-factor/verify-totp", &app.code()).await;
    assert_eq!(next.status, StatusCode::OK, "{}", next.json);
}

#[tokio::test]
async fn a_backup_code_works_once() {
    let mut client = app();
    let (_, codes) = client.enable().await;

    client.sign_out().await;
    client.sign_in().await;
    let res = client
        .verify("/two-factor/verify-backup-code", &codes[0])
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert!(client.has_cookie("session_token"));

    client.sign_out().await;
    client.sign_in().await;
    let res = client
        .verify("/two-factor/verify-backup-code", &codes[0])
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json["code"], "INVALID_BACKUP_CODE");
    let res = client
        .verify("/two-factor/verify-backup-code", &codes[1])
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
}

#[tokio::test]
async fn regenerating_backup_codes_replaces_the_old_ones() {
    let mut client = app();
    let (_, old) = client.enable().await;
    let res = client
        .post(
            "/two-factor/generate-backup-codes",
            json!({ "password": PASSWORD }),
        )
        .await;
    assert_eq!(res.json["status"], true);
    let new: Vec<String> = serde_json::from_value(res.json["backupCodes"].clone()).unwrap();
    assert_eq!(new.len(), 10);
    assert!(new.iter().all(|c| c.len() == 11 && c.as_bytes()[5] == b'-'));

    client.sign_out().await;
    client.sign_in().await;
    let res = client
        .verify("/two-factor/verify-backup-code", &old[0])
        .await;
    assert_eq!(res.json["code"], "INVALID_BACKUP_CODE");
    let res = client
        .verify("/two-factor/verify-backup-code", &new[0])
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
}

#[tokio::test]
async fn email_otp_finishes_a_sign_in() {
    let (auth, mailer) = build(TwoFactor::new(), RateLimit::disabled());
    let mut client = Client::new(auth);
    client.enable().await;
    client.sign_out().await;
    client.sign_in().await;

    let res = client.post("/two-factor/send-otp", json!({})).await;
    assert_eq!(res.json, json!({ "status": true }));
    let Some(AuthEmail::Plugin(email)) = mailer.last() else {
        panic!("no OTP email");
    };
    assert_eq!(email.kind, "two-factor-otp");
    assert_eq!(email.to, EMAIL);
    let code = email.code.unwrap();
    assert_eq!(code.len(), 6);
    assert!(email.text.contains(&code));

    let res = client.verify("/two-factor/verify-otp", &wrong(&code)).await;
    assert_eq!(res.json["code"], "INVALID_CODE");
    let res = client.verify("/two-factor/verify-otp", &code).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert!(client.has_cookie("session_token"));

    client.sign_out().await;
    client.sign_in().await;
    let res = client.verify("/two-factor/verify-otp", &code).await;
    assert_eq!(res.json["code"], "INVALID_CODE", "single use");
}

#[tokio::test]
async fn five_wrong_email_codes_burn_the_code() {
    let (auth, mailer) = build(TwoFactor::new(), RateLimit::disabled());
    let mut client = Client::new(auth);
    client.enable().await;
    client.sign_out().await;
    client.sign_in().await;
    client.post("/two-factor/send-otp", json!({})).await;
    let Some(AuthEmail::Plugin(email)) = mailer.last() else {
        panic!("no OTP email");
    };
    let code = email.code.unwrap();
    for _ in 0..4 {
        let res = client.verify("/two-factor/verify-otp", &wrong(&code)).await;
        assert_eq!(res.json["code"], "INVALID_CODE");
    }
    let res = client.verify("/two-factor/verify-otp", &wrong(&code)).await;
    assert_eq!(res.json["code"], "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE");
    let res = client.verify("/two-factor/verify-otp", &code).await;
    assert_eq!(res.json["code"], "INVALID_CODE");
}

#[tokio::test]
async fn a_trusted_device_skips_the_challenge() {
    let mut client = app();
    let (mut app, _) = client.enable().await;
    client.sign_out().await;
    client.sign_in().await;
    let res = client
        .post(
            "/two-factor/verify-totp",
            json!({ "code": app.code(), "trustDevice": true }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert!(client.has_cookie("trust_device"));

    client.sign_out().await;
    let res = client.sign_in().await;
    assert!(res.json["token"].is_string(), "{}", res.json);

    client.sign_out().await;
    client.enable_as("bob@acme.dk").await;
    client.sign_out().await;
    assert_eq!(
        client.sign_in_as("bob@acme.dk").await.json,
        json!({ "twoFactorRedirect": true, "twoFactorMethods": ["totp", "otp"] }),
        "the trusted device is Ada's, not Bob's"
    );
}

#[tokio::test]
async fn re_enabling_forgets_trusted_devices() {
    let mut client = app();
    let (mut app, _) = client.enable().await;
    client.sign_out().await;
    client.sign_in().await;
    client
        .post(
            "/two-factor/verify-totp",
            json!({ "code": app.code(), "trustDevice": true }),
        )
        .await;
    let res = client
        .post("/two-factor/enable", json!({ "password": PASSWORD }))
        .await;
    let mut app = Authenticator::from_uri(res.json["totpURI"].as_str().unwrap());
    client.sign_out().await;
    assert_eq!(
        client.sign_in().await.json,
        json!({ "twoFactorRedirect": true, "twoFactorMethods": ["totp", "otp"] })
    );
    let res = client.verify("/two-factor/verify-totp", &app.code()).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
}

#[tokio::test]
async fn disable_turns_the_challenge_off() {
    let mut client = app();
    client.enable().await;
    let res = client
        .post("/two-factor/disable", json!({ "password": "wrong" }))
        .await;
    assert_eq!(res.json["code"], "INVALID_PASSWORD");
    let res = client
        .post("/two-factor/disable", json!({ "password": PASSWORD }))
        .await;
    assert_eq!(res.json, json!({ "status": true }));
    assert_eq!(client.two_factor_enabled().await, false);
    assert!(client.auth.adapter().dump(TwoFactorRow::TABLE).is_empty());

    client.sign_out().await;
    assert!(client.sign_in().await.json["token"].is_string());
    let res = client
        .post("/two-factor/get-totp-uri", json!({ "password": PASSWORD }))
        .await;
    assert_eq!(res.json["code"], "TOTP_NOT_ENABLED");
}

#[tokio::test]
async fn get_totp_uri_shows_the_same_secret() {
    let mut client = app();
    client.sign_up(EMAIL, PASSWORD).await;
    let enabled = client
        .post("/two-factor/enable", json!({ "password": PASSWORD }))
        .await;
    let again = client
        .post("/two-factor/get-totp-uri", json!({ "password": PASSWORD }))
        .await;
    assert_eq!(again.json["totpURI"], enabled.json["totpURI"]);
}

#[tokio::test]
async fn the_pending_sign_in_expires() {
    let (auth, _) = build(
        TwoFactor::new().two_factor_cookie_max_age(Duration::seconds(1)),
        RateLimit::disabled(),
    );
    let mut client = Client::new(auth);
    let (mut app, _) = client.enable().await;
    client.sign_out().await;
    assert_eq!(
        client.sign_in().await.json,
        json!({ "twoFactorRedirect": true, "twoFactorMethods": ["totp", "otp"] })
    );
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    assert!(
        client.has_cookie("two_factor"),
        "the browser still sends it"
    );
    let res = client.verify("/two-factor/verify-totp", &app.code()).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json["code"], "INVALID_TWO_FACTOR_COOKIE");
    assert!(!client.has_cookie("session_token"));
}

#[tokio::test]
async fn verify_without_a_session_or_pending_sign_in_is_refused() {
    let mut client = app();
    let res = client.verify("/two-factor/verify-totp", "123456").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json["code"], "INVALID_TWO_FACTOR_COOKIE");
}

#[tokio::test]
async fn verify_endpoints_allow_five_attempts_a_minute() {
    let (auth, _) = build(TwoFactor::new(), RateLimit::default());
    let mut client = Client::new(auth);
    client.sign_up(EMAIL, PASSWORD).await;
    client
        .post("/two-factor/enable", json!({ "password": PASSWORD }))
        .await;
    for path in ["totp", "otp", "backup-code", "totp", "totp"] {
        let res = client
            .verify(&format!("/two-factor/verify-{path}"), "000000")
            .await;
        assert_ne!(res.status, StatusCode::TOO_MANY_REQUESTS);
    }
    let res = client.verify("/two-factor/verify-totp", "000000").await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn password_confirming_routes_are_rate_limited_like_sign_in() {
    let (auth, _) = build(TwoFactor::new(), RateLimit::default());
    let mut client = Client::new(auth);
    client.sign_up(EMAIL, PASSWORD).await;
    for path in [
        "/two-factor/enable",
        "/two-factor/disable",
        "/two-factor/get-totp-uri",
        "/two-factor/generate-backup-codes",
    ] {
        let mut statuses = Vec::new();
        for _ in 0..4 {
            let res = client.post(path, json!({ "password": "guess" })).await;
            statuses.push(res.status);
        }
        assert!(
            statuses[..3]
                .iter()
                .all(|s| *s != StatusCode::TOO_MANY_REQUESTS),
            "{path}: {statuses:?}"
        );
        assert_eq!(statuses[3], StatusCode::TOO_MANY_REQUESTS, "{path}");
    }
}

#[tokio::test]
async fn server_api_enables_verifies_and_disables() {
    let (auth, _) = build(TwoFactor::new(), RateLimit::disabled());
    let mut client = Client::new(auth.clone());
    client.sign_up(EMAIL, PASSWORD).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        client.cookie_header().unwrap().parse().unwrap(),
    );

    let enabled = auth
        .two_factor()
        .enable(
            &headers,
            EnableInput {
                password: PASSWORD.into(),
                issuer: None,
            },
        )
        .await
        .unwrap()
        .data;
    let mut app = Authenticator::from_uri(&enabled.totp_uri);
    let verified = auth
        .two_factor()
        .verify_totp(
            &headers,
            VerifyInput {
                code: app.code(),
                trust_device: None,
            },
        )
        .await
        .unwrap()
        .data;
    let VerifyOutput::Verified { user, .. } = verified else {
        panic!("not challenged when signed in");
    };
    assert_eq!(user["twoFactorEnabled"], true);

    let replay = auth
        .two_factor()
        .verify_totp(
            &headers,
            VerifyInput {
                code: totp::hotp(&app.secret, app.last_step.unwrap(), 6),
                trust_device: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(replay.code(), "INVALID_CODE");

    auth.two_factor()
        .disable(
            &headers,
            PasswordInput {
                password: PASSWORD.into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(client.two_factor_enabled().await, false);
}

// ------------------------------------------------- other plugins' gates after the challenge

/// Denies banned emails at sign-in, like the admin plugin.
#[derive(Clone, Default)]
struct Ban(Arc<Mutex<HashSet<String>>>);

impl Ban {
    fn ban(&self, email: &str) {
        self.0.lock().unwrap().insert(email.to_owned());
    }
}

impl Plugin for Ban {
    const ID: &'static str = "ban";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        let banned = self.0.clone();
        app.sign_in_gate(move |_ctx, attempt| {
            let banned = banned.lock().unwrap().contains(&attempt.user.email);
            async move {
                Ok(if banned {
                    Gate::Deny(AuthError::new(
                        StatusCode::FORBIDDEN,
                        "BANNED_USER",
                        "you have been banned",
                    ))
                } else {
                    Gate::Allow
                })
            }
        });
    }
}

macro_rules! with_ban {
    ($($plugin:expr),+) => {
        Client::new(
            FastAuth::builder()
                .secret(secret())
                .base_url("http://localhost:3000")
                .database(MemoryAdapter::new())
                .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
                .rate_limit(RateLimit::disabled())
                $(.plugin($plugin))+
                .build()
                .expect("valid config"),
        )
    };
}

/// Enables two-factor, bans the user, signs in up to the challenge and answers it.
async fn banned_after_challenge(
    client: &mut impl TwoFactorClient,
    ban: &Ban,
    path: &str,
    code: impl AsyncFnOnce(&mut Authenticator, &[String]) -> String,
) -> Res {
    let (mut app, codes) = client.enable().await;
    client.sign_out().await;
    let res = client.sign_in().await;
    assert_eq!(res.json["twoFactorRedirect"], true, "{}", res.json);
    ban.ban(EMAIL);
    let code = code(&mut app, &codes).await;
    client.verify(path, &code).await
}

#[tokio::test]
async fn a_ban_gate_registered_after_two_factor_denies_a_correct_code() {
    let ban = Ban::default();
    let mut client = with_ban!(TwoFactor::new(), ban.clone());
    let res = banned_after_challenge(
        &mut client,
        &ban,
        "/two-factor/verify-totp",
        async |app, _| app.code(),
    )
    .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.json);
    assert_eq!(res.json["code"], "BANNED_USER");
    assert!(!client.has_cookie("session_token"));
    assert!(!client.has_cookie("two_factor"), "pending sign-in gone");
}

#[tokio::test]
async fn a_ban_gate_registered_before_two_factor_denies_a_correct_code() {
    let ban = Ban::default();
    let mut client = with_ban!(ban.clone(), TwoFactor::new());
    let res = banned_after_challenge(
        &mut client,
        &ban,
        "/two-factor/verify-totp",
        async |app, _| app.code(),
    )
    .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.json);
    assert_eq!(res.json["code"], "BANNED_USER");
    assert!(!client.has_cookie("session_token"));
}

#[tokio::test]
async fn a_ban_gate_denies_a_correct_backup_code() {
    let ban = Ban::default();
    let mut client = with_ban!(TwoFactor::new(), ban.clone());
    let res = banned_after_challenge(
        &mut client,
        &ban,
        "/two-factor/verify-backup-code",
        async |_, codes| codes[0].clone(),
    )
    .await;
    assert_eq!(res.json["code"], "BANNED_USER", "{}", res.json);
    assert!(!client.has_cookie("session_token"));
}

#[tokio::test]
async fn an_unbanned_user_still_signs_in_through_both_gates() {
    let ban = Ban::default();
    let mut client = with_ban!(TwoFactor::new(), ban.clone());
    let (mut app, _) = client.enable().await;
    client.sign_out().await;
    client.sign_in().await;
    let res = client.verify("/two-factor/verify-totp", &app.code()).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["user"]["email"], EMAIL);
    assert!(client.has_cookie("session_token"));
}
