//! FAST-45 security review (area: identity, prefix ATO): account-takeover chains that cross
//! plugins. Each `sec_*` test asserts the secure behaviour and fails on fastauth 0.5.0
//! (7cd9718) on purpose, so it doubles as the regression test for the fix. `guard_*` tests
//! pass and pin behaviour that was checked and found right.
//!
//! Run: cargo +stable test -p fastauth --all-features --test security_fast45_identity -- --nocapture --test-threads=1
#![cfg(all(
    feature = "api-key",
    feature = "magic-link",
    feature = "email-otp",
    feature = "two-factor",
    feature = "passkey",
    feature = "username",
    feature = "anonymous"
))]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::Bytes;
use axum::http::{Request, header};
use fastauth::crypto::{Argon2id, Secret};
use fastauth::mail::{AuthEmail, MemoryMailer};
use fastauth::plugin_prelude::Gate;
use fastauth::plugins::anonymous::Anonymous;
use fastauth::plugins::api_key::ApiKeys;
use fastauth::plugins::email_otp::EmailOtp;
use fastauth::plugins::magic_link::MagicLink;
use fastauth::plugins::passkey::{Passkey, PasskeyRow};
use fastauth::plugins::two_factor::{TwoFactor, totp};
use fastauth::plugins::username::Username;
use fastauth::prelude::*;
use serde_json::{Value, json};

type AppAuth = Auth<
    MemoryAdapter,
    (),
    plugins![
        ApiKeys, MagicLink, EmailOtp, TwoFactor, Passkey, Username, Anonymous
    ],
>;

const ORIGIN: &str = "http://localhost:3000";
const ADA: &str = "ada@acme.dk";
const MALLORY_PASSWORD: &str = "mallory knows this one";
const ADA_PASSWORD: &str = "ada picked this herself";

#[derive(Default)]
struct Opts {
    require_email_verification: bool,
    /// While true, an app-level sign-in gate refuses every sign-in.
    paused: Option<Arc<AtomicBool>>,
}

fn build(opts: Opts) -> (AppAuth, MemoryMailer) {
    let mailer = MemoryMailer::new();
    let mut builder = FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(ORIGIN)
        .database(MemoryAdapter::new())
        .email_password(
            EmailPassword::default()
                .hasher(Argon2id::with_params(1024, 1, 1))
                .require_email_verification(opts.require_email_verification),
        )
        .email_verification(EmailVerification::default().send_on_sign_up(false))
        .rate_limit(RateLimit::disabled())
        .mailer(mailer.clone());
    if let Some(paused) = opts.paused {
        builder = builder.configure(move |app| {
            app.sign_in_gate(move |_, _| {
                let paused = paused.clone();
                async move {
                    Ok(if paused.load(Ordering::SeqCst) {
                        Gate::Deny(AuthError::bad_request(
                            "SIGN_IN_PAUSED",
                            "sign-ins are paused",
                        ))
                    } else {
                        Gate::Allow
                    })
                }
            });
        });
    }
    let auth = builder
        .plugin(ApiKeys::new().sessions(true))
        .plugin(MagicLink::new())
        .plugin(EmailOtp::new().change_email(true))
        .plugin(TwoFactor::new())
        .plugin(Passkey::new())
        .plugin(Username::new())
        .plugin(Anonymous::new())
        .build()
        .expect("valid config");
    (auth, mailer)
}

/// Speaks HTTP to `Auth::handle` with a cookie jar and, optionally, an API key.
struct Browser {
    auth: AppAuth,
    jar: HashMap<String, String>,
}

impl Browser {
    fn new(auth: &AppAuth) -> Self {
        Self {
            auth: auth.clone(),
            jar: HashMap::new(),
        }
    }

    async fn send(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Value>,
        api_key: Option<&str>,
    ) -> (u16, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("/api/auth{path}"))
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json");
        if !self.jar.is_empty() {
            let cookies = self
                .jar
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            builder = builder.header(header::COOKIE, cookies);
        }
        if let Some(key) = api_key {
            builder = builder.header("x-api-key", key);
        }
        let body = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
        let response = self.auth.handle(builder.body(body).unwrap()).await;
        for cookie in response.headers().get_all(header::SET_COOKIE) {
            let cookie = cookie.to_str().unwrap();
            let (pair, attrs) = cookie.split_once(';').unwrap_or((cookie, ""));
            let (name, value) = pair.split_once('=').unwrap();
            if attrs.contains("Max-Age=0") {
                self.jar.remove(name);
            } else {
                self.jar.insert(name.to_owned(), value.to_owned());
            }
        }
        let status = response.status().as_u16();
        let json = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
        (status, json)
    }

    async fn post(&mut self, path: &str, body: Value) -> (u16, Value) {
        self.send("POST", path, Some(body), None).await
    }

    async fn get(&mut self, path: &str) -> (u16, Value) {
        self.send("GET", path, None, None).await
    }

    async fn session(&mut self) -> Value {
        self.get("/get-session").await.1
    }

    async fn sign_up(&mut self, email: &str, password: &str) -> (u16, Value) {
        self.post(
            "/sign-up/email",
            json!({ "email": email, "password": password, "name": "Ada" }),
        )
        .await
    }

    async fn sign_in(&mut self, email: &str, password: &str) -> (u16, Value) {
        self.post(
            "/sign-in/email",
            json!({ "email": email, "password": password }),
        )
        .await
    }

    /// Asks for a magic link for `email` and opens it in this browser.
    async fn magic_link(&mut self, mailer: &MemoryMailer, email: &str) -> (u16, Value) {
        let (status, json) = self
            .post("/sign-in/magic-link", json!({ "email": email }))
            .await;
        assert_eq!(status, 200, "{json}");
        let url = magic_link_for(mailer, email);
        self.get(&url).await
    }

    /// Signs in (or up) with an email code sent to `email`.
    async fn email_otp(
        &mut self,
        mailer: &MemoryMailer,
        email: &str,
        extra: Value,
    ) -> (u16, Value) {
        let (status, json) = self
            .post(
                "/email-otp/send-verification-otp",
                json!({ "email": email, "type": "sign-in" }),
            )
            .await;
        assert_eq!(status, 200, "{json}");
        let mut body =
            json!({ "email": email, "otp": code_for(mailer, "email-otp-sign-in", email) });
        for (key, value) in extra.as_object().cloned().unwrap_or_default() {
            body[key] = value;
        }
        self.post("/sign-in/email-otp", body).await
    }

    /// Makes an API key with this browser's session and checks it signs in as `email`.
    async fn plant_api_key(&mut self, email: &str) -> String {
        let (status, created) = self.post("/api-key/create", json!({ "name": "ci" })).await;
        assert_eq!(status, 200, "{created}");
        let key = created["key"].as_str().unwrap().to_owned();
        assert_eq!(key_session(&self.auth, &key).await["user"]["email"], email);
        key
    }
}

/// The session an API key resolves to, or null.
async fn key_session(auth: &AppAuth, key: &str) -> Value {
    let (status, json) = Browser::new(auth)
        .send("GET", "/get-session", None, Some(key))
        .await;
    if status == 200 { json } else { Value::Null }
}

fn magic_link_for(mailer: &MemoryMailer, to: &str) -> String {
    mailer
        .sent()
        .into_iter()
        .rev()
        .find_map(|email| match email {
            AuthEmail::Plugin(e) if e.kind == "magic-link" && e.to == to => e.url,
            _ => None,
        })
        .expect("a magic link was sent")
        .strip_prefix("http://localhost:3000/api/auth")
        .unwrap()
        .to_owned()
}

fn code_for(mailer: &MemoryMailer, kind: &str, to: &str) -> String {
    mailer
        .sent()
        .into_iter()
        .rev()
        .find_map(|email| match email {
            AuthEmail::Plugin(e) if e.kind == kind && e.to == to => e.code,
            _ => None,
        })
        .unwrap_or_else(|| panic!("no {kind} code was sent to {to}"))
}

fn reset_token_for(mailer: &MemoryMailer, to: &str) -> String {
    mailer
        .sent()
        .into_iter()
        .rev()
        .find_map(|email| match email {
            AuthEmail::ResetPassword(e) if e.to == to => Some(e.token),
            _ => None,
        })
        .expect("a reset email was sent")
}

fn verify_token_for(mailer: &MemoryMailer, to: &str) -> String {
    mailer
        .sent()
        .into_iter()
        .rev()
        .find_map(|email| match email {
            AuthEmail::VerifyEmail(e) if e.to == to => Some(e.token),
            _ => None,
        })
        .expect("a verification email was sent")
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

/// Mallory, signed in to an account she registered with Ada's address, turns two-factor on.
/// Returns her backup codes.
async fn enable_two_factor(mallory: &mut Browser) -> Vec<String> {
    let (status, enabled) = mallory
        .post(
            "/two-factor/enable",
            json!({ "password": MALLORY_PASSWORD }),
        )
        .await;
    assert_eq!(status, 200, "{enabled}");
    let uri = enabled["totpURI"].as_str().unwrap();
    let secret = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
    let code = totp::totp(&base32_decode(secret), now, 30, 6);
    let (status, json) = mallory
        .post("/two-factor/verify-totp", json!({ "code": code }))
        .await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(mallory.session().await["user"]["twoFactorEnabled"], true);
    enabled["backupCodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect()
}

async fn user_row(auth: &AppAuth, email: &str) -> Option<User> {
    auth.api()
        .db()
        .find::<User>(User::EMAIL.eq(email))
        .one()
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------- ATO-1

/// ATO-1: a two-factor sign-in that was pending when the user was claimed still finishes.
/// Mallory registers Ada's address, turns two-factor on, and keeps a password sign-in
/// waiting at the two-factor step. Ada then proves the address with a magic link, which
/// deletes Mallory's password and sessions. Mallory finishes the waiting sign-in with a
/// backup code and is signed in to Ada's verified account.
#[tokio::test]
async fn sec_claim_ends_a_two_factor_sign_in_the_squatter_left_pending() {
    let (auth, mailer) = build(Opts::default());
    let mut mallory = Browser::new(&auth);
    let (status, json) = mallory.sign_up(ADA, MALLORY_PASSWORD).await;
    assert_eq!(status, 200, "{json}");
    let backup_codes = enable_two_factor(&mut mallory).await;

    let mut pending = Browser::new(&auth);
    let (status, json) = pending.sign_in(ADA, MALLORY_PASSWORD).await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["twoFactorRedirect"], true, "{json}");

    let mut ada = Browser::new(&auth);
    let (status, json) = ada.magic_link(&mailer, ADA).await;
    assert!(status < 400, "{status} {json}");
    let (status, _) = Browser::new(&auth).sign_in(ADA, MALLORY_PASSWORD).await;
    assert_eq!(status, 401, "the claim deleted Mallory's password");
    assert!(user_row(&auth, ADA).await.unwrap().email_verified);

    let (status, json) = pending
        .post(
            "/two-factor/verify-backup-code",
            json!({ "code": backup_codes[0] }),
        )
        .await;
    let session = pending.session().await;
    println!("[pending 2FA sign-in finished after the claim] status={status} body={json}");
    println!("[Mallory's /get-session after it] {session}");
    assert!(
        status != 200 && session.is_null(),
        "Mallory finished a sign-in that predates Ada's claim and holds a session for {}: {status} {json}",
        session["user"]["email"]
    );
}

/// ATO-5: the claim keeps the squatter's two-factor enrollment. Ada's magic link is answered
/// with Mallory's two-factor challenge instead of a session, and the account stays enrolled
/// with a TOTP secret and backup codes only Mallory has.
#[tokio::test]
async fn sec_claim_drops_the_squatters_two_factor_enrollment() {
    let (auth, mailer) = build(Opts::default());
    let mut mallory = Browser::new(&auth);
    mallory.sign_up(ADA, MALLORY_PASSWORD).await;
    enable_two_factor(&mut mallory).await;

    let mut ada = Browser::new(&auth);
    let (status, json) = ada.magic_link(&mailer, ADA).await;
    let session = ada.session().await;
    println!("[Ada opens her magic link] status={status} body={json} session={session}");
    let enrolled = auth
        .api()
        .db()
        .find::<fastauth::plugins::two_factor::TwoFactorRow>(
            fastauth::plugins::two_factor::TwoFactorRow::USER_ID
                .eq(&user_row(&auth, ADA).await.unwrap().id),
        )
        .one()
        .await
        .unwrap()
        .is_some();
    println!("[two_factor row after the claim] exists={enrolled}");
    assert!(
        !session.is_null() && !enrolled,
        "after the claim Ada is signed in: {}, and Mallory's TOTP secret and backup codes are still enrolled: {enrolled}",
        !session.is_null()
    );
}

// ---------------------------------------------------------------------------- ATO-2

/// ATO-2: the password-reset link proves the mailbox like a magic link does, but
/// `POST /reset-password` doesn't claim an unverified user. Mallory registers Ada's
/// address and plants an API key and a passkey; Ada uses "forgot password"; both of
/// Mallory's credentials still open the account afterwards.
#[tokio::test]
async fn sec_password_reset_link_claims_an_unverified_user() {
    let (auth, mailer) = build(Opts::default());
    let mut mallory = Browser::new(&auth);
    let (status, json) = mallory.sign_up(ADA, MALLORY_PASSWORD).await;
    assert_eq!(status, 200, "{json}");
    let key = mallory.plant_api_key(ADA).await;
    let user = user_row(&auth, ADA).await.unwrap();
    auth.api()
        .db()
        .insert(&PasskeyRow {
            id: Id::from("pk_mallory"),
            name: Some("Mallory's YubiKey".into()),
            public_key: "cGs".into(),
            user_id: user.id.clone(),
            credential_id: "mallory-credential".into(),
            counter: 0,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: None,
            created_at: time::OffsetDateTime::now_utc(),
            aaguid: None,
        })
        .await
        .unwrap();

    let mut ada = Browser::new(&auth);
    let (status, json) = ada
        .post("/request-password-reset", json!({ "email": ADA }))
        .await;
    assert_eq!(status, 200, "{json}");
    let (status, json) = ada
        .post(
            "/reset-password",
            json!({ "token": reset_token_for(&mailer, ADA), "newPassword": ADA_PASSWORD }),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let (status, json) = ada.sign_in(ADA, ADA_PASSWORD).await;
    assert_eq!(status, 200, "{json}");

    let session = key_session(&auth, &key).await;
    let passkeys = auth
        .api()
        .db()
        .find::<PasskeyRow>(PasskeyRow::USER_ID.eq(&user.id))
        .all()
        .await
        .unwrap()
        .len();
    let verified = user_row(&auth, ADA).await.unwrap().email_verified;
    println!("[Mallory's API key after Ada's reset] session={session}");
    println!("[after Ada's reset] passkeys Mallory planted={passkeys} emailVerified={verified}");
    assert!(
        session.is_null() && passkeys == 0,
        "after Ada reset the password by email, Mallory's API key still signs in as {} and {passkeys} of her passkeys remain",
        session["user"]["email"]
    );
}

// ---------------------------------------------------------------------------- ATO-3

/// ATO-3: with `require_email_verification`, sign-up for an address that already has an
/// unverified user answers as if it worked and keeps the first registrant's password. Ada
/// signs up, asks for the verification email again and clicks it; that verifies the user
/// Mallory made, and Mallory's password signs in to the verified account.
#[tokio::test]
async fn sec_verification_link_does_not_activate_a_squatters_password() {
    let (auth, mailer) = build(Opts {
        require_email_verification: true,
        ..Opts::default()
    });
    let (status, json) = Browser::new(&auth).sign_up(ADA, MALLORY_PASSWORD).await;
    assert_eq!(status, 200, "{json}");
    assert!(json["token"].is_null());
    let (status, _) = Browser::new(&auth).sign_in(ADA, MALLORY_PASSWORD).await;
    assert_eq!(status, 403, "unverified, so Mallory can't sign in yet");

    let mut ada = Browser::new(&auth);
    let (status, json) = ada.sign_up(ADA, ADA_PASSWORD).await;
    assert_eq!(status, 200, "sign-up looks like it worked: {json}");
    let (status, json) = ada
        .post("/send-verification-email", json!({ "email": ADA }))
        .await;
    assert_eq!(status, 200, "{json}");
    let token = verify_token_for(&mailer, ADA);
    let (status, json) = ada.get(&format!("/verify-email?token={token}")).await;
    assert_eq!(status, 200, "{json}");

    let (ada_status, _) = Browser::new(&auth).sign_in(ADA, ADA_PASSWORD).await;
    let mut mallory = Browser::new(&auth);
    let (status, json) = mallory.sign_in(ADA, MALLORY_PASSWORD).await;
    println!("[Ada signs in with the password she signed up with] status={ada_status}");
    println!("[Mallory signs in with the password she planted] status={status} body={json}");
    assert_ne!(
        status, 200,
        "the password Mallory set before anyone proved the address signs in to the account Ada verified: {json}"
    );
}

// ---------------------------------------------------------------------------- ATO-6

/// ATO-6: the claim's plugin cleanup (API keys, passkeys) rides on the `UserClaimed` event,
/// and events are dropped when the endpoint answers an error. Here an app-level sign-in gate
/// refuses Ada's first email-code sign-in after the claim already ran; the user is verified
/// now, so her next sign-in claims nothing and Mallory's API key lives on.
#[tokio::test]
async fn sec_claim_revokes_credentials_even_when_the_sign_in_is_then_refused() {
    let paused = Arc::new(AtomicBool::new(false));
    let (auth, mailer) = build(Opts {
        paused: Some(paused.clone()),
        ..Opts::default()
    });
    let mut mallory = Browser::new(&auth);
    mallory.sign_up(ADA, MALLORY_PASSWORD).await;
    let key = mallory.plant_api_key(ADA).await;

    paused.store(true, Ordering::SeqCst);
    let mut ada = Browser::new(&auth);
    let (status, json) = ada.email_otp(&mailer, ADA, json!({})).await;
    assert_eq!(status, 400, "the gate refused this sign-in: {json}");
    assert!(user_row(&auth, ADA).await.unwrap().email_verified);
    paused.store(false, Ordering::SeqCst);
    let (status, json) = ada.email_otp(&mailer, ADA, json!({})).await;
    assert_eq!(status, 200, "{json}");

    let session = key_session(&auth, &key).await;
    println!("[Mallory's API key after a claim whose sign-in was refused] session={session}");
    assert!(
        session.is_null(),
        "the claim committed but its cleanup never ran: Mallory's key signs in as {}",
        session["user"]["email"]
    );
}

/// The same flow without the refused sign-in: the email-code claim does revoke the key.
#[tokio::test]
async fn guard_email_otp_claim_revokes_api_keys_when_the_sign_in_succeeds() {
    let (auth, mailer) = build(Opts::default());
    let mut mallory = Browser::new(&auth);
    mallory.sign_up(ADA, MALLORY_PASSWORD).await;
    let key = mallory.plant_api_key(ADA).await;
    let (status, json) = Browser::new(&auth).email_otp(&mailer, ADA, json!({})).await;
    assert_eq!(status, 200, "{json}");
    assert!(key_session(&auth, &key).await.is_null());
    assert!(mallory.session().await.is_null(), "her session is gone too");
    let (status, _) = Browser::new(&auth).sign_in(ADA, MALLORY_PASSWORD).await;
    assert_eq!(status, 401, "and her password");
}

// ---------------------------------------------------------------------------- ATO-7

/// ATO-7: a password-reset link is bound to the user id only, so it outlives a change of
/// email. Whoever reads Ada's old mailbox requests a reset; Ada moves her account to a new
/// address; the link from the old mailbox still sets the password.
#[tokio::test]
async fn sec_password_reset_token_dies_when_the_email_changes() {
    let (auth, mailer) = build(Opts::default());
    let old = "ada@old-employer.dk";
    let new = "ada@new-home.dk";
    let mut ada = Browser::new(&auth);
    let (status, json) = ada.sign_up(old, ADA_PASSWORD).await;
    assert_eq!(status, 200, "{json}");

    let (status, json) = Browser::new(&auth)
        .post("/request-password-reset", json!({ "email": old }))
        .await;
    assert_eq!(status, 200, "{json}");
    let token = reset_token_for(&mailer, old);

    let (status, json) = ada
        .post(
            "/email-otp/request-email-change",
            json!({ "newEmail": new }),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let code = code_for(&mailer, "email-otp-change-email", new);
    let (status, json) = ada
        .post(
            "/email-otp/change-email",
            json!({ "newEmail": new, "otp": code }),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(ada.session().await["user"]["email"], new);

    let (status, json) = Browser::new(&auth)
        .post(
            "/reset-password",
            json!({ "token": token, "newPassword": MALLORY_PASSWORD }),
        )
        .await;
    let (signed_in, _) = Browser::new(&auth).sign_in(new, MALLORY_PASSWORD).await;
    println!(
        "[reset link mailed to the old address, used after the change] status={status} body={json}"
    );
    println!("[sign-in as {new} with the password it set] status={signed_in}");
    assert_ne!(
        status, 200,
        "a reset link sent to {old} set the password of the account that now belongs to {new}"
    );
}

// ---------------------------------------------------------------------------- ATO-8

/// ATO-8: an anonymous user who moves to a real, verified address with the email-code
/// change-email flow stays flagged anonymous. The next sign-in as anyone else in that
/// browser (here a magic link Mallory sent Ada) deletes Ada's account as "the anonymous
/// user that was linked".
#[tokio::test]
async fn sec_changing_an_anonymous_users_email_makes_it_a_real_account() {
    let (auth, mailer) = build(Opts::default());
    let mut ada = Browser::new(&auth);
    let (status, json) = ada.send("POST", "/sign-in/anonymous", None, None).await;
    assert_eq!(status, 200, "{json}");
    let (status, json) = ada
        .post(
            "/email-otp/request-email-change",
            json!({ "newEmail": ADA }),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let code = code_for(&mailer, "email-otp-change-email", ADA);
    let (status, json) = ada
        .post(
            "/email-otp/change-email",
            json!({ "newEmail": ADA, "otp": code }),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let user = ada.session().await["user"].clone();
    println!("[Ada after change-email] {user}");
    assert_eq!(user["email"], ADA);
    assert_eq!(user["emailVerified"], true);

    // Mallory asks for a magic link for her own address and gets Ada to open it.
    let (status, json) = Browser::new(&auth)
        .post(
            "/sign-in/magic-link",
            json!({ "email": "mallory@evil.example" }),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let link = magic_link_for(&mailer, "mallory@evil.example");
    let (status, json) = ada.get(&link).await;
    assert!(status < 400, "{status} {json}");
    let survived = user_row(&auth, ADA).await.is_some();
    println!("[Ada's user row after another sign-in in her browser] exists={survived}");
    assert!(
        user["isAnonymous"] == false && survived,
        "Ada's verified account is still flagged anonymous ({}) and was deleted by the next sign-in in her browser (exists: {survived})",
        user["isAnonymous"]
    );
}

// ---------------------------------------------------------------------------- ATO-10

/// ATO-10: email-code sign-up stores `username` straight from the body. The username plugin
/// only hooks `/sign-up/email`, server-side create and `/update-user`, so here nothing is
/// validated, normalized or checked against taken names.
#[tokio::test]
async fn sec_email_otp_sign_up_validates_the_username() {
    let (auth, mailer) = build(Opts::default());
    let (status, json) = Browser::new(&auth)
        .post(
            "/sign-up/email",
            json!({ "email": ADA, "password": ADA_PASSWORD, "name": "Ada", "username": "ada" }),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let (status, json) = Browser::new(&auth)
        .post(
            "/sign-up/email",
            json!({ "email": "m1@evil.example", "password": MALLORY_PASSWORD, "name": "M", "username": "ADA" }),
        )
        .await;
    assert_eq!(status, 400, "password sign-up refuses a taken name: {json}");

    let (taken_status, taken) = Browser::new(&auth)
        .email_otp(&mailer, "m2@evil.example", json!({ "username": "ADA" }))
        .await;
    let (invalid_status, invalid) = Browser::new(&auth)
        .email_otp(&mailer, "m3@evil.example", json!({ "username": "a d<a>" }))
        .await;
    println!(
        "[email-code sign-up with username \"ADA\" while \"ada\" exists] status={taken_status} user={}",
        taken["user"]
    );
    println!(
        "[email-code sign-up with username \"a d<a>\"] status={invalid_status} user={}",
        invalid["user"]
    );
    assert!(
        taken["user"]["username"] != "ADA" && invalid["user"]["username"] != "a d<a>",
        "email-code sign-up stored the usernames {} and {} unchecked",
        taken["user"]["username"],
        invalid["user"]["username"]
    );
}

// ---------------------------------------------------------------------------- guards

/// A token minted for one purpose doesn't work for another: a reset link can't verify an
/// email, and a verification or magic-link token can't reset a password.
#[tokio::test]
async fn guard_verification_tokens_are_bound_to_their_purpose() {
    let (auth, mailer) = build(Opts::default());
    let mut ada = Browser::new(&auth);
    ada.sign_up(ADA, ADA_PASSWORD).await;
    ada.post("/request-password-reset", json!({ "email": ADA }))
        .await;
    let reset = reset_token_for(&mailer, ADA);
    let (status, json) = ada.get(&format!("/verify-email?token={reset}")).await;
    assert_eq!(status, 400, "{json}");
    assert!(!user_row(&auth, ADA).await.unwrap().email_verified);

    ada.post("/send-verification-email", json!({ "email": ADA }))
        .await;
    let verify = verify_token_for(&mailer, ADA);
    ada.post("/sign-in/magic-link", json!({ "email": ADA }))
        .await;
    let link = magic_link_for(&mailer, ADA);
    let magic = link
        .split("token=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    for token in [verify.as_str(), magic] {
        let (status, json) = Browser::new(&auth)
            .post(
                "/reset-password",
                json!({ "token": token, "newPassword": MALLORY_PASSWORD }),
            )
            .await;
        assert_eq!(status, 400, "{json}");
    }
    let (status, _) = Browser::new(&auth).sign_in(ADA, MALLORY_PASSWORD).await;
    assert_eq!(status, 401);
    let (status, _) = Browser::new(&auth).sign_in(ADA, ADA_PASSWORD).await;
    assert_eq!(status, 200);
}

/// A change-email code works only for the user it was issued to and the address it was
/// sent to, and never moves an account onto an address another user holds.
#[tokio::test]
async fn guard_change_email_code_is_bound_to_user_and_address() {
    let (auth, mailer) = build(Opts::default());
    let mut ada = Browser::new(&auth);
    ada.sign_up(ADA, ADA_PASSWORD).await;
    let mut mallory = Browser::new(&auth);
    mallory
        .sign_up("mallory@evil.example", MALLORY_PASSWORD)
        .await;
    let squatted = "cfo@acme.dk";
    Browser::new(&auth)
        .sign_up(squatted, MALLORY_PASSWORD)
        .await;

    let new = "ada@new-home.dk";
    let (status, json) = ada
        .post(
            "/email-otp/request-email-change",
            json!({ "newEmail": new }),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let code = code_for(&mailer, "email-otp-change-email", new);

    let (status, json) = mallory
        .post(
            "/email-otp/change-email",
            json!({ "newEmail": new, "otp": code }),
        )
        .await;
    assert_eq!(status, 400, "another user can't use Ada's code: {json}");
    let (status, json) = ada
        .post(
            "/email-otp/change-email",
            json!({ "newEmail": "other@new-home.dk", "otp": code }),
        )
        .await;
    assert_eq!(status, 400, "nor Ada for another address: {json}");

    let before = mailer.sent().len();
    let (status, json) = ada
        .post(
            "/email-otp/request-email-change",
            json!({ "newEmail": squatted }),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(mailer.sent().len(), before, "no code for a taken address");
    let (status, json) = ada
        .post(
            "/email-otp/change-email",
            json!({ "newEmail": squatted, "otp": "000000" }),
        )
        .await;
    assert_eq!(status, 400, "{json}");
    assert_eq!(ada.session().await["user"]["email"], ADA);
    assert_eq!(
        mallory.session().await["user"]["email"],
        "mallory@evil.example"
    );
}

/// Case and surrounding whitespace never make a second user for one mailbox, on any path
/// that creates users.
#[tokio::test]
async fn guard_email_case_and_whitespace_map_to_one_user() {
    let (auth, mailer) = build(Opts::default());
    let (status, json) = Browser::new(&auth)
        .sign_up("  Ada@ACME.dk ", ADA_PASSWORD)
        .await;
    assert_eq!(status, 200, "{json}");
    let id = json["user"]["id"].clone();
    assert_eq!(json["user"]["email"], ADA);
    let (status, json) = Browser::new(&auth)
        .sign_up("ADA@acme.DK", MALLORY_PASSWORD)
        .await;
    assert_eq!(status, 422, "{json}");

    let mut by_link = Browser::new(&auth);
    let (status, json) = by_link
        .post("/sign-in/magic-link", json!({ "email": "ADA@ACME.DK" }))
        .await;
    assert_eq!(status, 200, "{json}");
    let (status, json) = by_link.get(&magic_link_for(&mailer, ADA)).await;
    assert!(status < 400, "{status} {json}");
    assert_eq!(by_link.session().await["user"]["id"], id);

    let mut by_code = Browser::new(&auth);
    let (status, json) = by_code
        .post(
            "/email-otp/send-verification-otp",
            json!({ "email": " ADA@acme.dk", "type": "sign-in" }),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let (status, json) = by_code
        .post(
            "/sign-in/email-otp",
            json!({ "email": "Ada@Acme.Dk", "otp": code_for(&mailer, "email-otp-sign-in", ADA) }),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["user"]["id"], id);
    assert_eq!(
        auth.api()
            .db()
            .find::<User>(User::ID.ne(Id::from("-")))
            .all()
            .await
            .unwrap()
            .len(),
        1
    );
}
