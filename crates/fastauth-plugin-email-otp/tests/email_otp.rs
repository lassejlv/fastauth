//! The email OTP routes through `Auth::handle` on the memory adapter.

mod common;

use common::{Client, plugin_emails, secret};
use fastauth_core::crypto::{Argon2id, Hash};
use fastauth_core::endpoint::Gate;
use fastauth_core::mail::MemoryMailer;
use fastauth_core::models::Verification;
use fastauth_core::prelude::*;
use fastauth_core::query::Where;
use fastauth_plugin_email_otp::{
    EmailOtp, EmailOtpExt, OtpType, SendOtpInput, SignInEmailOtpInput, SignInEmailOtpOutput,
};
use http::{HeaderMap, StatusCode};
use serde_json::{Value, json};

type Plugins = plugins![EmailOtp];
type App = Client<MemoryAdapter, (), Plugins>;

fn build(
    plugin: EmailOtp,
    verification: EmailVerification,
    mailer: &MemoryMailer,
) -> Auth<MemoryAdapter, (), Plugins> {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .email_verification(verification.send_on_sign_up(false))
        .rate_limit(RateLimit::disabled())
        .mailer(mailer.clone())
        .plugin(plugin)
        .configure(|app| {
            app.sign_in_gate(|_, attempt| async move {
                let email = attempt.user.email.clone();
                Ok(if email.starts_with("banned") {
                    Gate::Deny(AuthError::new(
                        StatusCode::FORBIDDEN,
                        "BANNED_USER",
                        "You have been banned",
                    ))
                } else if email.starts_with("pin") {
                    Gate::Challenge(json!({ "twoFactorRedirect": true }))
                } else {
                    Gate::Allow
                })
            });
        })
        .build()
        .expect("valid config")
}

fn setup(plugin: EmailOtp) -> (App, MemoryMailer) {
    let mailer = MemoryMailer::new();
    let auth = build(plugin, EmailVerification::default(), &mailer);
    (Client::new(auth), mailer)
}

async fn send(client: &mut App, email: &str, kind: &str) {
    let res = client
        .post(
            "/email-otp/send-verification-otp",
            json!({ "email": email, "type": kind }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json, json!({ "success": true }));
}

/// The code in the newest email, checking it went to `to` for `kind`.
fn last_code(mailer: &MemoryMailer, to: &str, kind: &str) -> String {
    let email = plugin_emails(mailer).pop().expect("a code was sent");
    assert_eq!(email.to, to);
    assert_eq!(email.kind, kind);
    assert_eq!(email.url, None);
    let code = email.code.expect("the email carries the code");
    assert!(email.text.contains(&code));
    code
}

fn wrong(code: &str) -> String {
    code.chars()
        .map(|c| {
            if c == '9' {
                '0'
            } else {
                char::from(c as u8 + 1)
            }
        })
        .collect()
}

async fn sign_in(client: &mut App, email: &str, otp: &str) -> common::Res {
    client
        .post("/sign-in/email-otp", json!({ "email": email, "otp": otp }))
        .await
}

fn assert_error(res: &common::Res, status: StatusCode, code: &str) {
    assert_eq!(res.status, status, "{}", res.json);
    assert_eq!(res.json["code"], code, "{}", res.json);
}

#[tokio::test]
async fn a_sign_in_code_signs_up_a_new_user_once() {
    let (mut client, mailer) = setup(EmailOtp::new());
    send(&mut client, "Ada@Acme.dk", "sign-in").await;
    let code = last_code(&mailer, "ada@acme.dk", "email-otp-sign-in");
    assert_eq!(code.len(), 6);
    assert!(code.bytes().all(|b| b.is_ascii_digit()));

    let res = client
        .post(
            "/sign-in/email-otp",
            json!({ "email": "ada@acme.dk", "otp": code, "name": "Ada", "image": "https://acme.dk/ada.png" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert!(res.json["token"].as_str().is_some_and(|t| !t.is_empty()));
    assert_eq!(res.json["user"]["email"], "ada@acme.dk");
    assert_eq!(res.json["user"]["name"], "Ada");
    assert_eq!(res.json["user"]["image"], "https://acme.dk/ada.png");
    assert_eq!(res.json["user"]["emailVerified"], true);
    let session = client.get("/get-session").await.json;
    assert_eq!(session["user"]["id"], res.json["user"]["id"]);

    let mut other: App = Client::new(client.auth.clone());
    assert_error(
        &sign_in(&mut other, "ada@acme.dk", &code).await,
        StatusCode::BAD_REQUEST,
        "INVALID_OTP",
    );
}

#[tokio::test]
async fn wrong_codes_burn_the_code_after_the_allowed_attempts() {
    let (mut client, mailer) = setup(EmailOtp::new());
    send(&mut client, "ada@acme.dk", "sign-in").await;
    let code = last_code(&mailer, "ada@acme.dk", "email-otp-sign-in");
    for _ in 0..3 {
        assert_error(
            &sign_in(&mut client, "ada@acme.dk", &wrong(&code)).await,
            StatusCode::BAD_REQUEST,
            "INVALID_OTP",
        );
    }
    let burnt = sign_in(&mut client, "ada@acme.dk", &code).await;
    assert_error(&burnt, StatusCode::FORBIDDEN, "TOO_MANY_ATTEMPTS");
    assert_eq!(burnt.json["message"], "Too many attempts");
    assert_error(
        &sign_in(&mut client, "ada@acme.dk", &code).await,
        StatusCode::BAD_REQUEST,
        "INVALID_OTP",
    );
    assert!(client.jar.is_empty());
}

#[tokio::test]
async fn allowed_attempts_and_otp_length_are_configurable() {
    let (mut client, mailer) = setup(EmailOtp::new().allowed_attempts(5).otp_length(8));
    send(&mut client, "ada@acme.dk", "sign-in").await;
    let code = last_code(&mailer, "ada@acme.dk", "email-otp-sign-in");
    assert_eq!(code.len(), 8);
    for _ in 0..4 {
        sign_in(&mut client, "ada@acme.dk", &wrong(&code)).await;
    }
    let res = sign_in(&mut client, "ada@acme.dk", &code).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
}

#[tokio::test]
async fn expired_codes_answer_otp_expired() {
    let (mut client, mailer) = setup(EmailOtp::new().expires_in(Duration::ZERO));
    send(&mut client, "ada@acme.dk", "sign-in").await;
    let code = last_code(&mailer, "ada@acme.dk", "email-otp-sign-in");
    let res = sign_in(&mut client, "ada@acme.dk", &code).await;
    assert_error(&res, StatusCode::BAD_REQUEST, "OTP_EXPIRED");
    assert_eq!(res.json["message"], "OTP expired");
}

#[tokio::test]
async fn a_new_code_replaces_the_old_one() {
    let (mut client, mailer) = setup(EmailOtp::new().otp_length(10));
    send(&mut client, "ada@acme.dk", "sign-in").await;
    let first = last_code(&mailer, "ada@acme.dk", "email-otp-sign-in");
    send(&mut client, "ada@acme.dk", "sign-in").await;
    let second = last_code(&mailer, "ada@acme.dk", "email-otp-sign-in");
    assert_error(
        &sign_in(&mut client, "ada@acme.dk", &first).await,
        StatusCode::BAD_REQUEST,
        "INVALID_OTP",
    );
    assert_eq!(
        sign_in(&mut client, "ada@acme.dk", &second).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn codes_are_per_purpose() {
    let (mut client, mailer) = setup(EmailOtp::new());
    client.sign_up("ada@acme.dk", "correct horse").await;
    send(&mut client, "ada@acme.dk", "forget-password").await;
    let code = last_code(&mailer, "ada@acme.dk", "email-otp-forget-password");
    assert_error(
        &sign_in(&mut client, "ada@acme.dk", &code).await,
        StatusCode::BAD_REQUEST,
        "INVALID_OTP",
    );
    let res = client
        .post(
            "/email-otp/verify-email",
            json!({ "email": "ada@acme.dk", "otp": code }),
        )
        .await;
    assert_error(&res, StatusCode::BAD_REQUEST, "INVALID_OTP");
}

#[tokio::test]
async fn codes_only_go_to_known_emails_unless_they_sign_up() {
    let (mut client, mailer) = setup(EmailOtp::new());
    send(&mut client, "nobody@acme.dk", "email-verification").await;
    send(&mut client, "nobody@acme.dk", "forget-password").await;
    let res = client
        .post(
            "/email-otp/request-password-reset",
            json!({ "email": "nobody@acme.dk" }),
        )
        .await;
    assert_eq!(res.json, json!({ "success": true }));
    assert!(plugin_emails(&mailer).is_empty());
    let rows = client
        .auth
        .api()
        .db()
        .count::<Verification>(Where::all())
        .await
        .unwrap();
    assert_eq!(rows, 0, "codes for unknown emails aren't kept");

    send(&mut client, "nobody@acme.dk", "sign-in").await;
    assert_eq!(plugin_emails(&mailer).len(), 1);
}

#[tokio::test]
async fn disabled_sign_up_keeps_codes_to_existing_users() {
    let (mut client, mailer) = setup(EmailOtp::new().disable_sign_up(true));
    send(&mut client, "nobody@acme.dk", "sign-in").await;
    assert!(plugin_emails(&mailer).is_empty());
    assert_error(
        &sign_in(&mut client, "nobody@acme.dk", "123456").await,
        StatusCode::BAD_REQUEST,
        "INVALID_OTP",
    );

    client.sign_up("ada@acme.dk", "correct horse").await;
    client.post("/sign-out", json!({})).await;
    send(&mut client, "ada@acme.dk", "sign-in").await;
    let code = last_code(&mailer, "ada@acme.dk", "email-otp-sign-in");
    assert_eq!(
        sign_in(&mut client, "ada@acme.dk", &code).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn verify_email_marks_the_email_verified() {
    let (mut client, mailer) = setup(EmailOtp::new());
    client.sign_up("ada@acme.dk", "correct horse").await;
    send(&mut client, "ada@acme.dk", "email-verification").await;
    let code = last_code(&mailer, "ada@acme.dk", "email-otp-email-verification");
    let res = client
        .post(
            "/email-otp/verify-email",
            json!({ "email": "ada@acme.dk", "otp": code }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["status"], true);
    assert_eq!(res.json["token"], Value::Null);
    assert_eq!(res.json["user"]["emailVerified"], true);
    assert_eq!(
        client.get("/get-session").await.json["user"]["emailVerified"],
        true
    );
    let again = client
        .post(
            "/email-otp/verify-email",
            json!({ "email": "ada@acme.dk", "otp": code }),
        )
        .await;
    assert_error(&again, StatusCode::BAD_REQUEST, "INVALID_OTP");
}

#[tokio::test]
async fn verify_email_signs_in_when_configured() {
    let mailer = MemoryMailer::new();
    let auth = build(
        EmailOtp::new(),
        EmailVerification::default().auto_sign_in_after_verification(true),
        &mailer,
    );
    let mut client: App = Client::new(auth);
    client.sign_up("ada@acme.dk", "correct horse").await;
    client.post("/sign-out", json!({})).await;
    send(&mut client, "ada@acme.dk", "email-verification").await;
    let code = last_code(&mailer, "ada@acme.dk", "email-otp-email-verification");
    let res = client
        .post(
            "/email-otp/verify-email",
            json!({ "email": "ada@acme.dk", "otp": code }),
        )
        .await;
    assert!(
        res.json["token"].as_str().is_some_and(|t| !t.is_empty()),
        "{}",
        res.json
    );
    assert_eq!(
        client.get("/get-session").await.json["user"]["email"],
        "ada@acme.dk"
    );
}

#[tokio::test]
async fn a_forget_password_code_resets_the_password() {
    let (mut client, mailer) = setup(EmailOtp::new());
    client.sign_up("ada@acme.dk", "correct horse").await;
    client.post("/sign-out", json!({})).await;
    let res = client
        .post(
            "/email-otp/request-password-reset",
            json!({ "email": "ada@acme.dk" }),
        )
        .await;
    assert_eq!(res.json, json!({ "success": true }));
    let code = last_code(&mailer, "ada@acme.dk", "email-otp-forget-password");

    let wrong_check = client
        .post(
            "/email-otp/check-verification-otp",
            json!({ "email": "ada@acme.dk", "type": "forget-password", "otp": wrong(&code) }),
        )
        .await;
    assert_error(&wrong_check, StatusCode::BAD_REQUEST, "INVALID_OTP");
    for _ in 0..2 {
        let check = client
            .post(
                "/email-otp/check-verification-otp",
                json!({ "email": "ada@acme.dk", "type": "forget-password", "otp": code }),
            )
            .await;
        assert_eq!(
            check.json,
            json!({ "success": true }),
            "a check keeps the code"
        );
    }

    let short = client
        .post(
            "/email-otp/reset-password",
            json!({ "email": "ada@acme.dk", "otp": code, "password": "short" }),
        )
        .await;
    assert_error(&short, StatusCode::BAD_REQUEST, "PASSWORD_TOO_SHORT");
    let reset = client
        .post(
            "/email-otp/reset-password",
            json!({ "email": "ada@acme.dk", "otp": code, "password": "battery staple" }),
        )
        .await;
    assert_eq!(reset.json, json!({ "success": true }), "{}", reset.json);
    let old = client
        .post(
            "/sign-in/email",
            json!({ "email": "ada@acme.dk", "password": "correct horse" }),
        )
        .await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED);
    let new = client
        .post(
            "/sign-in/email",
            json!({ "email": "ada@acme.dk", "password": "battery staple" }),
        )
        .await;
    assert_eq!(new.status, StatusCode::OK, "{}", new.json);
    assert_eq!(
        new.json["user"]["emailVerified"], true,
        "the code proved the email"
    );
    let reused = client
        .post(
            "/email-otp/reset-password",
            json!({ "email": "ada@acme.dk", "otp": code, "password": "another password" }),
        )
        .await;
    assert_error(&reused, StatusCode::BAD_REQUEST, "INVALID_OTP");
}

#[tokio::test]
async fn the_deprecated_forget_password_route_sends_a_code() {
    let (mut client, mailer) = setup(EmailOtp::new());
    client.sign_up("ada@acme.dk", "correct horse").await;
    let res = client
        .post(
            "/forget-password/email-otp",
            json!({ "email": "ada@acme.dk" }),
        )
        .await;
    assert_eq!(res.json, json!({ "success": true }));
    last_code(&mailer, "ada@acme.dk", "email-otp-forget-password");
}

#[tokio::test]
async fn bad_types_and_emails_are_refused() {
    let (mut client, mailer) = setup(EmailOtp::new());
    let change = client
        .post(
            "/email-otp/send-verification-otp",
            json!({ "email": "ada@acme.dk", "type": "change-email" }),
        )
        .await;
    assert_error(&change, StatusCode::BAD_REQUEST, "INVALID_OTP_TYPE");
    let unknown = client
        .post(
            "/email-otp/send-verification-otp",
            json!({ "email": "ada@acme.dk", "type": "magic" }),
        )
        .await;
    assert_error(&unknown, StatusCode::BAD_REQUEST, "INVALID_REQUEST_BODY");
    let email = client
        .post(
            "/email-otp/send-verification-otp",
            json!({ "email": "ada", "type": "sign-in" }),
        )
        .await;
    assert_error(&email, StatusCode::BAD_REQUEST, "INVALID_EMAIL");
    assert!(plugin_emails(&mailer).is_empty());
}

#[tokio::test]
async fn codes_are_stored_as_a_keyed_hash_and_never_returned() {
    let (mut client, mailer) = setup(EmailOtp::new());
    let res = client
        .post(
            "/email-otp/send-verification-otp",
            json!({ "email": "ada@acme.dk", "type": "sign-in" }),
        )
        .await;
    let code = last_code(&mailer, "ada@acme.dk", "email-otp-sign-in");
    assert!(!res.json.to_string().contains(&code));
    let rows = client
        .auth
        .api()
        .db()
        .find::<Verification>(Where::all())
        .all()
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.identifier, "sign-in-otp-ada@acme.dk");
    assert_eq!(row.data.as_deref(), Some("0"));
    assert_ne!(row.value_hash, Hash::sha256(&code));
    assert_ne!(
        row.value_hash,
        Hash::sha256(format!("{}:{code}", row.identifier))
    );
    assert!(row.expires_at - row.created_at <= Duration::seconds(300));

    sign_in(&mut client, "ada@acme.dk", &wrong(&code)).await;
    let row = client
        .auth
        .api()
        .db()
        .find::<Verification>(Where::all())
        .one()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.data.as_deref(), Some("1"), "the wrong guess is counted");
}

#[tokio::test]
async fn a_sign_in_code_claims_an_unverified_user() {
    let mailer = MemoryMailer::new();
    let auth = build(EmailOtp::new(), EmailVerification::default(), &mailer);
    let mut squatter: App = Client::new(auth.clone());
    squatter.sign_up("ada@acme.dk", "squatter password").await;

    let mut ada: App = Client::new(auth);
    send(&mut ada, "ada@acme.dk", "sign-in").await;
    let code = last_code(&mailer, "ada@acme.dk", "email-otp-sign-in");
    let res = sign_in(&mut ada, "ada@acme.dk", &code).await;
    assert_eq!(res.json["user"]["emailVerified"], true, "{}", res.json);
    assert_eq!(squatter.get("/get-session").await.json, json!(null));
    let password = squatter
        .post(
            "/sign-in/email",
            json!({ "email": "ada@acme.dk", "password": "squatter password" }),
        )
        .await;
    assert_error(
        &password,
        StatusCode::UNAUTHORIZED,
        "INVALID_EMAIL_OR_PASSWORD",
    );
}

#[tokio::test]
async fn new_users_only_take_known_fields() {
    let (mut client, mailer) = setup(EmailOtp::new());
    send(&mut client, "ada@acme.dk", "sign-in").await;
    let code = last_code(&mailer, "ada@acme.dk", "email-otp-sign-in");
    let res = client
        .post(
            "/sign-in/email-otp",
            json!({ "email": "ada@acme.dk", "otp": code, "role": "admin" }),
        )
        .await;
    assert_error(&res, StatusCode::BAD_REQUEST, "INVALID_FIELD");
}

#[tokio::test]
async fn sign_in_gates_run_for_codes() {
    let (mut client, mailer) = setup(EmailOtp::new());
    send(&mut client, "banned@acme.dk", "sign-in").await;
    let code = last_code(&mailer, "banned@acme.dk", "email-otp-sign-in");
    assert_error(
        &sign_in(&mut client, "banned@acme.dk", &code).await,
        StatusCode::FORBIDDEN,
        "BANNED_USER",
    );
    send(&mut client, "pin@acme.dk", "sign-in").await;
    let code = last_code(&mailer, "pin@acme.dk", "email-otp-sign-in");
    let res = sign_in(&mut client, "pin@acme.dk", &code).await;
    assert_eq!(res.json, json!({ "twoFactorRedirect": true }));
    assert_eq!(client.get("/get-session").await.json, json!(null));
}

#[tokio::test]
async fn the_server_api_signs_in_without_http() {
    let mailer = MemoryMailer::new();
    let auth = build(EmailOtp::new(), EmailVerification::default(), &mailer);
    auth.email_otp()
        .send_verification_otp(SendOtpInput {
            email: "ada@acme.dk".into(),
            kind: OtpType::SignIn,
        })
        .await
        .unwrap();
    let code = last_code(&mailer, "ada@acme.dk", "email-otp-sign-in");
    let signed_in = auth
        .email_otp()
        .sign_in(
            &HeaderMap::new(),
            SignInEmailOtpInput {
                email: "ada@acme.dk".into(),
                otp: code,
                name: Some("Ada".into()),
                image: None,
                extra: Default::default(),
            },
        )
        .await
        .unwrap();
    let SignInEmailOtpOutput::SignedIn { user, .. } = signed_in.data else {
        panic!("expected a session, got {:?}", signed_in.data);
    };
    assert_eq!(user["name"], "Ada");
    assert!(!signed_in.set_cookies.is_empty());
}
