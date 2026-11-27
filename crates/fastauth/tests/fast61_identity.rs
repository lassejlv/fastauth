//! FAST-61 review of the ATO-3 rule (#48): a verification link keeps the password only when the
//! browser that opens it holds the user's session or the signed `pending_verification` cookie,
//! which core sign-up and a core sign-in refused with `EMAIL_NOT_VERIFIED` leave. The username
//! plugin's sign-in refuses unverified users and mails a new link too, but leaves no cookie,
//! so the owner who opens that link in the same browser is claimed and loses the password.
//!
//! Run: cargo test -p fastauth --all-features --test fast61_identity -- --nocapture
#![cfg(feature = "username")]

use std::collections::HashMap;
use std::time::Duration as StdDuration;

use axum::body::Bytes;
use axum::http::{Request, header};
use fastauth::crypto::{Argon2id, Secret};
use fastauth::mail::{AuthEmail, MemoryMailer};
use fastauth::plugins::username::Username;
use fastauth::prelude::*;
use serde_json::{Value, json};

const ORIGIN: &str = "http://localhost:3000";
const ADA: &str = "ada@acme.dk";
const PASSWORD: &str = "correct horse battery";

type AppAuth = Auth<MemoryAdapter, (), plugins![Username]>;

fn build() -> (AppAuth, MemoryMailer) {
    let mail = MemoryMailer::new();
    let auth = FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(ORIGIN)
        .database(MemoryAdapter::new())
        .email_password(
            EmailPassword::default()
                .hasher(Argon2id::with_params(1024, 1, 1))
                .require_email_verification(true),
        )
        .email_verification(EmailVerification::default().send_on_sign_up(false))
        .rate_limit(RateLimit::disabled())
        .mailer(mail.clone())
        .plugin(Username::new())
        .build()
        .expect("valid config");
    (auth, mail)
}

struct Browser {
    auth: AppAuth,
    jar: HashMap<String, String>,
}

impl Browser {
    async fn send(&mut self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
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
        (
            status,
            serde_json::from_slice(response.body()).unwrap_or(Value::Null),
        )
    }
}

async fn verification_token(mail: &MemoryMailer, before: usize) -> String {
    for _ in 0..1000 {
        if let Some(token) = mail.sent().into_iter().skip(before).find_map(|e| match e {
            AuthEmail::VerifyEmail(e) if e.to == ADA => Some(e.token),
            _ => None,
        }) {
            return token;
        }
        tokio::time::sleep(StdDuration::from_millis(5)).await;
    }
    panic!("no verification email");
}

/// Ada signs up with a username, comes back later (a new browser session, so sign-up's
/// cookie is gone), signs in and is refused for the unverified email, then opens the link
/// that sign-in mailed in this same browser. Answers whether her password still signs in.
async fn come_back_and_verify(path: &str, body: Value) -> (u16, u16) {
    let (auth, mail) = build();
    let mut first_visit = Browser {
        auth: auth.clone(),
        jar: HashMap::new(),
    };
    let (status, json) = first_visit
        .send(
            "POST",
            "/sign-up/email",
            Some(json!({ "email": ADA, "password": PASSWORD, "name": "Ada", "username": "ada" })),
        )
        .await;
    assert_eq!(status, 200, "{json}");

    let mut later = Browser {
        auth: auth.clone(),
        jar: HashMap::new(),
    };
    let before = mail.sent().len();
    let (refused, json) = later.send("POST", path, Some(body)).await;
    assert_eq!(refused, 403, "{json}");
    let token = verification_token(&mail, before).await;
    let (status, json) = later
        .send("GET", &format!("/verify-email?token={token}"), None)
        .await;
    assert_eq!(status, 200, "{json}");
    let (signed_in, _) = Browser {
        auth,
        jar: HashMap::new(),
    }
    .send(
        "POST",
        "/sign-in/email",
        Some(json!({ "email": ADA, "password": PASSWORD })),
    )
    .await;
    (refused, signed_in)
}

#[tokio::test]
async fn guard_core_sign_in_refused_for_verification_keeps_the_password_through_the_link() {
    let (_, signed_in) = come_back_and_verify(
        "/sign-in/email",
        json!({ "email": ADA, "password": PASSWORD }),
    )
    .await;
    assert_eq!(signed_in, 200);
}

#[tokio::test]
async fn sec_username_sign_in_refused_for_verification_keeps_the_password_through_the_link() {
    let (_, signed_in) = come_back_and_verify(
        "/sign-in/username",
        json!({ "username": "ada", "password": PASSWORD }),
    )
    .await;
    assert_eq!(
        signed_in, 200,
        "Ada signed in by username, was refused for her unverified email, opened the link it \
         mailed in the same browser, and her password no longer signs in"
    );
}
