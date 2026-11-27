//! FAST-61 adversarial review of the 0.6.0 rotation fix in #47 (`Keys::verify` current secret
//! only, `Keys::verify_token` any secret), per plugin caller. Every test here is a `guard_*`:
//! it passes on main e1c00a33 and pins that a value which is only a pointer to a row, or an
//! encrypted column, keeps working across `.secrets([new, old])`.
//!
//! Run: cargo test -p fastauth --all-features --test fast61_rotation_plugins -- --nocapture --test-threads=1
#![cfg(all(
    feature = "admin",
    feature = "two-factor",
    feature = "jwt",
    feature = "multi-session"
))]

use std::collections::HashMap;

use axum::body::Bytes;
use axum::http::{Request, header};
use fastauth::crypto::{Argon2id, Secret};
use fastauth::plugins::admin::{Admin, AdminExt};
use fastauth::plugins::jwt::Jwt;
use fastauth::plugins::multi_session::MultiSession;
use fastauth::plugins::two_factor::TwoFactor;
use fastauth::prelude::*;
use serde_json::{Value, json};

type AppAuth = Auth<MemoryAdapter, (), plugins![Admin, TwoFactor, Jwt, MultiSession]>;

const ORIGIN: &str = "http://localhost:3000";
const PASSWORD: &str = "correct horse";

fn generated() -> Secret {
    Secret::from_base64(&Secret::generate())
}

fn build(db: &MemoryAdapter, secrets: Vec<Secret>) -> AppAuth {
    FastAuth::builder()
        .secrets(secrets)
        .base_url(ORIGIN)
        .database(db.clone())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Admin::new())
        .plugin(TwoFactor::new().skip_verification_on_enable(true))
        .plugin(Jwt::new())
        .plugin(MultiSession::new())
        .build()
        .expect("valid config")
}

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

    async fn send(&mut self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("/api/auth{path}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, ORIGIN);
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
        let json = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
        (response.status().as_u16(), json)
    }

    async fn sign_up(&mut self, email: &str) -> Value {
        let (status, json) = self
            .send(
                "POST",
                "/sign-up/email",
                Some(json!({ "email": email, "password": PASSWORD, "name": "Test User" })),
            )
            .await;
        assert_eq!(status, 200, "{json}");
        json
    }

    async fn sign_in(&mut self, email: &str) {
        let (status, json) = self
            .send(
                "POST",
                "/sign-in/email",
                Some(json!({ "email": email, "password": PASSWORD })),
            )
            .await;
        assert_eq!(status, 200, "{json}");
    }

    async fn email(&mut self) -> Value {
        self.send("GET", "/get-session", None).await.1["user"]["email"].clone()
    }
}

/// guard: multi-session device cookies hold session tokens and are read with
/// `verify_token`, so switching between the browser's accounts works across a rotation.
#[tokio::test]
async fn guard_device_sessions_survive_a_rotation() {
    let db = MemoryAdapter::new();
    let old = generated();
    let auth = build(&db, vec![old.clone()]);
    let mut browser = Browser::new(&auth);
    browser.sign_up("ada@acme.dk").await;
    Browser::new(&auth).sign_up("bob@acme.dk").await;
    browser.sign_in("bob@acme.dk").await;
    let (_, list) = browser
        .send("GET", "/multi-session/list-device-sessions", None)
        .await;
    let ada_token = list
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["user"]["email"] == "ada@acme.dk")
        .unwrap()["session"]["token"]
        .as_str()
        .unwrap()
        .to_owned();

    browser.auth = build(&db, vec![generated(), old]);
    let (status, json) = browser
        .send(
            "POST",
            "/multi-session/set-active",
            Some(json!({ "sessionToken": ada_token })),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(browser.email().await, "ada@acme.dk");
}

/// guard: the admin_session cookie (the admin's session token) is read with
/// `signed_token_cookie`, so an impersonation started before a rotation can be stopped after
/// it and restores the admin.
#[tokio::test]
async fn guard_stop_impersonating_survives_a_rotation() {
    let db = MemoryAdapter::new();
    let old = generated();
    let auth = build(&db, vec![old.clone()]);
    let mut admin = Browser::new(&auth);
    let admin_id = admin.sign_up("root@acme.dk").await["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    auth.admin()
        .set_role(&Id::from(admin_id.as_str()), "admin")
        .await
        .unwrap();
    let bob = Browser::new(&auth).sign_up("bob@acme.dk").await["user"]["id"].clone();
    let (status, json) = admin
        .send(
            "POST",
            "/admin/impersonate-user",
            Some(json!({ "userId": bob })),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(admin.email().await, "bob@acme.dk");

    admin.auth = build(&db, vec![generated(), old]);
    let (status, json) = admin.send("POST", "/admin/stop-impersonating", None).await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(admin.email().await, "root@acme.dk");
}

/// guard: encrypted columns written under the old secret (the two-factor secret, the JWKS
/// private key) still decrypt after a rotation, because every listed secret decrypts.
#[tokio::test]
async fn guard_encrypted_columns_decrypt_after_a_rotation() {
    let db = MemoryAdapter::new();
    let old = generated();
    let auth = build(&db, vec![old.clone()]);
    let mut user = Browser::new(&auth);
    user.sign_up("ada@acme.dk").await;
    let (status, json) = user
        .send(
            "POST",
            "/two-factor/enable",
            Some(json!({ "password": PASSWORD })),
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let (status, before) = user.send("GET", "/token", None).await;
    assert_eq!(status, 200, "{before}");
    let (_, uri_before) = user
        .send(
            "POST",
            "/two-factor/get-totp-uri",
            Some(json!({ "password": PASSWORD })),
        )
        .await;

    user.auth = build(&db, vec![generated(), old]);
    let (status, uri_after) = user
        .send(
            "POST",
            "/two-factor/get-totp-uri",
            Some(json!({ "password": PASSWORD })),
        )
        .await;
    assert_eq!(status, 200, "{uri_after}");
    assert_eq!(uri_before, uri_after);
    let (status, after) = user.send("GET", "/token", None).await;
    assert_eq!(status, 200, "{after}");
}
