//! Claiming an unverified user (a magic link here) takes away every credential its first
//! registrant made: accounts and sessions in core, API keys and passkeys in their plugins.
#![cfg(all(feature = "api-key", feature = "magic-link", feature = "passkey"))]

use std::collections::HashMap;

use axum::body::Bytes;
use axum::http::{Request, header};
use fastauth::crypto::{Argon2id, Secret};
use fastauth::mail::{AuthEmail, MemoryMailer};
use fastauth::plugins::api_key::ApiKeys;
use fastauth::plugins::magic_link::MagicLink;
use fastauth::plugins::passkey::Passkey;
use fastauth::prelude::*;
use serde_json::{Value, json};

type AppAuth = Auth<MemoryAdapter, (), plugins![ApiKeys, MagicLink, Passkey]>;

const ORIGIN: &str = "http://localhost:3000";

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
}

#[tokio::test]
async fn sec_magic_link_claim_revokes_api_keys_made_before_the_proof() {
    let mailer = MemoryMailer::new();
    let auth: AppAuth = FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(ORIGIN)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .email_verification(EmailVerification::default().send_on_sign_up(false))
        .rate_limit(RateLimit::disabled())
        .mailer(mailer.clone())
        .plugin(ApiKeys::new().sessions(true))
        .plugin(MagicLink::new())
        .plugin(Passkey::new())
        .build()
        .unwrap();

    // Mallory registers Ada's address first (unverified) and makes a key.
    let mut mallory = Browser::new(&auth);
    let (status, json) = mallory
        .send(
            "POST",
            "/sign-up/email",
            Some(json!({ "email": "ada@acme.dk", "password": "correct horse battery", "name": "Ada" })),
            None,
        )
        .await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["user"]["emailVerified"], false);
    let (status, created) = mallory
        .send(
            "POST",
            "/api-key/create",
            Some(json!({ "name": "ci" })),
            None,
        )
        .await;
    assert_eq!(status, 200, "{created}");
    let key = created["key"].as_str().unwrap().to_owned();
    let (status, session) = Browser::new(&auth)
        .send("GET", "/get-session", None, Some(&key))
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        session["user"]["email"], "ada@acme.dk",
        "the key works before"
    );

    // Ada proves the address with a magic link, which claims the user.
    let mut ada = Browser::new(&auth);
    let (status, json) = ada
        .send(
            "POST",
            "/sign-in/magic-link",
            Some(json!({ "email": "ada@acme.dk" })),
            None,
        )
        .await;
    assert_eq!(status, 200, "{json}");
    let url = mailer
        .sent()
        .into_iter()
        .find_map(|email| match email {
            AuthEmail::Plugin(e) if e.kind == "magic-link" => e.url,
            _ => None,
        })
        .expect("a magic link was sent");
    let path = url.strip_prefix("http://localhost:3000/api/auth").unwrap();
    let (status, json) = ada.send("GET", path, None, None).await;
    assert!(status < 400, "{status} {json}");
    let (_, session) = ada.send("GET", "/get-session", None, None).await;
    assert_eq!(session["user"]["emailVerified"], true);

    // Mallory's key no longer signs anyone in, and Ada has no keys she didn't make.
    let (status, session) = Browser::new(&auth)
        .send("GET", "/get-session", None, Some(&key))
        .await;
    println!("[key made before the claim -> /get-session] status={status} body={session}");
    assert!(
        session.is_null() || status == 401,
        "the key outlived the claim: {status} {session}"
    );
    let (status, keys) = ada.send("GET", "/api-key/list", None, None).await;
    assert_eq!(status, 200, "{keys}");
    assert_eq!(keys["total"], 0, "{keys}");
}
