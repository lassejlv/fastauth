//! FAST-31 security review (area: authz): findings that need several plugins at once, so
//! they live in the umbrella crate and run with `--all-features`. Each test asserts the
//! secure behaviour and fails on 0.3.0.
#![cfg(all(feature = "admin", feature = "api-key", feature = "passkey"))]

use std::collections::HashMap;

use axum::body::Bytes;
use axum::http::{Request, header};
use fastauth::crypto::{Argon2id, Secret};
use fastauth::plugins::admin::{Admin, AdminExt, BanUserInput, Permissions};
use fastauth::plugins::api_key::{ApiKeys, ApiKeysExt, CreateApiKeyInput};
use fastauth::plugins::passkey::Passkey;
use fastauth::prelude::*;
use fastauth::query::Db;

type AppAuth = Auth<MemoryAdapter, (), plugins![Admin, ApiKeys, Passkey]>;

const ORIGIN: &str = "http://localhost:3000";

fn build() -> AppAuth {
    FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(ORIGIN)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(Admin::new().role("support", Permissions::new().allow("user", ["impersonate"])))
        .plugin(ApiKeys::new().sessions(true))
        .plugin(Passkey::new())
        .build()
        .expect("valid config")
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
        body: Option<&str>,
        api_key: Option<&str>,
    ) -> (u16, String) {
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
        let body = Bytes::from(body.unwrap_or_default().to_owned());
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
        (
            response.status().as_u16(),
            String::from_utf8_lossy(response.body()).into_owned(),
        )
    }
}

async fn signed_up(auth: &AppAuth, email: &str) -> (Browser, Id) {
    let mut browser = Browser::new(auth);
    let body = format!(r#"{{"email":"{email}","password":"correct horse","name":"Test User"}}"#);
    let (status, json) = browser
        .send("POST", "/sign-up/email", Some(&body), None)
        .await;
    assert_eq!(status, 200, "{json}");
    let user = Db::new(auth.adapter(), auth.schema())
        .find::<User>(User::EMAIL.eq(email))
        .one()
        .await
        .unwrap()
        .unwrap();
    (browser, user.id)
}

async fn key_for(auth: &AppAuth, user_id: &Id) -> String {
    auth.api_keys()
        .create(CreateApiKeyInput {
            user_id: Some(user_id.clone()),
            ..Default::default()
        })
        .await
        .expect("server create")
        .key
}

/// The value of `"field":"..."` in a JSON body.
fn string_field(json: &str, field: &str) -> Option<String> {
    let start = json.find(&format!(r#""{field}":""#))? + field.len() + 4;
    Some(json[start..].split('"').next()?.to_owned())
}

/// AUTHZ-1: a banned user is refused at every sign-in gate, and the ban revokes their
/// sessions, but their API key keeps resolving to a full session for them.
#[tokio::test]
async fn sec_banned_users_api_key_no_longer_authenticates() {
    let auth = build();
    let (_, bob) = signed_up(&auth, "bob@acme.dk").await;
    let key = key_for(&auth, &bob).await;
    let mut client = Browser::new(&auth);
    let (status, before) = client.send("GET", "/get-session", None, Some(&key)).await;
    assert_eq!(status, 200);
    assert!(
        before.contains("bob@acme.dk"),
        "baseline: the key is a session: {before}"
    );

    auth.admin()
        .ban(BanUserInput::new(bob.clone()).reason("fraud"))
        .await
        .unwrap();
    let (signin_status, signin) = Browser::new(&auth)
        .send(
            "POST",
            "/sign-in/email",
            Some(r#"{"email":"bob@acme.dk","password":"correct horse"}"#),
            None,
        )
        .await;
    println!("[banned sign-in with password] status={signin_status} body={signin}");
    let (status, after) = client.send("GET", "/get-session", None, Some(&key)).await;
    println!("[banned user's API key -> /get-session] status={status} body={after}");
    let (mint_status, minted) = client
        .send(
            "POST",
            "/api-key/create",
            Some(r#"{"name":"after ban"}"#),
            Some(&key),
        )
        .await;
    println!("[banned user's API key -> /api-key/create] status={mint_status} body={minted}");
    assert_eq!(signin_status, 403, "baseline: the gate refuses sign-in");
    assert!(
        !after.contains("bob@acme.dk"),
        "a banned user's API key still authenticates as them: {status} {after}"
    );
}

/// AUTHZ-2: an API key passes `Access = Fresh`, so it can start (and with
/// `verify-registration`, finish) registering a passkey: a key leaked from CI becomes an
/// interactive sign-in method, and `createSession: true` a 7-day cookie session.
#[tokio::test]
async fn sec_api_key_cannot_start_passkey_registration() {
    let auth = build();
    let (_, bob) = signed_up(&auth, "bob@acme.dk").await;
    let key = key_for(&auth, &bob).await;
    let (status, body) = Browser::new(&auth)
        .send(
            "GET",
            "/passkey/generate-register-options",
            None,
            Some(&key),
        )
        .await;
    println!(
        "[API key -> /passkey/generate-register-options] status={status} body={}",
        &body[..body.len().min(200)]
    );
    assert!(
        status == 401 || status == 403,
        "an API key started passkey registration: {status} {body}"
    );
}

/// AUTHZ-7: a role with only `user:impersonate` gets a one-hour session as the user, but can
/// use it to mint an API key that never expires and keeps working after stop-impersonating.
#[tokio::test]
async fn sec_impersonation_session_cannot_mint_api_key() {
    let auth = build();
    let (_, bob) = signed_up(&auth, "bob@acme.dk").await;
    let (mut support, support_id) = signed_up(&auth, "support@acme.dk").await;
    auth.admin().set_role(&support_id, "support").await.unwrap();

    let body = format!(r#"{{"userId":"{bob}"}}"#);
    let (status, json) = support
        .send("POST", "/admin/impersonate-user", Some(&body), None)
        .await;
    assert_eq!(status, 200, "{json}");
    let (status, created) = support
        .send(
            "POST",
            "/api-key/create",
            Some(r#"{"name":"backdoor"}"#),
            None,
        )
        .await;
    println!("[impersonation session -> /api-key/create] status={status} body={created}");
    let (stop, _) = support
        .send("POST", "/admin/stop-impersonating", Some("{}"), None)
        .await;
    assert_eq!(stop, 200);
    if let Some(key) = string_field(&created, "key") {
        let (status, session) = Browser::new(&auth)
            .send("GET", "/get-session", None, Some(&key))
            .await;
        println!(
            "[minted key after stop-impersonating -> /get-session] status={status} body={session}"
        );
    }
    assert!(
        status == 401 || status == 403,
        "an impersonation session minted an API key for the impersonated user: {status} {created}"
    );
}
