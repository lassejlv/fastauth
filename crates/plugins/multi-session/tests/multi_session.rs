//! The multi-session plugin through `Auth::handle` on the memory adapter.

mod common;

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_plugin_multi_session::{MultiSession, MultiSessionExt};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde_json::{Value, json};

type Plugins = plugins![MultiSession];
type App = Client<MemoryAdapter, (), Plugins>;

fn build(plugin: MultiSession) -> Auth<MemoryAdapter, (), Plugins> {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(plugin)
        .build()
        .expect("valid config")
}

async fn create_users(auth: &Auth<MemoryAdapter, (), Plugins>, emails: &[&str]) {
    for email in emails {
        Client::new(auth.clone())
            .sign_up(email, "correct horse")
            .await;
    }
}

async fn sign_in(app: &mut App, email: &str) -> String {
    let res = app
        .post(
            "/sign-in/email",
            json!({ "email": email, "password": "correct horse" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    res.json["token"].as_str().unwrap().to_owned()
}

fn device_cookies(app: &App) -> Vec<String> {
    let mut names: Vec<_> = app
        .jar
        .keys()
        .filter(|name| name.contains("_multi-"))
        .cloned()
        .collect();
    names.sort();
    names
}

async fn listed_emails(app: &mut App) -> Vec<String> {
    let res = app.get("/multi-session/list-device-sessions").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let mut emails: Vec<String> = res
        .json
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["user"]["email"].as_str().unwrap().to_owned())
        .collect();
    emails.sort();
    emails
}

async fn active_email(app: &mut App) -> Value {
    app.get("/get-session").await.json["user"]["email"].clone()
}

fn assert_error(res: &common::Res, status: StatusCode, code: &str) {
    assert_eq!(res.status, status, "{}", res.json);
    assert_eq!(res.json["code"], code, "{}", res.json);
}

#[tokio::test]
async fn every_sign_in_is_remembered_in_a_signed_device_cookie() {
    let auth = build(MultiSession::new());
    create_users(&auth, &["ada@acme.dk", "bob@acme.dk"]).await;
    let mut browser = Client::new(auth.clone());
    let res = browser
        .post(
            "/sign-in/email",
            json!({ "email": "ada@acme.dk", "password": "correct horse" }),
        )
        .await;
    let ada_token = res.json["token"].as_str().unwrap().to_owned();
    let name = format!("fastauth.session_token_multi-{}", ada_token.to_lowercase());
    let cookie = res
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with(&format!("{name}=")))
        .expect("device cookie set");
    assert!(cookie.contains("Max-Age=604800"), "{cookie}");
    assert!(
        cookie.contains("HttpOnly") && cookie.contains("Path=/"),
        "{cookie}"
    );
    assert_eq!(browser.jar[&name], browser.jar["fastauth.session_token"]);

    let bob_token = sign_in(&mut browser, "bob@acme.dk").await;
    assert_eq!(device_cookies(&browser).len(), 2);
    assert_eq!(active_email(&mut browser).await, "bob@acme.dk");

    let res = browser.get("/multi-session/list-device-sessions").await;
    let entries = res.json.as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let mut tokens: Vec<&str> = entries
        .iter()
        .map(|e| e["session"]["token"].as_str().unwrap())
        .collect();
    tokens.sort();
    let mut expected = vec![ada_token.as_str(), bob_token.as_str()];
    expected.sort();
    assert_eq!(tokens, expected);
    for entry in entries {
        assert_eq!(entry["session"]["userId"], entry["user"]["id"]);
    }

    let stranger = Client::new(auth.clone())
        .get("/multi-session/list-device-sessions")
        .await;
    assert_eq!(stranger.json, json!([]));
}

#[tokio::test]
async fn set_active_switches_accounts() {
    let auth = build(MultiSession::new());
    create_users(&auth, &["ada@acme.dk", "bob@acme.dk"]).await;
    let mut browser = Client::new(auth.clone());
    let ada = sign_in(&mut browser, "ada@acme.dk").await;
    sign_in(&mut browser, "bob@acme.dk").await;

    let res = browser
        .post("/multi-session/set-active", json!({ "sessionToken": ada }))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["user"]["email"], "ada@acme.dk");
    assert_eq!(res.json["session"]["token"], ada.as_str());
    assert_eq!(active_email(&mut browser).await, "ada@acme.dk");
    assert_eq!(device_cookies(&browser).len(), 2, "switching keeps both");

    let unknown = browser
        .post(
            "/multi-session/set-active",
            json!({ "sessionToken": "nope" }),
        )
        .await;
    assert_error(&unknown, StatusCode::UNAUTHORIZED, "INVALID_SESSION_TOKEN");
    assert_eq!(unknown.json["message"], "Invalid session token");

    let mut other = Client::new(auth.clone());
    let res = other
        .post("/multi-session/set-active", json!({ "sessionToken": ada }))
        .await;
    assert_error(&res, StatusCode::UNAUTHORIZED, "INVALID_SESSION_TOKEN");
}

#[tokio::test]
async fn set_active_forgets_a_session_that_is_gone() {
    let auth = build(MultiSession::new());
    create_users(&auth, &["ada@acme.dk", "bob@acme.dk"]).await;
    let mut browser = Client::new(auth.clone());
    let ada = sign_in(&mut browser, "ada@acme.dk").await;
    sign_in(&mut browser, "bob@acme.dk").await;

    auth.api().session_token(&ada).sign_out().await.unwrap();
    let res = browser
        .post("/multi-session/set-active", json!({ "sessionToken": ada }))
        .await;
    assert_error(&res, StatusCode::UNAUTHORIZED, "INVALID_SESSION_TOKEN");
    assert_eq!(
        device_cookies(&browser).len(),
        1,
        "the dead cookie is cleared"
    );
    assert_eq!(listed_emails(&mut browser).await, vec!["bob@acme.dk"]);
}

#[tokio::test]
async fn revoke_signs_one_account_out() {
    let auth = build(MultiSession::new());
    create_users(&auth, &["ada@acme.dk", "bob@acme.dk", "cy@acme.dk"]).await;
    let mut browser = Client::new(auth.clone());
    let ada = sign_in(&mut browser, "ada@acme.dk").await;
    let bob = sign_in(&mut browser, "bob@acme.dk").await;
    let cy = sign_in(&mut browser, "cy@acme.dk").await;

    let res = browser
        .post("/multi-session/revoke", json!({ "sessionToken": bob }))
        .await;
    assert_eq!(res.json, json!({ "status": true }));
    assert_eq!(
        listed_emails(&mut browser).await,
        vec!["ada@acme.dk", "cy@acme.dk"]
    );
    assert_eq!(active_email(&mut browser).await, "cy@acme.dk");
    assert!(
        auth.api()
            .session_token(&bob)
            .list_sessions()
            .await
            .is_err(),
        "bob's session is gone"
    );

    let res = browser
        .post("/multi-session/revoke", json!({ "sessionToken": cy }))
        .await;
    assert_eq!(res.json, json!({ "status": true }));
    assert_eq!(
        active_email(&mut browser).await,
        "ada@acme.dk",
        "next account takes over"
    );

    let res = browser
        .post("/multi-session/revoke", json!({ "sessionToken": ada }))
        .await;
    assert_eq!(res.json, json!({ "status": true }));
    assert_eq!(browser.get("/get-session").await.json, Value::Null);
    assert!(device_cookies(&browser).is_empty());

    let res = browser
        .post("/multi-session/revoke", json!({ "sessionToken": ada }))
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoke_refuses_tokens_the_browser_does_not_hold() {
    let auth = build(MultiSession::new());
    create_users(&auth, &["ada@acme.dk", "bob@acme.dk"]).await;
    let mut ada_browser = Client::new(auth.clone());
    sign_in(&mut ada_browser, "ada@acme.dk").await;
    let mut bob_browser = Client::new(auth.clone());
    let bob = sign_in(&mut bob_browser, "bob@acme.dk").await;
    let res = ada_browser
        .post("/multi-session/revoke", json!({ "sessionToken": bob }))
        .await;
    assert_error(&res, StatusCode::UNAUTHORIZED, "INVALID_SESSION_TOKEN");
    assert_eq!(active_email(&mut bob_browser).await, "bob@acme.dk");
}

#[tokio::test]
async fn signing_in_again_replaces_the_older_session_of_that_user() {
    let auth = build(MultiSession::new());
    create_users(&auth, &["ada@acme.dk", "bob@acme.dk"]).await;
    let mut browser = Client::new(auth.clone());
    let first = sign_in(&mut browser, "ada@acme.dk").await;
    sign_in(&mut browser, "bob@acme.dk").await;
    let second = sign_in(&mut browser, "ada@acme.dk").await;
    assert_ne!(first, second);
    assert_eq!(device_cookies(&browser).len(), 2);
    assert_eq!(
        listed_emails(&mut browser).await,
        vec!["ada@acme.dk", "bob@acme.dk"]
    );
    assert!(
        auth.api()
            .session_token(&first)
            .list_sessions()
            .await
            .is_err(),
        "the older session was deleted"
    );
}

#[tokio::test]
async fn maximum_sessions_caps_the_remembered_accounts() {
    let auth = build(MultiSession::new().maximum_sessions(2));
    create_users(&auth, &["ada@acme.dk", "bob@acme.dk", "cy@acme.dk"]).await;
    let mut browser = Client::new(auth.clone());
    sign_in(&mut browser, "ada@acme.dk").await;
    sign_in(&mut browser, "bob@acme.dk").await;
    sign_in(&mut browser, "cy@acme.dk").await;
    assert_eq!(
        active_email(&mut browser).await,
        "cy@acme.dk",
        "still signed in"
    );
    assert_eq!(device_cookies(&browser).len(), 2);
    assert_eq!(
        listed_emails(&mut browser).await,
        vec!["ada@acme.dk", "bob@acme.dk"]
    );
}

#[tokio::test]
async fn sign_out_signs_every_account_out() {
    let auth = build(MultiSession::new());
    create_users(&auth, &["ada@acme.dk", "bob@acme.dk"]).await;
    let mut browser = Client::new(auth.clone());
    let ada = sign_in(&mut browser, "ada@acme.dk").await;
    let bob = sign_in(&mut browser, "bob@acme.dk").await;
    let res = browser.post("/sign-out", json!({})).await;
    assert_eq!(res.json, json!({ "success": true }));
    assert!(device_cookies(&browser).is_empty(), "{:?}", browser.jar);
    assert_eq!(browser.get("/get-session").await.json, Value::Null);
    for token in [ada, bob] {
        assert!(
            auth.api()
                .session_token(&token)
                .list_sessions()
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn forged_device_cookies_are_ignored() {
    let auth = build(MultiSession::new());
    create_users(&auth, &["ada@acme.dk"]).await;
    let mut victim = Client::new(auth.clone());
    let token = sign_in(&mut victim, "ada@acme.dk").await;
    let mut attacker = Client::new(auth.clone());
    attacker.jar.insert(
        format!("fastauth.session_token_multi-{}", token.to_lowercase()),
        token.clone(),
    );
    assert_eq!(listed_emails(&mut attacker).await, Vec::<String>::new());
    let res = attacker
        .post(
            "/multi-session/set-active",
            json!({ "sessionToken": token }),
        )
        .await;
    assert_error(&res, StatusCode::UNAUTHORIZED, "INVALID_SESSION_TOKEN");
}

#[tokio::test]
async fn server_api() {
    let auth = build(MultiSession::new());
    create_users(&auth, &["ada@acme.dk", "bob@acme.dk"]).await;
    let mut browser = Client::new(auth.clone());
    let ada = sign_in(&mut browser, "ada@acme.dk").await;
    sign_in(&mut browser, "bob@acme.dk").await;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&browser.cookie_header().unwrap()).unwrap(),
    );
    let api = auth.multi_session();
    assert_eq!(
        api.list_device_sessions(&headers).await.unwrap().data.len(),
        2
    );
    let res = api.set_active(&headers, &ada).await.unwrap();
    assert_eq!(res.data["user"]["email"], "ada@acme.dk");
    assert!(!res.set_cookies.is_empty());
    assert!(api.revoke(&headers, &ada).await.unwrap().data.status);
}
