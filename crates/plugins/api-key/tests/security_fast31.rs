//! FAST-31 security review (area: authz). Each test asserts the secure behaviour, so the
//! ones covering a finding fail on 0.3.0 and pass once it is fixed.

mod common;

use axum::body::Body;
use axum::routing::get;
use axum::{Json, Router};
use bytes::Bytes;
use common::{Client, secret};
use fastauth_axum::{AuthRouter, FreshSession};
use fastauth_core::crypto::Argon2id;
use fastauth_core::models::Session as SessionRow;
use fastauth_core::prelude::*;
use fastauth_core::query::{Db, Where};
use fastauth_plugin_api_key::{ApiKey, ApiKeys, ApiKeysExt, CreateApiKeyInput, CreatedApiKey};
use http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type AppAuth = Auth<MemoryAdapter, (), plugins![ApiKeys]>;

fn build_with(plugin: ApiKeys, session: SessionConfig) -> AppAuth {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .session(session)
        .plugin(plugin)
        .build()
        .expect("valid config")
}

fn build(plugin: ApiKeys) -> AppAuth {
    build_with(plugin, SessionConfig::default())
}

fn db(auth: &AppAuth) -> Db<'_, MemoryAdapter> {
    Db::new(auth.adapter(), auth.schema())
}

/// A key with every limit the server can set: 3 uses, a 1-day expiry, 5 requests a day.
async fn limited_key(auth: &AppAuth, user_id: &str) -> CreatedApiKey {
    auth.api_keys()
        .create(CreateApiKeyInput {
            user_id: Some(user_id.into()),
            remaining: Some(3),
            expires_in: Some(Duration::days(1).whole_seconds()),
            rate_limit_max: Some(5),
            ..Default::default()
        })
        .await
        .expect("server create")
}

/// One request to the auth handler carrying only an API key, no cookies.
async fn with_key(
    auth: &AppAuth,
    method: Method,
    path: &str,
    key: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(format!("/api/auth{path}"))
        .header(header::ORIGIN, common::ORIGIN)
        .header("x-api-key", key)
        .body(body.map(|b| Bytes::from(b.to_string())).unwrap_or_default())
        .unwrap();
    let response = auth.handle(request).await;
    (
        response.status(),
        serde_json::from_slice(response.body()).unwrap_or(Value::Null),
    )
}

/// AUTHZ-3: a request authenticated only by an API key must not mint a new key. On 0.3.0
/// it does, and the new key drops the parent key's server-set `remaining`, expiry and rate
/// limit, so whoever holds a limited key turns it into an unlimited, never-expiring one.
#[tokio::test]
async fn sec_key_session_cannot_mint_a_new_key() {
    let mut c = Client::new(build(ApiKeys::new().sessions(true)));
    let user_id = c.sign_up("ada@acme.dk").await;
    let auth = c.auth.clone();
    let parent = limited_key(&auth, &user_id).await;

    let (status, json) = with_key(
        &auth,
        Method::POST,
        "/api-key/create",
        &parent.key,
        Some(json!({ "name": "escape" })),
    )
    .await;
    println!(
        "[key mints key] status={status} remaining={} expiresAt={} rateLimitMax={} (parent: remaining=3, expires in 1 day, rateLimitMax=5)",
        json["remaining"], json["expiresAt"], json["rateLimitMax"]
    );
    assert!(
        !status.is_success(),
        "an API-key session minted a new key: {json}"
    );
}

/// AUTHZ-3: nor may it lift its own server-set expiry.
#[tokio::test]
async fn sec_key_session_cannot_remove_its_own_expiry() {
    let mut c = Client::new(build(ApiKeys::new().sessions(true)));
    let user_id = c.sign_up("ada@acme.dk").await;
    let auth = c.auth.clone();
    let key = limited_key(&auth, &user_id).await;

    let (status, json) = with_key(
        &auth,
        Method::POST,
        "/api-key/update",
        &key.key,
        Some(json!({ "keyId": key.api_key.id, "expiresIn": null })),
    )
    .await;
    let row = db(&auth)
        .find::<ApiKey>(ApiKey::ID.eq(&key.api_key.id))
        .one()
        .await
        .unwrap()
        .unwrap();
    println!(
        "[key clears own expiry] status={status} expiresAt now={:?}",
        row.expires_at
    );
    assert!(
        !status.is_success() && row.expires_at.is_some(),
        "an API-key session removed its own expiry: {json}"
    );
}

async fn fresh(session: FreshSession<AppAuth>) -> Json<Value> {
    Json(json!({ "email": session.user.email, "ephemeral": session.view().ephemeral }))
}

/// AUTHZ-2: an API key is not a recent sign-in, so it must not pass `Fresh` checks
/// (`FreshSession`, `Access = Fresh` endpoints such as passkey registration). On 0.3.0 the
/// ephemeral session is created `now`, so it is always fresh.
#[tokio::test]
async fn sec_key_session_is_never_fresh() {
    let mut c = Client::new(build(ApiKeys::new().sessions(true)));
    let user_id = c.sign_up("ada@acme.dk").await;
    let auth = c.auth.clone();
    let key = limited_key(&auth, &user_id).await;
    let app = Router::new()
        .route("/sensitive", get(fresh))
        .merge(auth.router())
        .with_state(auth.clone());
    let request = Request::get("/sensitive")
        .header("x-api-key", &key.key)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    println!(
        "[FreshSession via API key] status={status} body={}",
        String::from_utf8_lossy(&bytes)
    );
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an API key passed FreshSession: {}",
        String::from_utf8_lossy(&bytes)
    );
}

/// AUTHZ-5: with the cookie cache on, a revoked session (sign-out elsewhere, ban,
/// revoke-sessions) is still accepted from the cache for its max-age. Minting a long-lived
/// credential must read the session from the database, as Better Auth's create-api-key does.
#[tokio::test]
async fn sec_revoked_session_cannot_mint_key_from_cookie_cache() {
    let auth = build_with(
        ApiKeys::new(),
        SessionConfig::default().cookie_cache(Duration::minutes(5)),
    );
    let mut c = Client::new(auth.clone());
    c.sign_up("ada@acme.dk").await;
    let res = c.get("/get-session").await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(
        c.jar.keys().any(|k| k.ends_with("session_data")),
        "cache cookie set"
    );

    let revoked = db(&auth).delete::<SessionRow>(Where::all()).await.unwrap();
    assert_eq!(revoked, 1);

    let res = c
        .post("/api-key/create", json!({ "name": "after revoke" }))
        .await;
    println!(
        "[mint key after session revoked] status={} body={}",
        res.status, res.json
    );
    assert_eq!(
        res.status,
        StatusCode::UNAUTHORIZED,
        "a revoked session minted an API key from the cookie cache: {}",
        res.json
    );
}

/// Coverage: one user's key ids are useless to another user over HTTP.
#[tokio::test]
async fn sec_keys_are_scoped_to_their_owner() {
    let mut ada = Client::new(build(ApiKeys::new()));
    ada.sign_up("ada@acme.dk").await;
    let auth = ada.auth.clone();
    let mut eve = Client::new(auth.clone());
    eve.sign_up("eve@acme.dk").await;
    let created = ada.post("/api-key/create", json!({ "name": "ada" })).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.json);
    let id = created.json["id"].as_str().unwrap().to_owned();

    let res = eve.get(&format!("/api-key/get?id={id}")).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND, "{}", res.json);
    let res = eve
        .post("/api-key/update", json!({ "keyId": id, "enabled": false }))
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND, "{}", res.json);
    let res = eve.post("/api-key/delete", json!({ "keyId": id })).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND, "{}", res.json);
    let res = eve
        .post(
            "/api-key/create",
            json!({ "userId": created.json["userId"] }),
        )
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.json);
    let listed = eve.get("/api-key/list").await;
    assert_eq!(listed.json["total"], 0, "{}", listed.json);
    assert!(ada.get(&format!("/api-key/get?id={id}")).await.json["enabled"] == true);
}
