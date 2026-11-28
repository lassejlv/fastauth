mod common;

use std::collections::BTreeMap;

use axum::body::Body;
use axum::routing::get;
use axum::{Json, Router};
use common::{Client, secret};
use fastauth_axum::{AuthRouter, Session};
use fastauth_core::crypto::{Argon2id, Hash};
use fastauth_core::model::Model;
use fastauth_core::prelude::*;
use fastauth_core::query::{Db, Where};
use fastauth_core::value::Value as DbValue;
use fastauth_plugin_api_key::{
    ApiKey, ApiKeys, ApiKeysExt, CreateApiKeyInput, CreatedApiKey, DeleteApiKeyInput,
    GetApiKeyInput, ListApiKeysInput, Permissions, UpdateApiKeyInput,
};
use http::{HeaderName, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt;

type AppAuth = Auth<MemoryAdapter, (), plugins![ApiKeys]>;

fn build(plugin: ApiKeys) -> AppAuth {
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

fn client(plugin: ApiKeys) -> Client<MemoryAdapter, (), plugins![ApiKeys]> {
    Client::new(build(plugin))
}

async fn server_key(auth: &AppAuth, user_id: &str, input: CreateApiKeyInput) -> CreatedApiKey {
    auth.api_keys()
        .create(CreateApiKeyInput {
            user_id: Some(user_id.into()),
            ..input
        })
        .await
        .expect("server create")
}

async fn row(auth: &AppAuth, id: &Id) -> Option<ApiKey> {
    Db::new(auth.adapter(), auth.schema())
        .find::<ApiKey>(ApiKey::ID.eq(id))
        .one()
        .await
        .unwrap()
}

fn db(auth: &AppAuth) -> Db<'_, MemoryAdapter> {
    Db::new(auth.adapter(), auth.schema())
}

fn perms(pairs: &[(&str, &[&str])]) -> Permissions {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.iter().map(|a| a.to_string()).collect()))
        .collect::<BTreeMap<_, _>>()
}

async fn verify_code(auth: &AppAuth, key: &str) -> Option<String> {
    let out = auth.api_keys().verify(key, None).await.unwrap();
    out.error.map(|e| e.code)
}

#[tokio::test]
async fn create_over_http_then_verify() {
    let mut c = client(ApiKeys::new().default_prefix("ak_"));
    let user_id = c.sign_up("ada@acme.dk").await;

    let res = c.post("/api-key/create", json!({ "name": "ci" })).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let key = res.json["key"].as_str().unwrap().to_owned();
    assert!(key.starts_with("ak_"));
    assert_eq!(key.len(), 3 + 64);
    assert!(key[3..].bytes().all(|b| b.is_ascii_alphabetic()));
    assert_eq!(res.json["start"], key[..6]);
    assert_eq!(res.json["prefix"], "ak_");
    assert_eq!(res.json["name"], "ci");
    assert_eq!(res.json["referenceId"], user_id);
    assert_eq!(res.json["userId"], user_id);
    assert_eq!(res.json["configId"], "default");
    assert_eq!(res.json["enabled"], true);
    assert_eq!(res.json["rateLimitEnabled"], true);
    assert_eq!(res.json["rateLimitMax"], 10);
    assert_eq!(res.json["rateLimitTimeWindow"], 86_400_000);
    assert_eq!(res.json["requestCount"], 0);
    assert_eq!(res.json["remaining"], Value::Null);
    assert_eq!(res.json["permissions"], Value::Null);
    assert_eq!(res.json["metadata"], Value::Null);
    assert_eq!(res.json["expiresAt"], Value::Null);
    assert!(res.json.get("keyHash").is_none());

    let out = c.auth.api_keys().verify(&key, None).await.unwrap();
    assert!(out.valid);
    assert!(out.error.is_none());
    let verified = out.key.unwrap();
    assert_eq!(verified.request_count, 1);
    assert!(verified.last_request.is_some());

    let out = c.auth.api_keys().verify("ak_nope", None).await.unwrap();
    assert!(!out.valid);
    let error = serde_json::to_value(&out).unwrap();
    assert_eq!(error["error"]["code"], "INVALID_API_KEY");
    assert_eq!(error["key"], Value::Null);
}

#[tokio::test]
async fn only_the_hash_is_stored() {
    let mut c = client(ApiKeys::new());
    c.sign_up("ada@acme.dk").await;
    let res = c.post("/api-key/create", json!({})).await;
    let key = res.json["key"].as_str().unwrap().to_owned();

    let rows = db(&c.auth)
        .find::<ApiKey>(Where::all())
        .all_rows()
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    for value in rows[0].values() {
        if let DbValue::Text(text) = value {
            assert!(!text.contains(&key), "plaintext key stored: {text}");
        }
    }
    let stored = ApiKey::decode(&rows[0]).unwrap();
    assert!(stored.key_hash == Hash::sha256(&key));

    let res = c.get("/api-key/list").await;
    assert_eq!(res.json["total"], 1);
    assert!(res.json["apiKeys"][0].get("key").is_none());
    assert!(res.json["apiKeys"][0].get("keyHash").is_none());
}

#[tokio::test]
async fn expired_keys_fail_and_are_deleted() {
    let mut c = client(ApiKeys::new());
    let user_id = c.sign_up("ada@acme.dk").await;

    let res = c
        .post("/api-key/create", json!({ "expiresIn": 3600 }))
        .await;
    assert_eq!(res.json["code"], "EXPIRES_IN_IS_TOO_SMALL", "{}", res.json);
    let res = c
        .post("/api-key/create", json!({ "expiresIn": 400 * 86_400 }))
        .await;
    assert_eq!(res.json["code"], "EXPIRES_IN_IS_TOO_LARGE");
    let res = c
        .post("/api-key/create", json!({ "expiresIn": 7 * 86_400 }))
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.json["expiresAt"].is_string());

    let created = server_key(&c.auth, &user_id, CreateApiKeyInput::default()).await;
    db(&c.auth)
        .update::<ApiKey>(ApiKey::ID.eq(&created.api_key.id))
        .set(
            ApiKey::EXPIRES_AT,
            Some(OffsetDateTime::now_utc() - Duration::seconds(1)),
        )
        .exec()
        .await
        .unwrap();
    assert_eq!(
        verify_code(&c.auth, &created.key).await.as_deref(),
        Some("KEY_EXPIRED")
    );
    assert!(row(&c.auth, &created.api_key.id).await.is_none());

    let stale = server_key(&c.auth, &user_id, CreateApiKeyInput::default()).await;
    db(&c.auth)
        .update::<ApiKey>(ApiKey::ID.eq(&stale.api_key.id))
        .set(
            ApiKey::EXPIRES_AT,
            Some(OffsetDateTime::now_utc() - Duration::days(1)),
        )
        .exec()
        .await
        .unwrap();
    let out = c.auth.api_keys().delete_all_expired().await.unwrap();
    assert!(out.success);
    assert_eq!(out.deleted, 1);
    assert!(row(&c.auth, &stale.api_key.id).await.is_none());
    assert_eq!(c.get("/api-key/list").await.json["total"], 1);
}

#[tokio::test]
async fn remaining_runs_out_then_refills() {
    let c = client(ApiKeys::new().disable_rate_limit());
    let mut c = c;
    let user_id = c.sign_up("ada@acme.dk").await;
    let auth = c.auth.clone();

    let once = server_key(
        &auth,
        &user_id,
        CreateApiKeyInput {
            remaining: Some(1),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(once.api_key.remaining, Some(1));
    assert_eq!(verify_code(&auth, &once.key).await, None);
    assert_eq!(
        verify_code(&auth, &once.key).await.as_deref(),
        Some("USAGE_EXCEEDED")
    );
    assert!(
        row(&auth, &once.api_key.id).await.is_none(),
        "an exhausted key without refill is deleted"
    );

    let refilling = server_key(
        &auth,
        &user_id,
        CreateApiKeyInput {
            refill_amount: Some(2),
            refill_interval: Some(60_000),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        refilling.api_key.remaining,
        Some(2),
        "remaining starts at refillAmount"
    );
    assert_eq!(verify_code(&auth, &refilling.key).await, None);
    assert_eq!(verify_code(&auth, &refilling.key).await, None);
    assert_eq!(
        verify_code(&auth, &refilling.key).await.as_deref(),
        Some("USAGE_EXCEEDED")
    );
    assert!(
        row(&auth, &refilling.api_key.id).await.is_some(),
        "a refilling key is kept"
    );

    let past = OffsetDateTime::now_utc() - Duration::minutes(2);
    db(&auth)
        .update::<ApiKey>(ApiKey::ID.eq(&refilling.api_key.id))
        .set(ApiKey::CREATED_AT, past)
        .exec()
        .await
        .unwrap();
    let out = auth.api_keys().verify(&refilling.key, None).await.unwrap();
    assert!(out.valid, "{:?}", out.error);
    let key = out.key.unwrap();
    assert_eq!(key.remaining, Some(1));
    assert!(key.last_refill_at.is_some());
    assert_eq!(verify_code(&auth, &refilling.key).await, None);
    assert_eq!(
        verify_code(&auth, &refilling.key).await.as_deref(),
        Some("USAGE_EXCEEDED")
    );

    let res = c
        .post("/api-key/create", json!({ "refillAmount": 5 }))
        .await;
    assert_eq!(res.json["code"], "SERVER_ONLY_PROPERTY");
    let err = auth
        .api_keys()
        .create(CreateApiKeyInput {
            user_id: Some(user_id.as_str().into()),
            refill_amount: Some(5),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), "REFILL_AMOUNT_AND_INTERVAL_REQUIRED");
}

#[tokio::test]
async fn rate_limit_per_key() {
    let mut c = client(ApiKeys::new());
    let user_id = c.sign_up("ada@acme.dk").await;
    let auth = c.auth.clone();
    let limited = server_key(
        &auth,
        &user_id,
        CreateApiKeyInput {
            rate_limit_max: Some(2),
            rate_limit_time_window: Some(60_000),
            ..Default::default()
        },
    )
    .await;
    let other = server_key(
        &auth,
        &user_id,
        CreateApiKeyInput {
            rate_limit_max: Some(2),
            rate_limit_time_window: Some(60_000),
            ..Default::default()
        },
    )
    .await;

    assert_eq!(verify_code(&auth, &limited.key).await, None);
    assert_eq!(verify_code(&auth, &limited.key).await, None);
    let out = auth.api_keys().verify(&limited.key, None).await.unwrap();
    let error = out.error.unwrap();
    assert_eq!(error.code, "RATE_LIMITED");
    assert_eq!(error.message, "Rate limit exceeded.");
    let wait = error.details.unwrap()["tryAgainIn"].as_i64().unwrap();
    assert!(wait > 0 && wait <= 60_000, "{wait}");
    assert_eq!(
        verify_code(&auth, &other.key).await,
        None,
        "limits are per key"
    );

    db(&auth)
        .update::<ApiKey>(ApiKey::ID.eq(&limited.api_key.id))
        .set(
            ApiKey::LAST_REQUEST,
            Some(OffsetDateTime::now_utc() - Duration::minutes(2)),
        )
        .exec()
        .await
        .unwrap();
    let out = auth.api_keys().verify(&limited.key, None).await.unwrap();
    assert!(out.valid, "a new window starts after the old one passes");
    assert_eq!(out.key.unwrap().request_count, 1);

    let unlimited = server_key(
        &auth,
        &user_id,
        CreateApiKeyInput {
            rate_limit_enabled: Some(false),
            rate_limit_max: Some(1),
            ..Default::default()
        },
    )
    .await;
    for _ in 0..3 {
        assert_eq!(verify_code(&auth, &unlimited.key).await, None);
    }
}

#[tokio::test]
async fn permissions_match_and_mismatch() {
    let mut c = client(ApiKeys::new());
    let user_id = c.sign_up("ada@acme.dk").await;
    let auth = c.auth.clone();
    let scoped = server_key(
        &auth,
        &user_id,
        CreateApiKeyInput {
            permissions: Some(perms(&[("files", &["read", "write"])])),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        serde_json::to_value(&scoped.api_key).unwrap()["permissions"],
        json!({ "files": ["read", "write"] })
    );

    let check = |key: String, requested: Permissions| {
        let auth = auth.clone();
        async move { auth.api_keys().verify(&key, Some(requested)).await.unwrap() }
    };
    assert!(
        check(scoped.key.clone(), perms(&[("files", &["read"])]))
            .await
            .valid
    );
    assert!(
        check(scoped.key.clone(), perms(&[("files", &["read", "write"])]))
            .await
            .valid
    );
    let out = check(scoped.key.clone(), perms(&[("files", &["delete"])])).await;
    assert_eq!(out.error.unwrap().code, "KEY_NOT_FOUND");
    let out = check(
        scoped.key.clone(),
        perms(&[("files", &["read"]), ("users", &["read"])]),
    )
    .await;
    assert!(!out.valid);
    assert!(!check(scoped.key.clone(), Permissions::new()).await.valid);

    let plain = server_key(&auth, &user_id, CreateApiKeyInput::default()).await;
    assert!(!check(plain.key, perms(&[("files", &["read"])])).await.valid);

    let res = c
        .post(
            "/api-key/create",
            json!({ "permissions": { "files": ["read"] } }),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json["code"], "SERVER_ONLY_PROPERTY");
}

async fn me(session: Session<AppAuth>) -> Json<Value> {
    Json(json!({ "email": session.user.email, "ephemeral": session.view().ephemeral }))
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn me_with(header: Option<(&str, &str)>) -> Request<Body> {
    let mut request = Request::get("/me");
    if let Some((name, value)) = header {
        request = request.header(name, value);
    }
    request.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn resolver_turns_keys_into_sessions_through_axum() {
    let mut c = client(ApiKeys::new().sessions(true));
    let user_id = c.sign_up("ada@acme.dk").await;
    let auth = c.auth.clone();
    let app = Router::new()
        .route("/me", get(me))
        .merge(auth.router())
        .with_state(auth.clone());
    let created = server_key(&auth, &user_id, CreateApiKeyInput::default()).await;

    let (status, json) = send(&app, me_with(Some(("x-api-key", &created.key)))).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["email"], "ada@acme.dk");
    assert_eq!(json["ephemeral"], true);
    assert_eq!(
        row(&auth, &created.api_key.id).await.unwrap().request_count,
        1
    );
    assert_eq!(
        db(&auth)
            .count::<fastauth_core::models::Session>(Where::all())
            .await
            .unwrap(),
        1,
        "only the sign-up session is stored"
    );

    let (status, json) = send(&app, me_with(None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["code"], "UNAUTHORIZED");

    let (status, json) = send(&app, me_with(Some(("x-api-key", "short")))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json["code"], "INVALID_API_KEY");

    let unknown = "x".repeat(64);
    let (status, json) = send(&app, me_with(Some(("x-api-key", &unknown)))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["code"], "INVALID_API_KEY");

    let mut update = UpdateApiKeyInput::new(created.api_key.id.clone());
    update.user_id = Some(user_id.as_str().into());
    update.enabled = Some(false);
    auth.api_keys().update(update).await.unwrap();
    let (status, json) = send(&app, me_with(Some(("x-api-key", &created.key)))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["code"], "KEY_DISABLED");

    let (status, json) = send(
        &app,
        Request::get("/api/auth/get-session")
            .header(
                "x-api-key",
                server_key(&auth, &user_id, CreateApiKeyInput::default())
                    .await
                    .key,
            )
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["user"]["id"], user_id);
}

#[tokio::test]
async fn custom_header_and_getter() {
    let mut c = client(
        ApiKeys::new()
            .sessions(true)
            .header(HeaderName::from_static("x-acme-key")),
    );
    let user_id = c.sign_up("ada@acme.dk").await;
    let created = server_key(&c.auth, &user_id, CreateApiKeyInput::default()).await;
    let mut headers = http::HeaderMap::new();
    headers.insert("x-api-key", created.key.parse().unwrap());
    assert!(c.auth.get_session(&headers).await.unwrap().is_none());
    headers.insert("x-acme-key", created.key.parse().unwrap());
    let session = c.auth.get_session(&headers).await.unwrap().unwrap();
    assert_eq!(session.user.id.as_str(), user_id);

    let mut c = client(ApiKeys::new().sessions(true).key_getter(|headers| {
        headers
            .get(header::AUTHORIZATION)?
            .to_str()
            .ok()?
            .strip_prefix("ApiKey ")
            .map(str::to_owned)
    }));
    let user_id = c.sign_up("ada@acme.dk").await;
    let created = server_key(&c.auth, &user_id, CreateApiKeyInput::default()).await;
    let mut headers = http::HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("ApiKey {}", created.key).parse().unwrap(),
    );
    let session = c.auth.get_session(&headers).await.unwrap().unwrap();
    assert_eq!(session.user.id.as_str(), user_id);

    let mut c = client(ApiKeys::new());
    let user_id = c.sign_up("ada@acme.dk").await;
    let created = server_key(&c.auth, &user_id, CreateApiKeyInput::default()).await;
    let mut headers = http::HeaderMap::new();
    headers.insert("x-api-key", created.key.parse().unwrap());
    assert!(
        c.auth.get_session(&headers).await.unwrap().is_none(),
        "sessions from keys are opt-in"
    );
    assert_eq!(
        row(&c.auth, &created.api_key.id)
            .await
            .unwrap()
            .request_count,
        0,
        "an ignored header doesn't count as a use"
    );
}

#[tokio::test]
async fn disabled_key_fails_verification() {
    let mut c = client(ApiKeys::new());
    c.sign_up("ada@acme.dk").await;
    let res = c.post("/api-key/create", json!({ "name": "ci" })).await;
    let key = res.json["key"].as_str().unwrap().to_owned();
    let id = res.json["id"].as_str().unwrap().to_owned();

    let res = c
        .post("/api-key/update", json!({ "keyId": id, "enabled": false }))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["enabled"], false);
    assert_eq!(
        verify_code(&c.auth, &key).await.as_deref(),
        Some("KEY_DISABLED")
    );

    let res = c
        .post("/api-key/update", json!({ "keyId": id, "enabled": true }))
        .await;
    assert_eq!(res.json["enabled"], true);
    assert_eq!(verify_code(&c.auth, &key).await, None);
}

#[tokio::test]
async fn clients_cannot_set_server_only_fields() {
    let mut c = client(ApiKeys::new());
    let user_id = c.sign_up("ada@acme.dk").await;

    for body in [
        json!({ "remaining": 100 }),
        json!({ "refillAmount": 10, "refillInterval": 1000 }),
        json!({ "rateLimitMax": 1000 }),
        json!({ "rateLimitTimeWindow": 1000 }),
        json!({ "rateLimitEnabled": false }),
        json!({ "permissions": { "admin": ["*"] } }),
    ] {
        let res = c.post("/api-key/create", body.clone()).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(res.json["code"], "SERVER_ONLY_PROPERTY", "{body}");
    }
    let res = c
        .post("/api-key/create", json!({ "userId": "someone-else" }))
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json["code"], "UNAUTHORIZED_SESSION");
    assert_eq!(c.get("/api-key/list").await.json["total"], 0);

    let res = c.post("/api-key/create", json!({})).await;
    let id = res.json["id"].as_str().unwrap().to_owned();
    for body in [
        json!({ "keyId": id, "remaining": 100 }),
        json!({ "keyId": id, "rateLimitEnabled": false }),
        json!({ "keyId": id, "permissions": null }),
    ] {
        let res = c.post("/api-key/update", body.clone()).await;
        assert_eq!(res.json["code"], "SERVER_ONLY_PROPERTY", "{body}");
    }

    let mut update = UpdateApiKeyInput::new(id.clone());
    update.user_id = Some(user_id.as_str().into());
    update.remaining = Some(100);
    update.permissions = Some(Some(perms(&[("files", &["read"])])));
    let key = c.auth.api_keys().update(update).await.unwrap();
    assert_eq!(key.remaining, Some(100));
    assert_eq!(key.permissions, Some(perms(&[("files", &["read"])])));

    let mut stranger = client(ApiKeys::new());
    stranger.auth = c.auth.clone();
    stranger.sign_up("eve@acme.dk").await;
    let res = stranger
        .post("/api-key/update", json!({ "keyId": id, "name": "mine" }))
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(res.json["code"], "KEY_NOT_FOUND");

    let mut anonymous = client(ApiKeys::new());
    anonymous.auth = c.auth.clone();
    let res = anonymous.post("/api-key/create", json!({})).await;
    assert_eq!(res.json["code"], "UNAUTHORIZED_SESSION");
    assert_eq!(
        anonymous.get("/api-key/list").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn get_list_update_delete_over_http() {
    let mut c = client(ApiKeys::new().enable_metadata(true));
    let user_id = c.sign_up("ada@acme.dk").await;

    for name in ["a", "b", "c"] {
        let res = c
            .post(
                "/api-key/create",
                json!({ "name": name, "metadata": { "team": name } }),
            )
            .await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.json);
        assert_eq!(res.json["metadata"], json!({ "team": name }));
    }
    let res = c
        .post("/api-key/create", json!({ "metadata": "nope" }))
        .await;
    assert_eq!(res.json["code"], "INVALID_METADATA_TYPE");
    let res = c
        .post("/api-key/create", json!({ "name": "x".repeat(33) }))
        .await;
    assert_eq!(res.json["code"], "INVALID_NAME_LENGTH");

    let res = c
        .get("/api-key/list?sortBy=name&sortDirection=desc&limit=2")
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["total"], 3);
    assert_eq!(res.json["limit"], 2);
    let names: Vec<_> = res.json["apiKeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["name"].clone())
        .collect();
    assert_eq!(names, [json!("c"), json!("b")]);
    let id = res.json["apiKeys"][0]["id"].as_str().unwrap().to_owned();

    let res = c.get(&format!("/api-key/get?id={id}")).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json["name"], "c");

    let res = c
        .post(
            "/api-key/update",
            json!({ "keyId": id, "name": "renamed", "metadata": null, "expiresIn": 2 * 86_400 }),
        )
        .await;
    assert_eq!(res.json["name"], "renamed");
    assert_eq!(res.json["metadata"], Value::Null);
    assert!(res.json["expiresAt"].is_string());
    let res = c
        .post("/api-key/update", json!({ "keyId": id, "expiresIn": null }))
        .await;
    assert_eq!(res.json["expiresAt"], Value::Null);
    let res = c.post("/api-key/update", json!({ "keyId": id })).await;
    assert_eq!(res.json["code"], "NO_VALUES_TO_UPDATE");

    let res = c.post("/api-key/delete", json!({ "keyId": id })).await;
    assert_eq!(res.json, json!({ "success": true }));
    let res = c.get(&format!("/api-key/get?id={id}")).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(res.json["code"], "KEY_NOT_FOUND");

    let list = c
        .auth
        .api_keys()
        .list(ListApiKeysInput {
            user_id: Some(user_id.as_str().into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(list.total, 2);
    let first = list.api_keys[0].id.clone();
    let got = c
        .auth
        .api_keys()
        .get(GetApiKeyInput {
            id: first.clone(),
            user_id: Some(user_id.as_str().into()),
        })
        .await
        .unwrap();
    assert_eq!(got.name.as_deref(), Some("a"));
    let err = c
        .auth
        .api_keys()
        .get(GetApiKeyInput {
            id: first.clone(),
            user_id: Some("someone-else".into()),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), "KEY_NOT_FOUND");
    c.auth
        .api_keys()
        .delete(DeleteApiKeyInput {
            key_id: first,
            user_id: Some(user_id.as_str().into()),
        })
        .await
        .unwrap();
    assert_eq!(c.get("/api-key/list").await.json["total"], 1);

    let res = c
        .post("/api-key/verify", json!({ "key": "anything" }))
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND, "verify is server-only");
    let res = c
        .post("/api-key/delete-all-expired-api-keys", json!({}))
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND, "cleanup is server-only");
}

#[tokio::test]
async fn metadata_is_off_by_default() {
    let mut c = client(ApiKeys::new());
    c.sign_up("ada@acme.dk").await;
    let res = c
        .post("/api-key/create", json!({ "metadata": { "a": 1 } }))
        .await;
    assert_eq!(res.json["code"], "METADATA_DISABLED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_verifies_spend_remaining_exactly_once() {
    let mut c = client(ApiKeys::new());
    let user_id = c.sign_up("ada@acme.dk").await;
    let auth = c.auth.clone();
    let created = server_key(
        &auth,
        &user_id,
        CreateApiKeyInput {
            remaining: Some(7),
            rate_limit_enabled: Some(false),
            ..Default::default()
        },
    )
    .await;

    let tasks: Vec<_> = (0..64)
        .map(|_| {
            let auth = auth.clone();
            let key = created.key.clone();
            tokio::spawn(async move { auth.api_keys().verify(&key, None).await.unwrap() })
        })
        .collect();
    let mut valid = 0;
    for task in tasks {
        let out = task.await.unwrap();
        if out.valid {
            valid += 1;
        } else {
            let code = out.error.unwrap().code;
            assert!(
                code == "USAGE_EXCEEDED" || code == "INVALID_API_KEY",
                "{code}"
            );
        }
    }
    assert_eq!(valid, 7);

    let limited = server_key(
        &auth,
        &user_id,
        CreateApiKeyInput {
            rate_limit_max: Some(5),
            rate_limit_time_window: Some(60_000),
            ..Default::default()
        },
    )
    .await;
    let tasks: Vec<_> = (0..64)
        .map(|_| {
            let auth = auth.clone();
            let key = limited.key.clone();
            tokio::spawn(async move { auth.api_keys().verify(&key, None).await.unwrap().valid })
        })
        .collect();
    let mut valid = 0;
    for task in tasks {
        valid += usize::from(task.await.unwrap());
    }
    assert_eq!(valid, 5);
    assert_eq!(
        row(&auth, &limited.api_key.id).await.unwrap().request_count,
        5
    );
}
