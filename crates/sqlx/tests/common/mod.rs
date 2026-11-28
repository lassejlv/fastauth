#![allow(dead_code)]

use bytes::Bytes;
use fastauth_core::adapter::Adapter;
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};

async fn send<D: Adapter>(
    auth: &Auth<D>,
    method: Method,
    path: &str,
    body: Option<Value>,
    cookies: &str,
) -> (StatusCode, Value, String) {
    let mut request = Request::builder()
        .method(method)
        .uri(format!("/api/auth{path}"))
        .header(header::ORIGIN, "http://localhost:3000");
    if !cookies.is_empty() {
        request = request.header(header::COOKIE, cookies);
    }
    let body = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
    let response = auth.handle(request.body(body).unwrap()).await;
    let set_cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok()?.split(';').next().map(str::to_owned))
        .collect::<Vec<_>>()
        .join("; ");
    let json = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
    (response.status(), json, set_cookies)
}

/// Sign-up, sign-in and get-session over HTTP against `db` with ids from `ids`, after
/// running the migrator.
pub async fn http_flow<D: Adapter>(db: D, ids: IdStrategy) {
    let id_len = match ids {
        IdStrategy::Ulid => 26,
        IdStrategy::UuidV7 | IdStrategy::UuidV4 => 36,
        IdStrategy::Custom(_) => panic!("the sqlx flow runs the built-in strategies"),
    };
    let auth = FastAuth::builder()
        .secret(fastauth_core::crypto::Secret::from_bytes(vec![42u8; 32]))
        .base_url("http://localhost:3000")
        .database(db)
        .ids(ids)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .build()
        .expect("valid config");
    auth.migrator().run().await.expect("migrate");
    assert!(auth.migrator().plan().await.unwrap().is_empty());

    let credentials =
        json!({ "email": "Lasse@Acme.dk", "password": "correct horse", "name": "Lasse" });
    let (status, body, _) = send(
        &auth,
        Method::POST,
        "/sign-up/email",
        Some(credentials.clone()),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user"]["email"], "lasse@acme.dk");
    let user_id = body["user"]["id"].as_str().unwrap().to_owned();
    assert_eq!(user_id.len(), id_len, "{user_id}");

    let (status, body, _) =
        send(&auth, Method::POST, "/sign-up/email", Some(credentials), "").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL");

    let (status, body, cookies) = send(
        &auth,
        Method::POST,
        "/sign-in/email",
        Some(json!({ "email": "lasse@acme.dk", "password": "correct horse" })),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(cookies.contains("fastauth.session_token="), "{cookies}");

    let session_only = cookies
        .split("; ")
        .find(|c| c.starts_with("fastauth.session_token="))
        .unwrap()
        .to_owned();
    let (status, session, _) = send(&auth, Method::GET, "/get-session", None, &session_only).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["user"]["email"], "lasse@acme.dk");
    assert_eq!(session["user"]["name"], "Lasse");
    assert_eq!(session["session"]["token"], body["token"]);
    assert_eq!(session["user"]["id"], user_id.as_str());
    assert_eq!(session["session"]["userId"], user_id.as_str());
    assert_eq!(session["session"]["id"].as_str().unwrap().len(), id_len);

    let (_, signed_out, _) = send(
        &auth,
        Method::POST,
        "/sign-out",
        Some(json!({})),
        &session_only,
    )
    .await;
    assert_eq!(signed_out, json!({ "success": true }));
    let (_, session, _) = send(&auth, Method::GET, "/get-session", None, &session_only).await;
    assert_eq!(session, Value::Null);
}
