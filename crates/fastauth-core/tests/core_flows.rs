mod common;

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::mail::AuthEmail;
use fastauth_core::prelude::*;
use http::{Method, Request, StatusCode, header};
use serde_json::json;

fn fast_hasher() -> EmailPassword {
    EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1))
}

fn auth_with(email_password: EmailPassword, mailer: MemoryMailer) -> Auth<MemoryAdapter> {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(email_password)
        .mailer(mailer)
        .rate_limit(RateLimit::disabled())
        .build()
        .expect("valid config")
}

fn auth() -> Auth<MemoryAdapter> {
    auth_with(fast_hasher(), MemoryMailer::new())
}

#[tokio::test]
async fn sign_up_get_session_sign_out() {
    let mut client = Client::new(auth());
    let res = client.sign_up("Lasse@Acme.dk", "correct horse").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["user"]["email"], "lasse@acme.dk");
    assert!(res.json["token"].as_str().unwrap().len() >= 43);
    assert!(res.json["user"].get("passwordHash").is_none());
    let cookie = res
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("fastauth.session_token="))
        .unwrap();
    assert!(
        cookie.contains("HttpOnly")
            && cookie.contains("SameSite=Lax")
            && !cookie.contains("Secure")
    );

    let session = client.get("/get-session").await;
    assert_eq!(session.json["user"]["email"], "lasse@acme.dk");
    assert_eq!(session.json["session"]["token"], res.json["token"]);

    let out = client.post("/sign-out", json!({})).await;
    assert_eq!(out.json, json!({ "success": true }));
    assert_eq!(
        client.get("/get-session").await.json,
        serde_json::Value::Null
    );
}

#[tokio::test]
async fn wrong_password_and_unknown_email_look_the_same() {
    let mut client = Client::new(auth());
    client.sign_up("a@acme.dk", "correct horse").await;
    client.jar.clear();
    let wrong = client
        .post(
            "/sign-in/email",
            json!({ "email": "a@acme.dk", "password": "nope nope" }),
        )
        .await;
    let unknown = client
        .post(
            "/sign-in/email",
            json!({ "email": "b@acme.dk", "password": "nope nope" }),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.json, unknown.json);
    assert_eq!(wrong.json["code"], "INVALID_EMAIL_OR_PASSWORD");

    let ok = client
        .post(
            "/sign-in/email",
            json!({ "email": "A@acme.dk ", "password": "correct horse" }),
        )
        .await;
    assert_eq!(ok.status, StatusCode::OK);
    assert_eq!(ok.json["redirect"], false);
}

#[tokio::test]
async fn duplicate_sign_up_is_422_and_short_password_is_400() {
    let mut client = Client::new(auth());
    client.sign_up("a@acme.dk", "correct horse").await;
    let again = client.sign_up("a@acme.dk", "correct horse").await;
    assert_eq!(again.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(again.json["code"], "USER_ALREADY_EXISTS");
    let short = client.sign_up("b@acme.dk", "short").await;
    assert_eq!(short.json["code"], "PASSWORD_TOO_SHORT");
}

#[tokio::test]
async fn cookie_requests_from_untrusted_origins_are_rejected() {
    let auth = auth();
    let mut client = Client::new(auth.clone());
    client.sign_up("a@acme.dk", "correct horse").await;
    let cookies = client.cookie_header().unwrap();
    for origin in [Some("https://evil.example"), None] {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/api/auth/sign-out")
            .header(header::COOKIE, &cookies);
        if let Some(origin) = origin {
            req = req.header(header::ORIGIN, origin);
        }
        let res = auth.handle(req.body(Default::default()).unwrap()).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "origin {origin:?}");
    }
    assert_eq!(
        client.get("/get-session").await.json["user"]["email"],
        "a@acme.dk"
    );
}

#[tokio::test]
async fn sign_in_is_rate_limited_per_client() {
    let auth = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(fast_hasher())
        .build()
        .unwrap();
    let mut client = Client::new(auth);
    let mut statuses = Vec::new();
    for _ in 0..4 {
        statuses.push(
            client
                .post(
                    "/sign-in/email",
                    json!({ "email": "x@acme.dk", "password": "whatever1" }),
                )
                .await
                .status,
        );
    }
    assert_eq!(statuses[3], StatusCode::TOO_MANY_REQUESTS);
    assert!(statuses[..3].iter().all(|s| *s == StatusCode::UNAUTHORIZED));
}

#[tokio::test]
async fn email_verification_gate() {
    let mailer = MemoryMailer::new();
    let mut client = Client::new(auth_with(
        fast_hasher().require_email_verification(true),
        mailer.clone(),
    ));
    let res = client.sign_up("v@acme.dk", "correct horse").await;
    assert_eq!(res.json["token"], serde_json::Value::Null);
    assert!(client.jar.is_empty());

    let blocked = client
        .post(
            "/sign-in/email",
            json!({ "email": "v@acme.dk", "password": "correct horse" }),
        )
        .await;
    assert_eq!(blocked.json["code"], "EMAIL_NOT_VERIFIED");

    let Some(AuthEmail::VerifyEmail(email)) = mailer.sent().into_iter().next() else {
        panic!("no verification email")
    };
    assert!(
        email
            .url
            .starts_with("http://localhost:3000/api/auth/verify-email?token=")
    );
    let verified = client
        .get(&format!(
            "/verify-email?token={}&callbackURL=%2Fwelcome",
            email.token
        ))
        .await;
    assert_eq!(verified.status, StatusCode::FOUND);
    assert_eq!(verified.location(), Some("/welcome"));
    let reused = client
        .get(&format!("/verify-email?token={}", email.token))
        .await;
    assert_eq!(reused.json["code"], "INVALID_TOKEN");

    let ok = client
        .post(
            "/sign-in/email",
            json!({ "email": "v@acme.dk", "password": "correct horse" }),
        )
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.json);
    assert_eq!(ok.json["user"]["emailVerified"], true);
}

#[tokio::test]
async fn sign_up_with_existing_email_does_not_reveal_it_when_verification_is_required() {
    let mailer = MemoryMailer::new();
    let mut client = Client::new(auth_with(
        fast_hasher().require_email_verification(true),
        mailer,
    ));
    let first = client.sign_up("v@acme.dk", "correct horse").await;
    let second = client.sign_up("v@acme.dk", "correct horse").await;
    assert_eq!(first.status, second.status);
    assert_eq!(second.json["user"]["email"], "v@acme.dk");
}

#[tokio::test]
async fn password_reset_flow() {
    let mailer = MemoryMailer::new();
    let mut client = Client::new(auth_with(
        fast_hasher().revoke_sessions_on_password_reset(true),
        mailer.clone(),
    ));
    client.sign_up("r@acme.dk", "correct horse").await;
    let res = client
        .post(
            "/request-password-reset",
            json!({ "email": "r@acme.dk", "redirectTo": "/reset" }),
        )
        .await;
    assert_eq!(res.json["status"], true);
    let unknown = client
        .post(
            "/request-password-reset",
            json!({ "email": "nobody@acme.dk" }),
        )
        .await;
    assert_eq!(unknown.json, res.json, "unknown emails get the same answer");

    let Some(AuthEmail::ResetPassword(email)) = mailer.last() else {
        panic!("no reset email")
    };
    let link = client
        .get(&format!(
            "/reset-password/{}?callbackURL=%2Freset",
            email.token
        ))
        .await;
    assert_eq!(
        link.location().unwrap(),
        format!("/reset?token={}", email.token)
    );

    let reset = client
        .post(
            "/reset-password",
            json!({ "newPassword": "battery staple", "token": email.token }),
        )
        .await;
    assert_eq!(reset.json["status"], true, "{}", reset.json);
    assert_eq!(
        client.get("/get-session").await.json,
        serde_json::Value::Null,
        "sessions were revoked"
    );

    let old = client
        .post(
            "/sign-in/email",
            json!({ "email": "r@acme.dk", "password": "correct horse" }),
        )
        .await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED);
    let new = client
        .post(
            "/sign-in/email",
            json!({ "email": "r@acme.dk", "password": "battery staple" }),
        )
        .await;
    assert_eq!(new.status, StatusCode::OK);
    let replay = client
        .post(
            "/reset-password",
            json!({ "newPassword": "another one", "token": email.token }),
        )
        .await;
    assert_eq!(replay.json["code"], "INVALID_TOKEN");
}

#[tokio::test]
async fn callback_urls_must_be_trusted() {
    let mut client = Client::new(auth());
    client.sign_up("a@acme.dk", "correct horse").await;
    let res = client
        .post("/sign-in/email", json!({ "email": "a@acme.dk", "password": "correct horse", "callbackURL": "https://evil.example/" }))
        .await;
    assert_eq!(res.json["code"], "INVALID_CALLBACK_URL");
    let ok = client
        .post("/sign-in/email", json!({ "email": "a@acme.dk", "password": "correct horse", "callbackURL": "http://localhost:3000/app" }))
        .await;
    assert_eq!(ok.status, StatusCode::FOUND);
}

#[tokio::test]
async fn sessions_can_be_listed_and_revoked() {
    let auth = auth();
    let mut laptop = Client::new(auth.clone());
    laptop.sign_up("s@acme.dk", "correct horse").await;
    let mut phone = Client::new(auth.clone());
    let phone_token = phone
        .post(
            "/sign-in/email",
            json!({ "email": "s@acme.dk", "password": "correct horse" }),
        )
        .await
        .json["token"]
        .as_str()
        .unwrap()
        .to_owned();

    let listed = laptop.get("/list-sessions").await;
    assert_eq!(listed.json.as_array().unwrap().len(), 2);
    assert!(listed.json[0].get("token").is_none() && listed.json[0].get("tokenHash").is_none());

    let revoked = laptop
        .post("/revoke-session", json!({ "token": phone_token }))
        .await;
    assert_eq!(revoked.json["status"], true);
    assert_eq!(
        phone.get("/get-session").await.json,
        serde_json::Value::Null
    );
    assert_eq!(
        laptop
            .get("/list-sessions")
            .await
            .json
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn change_password_and_update_user() {
    let mut client = Client::new(auth());
    client.sign_up("c@acme.dk", "correct horse").await;
    let wrong = client
        .post(
            "/change-password",
            json!({ "currentPassword": "nope nope", "newPassword": "battery staple" }),
        )
        .await;
    assert_eq!(wrong.json["code"], "INVALID_PASSWORD");
    let ok = client
        .post(
            "/change-password",
            json!({ "currentPassword": "correct horse", "newPassword": "battery staple" }),
        )
        .await;
    assert_eq!(ok.status, StatusCode::OK);

    let updated = client
        .post(
            "/update-user",
            json!({ "name": "Lasse", "image": "https://img/x.png" }),
        )
        .await;
    assert_eq!(updated.json["status"], true);
    let session = client.get("/get-session").await;
    assert_eq!(session.json["user"]["name"], "Lasse");
    assert_eq!(session.json["user"]["image"], "https://img/x.png");
    let email = client
        .post("/update-user", json!({ "email": "x@acme.dk" }))
        .await;
    assert_eq!(email.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unauthenticated_requests_get_401_json() {
    let mut client = Client::new(auth());
    let res = client.get("/list-sessions").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json["code"], "UNAUTHORIZED");
    assert_eq!(client.get("/nope").await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        client.post("/get-session", json!({})).await.status,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn server_api_skips_http() {
    let auth = auth();
    let signed_up = auth
        .api()
        .sign_up_email(
            serde_json::from_value(
                json!({ "email": "api@acme.dk", "password": "correct horse", "name": "Api" }),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let token = signed_up.data.token.clone().unwrap();
    assert!(
        signed_up
            .set_cookies
            .iter()
            .any(|c| c.to_str().unwrap().starts_with("fastauth.session_token="))
    );

    let sessions = auth
        .api()
        .session_token(&token)
        .list_sessions()
        .await
        .unwrap();
    assert_eq!(sessions.data.len(), 1);
    let typed = auth.get_session_by_token(&token).await.unwrap().unwrap();
    assert_eq!(typed.user.email, "api@acme.dk");
    assert!(
        auth.api().list_sessions().await.is_err(),
        "no session, no access"
    );
}

#[tokio::test]
async fn cookie_cache_answers_without_the_database() {
    let auth = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(fast_hasher())
        .session(SessionConfig::default().cookie_cache(Duration::minutes(5)))
        .rate_limit(RateLimit::disabled())
        .build()
        .unwrap();
    let mut client = Client::new(auth.clone());
    client.sign_up("cache@acme.dk", "correct horse").await;
    client.get("/get-session").await;
    assert!(client.jar.contains_key("fastauth.session_data"));
    // Delete the session behind the cache's back: the cached answer still works until it expires.
    let token = client.get("/get-session").await.json["session"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let session = auth.get_session_by_token(&token).await.unwrap().unwrap();
    let deleted = fastauth_core::query::Db::new(auth.adapter(), auth.schema())
        .delete::<Session>(Session::ID.eq(&session.session.id))
        .await
        .unwrap();
    assert_eq!(deleted, 1);
    assert_eq!(
        client.get("/get-session").await.json["user"]["email"],
        "cache@acme.dk"
    );
    client.jar.remove("fastauth.session_data");
    assert_eq!(
        client.get("/get-session").await.json,
        serde_json::Value::Null
    );
}

#[tokio::test]
async fn sessions_refresh_after_update_age() {
    let auth = FastAuth::builder()
        .secret(secret())
        .base_url("https://acme.dk")
        .database(MemoryAdapter::new())
        .email_password(fast_hasher())
        .session(SessionConfig::default().update_age(Duration::ZERO))
        .trusted_origins(["http://localhost:3000"])
        .rate_limit(RateLimit::disabled())
        .build()
        .unwrap();
    let mut client = Client::new(auth);
    let res = client.sign_up("r@acme.dk", "correct horse").await;
    assert!(
        res.set_cookies()
            .iter()
            .all(|c| c.starts_with("__Secure-") && c.contains("; Secure"))
    );
    let refreshed = client.get("/get-session").await;
    assert!(
        refreshed
            .set_cookies()
            .iter()
            .any(|c| c.starts_with("__Secure-fastauth.session_token="))
    );
}

#[tokio::test]
async fn migrator_creates_then_has_nothing_to_do() {
    let auth = auth();
    let plan = auth.migrator().run().await.unwrap();
    assert!(plan.steps.len() >= 4, "{plan:?}");
    assert!(auth.migrator().plan().await.unwrap().is_empty());
}

#[test]
fn build_reports_every_problem() {
    let err = FastAuth::builder()
        .secret(Secret::from_bytes(b"short".to_vec()))
        .base_url("not a url")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().require_email_verification(true))
        .build()
        .unwrap_err();
    assert_eq!(err.problems.len(), 3, "{err}");
}
