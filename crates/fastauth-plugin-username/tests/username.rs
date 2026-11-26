//! The username plugin through `Auth::handle` on the memory adapter.

mod common;

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::endpoint::Gate;
use fastauth_core::mail::MemoryMailer;
use fastauth_core::prelude::*;
use fastauth_core::routes::CreateUserInput;
use fastauth_plugin_username::{
    SignInUsernameInput, Username, UsernameExt, UsernameUser, ValidationOrder,
};
use http::{HeaderMap, StatusCode};
use serde_json::{Value, json};

type Plugins = plugins![Username];
type App = Client<MemoryAdapter, (), Plugins>;

fn build_with(plugin: Username, email_password: EmailPassword) -> Auth<MemoryAdapter, (), Plugins> {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(email_password.hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(plugin)
        .configure(|app| {
            app.sign_in_gate(|_, attempt| async move {
                Ok(if attempt.user.email.starts_with("pin") {
                    Gate::Challenge(json!({ "pinRequired": true }))
                } else {
                    Gate::Allow
                })
            });
        })
        .build()
        .expect("valid config")
}

fn build(plugin: Username) -> Auth<MemoryAdapter, (), Plugins> {
    build_with(plugin, EmailPassword::default())
}

async fn sign_up(app: &mut App, email: &str, extra: Value) -> common::Res {
    let mut body = json!({ "email": email, "password": "correct horse", "name": "Test" });
    body.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    app.post("/sign-up/email", body).await
}

fn assert_error(res: &common::Res, status: StatusCode, code: &str) {
    assert_eq!(res.status, status, "{}", res.json);
    assert_eq!(res.json["code"], code, "{}", res.json);
    assert!(res.json["message"].is_string(), "{}", res.json);
}

#[tokio::test]
async fn sign_up_stores_a_normalized_username_and_signs_in_with_it() {
    let auth = build(Username::new());
    let mut ada = Client::new(auth.clone());
    let res = sign_up(
        &mut ada,
        "ada@acme.dk",
        json!({ "username": "Ada_Lovelace" }),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["user"]["username"], "ada_lovelace");
    assert_eq!(res.json["user"]["displayUsername"], "Ada_Lovelace");

    let mut again = Client::new(auth.clone());
    let res = again
        .post(
            "/sign-in/username",
            json!({ "username": "ADA_lovelace", "password": "correct horse" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["redirect"], false);
    assert!(res.json["token"].as_str().is_some_and(|t| !t.is_empty()));
    assert_eq!(res.json["user"]["email"], "ada@acme.dk");
    assert_eq!(res.json["user"]["username"], "ada_lovelace");
    let session = again.get("/get-session").await.json;
    assert_eq!(session["user"]["username"], "ada_lovelace");
    assert_eq!(session["user"]["displayUsername"], "Ada_Lovelace");

    let user = auth
        .username()
        .find_user("Ada_Lovelace")
        .await
        .unwrap()
        .unwrap();
    let fields = user.fields::<UsernameUser>().unwrap();
    assert_eq!(fields.username.as_deref(), Some("ada_lovelace"));
    assert_eq!(fields.display_username.as_deref(), Some("Ada_Lovelace"));
}

#[tokio::test]
async fn sign_up_refuses_bad_and_taken_usernames() {
    let auth = build(Username::new());
    let mut app = Client::new(auth.clone());
    assert_eq!(
        sign_up(&mut app, "ada@acme.dk", json!({ "username": "ada" }))
            .await
            .status,
        StatusCode::OK
    );
    let mut app = Client::new(auth.clone());
    let taken = sign_up(&mut app, "other@acme.dk", json!({ "username": "ADA" })).await;
    assert_error(&taken, StatusCode::BAD_REQUEST, "USERNAME_IS_ALREADY_TAKEN");
    assert_eq!(
        taken.json["message"],
        "Username is already taken. Please try another."
    );
    let short = sign_up(&mut app, "other@acme.dk", json!({ "username": "ab" })).await;
    assert_error(&short, StatusCode::BAD_REQUEST, "USERNAME_TOO_SHORT");
    let long = sign_up(
        &mut app,
        "other@acme.dk",
        json!({ "username": "a".repeat(31) }),
    )
    .await;
    assert_error(&long, StatusCode::BAD_REQUEST, "USERNAME_TOO_LONG");
    let invalid = sign_up(
        &mut app,
        "other@acme.dk",
        json!({ "username": "ada lovelace" }),
    )
    .await;
    assert_error(&invalid, StatusCode::BAD_REQUEST, "INVALID_USERNAME");
    assert!(
        auth.api()
            .db()
            .find::<User>(User::EMAIL.eq("other@acme.dk"))
            .one()
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn display_username_alone_becomes_the_username_when_valid() {
    let auth = build(Username::new());
    let mut app = Client::new(auth.clone());
    let res = sign_up(
        &mut app,
        "ada@acme.dk",
        json!({ "displayUsername": "AdaL" }),
    )
    .await;
    assert_eq!(res.json["user"]["username"], "adal");
    assert_eq!(res.json["user"]["displayUsername"], "AdaL");

    let mut app = Client::new(auth.clone());
    let res = sign_up(
        &mut app,
        "bob@acme.dk",
        json!({ "displayUsername": "Bob the Builder" }),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["user"]["username"], Value::Null);
    assert_eq!(res.json["user"]["displayUsername"], "Bob the Builder");

    let mut app = Client::new(auth.clone());
    let res = sign_up(&mut app, "eve@acme.dk", json!({})).await;
    assert_eq!(res.json["user"]["username"], Value::Null);
    assert_eq!(res.json["user"]["displayUsername"], Value::Null);
}

#[tokio::test]
async fn sign_in_failures_match_better_auth() {
    let auth = build(Username::new());
    let mut app = Client::new(auth.clone());
    sign_up(&mut app, "ada@acme.dk", json!({ "username": "ada" })).await;
    let mut stranger = Client::new(auth.clone());
    let wrong = stranger
        .post(
            "/sign-in/username",
            json!({ "username": "ada", "password": "wrong password" }),
        )
        .await;
    assert_error(
        &wrong,
        StatusCode::UNAUTHORIZED,
        "INVALID_USERNAME_OR_PASSWORD",
    );
    assert_eq!(wrong.json["message"], "Invalid username or password");
    assert!(wrong.set_cookies().is_empty());
    let unknown = stranger
        .post(
            "/sign-in/username",
            json!({ "username": "nobody", "password": "correct horse" }),
        )
        .await;
    assert_error(
        &unknown,
        StatusCode::UNAUTHORIZED,
        "INVALID_USERNAME_OR_PASSWORD",
    );
    let empty = stranger
        .post(
            "/sign-in/username",
            json!({ "username": "", "password": "correct horse" }),
        )
        .await;
    assert_error(
        &empty,
        StatusCode::UNAUTHORIZED,
        "INVALID_USERNAME_OR_PASSWORD",
    );
    let invalid = stranger
        .post(
            "/sign-in/username",
            json!({ "username": "a b", "password": "correct horse" }),
        )
        .await;
    assert_error(
        &invalid,
        StatusCode::UNPROCESSABLE_ENTITY,
        "INVALID_USERNAME",
    );
    let short = stranger
        .post(
            "/sign-in/username",
            json!({ "username": "ab", "password": "correct horse" }),
        )
        .await;
    assert_error(
        &short,
        StatusCode::UNPROCESSABLE_ENTITY,
        "USERNAME_TOO_SHORT",
    );
    let long_password = stranger
        .post(
            "/sign-in/username",
            json!({ "username": "ada", "password": "x".repeat(200) }),
        )
        .await;
    assert_error(&long_password, StatusCode::BAD_REQUEST, "PASSWORD_TOO_LONG");
    let untrusted = stranger
        .post(
            "/sign-in/username",
            json!({ "username": "ada", "password": "correct horse", "callbackURL": "https://evil.dev" }),
        )
        .await;
    assert_error(&untrusted, StatusCode::FORBIDDEN, "INVALID_CALLBACK_URL");
    assert_eq!(stranger.get("/get-session").await.json, Value::Null);
}

#[tokio::test]
async fn sign_in_runs_gates_and_honours_remember_me_and_callback() {
    let auth = build(Username::new());
    let mut app = Client::new(auth.clone());
    sign_up(&mut app, "pin@acme.dk", json!({ "username": "pinned" })).await;
    sign_up(
        &mut Client::new(auth.clone()),
        "ada@acme.dk",
        json!({ "username": "ada" }),
    )
    .await;

    let mut fresh = Client::new(auth.clone());
    let challenged = fresh
        .post(
            "/sign-in/username",
            json!({ "username": "pinned", "password": "correct horse" }),
        )
        .await;
    assert_eq!(challenged.json, json!({ "pinRequired": true }));
    assert_eq!(fresh.get("/get-session").await.json, Value::Null);

    let mut browser = Client::new(auth.clone());
    let res = browser
        .post(
            "/sign-in/username",
            json!({ "username": "ada", "password": "correct horse", "rememberMe": false }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    let token_cookie = res
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("fastauth.session_token="))
        .unwrap();
    assert!(!token_cookie.contains("Max-Age"), "{token_cookie}");
    assert!(browser.jar.contains_key("fastauth.dont_remember"));

    let mut redirected = Client::new(auth.clone());
    let res = redirected
        .post(
            "/sign-in/username",
            json!({ "username": "ada", "password": "correct horse", "callbackURL": "/dashboard" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::FOUND);
    assert_eq!(res.location(), Some("/dashboard"));
    assert_eq!(
        redirected.get("/get-session").await.json["user"]["username"],
        "ada"
    );
}

#[tokio::test]
async fn unverified_email_is_refused_when_verification_is_required() {
    let mailer = MemoryMailer::new();
    let auth: Auth<MemoryAdapter, (), Plugins> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(
            EmailPassword::default()
                .hasher(Argon2id::with_params(1024, 1, 1))
                .require_email_verification(true),
        )
        .rate_limit(RateLimit::disabled())
        .mailer(mailer.clone())
        .plugin(Username::new())
        .build()
        .unwrap();
    auth.api()
        .create_user(CreateUserInput {
            email: "ada@acme.dk".into(),
            name: "Ada".into(),
            password: Some("correct horse".into()),
            fields: json!({ "username": "ada" }).as_object().unwrap().clone(),
        })
        .await
        .unwrap();
    let mut app = Client::new(auth.clone());
    let res = app
        .post(
            "/sign-in/username",
            json!({ "username": "ada", "password": "correct horse" }),
        )
        .await;
    assert_error(&res, StatusCode::FORBIDDEN, "EMAIL_NOT_VERIFIED");
    assert!(
        mailer
            .sent()
            .iter()
            .any(|email| matches!(email, AuthEmail::VerifyEmail(v) if v.to == "ada@acme.dk"))
    );
}

#[tokio::test]
async fn is_username_available() {
    let auth = build(Username::new());
    sign_up(
        &mut Client::new(auth.clone()),
        "ada@acme.dk",
        json!({ "username": "ada" }),
    )
    .await;
    let mut app = Client::new(auth.clone());
    let taken = app
        .post("/is-username-available", json!({ "username": "ADA" }))
        .await;
    assert_eq!(taken.json, json!({ "available": false }));
    let free = app
        .post("/is-username-available", json!({ "username": "grace" }))
        .await;
    assert_eq!(free.json, json!({ "available": true }));
    let short = app
        .post("/is-username-available", json!({ "username": "ab" }))
        .await;
    assert_error(
        &short,
        StatusCode::UNPROCESSABLE_ENTITY,
        "USERNAME_TOO_SHORT",
    );
    let empty = app
        .post("/is-username-available", json!({ "username": "" }))
        .await;
    assert_error(&empty, StatusCode::UNPROCESSABLE_ENTITY, "INVALID_USERNAME");
    assert!(
        !auth
            .username()
            .is_available("Ada")
            .await
            .unwrap()
            .data
            .available
    );
}

#[tokio::test]
async fn update_user_changes_and_guards_the_username() {
    let auth = build(Username::new());
    sign_up(
        &mut Client::new(auth.clone()),
        "bob@acme.dk",
        json!({ "username": "bob" }),
    )
    .await;
    let mut ada = Client::new(auth.clone());
    sign_up(&mut ada, "ada@acme.dk", json!({ "username": "ada" })).await;

    let res = ada
        .post("/update-user", json!({ "username": "Countess" }))
        .await;
    assert_eq!(res.json, json!({ "status": true }));
    let user = ada.get("/get-session").await.json["user"].clone();
    assert_eq!(user["username"], "countess");
    assert_eq!(user["displayUsername"], "ada", "display name stays");

    let same = ada
        .post("/update-user", json!({ "username": "COUNTESS" }))
        .await;
    assert_eq!(same.status, StatusCode::OK, "{}", same.json);
    let taken = ada.post("/update-user", json!({ "username": "Bob" })).await;
    assert_error(&taken, StatusCode::BAD_REQUEST, "USERNAME_IS_ALREADY_TAKEN");
    let bad = ada
        .post("/update-user", json!({ "username": "no spaces" }))
        .await;
    assert_error(&bad, StatusCode::BAD_REQUEST, "INVALID_USERNAME");

    let res = ada
        .post("/update-user", json!({ "displayUsername": "The Countess" }))
        .await;
    assert_eq!(res.status, StatusCode::OK);
    let user = ada.get("/get-session").await.json["user"].clone();
    assert_eq!(user["displayUsername"], "The Countess");
    assert_eq!(user["username"], "countess");
}

#[tokio::test]
async fn immutable_usernames_can_be_set_once() {
    let auth = build(Username::new().immutable_username(true));
    let mut ada = Client::new(auth.clone());
    sign_up(&mut ada, "ada@acme.dk", json!({})).await;
    let first = ada.post("/update-user", json!({ "username": "ada" })).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.json);
    let res = ada
        .post("/update-user", json!({ "username": "countess" }))
        .await;
    assert_error(&res, StatusCode::BAD_REQUEST, "USERNAME_IS_IMMUTABLE");
    assert_eq!(res.json["message"], "Username cannot be updated");
    let same = ada.post("/update-user", json!({ "username": "ADA" })).await;
    assert_eq!(same.status, StatusCode::OK, "{}", same.json);
}

#[tokio::test]
async fn options_change_length_validation_and_normalization() {
    let plugin = Username::new()
        .min_username_length(5)
        .max_username_length(8)
        .username_validator(|u| u.chars().all(|c| c.is_ascii_lowercase()))
        .display_username_validator(|d| !d.contains("admin"))
        .display_username_normalization(|d| d.trim().to_owned());
    let auth = build(plugin);
    let mut app = Client::new(auth.clone());
    assert_error(
        &sign_up(&mut app, "a@acme.dk", json!({ "username": "abcd" })).await,
        StatusCode::BAD_REQUEST,
        "USERNAME_TOO_SHORT",
    );
    assert_error(
        &sign_up(&mut app, "a@acme.dk", json!({ "username": "abcdefghi" })).await,
        StatusCode::BAD_REQUEST,
        "USERNAME_TOO_LONG",
    );
    assert_error(
        &sign_up(&mut app, "a@acme.dk", json!({ "username": "Grace" })).await,
        StatusCode::BAD_REQUEST,
        "INVALID_USERNAME",
    );
    assert_error(
        &sign_up(
            &mut app,
            "a@acme.dk",
            json!({ "username": "grace", "displayUsername": "admin" }),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "INVALID_DISPLAY_USERNAME",
    );
    let res = sign_up(
        &mut app,
        "a@acme.dk",
        json!({ "username": "grace", "displayUsername": "  Grace H  " }),
    )
    .await;
    assert_eq!(res.json["user"]["displayUsername"], "Grace H");

    let post = build(
        Username::new()
            .username_validator(|u| u.chars().all(|c| c.is_ascii_lowercase()))
            .username_validation_order(ValidationOrder::PostNormalization),
    );
    let mut app = Client::new(post.clone());
    let res = sign_up(&mut app, "a@acme.dk", json!({ "username": "Grace" })).await;
    assert_eq!(res.json["user"]["username"], "grace", "{}", res.json);

    let exact = build(Username::new().disable_username_normalization());
    let mut app = Client::new(exact.clone());
    let res = sign_up(&mut app, "a@acme.dk", json!({ "username": "Grace" })).await;
    assert_eq!(res.json["user"]["username"], "Grace");
    let mut other = Client::new(exact.clone());
    let res = other
        .post(
            "/sign-in/username",
            json!({ "username": "grace", "password": "correct horse" }),
        )
        .await;
    assert_error(
        &res,
        StatusCode::UNAUTHORIZED,
        "INVALID_USERNAME_OR_PASSWORD",
    );
    let res = sign_up(&mut other, "b@acme.dk", json!({ "username": "grace" })).await;
    assert_eq!(
        res.status,
        StatusCode::OK,
        "case differs, so it isn't taken"
    );

    let custom =
        build(Username::new().username_normalization(|u| u.replace('.', "_").to_lowercase()));
    let mut app = Client::new(custom.clone());
    let res = sign_up(&mut app, "a@acme.dk", json!({ "username": "Grace.H" })).await;
    assert_eq!(res.json["user"]["username"], "grace_h");
}

#[tokio::test]
async fn server_side_user_creation_is_checked_and_normalized() {
    let auth = build(Username::new());
    let input = |email: &str, username: &str| CreateUserInput {
        email: email.into(),
        name: "Ada".into(),
        password: Some("correct horse".into()),
        fields: json!({ "username": username }).as_object().unwrap().clone(),
    };
    let user = auth
        .api()
        .create_user(input("ada@acme.dk", "Ada"))
        .await
        .unwrap();
    let fields = user.fields::<UsernameUser>().unwrap();
    assert_eq!(fields.username.as_deref(), Some("ada"));
    assert_eq!(fields.display_username.as_deref(), Some("Ada"));
    let err = auth
        .api()
        .create_user(input("b@acme.dk", "ADA"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "USERNAME_IS_ALREADY_TAKEN");
    let err = auth
        .api()
        .create_user(input("b@acme.dk", "x"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "USERNAME_TOO_SHORT");

    let res = auth
        .username()
        .sign_in(
            &HeaderMap::new(),
            SignInUsernameInput {
                username: "ADA".into(),
                password: "correct horse".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(!res.set_cookies.is_empty());
}
