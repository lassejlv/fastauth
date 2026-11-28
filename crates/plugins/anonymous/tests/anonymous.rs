//! The anonymous plugin through `Auth::handle` on the memory adapter.

mod common;

use std::sync::{Arc, Mutex};

use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_core::session::UserView;
use fastauth_plugin_anonymous::{
    Anonymous, AnonymousExt, AnonymousUser, LinkAccount, SignInAnonymousOutput,
};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde_json::{Value, json};

type Plugins = plugins![Anonymous];
type App = Client<MemoryAdapter, (), Plugins>;

fn build(plugin: Anonymous) -> Auth<MemoryAdapter, (), Plugins> {
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

/// Every `on_link_account` call as (anonymous user id, new user id).
type Links = Arc<Mutex<Vec<(String, String)>>>;

fn recorder() -> (Links, Anonymous) {
    let links = Arc::new(Mutex::new(Vec::new()));
    let seen = links.clone();
    let plugin = Anonymous::new().on_link_account(move |link: LinkAccount| {
        let seen = seen.clone();
        async move {
            seen.lock().unwrap().push((
                link.anonymous_user.user.id.to_string(),
                link.new_user.user.id.to_string(),
            ));
            Ok(())
        }
    });
    (links, plugin)
}

async fn user_exists(auth: &Auth<MemoryAdapter, (), Plugins>, id: &str) -> bool {
    auth.api()
        .db()
        .find::<User>(User::ID.eq(Id::from(id)))
        .one()
        .await
        .unwrap()
        .is_some()
}

async fn sign_in_anonymously(app: &mut App) -> Value {
    let res = app.post("/sign-in/anonymous", json!({})).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    res.json
}

fn assert_error(res: &common::Res, status: StatusCode, code: &str) {
    assert_eq!(res.status, status, "{}", res.json);
    assert_eq!(res.json["code"], code, "{}", res.json);
    assert!(res.json["message"].is_string());
}

#[tokio::test]
async fn sign_in_creates_an_anonymous_user_with_a_placeholder_email() {
    let auth = build(Anonymous::new());
    let mut app = Client::new(auth.clone());
    let res = sign_in_anonymously(&mut app).await;
    assert!(res["token"].as_str().is_some_and(|t| !t.is_empty()));
    let user = &res["user"];
    assert_eq!(user["isAnonymous"], true);
    assert_eq!(user["name"], "Anonymous");
    assert_eq!(user["emailVerified"], false);
    let email = user["email"].as_str().unwrap();
    assert!(email.ends_with("@anonymous.placeholder.invalid"), "{email}");
    let session = app.get("/get-session").await.json;
    assert_eq!(session["user"]["isAnonymous"], true);
    assert_eq!(session["user"]["id"], user["id"]);

    let again = app.post("/sign-in/anonymous", json!({})).await;
    assert_error(
        &again,
        StatusCode::BAD_REQUEST,
        "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
    );
    assert_eq!(
        again.json["message"],
        "Anonymous users cannot sign in again anonymously"
    );
}

#[tokio::test]
async fn real_users_are_not_anonymous_and_cannot_claim_it() {
    let auth = build(Anonymous::new());
    let mut app = Client::new(auth.clone());
    let res = app.sign_up("ada@acme.dk", "correct horse").await;
    assert_eq!(res.json["user"]["isAnonymous"], false);
    let res = Client::new(auth.clone())
        .post(
            "/sign-up/email",
            json!({ "email": "eve@acme.dk", "password": "correct horse", "name": "Eve", "isAnonymous": true }),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.json);

    let res = app.post("/sign-in/anonymous", json!({})).await;
    assert_eq!(
        res.status,
        StatusCode::OK,
        "a real user may start an anonymous session"
    );
    assert_eq!(
        app.get("/get-session").await.json["user"]["isAnonymous"],
        true
    );
    let ada = auth
        .api()
        .db()
        .find::<User>(User::EMAIL.eq("ada@acme.dk"))
        .one()
        .await
        .unwrap();
    assert!(ada.is_some(), "the real user is never deleted");
}

#[tokio::test]
async fn signing_up_links_and_deletes_the_anonymous_user() {
    let (links, plugin) = recorder();
    let auth = build(plugin);
    let mut app = Client::new(auth.clone());
    let anonymous = sign_in_anonymously(&mut app).await["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let anonymous_token = app.jar["fastauth.session_token"].clone();

    let res = app.sign_up("ada@acme.dk", "correct horse").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let ada = res.json["user"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        *links.lock().unwrap(),
        vec![(anonymous.clone(), ada.clone())]
    );
    assert!(
        !user_exists(&auth, &anonymous).await,
        "anonymous user deleted"
    );
    let session = app.get("/get-session").await.json;
    assert_eq!(session["user"]["id"], ada);
    assert_eq!(session["user"]["isAnonymous"], false);

    let mut stale = Client::new(auth.clone());
    stale
        .jar
        .insert("fastauth.session_token".into(), anonymous_token);
    assert_eq!(stale.get("/get-session").await.json, Value::Null);
}

#[tokio::test]
async fn signing_in_to_an_existing_account_links_too() {
    let (links, plugin) = recorder();
    let auth = build(plugin);
    let ada = Client::new(auth.clone())
        .sign_up("ada@acme.dk", "correct horse")
        .await
        .json["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let mut app = Client::new(auth.clone());
    let anonymous = sign_in_anonymously(&mut app).await["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let res = app
        .post(
            "/sign-in/email",
            json!({ "email": "ada@acme.dk", "password": "correct horse" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(*links.lock().unwrap(), vec![(anonymous.clone(), ada)]);
    assert!(!user_exists(&auth, &anonymous).await);

    let res = app
        .post(
            "/sign-in/email",
            json!({ "email": "ada@acme.dk", "password": "correct horse" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(
        links.lock().unwrap().len(),
        1,
        "a real session links nothing"
    );
}

#[tokio::test]
async fn disable_delete_keeps_the_anonymous_user() {
    let links = Arc::new(Mutex::new(0));
    let seen = links.clone();
    let auth = build(
        Anonymous::new()
            .disable_delete_anonymous_user(true)
            .on_link_account(move |_| {
                let seen = seen.clone();
                async move {
                    *seen.lock().unwrap() += 1;
                    Ok(())
                }
            }),
    );
    let mut app = Client::new(auth.clone());
    let anonymous = sign_in_anonymously(&mut app).await["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    app.sign_up("ada@acme.dk", "correct horse").await;
    assert_eq!(*links.lock().unwrap(), 1);
    assert!(user_exists(&auth, &anonymous).await);

    let mut other = Client::new(auth.clone());
    sign_in_anonymously(&mut other).await;
    let res = other.post("/delete-anonymous-user", json!({})).await;
    assert_error(
        &res,
        StatusCode::BAD_REQUEST,
        "DELETE_ANONYMOUS_USER_DISABLED",
    );
}

#[tokio::test]
async fn a_failing_link_hook_fails_the_response_and_keeps_the_anonymous_user() {
    let auth = build(Anonymous::new().on_link_account(|_| async {
        Err(AuthError::new(
            StatusCode::CONFLICT,
            "CART_MERGE_FAILED",
            "cart merge failed",
        ))
    }));
    let mut app = Client::new(auth.clone());
    let anonymous = sign_in_anonymously(&mut app).await["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let res = app.sign_up("ada@acme.dk", "correct horse").await;
    assert_error(&res, StatusCode::CONFLICT, "CART_MERGE_FAILED");
    assert!(user_exists(&auth, &anonymous).await);
}

#[tokio::test]
async fn delete_anonymous_user() {
    let auth = build(Anonymous::new());
    let mut app = Client::new(auth.clone());
    let anonymous = sign_in_anonymously(&mut app).await["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let res = app.post("/delete-anonymous-user", json!({})).await;
    assert_eq!(res.json, json!({ "success": true }));
    assert!(!app.jar.contains_key("fastauth.session_token"));
    assert!(!user_exists(&auth, &anonymous).await);
    assert_eq!(app.get("/get-session").await.json, Value::Null);

    let res = app.post("/delete-anonymous-user", json!({})).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);

    let mut ada = Client::new(auth.clone());
    ada.sign_up("ada@acme.dk", "correct horse").await;
    let res = ada.post("/delete-anonymous-user", json!({})).await;
    assert_error(&res, StatusCode::FORBIDDEN, "USER_IS_NOT_ANONYMOUS");
    assert_eq!(res.json["message"], "User is not anonymous");
}

#[tokio::test]
async fn email_and_name_options() {
    let auth = build(
        Anonymous::new()
            .email_domain_name("guests.acme.dk")
            .generate_name(|| "Guest".to_owned()),
    );
    let mut app = Client::new(auth.clone());
    let user = sign_in_anonymously(&mut app).await["user"].clone();
    let email = user["email"].as_str().unwrap();
    assert!(
        email.starts_with("temp-") && email.ends_with("@guests.acme.dk"),
        "{email}"
    );
    assert_eq!(user["name"], "Guest");

    let counter = Arc::new(Mutex::new(0));
    let auth = build(Anonymous::new().generate_random_email(move || {
        let mut n = counter.lock().unwrap();
        *n += 1;
        format!("Guest-{n}@Acme.dk")
    }));
    let user = sign_in_anonymously(&mut Client::new(auth.clone())).await["user"].clone();
    assert_eq!(user["email"], "guest-1@acme.dk");

    let auth = build(Anonymous::new().generate_random_email(|| "not an email".to_owned()));
    let res = Client::new(auth.clone())
        .post("/sign-in/anonymous", json!({}))
        .await;
    assert_error(&res, StatusCode::BAD_REQUEST, "INVALID_EMAIL_FORMAT");
}

#[tokio::test]
async fn server_api() {
    let auth = build(Anonymous::new());
    let res = auth.anonymous().sign_in(&HeaderMap::new()).await.unwrap();
    let SignInAnonymousOutput::SignedIn { user, .. } = res.data else {
        panic!("signed in");
    };
    assert_eq!(user["isAnonymous"], true);
    let cookie = res
        .set_cookies
        .iter()
        .map(|c| c.to_str().unwrap().split(';').next().unwrap().to_owned())
        .collect::<Vec<_>>()
        .join("; ");
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
    let row = auth
        .api()
        .db()
        .find::<User>(AnonymousUser::IS_ANONYMOUS.eq(true))
        .one_row()
        .await
        .unwrap()
        .unwrap();
    assert!(fastauth_plugin_anonymous::is_anonymous(
        &UserView::from_row(row).unwrap()
    ));
    let res = auth.anonymous().delete_user(&headers).await.unwrap();
    assert!(res.data.success);
}
