//! The magic link flow through `Auth::handle` on the memory adapter.

mod common;

use common::{Client, auth_path, plugin_emails, secret};
use fastauth_core::crypto::{Argon2id, Hash};
use fastauth_core::endpoint::Gate;
use fastauth_core::mail::MemoryMailer;
use fastauth_core::models::Verification;
use fastauth_core::prelude::*;
use fastauth_core::query::Where;
use fastauth_plugin_magic_link::{
    MagicLink, MagicLinkExt, SignInMagicLinkInput, VerifyMagicLinkInput, VerifyMagicLinkOutput,
};
use http::{HeaderMap, StatusCode};
use serde_json::json;

type Plugins = plugins![MagicLink];
type App = Client<MemoryAdapter, (), Plugins>;

fn build(plugin: MagicLink, mailer: &MemoryMailer) -> Auth<MemoryAdapter, (), Plugins> {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .mailer(mailer.clone())
        .plugin(plugin)
        .configure(|app| {
            app.sign_in_gate(|_, attempt| async move {
                let email = attempt.user.email.clone();
                Ok(if email.starts_with("banned") {
                    Gate::Deny(AuthError::new(
                        StatusCode::FORBIDDEN,
                        "BANNED_USER",
                        "You have been banned",
                    ))
                } else if email.starts_with("pin") {
                    Gate::Challenge(
                        json!({ "twoFactorRedirect": true, "twoFactorMethods": ["totp", "otp"] }),
                    )
                } else {
                    Gate::Allow
                })
            });
        })
        .build()
        .expect("valid config")
}

fn setup(plugin: MagicLink) -> (App, MemoryMailer) {
    let mailer = MemoryMailer::new();
    (Client::new(build(plugin, &mailer)), mailer)
}

/// The path of the newest magic link, under the auth base path.
fn last_link(mailer: &MemoryMailer) -> String {
    let email = plugin_emails(mailer).pop().expect("a magic link was sent");
    assert_eq!(email.kind, "magic-link");
    assert_eq!(email.code, None);
    auth_path(email.url.as_deref().expect("the email has a link"))
}

fn token_of(link: &str) -> String {
    link.split(['?', '&'])
        .find_map(|pair| pair.strip_prefix("token="))
        .expect("the link has a token")
        .to_owned()
}

async fn request_link(client: &mut App, body: serde_json::Value) {
    let res = client.post("/sign-in/magic-link", body).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json, json!({ "status": true }));
}

#[tokio::test]
async fn first_link_signs_up_and_lands_on_the_new_user_callback() {
    let (mut client, mailer) = setup(MagicLink::new());
    request_link(
        &mut client,
        json!({
            "email": "Ada@Acme.dk",
            "name": "Ada",
            "callbackURL": "/dashboard",
            "newUserCallbackURL": "/welcome",
        }),
    )
    .await;
    let email = plugin_emails(&mailer).pop().unwrap();
    assert_eq!(email.to, "ada@acme.dk");
    let link = last_link(&mailer);
    assert!(link.starts_with("/magic-link/verify?token="), "{link}");
    assert!(link.contains("callbackURL=%2Fdashboard"), "{link}");
    assert!(link.contains("newUserCallbackURL=%2Fwelcome"), "{link}");

    let res = client.get(&link).await;
    assert_eq!(res.status, StatusCode::FOUND);
    assert_eq!(res.location(), Some("http://localhost:3000/welcome"));
    let session = client.get("/get-session").await.json;
    assert_eq!(session["user"]["email"], "ada@acme.dk");
    assert_eq!(session["user"]["name"], "Ada");
    assert_eq!(session["user"]["emailVerified"], true);
}

#[tokio::test]
async fn existing_users_land_on_the_callback_and_links_work_once() {
    let (mut client, mailer) = setup(MagicLink::new());
    client.sign_up("ada@acme.dk", "correct horse").await;
    client.post("/sign-out", json!({})).await;
    request_link(&mut client, json!({ "email": "ada@acme.dk", "callbackURL": "/dashboard", "newUserCallbackURL": "/welcome" })).await;
    let link = last_link(&mailer);

    let res = client.get(&link).await;
    assert_eq!(res.location(), Some("http://localhost:3000/dashboard"));
    assert_eq!(
        client.get("/get-session").await.json["user"]["email"],
        "ada@acme.dk"
    );

    let mut other: App = Client::new(client.auth.clone());
    let again = other.get(&link).await;
    assert_eq!(again.status, StatusCode::FOUND);
    assert_eq!(
        again.location(),
        Some("http://localhost:3000/dashboard?error=INVALID_TOKEN")
    );
    assert!(other.jar.is_empty(), "a used link sets no session");
}

#[tokio::test]
async fn without_a_callback_the_link_answers_token_user_and_session() {
    let (mut client, mailer) = setup(MagicLink::new());
    request_link(&mut client, json!({ "email": "ada@acme.dk" })).await;
    let token = token_of(&last_link(&mailer));

    let res = client
        .get(&format!("/magic-link/verify?token={token}"))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert!(res.json["token"].as_str().is_some_and(|t| !t.is_empty()));
    assert_ne!(res.json["token"], json!(token), "the session token is new");
    assert_eq!(res.json["user"]["email"], "ada@acme.dk");
    assert_eq!(res.json["user"]["name"], "");
    assert_eq!(res.json["session"]["userId"], res.json["user"]["id"]);
    assert_eq!(res.json["session"]["token"], res.json["token"]);
}

#[tokio::test]
async fn the_email_link_defaults_its_callback_to_the_root() {
    let (mut client, mailer) = setup(MagicLink::new());
    request_link(&mut client, json!({ "email": "ada@acme.dk" })).await;
    let link = last_link(&mailer);
    assert!(link.ends_with("&callbackURL=%2F"), "{link}");
    let res = client.get(&link).await;
    assert_eq!(res.location(), Some("http://localhost:3000/"));
}

#[tokio::test]
async fn expired_and_unknown_tokens_redirect_with_invalid_token() {
    let (mut client, mailer) = setup(MagicLink::new().expires_in(Duration::ZERO));
    request_link(
        &mut client,
        json!({ "email": "ada@acme.dk", "errorCallbackURL": "/oops" }),
    )
    .await;
    let res = client.get(&last_link(&mailer)).await;
    assert_eq!(
        res.location(),
        Some("http://localhost:3000/oops?error=INVALID_TOKEN")
    );
    let unknown = client
        .get("/magic-link/verify?token=nope&callbackURL=http%3A%2F%2Flocalhost%3A3000%2Fapp")
        .await;
    assert_eq!(
        unknown.location(),
        Some("http://localhost:3000/app?error=INVALID_TOKEN")
    );
    let bare = client.get("/magic-link/verify?token=nope").await;
    assert_eq!(
        bare.location(),
        Some("http://localhost:3000/?error=INVALID_TOKEN")
    );
}

#[tokio::test]
async fn disabled_sign_up_only_signs_in_existing_users() {
    let (mut client, mailer) = setup(MagicLink::new().disable_sign_up(true));
    request_link(
        &mut client,
        json!({ "email": "new@acme.dk", "callbackURL": "/app" }),
    )
    .await;
    let res = client.get(&last_link(&mailer)).await;
    assert_eq!(
        res.location(),
        Some("http://localhost:3000/app?error=new_user_signup_disabled")
    );
    assert!(client.jar.is_empty());

    client.sign_up("ada@acme.dk", "correct horse").await;
    client.post("/sign-out", json!({})).await;
    request_link(
        &mut client,
        json!({ "email": "ada@acme.dk", "callbackURL": "/app" }),
    )
    .await;
    let res = client.get(&last_link(&mailer)).await;
    assert_eq!(res.location(), Some("http://localhost:3000/app"));
}

#[tokio::test]
async fn untrusted_urls_are_refused() {
    let (mut client, mailer) = setup(MagicLink::new());
    for (field, code) in [
        ("callbackURL", "INVALID_CALLBACK_URL"),
        ("errorCallbackURL", "INVALID_ERROR_CALLBACK_URL"),
        ("newUserCallbackURL", "INVALID_NEW_USER_CALLBACK_URL"),
    ] {
        let res = client
            .post(
                "/sign-in/magic-link",
                json!({ "email": "ada@acme.dk", field: "https://evil.example/steal" }),
            )
            .await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{field}");
        assert_eq!(res.json["code"], code);
        let res = client
            .get(&format!(
                "/magic-link/verify?token=x&{field}=https%3A%2F%2Fevil.example"
            ))
            .await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{field}");
        assert_eq!(res.json["code"], code);
    }
    let protocol_relative = client
        .post(
            "/sign-in/magic-link",
            json!({ "email": "ada@acme.dk", "callbackURL": "//evil.example" }),
        )
        .await;
    assert_eq!(protocol_relative.status, StatusCode::FORBIDDEN);
    assert!(plugin_emails(&mailer).is_empty());
}

#[tokio::test]
async fn invalid_emails_are_refused() {
    let (mut client, mailer) = setup(MagicLink::new());
    let res = client
        .post("/sign-in/magic-link", json!({ "email": "not-an-email" }))
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json["code"], "INVALID_EMAIL");
    assert!(plugin_emails(&mailer).is_empty());
}

#[tokio::test]
async fn the_token_is_stored_hashed_and_never_returned() {
    let (mut client, mailer) = setup(MagicLink::new());
    let res = client
        .post(
            "/sign-in/magic-link",
            json!({ "email": "ada@acme.dk", "name": "Ada" }),
        )
        .await;
    assert_eq!(res.json, json!({ "status": true }));
    let token = token_of(&last_link(&mailer));
    for (_, value) in res.headers.iter() {
        assert!(!value.to_str().unwrap().contains(&token));
    }

    let rows = client
        .auth
        .api()
        .db()
        .find::<Verification>(Where::all())
        .all()
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.identifier, "magic-link");
    assert_eq!(row.value_hash, Hash::sha256(&token));
    assert!(!row.data.as_deref().unwrap().contains(&token));
    assert!(row.expires_at - row.created_at <= Duration::seconds(300));

    client.get(&last_link(&mailer)).await;
    let left = client
        .auth
        .api()
        .db()
        .count::<Verification>(Where::all())
        .await
        .unwrap();
    assert_eq!(left, 0, "verifying consumes the token");
}

#[tokio::test]
async fn other_verification_tokens_are_not_magic_links() {
    let (mut client, mailer) = setup(MagicLink::new());
    client.sign_up("ada@acme.dk", "correct horse").await;
    let Some(AuthEmail::VerifyEmail(verify)) = mailer.last() else {
        panic!("sign-up sends a verification email");
    };
    let mut stranger: App = Client::new(client.auth.clone());
    let res = stranger
        .get(&format!(
            "/magic-link/verify?token={}&callbackURL=%2Fapp",
            verify.token
        ))
        .await;
    assert_eq!(
        res.location(),
        Some("http://localhost:3000/app?error=INVALID_TOKEN")
    );
    assert!(stranger.jar.is_empty());
    let verified = stranger
        .get(&format!("/verify-email?token={}", verify.token))
        .await;
    assert_eq!(verified.json["status"], true, "the email token still works");
}

#[tokio::test]
async fn a_link_claims_an_unverified_user() {
    let mailer = MemoryMailer::new();
    let auth = build(MagicLink::new(), &mailer);
    let mut squatter: App = Client::new(auth.clone());
    squatter.sign_up("ada@acme.dk", "squatter password").await;
    assert_eq!(
        squatter.get("/get-session").await.json["user"]["emailVerified"],
        false
    );

    let mut ada: App = Client::new(auth.clone());
    request_link(
        &mut ada,
        json!({ "email": "ada@acme.dk", "callbackURL": "/app" }),
    )
    .await;
    let res = ada.get(&last_link(&mailer)).await;
    assert_eq!(res.location(), Some("http://localhost:3000/app"));
    let session = ada.get("/get-session").await.json;
    assert_eq!(session["user"]["emailVerified"], true);

    assert_eq!(squatter.get("/get-session").await.json, json!(null));
    let password = squatter
        .post(
            "/sign-in/email",
            json!({ "email": "ada@acme.dk", "password": "squatter password" }),
        )
        .await;
    assert_eq!(password.status, StatusCode::UNAUTHORIZED);
    assert_eq!(password.json["code"], "INVALID_EMAIL_OR_PASSWORD");
}

#[tokio::test]
async fn sign_in_gates_run_for_magic_links() {
    let (mut client, mailer) = setup(MagicLink::new());
    request_link(
        &mut client,
        json!({ "email": "banned@acme.dk", "callbackURL": "/app", "errorCallbackURL": "/denied" }),
    )
    .await;
    let res = client.get(&last_link(&mailer)).await;
    assert_eq!(
        res.location(),
        Some(
            "http://localhost:3000/denied?error=BANNED_USER&error_description=You+have+been+banned"
        )
    );
    assert!(client.jar.is_empty());

    request_link(
        &mut client,
        json!({ "email": "pin@acme.dk", "callbackURL": "/app" }),
    )
    .await;
    let res = client.get(&last_link(&mailer)).await;
    assert_eq!(
        res.location(),
        Some("http://localhost:3000/app?twoFactorMethods=totp%2Cotp&twoFactorRedirect=true")
    );
    assert_eq!(client.get("/get-session").await.json, json!(null));

    request_link(&mut client, json!({ "email": "pin@acme.dk" })).await;
    let token = token_of(&last_link(&mailer));
    let res = client
        .get(&format!("/magic-link/verify?token={token}"))
        .await;
    assert_eq!(
        res.json,
        json!({ "twoFactorRedirect": true, "twoFactorMethods": ["totp", "otp"] })
    );
}

#[tokio::test]
async fn the_server_api_signs_in_without_http() {
    let mailer = MemoryMailer::new();
    let auth = build(MagicLink::new(), &mailer);
    let sent = auth
        .magic_link()
        .sign_in(SignInMagicLinkInput {
            email: "ada@acme.dk".into(),
            name: Some("Ada".into()),
            ..SignInMagicLinkInput::default()
        })
        .await
        .unwrap();
    assert!(sent.data.status);
    let token = token_of(&last_link(&mailer));
    let verified = auth
        .magic_link()
        .verify(
            &HeaderMap::new(),
            VerifyMagicLinkInput {
                token,
                ..VerifyMagicLinkInput::default()
            },
        )
        .await
        .unwrap();
    let VerifyMagicLinkOutput::SignedIn { user, .. } = verified.data else {
        panic!("expected a session, got {:?}", verified.data);
    };
    assert_eq!(user["name"], "Ada");
    assert!(!verified.set_cookies.is_empty());
}
