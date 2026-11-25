mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use common::{Client, secret};
use fastauth_core::crypto::Argon2id;
use fastauth_core::prelude::*;
use fastauth_oauth::{Github, HttpClient, HttpClientError, Social};
use fastauth_plugin_admin::{Admin, AdminExt, BanUserInput};
use fastauth_plugin_two_factor::{TwoFactor, totp};
use http::{Request, Response};
use serde_json::{Value, json};
use url::Url;

const PASSWORD: &str = "correct horse";

/// GitHub, answering every user as `ada@acme.dk`.
#[derive(Clone, Default)]
struct MockGithub;

impl HttpClient for MockGithub {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpClientError> {
        let body = match request.uri().to_string().as_str() {
            "https://github.com/login/oauth/access_token" => {
                json!({ "access_token": "gho_token", "scope": "read:user,user:email", "token_type": "bearer" })
            }
            "https://api.github.com/user" => {
                json!({ "id": 7, "login": "ada", "name": "Ada", "email": null, "avatar_url": null })
            }
            "https://api.github.com/user/emails" => {
                json!([{ "email": "ada@acme.dk", "primary": true, "verified": true, "visibility": null }])
            }
            _ => json!({ "message": "Not Found" }),
        };
        Ok(Response::new(Bytes::from(body.to_string())))
    }
}

fn builder() -> fastauth_core::Builder<
    MemoryAdapter,
    (),
    fastauth_core::Nil,
    fastauth_core::Present,
    fastauth_core::Present,
> {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
}

/// Signs in with GitHub and returns where the callback redirected.
async fn github_sign_in<P: fastauth_core::PluginSet>(
    browser: &mut Client<MemoryAdapter, (), P>,
) -> String {
    let res = browser
        .post(
            "/sign-in/social",
            json!({ "provider": "github", "callbackURL": "/dashboard", "errorCallbackURL": "/error" }),
        )
        .await;
    assert_eq!(res.status, 200, "{}", res.json);
    let url = Url::parse(res.json["url"].as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    let res = browser
        .get(&format!("/callback/github?code=the-code&state={state}"))
        .await;
    assert_eq!(res.status, 302);
    res.location().unwrap().to_owned()
}

#[tokio::test]
async fn the_ban_gate_covers_social_sign_in() {
    let auth: Auth<MemoryAdapter, (), plugins![Admin, Social]> = builder()
        .plugin(Admin::new())
        .plugin(Social::with_http_client(MockGithub).provider(Github::new("id", "secret")))
        .build()
        .unwrap();
    let mut browser = Client::new(auth.clone());
    assert_eq!(github_sign_in(&mut browser).await, "/dashboard");
    let user = browser.get("/get-session").await.json["user"].clone();
    assert_eq!(user["role"], "user");
    let id = Id::from(user["id"].as_str().unwrap());

    auth.admin()
        .ban(BanUserInput::new(id.clone()).reason("bots"))
        .await
        .unwrap();
    assert_eq!(browser.get("/get-session").await.json, Value::Null);
    let mut browser = Client::new(auth.clone());
    assert_eq!(
        github_sign_in(&mut browser).await,
        "/error?error=BANNED_USER"
    );
    assert_eq!(browser.get("/get-session").await.json, Value::Null);

    auth.admin().unban(&id).await.unwrap();
    assert_eq!(github_sign_in(&mut browser).await, "/dashboard");
}

#[tokio::test]
async fn a_challenge_that_finishes_later_still_cant_sign_a_banned_user_in() {
    let auth: Auth<MemoryAdapter, (), plugins![TwoFactor, Admin]> = builder()
        .plugin(TwoFactor::new().skip_verification_on_enable(true))
        .plugin(Admin::new())
        .build()
        .unwrap();
    let mut browser = Client::new(auth.clone());
    let res = browser.sign_up("ada@acme.dk", PASSWORD).await;
    let id = Id::from(res.json["user"]["id"].as_str().unwrap());
    let res = browser
        .post("/two-factor/enable", json!({ "password": PASSWORD }))
        .await;
    assert_eq!(res.status, 200, "{}", res.json);
    let uri = res.json["totpURI"].as_str().unwrap().to_owned();
    let secret = base32_decode(
        uri.split(['?', '&'])
            .find_map(|p| p.strip_prefix("secret="))
            .unwrap(),
    );

    auth.admin().ban(BanUserInput::new(id)).await.unwrap();
    let mut browser = Client::new(auth.clone());
    let res = browser
        .post(
            "/sign-in/email",
            json!({ "email": "ada@acme.dk", "password": PASSWORD }),
        )
        .await;
    assert_eq!(
        res.json["twoFactorRedirect"], true,
        "two-factor's gate runs first"
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let res = browser
        .post(
            "/two-factor/verify-totp",
            json!({ "code": totp::totp(&secret, now, 30, 6) }),
        )
        .await;
    assert_eq!(res.status, 200, "{}", res.json);
    assert_eq!(
        browser.get("/get-session").await.json,
        Value::Null,
        "the session a banned user ends up with is dropped"
    );
}

fn base32_decode(input: &str) -> Vec<u8> {
    let mut bits = 0u64;
    let mut count = 0;
    let mut out = Vec::new();
    for c in input.bytes() {
        let value = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            .iter()
            .position(|&a| a == c)
            .expect("base32 character");
        bits = (bits << 5) | value as u64;
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    out
}
