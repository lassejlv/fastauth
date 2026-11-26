//! FAST-45 security review (area: identity, prefix ATO): social sign-in. Each `sec_*` test
//! asserts the secure behaviour and fails on fastauth 0.5.0 (7cd9718); `guard_*` tests pass.
//!
//! Run: cargo +stable test -p fastauth-oauth --all-features --test security_fast45 -- --nocapture --test-threads=1
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use fastauth_core::crypto::{Argon2id, Secret};
use fastauth_core::plugin_prelude::*;
use fastauth_core::prelude::{EmailPassword, FastAuth, MemoryAdapter, RateLimit};
use fastauth_core::query::Db;
use fastauth_core::{Auth, plugins};
use fastauth_oauth::{AccountLinking, Github, Google, HttpClient, HttpClientError, Social};
use http::{Request, Response, header};
use serde_json::{Value as Json, json};
use url::Url;

const ORIGIN: &str = "http://localhost:3000";

#[derive(Clone, Default)]
struct MockHttp {
    routes: Arc<Mutex<HashMap<String, (u16, String)>>>,
}

impl MockHttp {
    fn respond(&self, url: &str, status: u16, body: Json) {
        self.routes
            .lock()
            .unwrap()
            .insert(url.to_owned(), (status, body.to_string()));
    }

    fn google_user(&self, sub: &str, email: &str, verified: bool) {
        self.google_token(json!({ "access_token": "ya29.google-access", "expires_in": 3599 }));
        self.respond(
            "https://openidconnect.googleapis.com/v1/userinfo",
            200,
            json!({ "sub": sub, "email": email, "email_verified": verified, "name": "Mallory" }),
        );
    }

    fn github_user(&self, id: u64, email: &str) {
        self.respond(
            "https://github.com/login/oauth/access_token",
            200,
            json!({ "access_token": "gho_github-access", "scope": "read:user,user:email", "token_type": "bearer" }),
        );
        self.respond(
            "https://api.github.com/user",
            200,
            json!({ "id": id, "login": "ada", "name": null, "email": null, "avatar_url": "https://avatars.example/ada" }),
        );
        self.respond(
            "https://api.github.com/user/emails",
            200,
            json!([{ "email": email, "primary": true, "verified": true, "visibility": "private" }]),
        );
    }

    fn google_token(&self, body: Json) {
        self.respond("https://oauth2.googleapis.com/token", 200, body);
    }
}

impl HttpClient for MockHttp {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpClientError> {
        let url = request.uri().to_string();
        let (status, body) = self
            .routes
            .lock()
            .unwrap()
            .get(&url)
            .cloned()
            .unwrap_or((404, r#"{"message":"Not Found"}"#.into()));
        let mut response = Response::new(Bytes::from(body));
        *response.status_mut() = http::StatusCode::from_u16(status).unwrap();
        Ok(response)
    }
}

type AppAuth = Auth<MemoryAdapter, (), plugins![Social]>;

fn app(linking: AccountLinking) -> (AppAuth, MockHttp) {
    let mock = MockHttp::default();
    let social = Social::with_http_client(mock.clone())
        .provider(Github::new("gh-id", "gh-secret"))
        .provider(Google::new("google-id", "google-secret"))
        .account_linking(linking);
    let auth = FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(ORIGIN)
        .trusted_origins(["https://app.acme.dk"])
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .plugin(social)
        .build()
        .expect("valid config");
    (auth, mock)
}

struct Client {
    auth: AppAuth,
    jar: HashMap<String, String>,
}

struct Res {
    status: http::StatusCode,
    headers: http::HeaderMap,
    json: Json,
}

impl Res {
    fn location(&self) -> &str {
        self.headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
    }
}

impl Client {
    fn new(auth: &AppAuth) -> Self {
        Self {
            auth: auth.clone(),
            jar: HashMap::new(),
        }
    }

    async fn send(&mut self, method: Method, path: &str, body: Option<Json>) -> Res {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("/api/auth{path}"))
            .header(header::ORIGIN, ORIGIN);
        if !self.jar.is_empty() {
            let cookies: Vec<String> = self.jar.iter().map(|(k, v)| format!("{k}={v}")).collect();
            builder = builder.header(header::COOKIE, cookies.join("; "));
        }
        let body = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
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
        Res {
            status: response.status(),
            headers: response.headers().clone(),
            json: serde_json::from_slice(response.body()).unwrap_or(Json::Null),
        }
    }

    async fn post(&mut self, path: &str, body: Json) -> Res {
        self.send(Method::POST, path, Some(body)).await
    }

    async fn get(&mut self, path: &str) -> Res {
        self.send(Method::GET, path, None).await
    }

    async fn sign_up(&mut self, email: &str) {
        let res = self
            .post(
                "/sign-up/email",
                json!({ "email": email, "password": "correct horse", "name": "Ada" }),
            )
            .await;
        assert_eq!(res.status, 200, "{}", res.json);
    }

    async fn start(&mut self, path: &str, body: Json) -> Url {
        let res = self.post(path, body).await;
        assert_eq!(res.status, 200, "{}", res.json);
        Url::parse(res.json["url"].as_str().unwrap()).unwrap()
    }

    async fn callback(&mut self, provider: &str, url: &Url) -> Res {
        let state = url
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.into_owned())
            .unwrap();
        self.get(&format!("/callback/{provider}?code=the-code&state={state}"))
            .await
    }
}

async fn linked_providers(auth: &AppAuth, user_email: &str) -> Vec<String> {
    let db = Db::new(auth.adapter(), auth.schema());
    let user = db
        .find::<User>(User::EMAIL.eq(user_email))
        .one()
        .await
        .unwrap()
        .unwrap();
    db.find::<Account>(Account::USER_ID.eq(&user.id))
        .all()
        .await
        .unwrap()
        .into_iter()
        .map(|a| a.provider_id)
        .collect()
}

/// ATO-4: a social sign-in with a verified email claims an unverified user, but the claim only
/// deletes the password account. A provider link made before the proof stays. Mallory makes
/// the user through a Google account whose email says ada@acme.dk without being verified;
/// Ada then signs in with GitHub, which verifies the address; Mallory's Google account still
/// signs in to Ada's now verified user.
#[tokio::test]
async fn sec_social_claim_removes_provider_links_made_before_the_proof() {
    let (auth, mock) = app(AccountLinking::default());
    mock.google_user("mallory-google-sub", "ada@acme.dk", false);
    let mut mallory = Client::new(&auth);
    let url = mallory
        .start("/sign-in/social", json!({ "provider": "google" }))
        .await;
    mallory.callback("google", &url).await;
    let session = mallory.get("/get-session").await.json;
    assert_eq!(session["user"]["email"], "ada@acme.dk", "{session}");
    assert_eq!(session["user"]["emailVerified"], false, "{session}");

    mock.github_user(42, "ada@acme.dk");
    let mut ada = Client::new(&auth);
    let url = ada
        .start("/sign-in/social", json!({ "provider": "github" }))
        .await;
    ada.callback("github", &url).await;
    let claimed = ada.get("/get-session").await.json;
    assert_eq!(claimed["user"]["id"], session["user"]["id"], "{claimed}");
    assert_eq!(claimed["user"]["emailVerified"], true, "{claimed}");
    assert!(
        mallory.get("/get-session").await.json.is_null(),
        "the claim ended Mallory's session"
    );

    let mut again = Client::new(&auth);
    let url = again
        .start("/sign-in/social", json!({ "provider": "google" }))
        .await;
    let res = again.callback("google", &url).await;
    let session = again.get("/get-session").await.json;
    let providers = linked_providers(&auth, "ada@acme.dk").await;
    println!(
        "[Mallory signs in with Google after Ada's claim] location={} session={session}",
        res.location()
    );
    println!("[accounts on Ada's user after the claim] {providers:?}");
    assert!(
        session.is_null() && !providers.contains(&"google".to_owned()),
        "Mallory's Google link survived the claim ({providers:?}) and signs her in as {}",
        session["user"]["email"]
    );
}

/// The claim does remove what it says it removes: the password and the sessions.
#[tokio::test]
async fn guard_social_claim_removes_the_password_and_sessions() {
    let (auth, mock) = app(AccountLinking::default());
    let mut mallory = Client::new(&auth);
    mallory.sign_up("ada@acme.dk").await;
    mock.github_user(42, "ada@acme.dk");
    let mut ada = Client::new(&auth);
    let url = ada
        .start("/sign-in/social", json!({ "provider": "github" }))
        .await;
    ada.callback("github", &url).await;
    assert_eq!(
        ada.get("/get-session").await.json["user"]["emailVerified"],
        true
    );
    assert!(mallory.get("/get-session").await.json.is_null());
    assert_eq!(linked_providers(&auth, "ada@acme.dk").await, ["github"]);
    let res = Client::new(&auth)
        .post(
            "/sign-in/email",
            json!({ "email": "ada@acme.dk", "password": "correct horse" }),
        )
        .await;
    assert_eq!(res.status, 401, "{}", res.json);
}

/// A provider that doesn't vouch for the email never links to, or claims, an existing user.
#[tokio::test]
async fn guard_unverified_provider_email_never_links_to_an_existing_user() {
    let (auth, mock) = app(AccountLinking::default());
    Client::new(&auth).sign_up("ada@acme.dk").await;
    mock.google_user("mallory-google-sub", "ada@acme.dk", false);
    let mut mallory = Client::new(&auth);
    let url = mallory
        .start("/sign-in/social", json!({ "provider": "google" }))
        .await;
    let res = mallory.callback("google", &url).await;
    assert!(
        res.location().contains("error=account_not_linked"),
        "{}",
        res.location()
    );
    assert!(mallory.get("/get-session").await.json.is_null());
    assert_eq!(linked_providers(&auth, "ada@acme.dk").await, ["credential"]);
}
