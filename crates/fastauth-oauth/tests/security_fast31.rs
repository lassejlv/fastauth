//! FAST-31 security review (area: tokens / social sign-in). Each `sec_*` test asserts the
//! secure behaviour and fails on fastauth 0.3.0.

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

/// Where a browser ends up when it follows `location` from the app's origin. WHATWG URL
/// parsing strips ASCII tab and newline before parsing, as browsers do.
fn followed(location: &str) -> Url {
    Url::parse(ORIGIN).unwrap().join(location).unwrap()
}

/// TOKENS-1: a root-relative callback URL with an ASCII tab after the first slash passes
/// `is_safe_redirect`, is stored in the OAuth state, and comes back as the `Location` of the
/// callback. Browsers strip the tab, read `//evil.example`, and leave the site.
#[tokio::test]
async fn sec_relative_callback_url_with_tab_is_refused() {
    let (auth, mock) = app(AccountLinking::default());
    mock.google_user("google-ada", "ada@acme.dk", true);
    let mut browser = Client::new(&auth);

    let payload = "/\t/evil.example/phish";
    let res = browser
        .post(
            "/sign-in/social",
            json!({ "provider": "google", "callbackURL": payload }),
        )
        .await;
    if res.status == 200 {
        let url = Url::parse(res.json["url"].as_str().unwrap()).unwrap();
        let done = browser.callback("google", &url).await;
        println!(
            "callback answered {} Location: {:?}; a browser following it lands on {}",
            done.status,
            done.location(),
            followed(done.location())
        );
    }
    assert_eq!(
        res.status,
        403,
        "callbackURL {payload:?} must be refused; a browser resolves it to {}",
        followed(payload)
    );
    assert_eq!(res.json["code"], "INVALID_CALLBACK_URL");

    for payload in ["/\n/evil.example", "/\r/evil.example", "/%2f/evil.example"] {
        let res = browser
            .post(
                "/sign-in/social",
                json!({ "provider": "google", "errorCallbackURL": payload }),
            )
            .await;
        assert_eq!(res.status, 403, "errorCallbackURL {payload:?}");
    }
}

/// TOKENS-2a: `/link-social` attaches a provider identity whose email differs from the
/// signed-in user's. Better Auth refuses with `email_doesn't_match` unless
/// `allowDifferentEmails` is set.
#[tokio::test]
async fn sec_link_social_refuses_a_different_email() {
    let (auth, mock) = app(AccountLinking::default());
    mock.google_user("google-mallory", "mallory@evil.example", true);
    let mut victim = Client::new(&auth);
    victim.sign_up("ada@acme.dk").await;

    let url = victim
        .start(
            "/link-social",
            json!({ "provider": "google", "callbackURL": "/settings", "errorCallbackURL": "/oops" }),
        )
        .await;
    let res = victim.callback("google", &url).await;
    println!("link callback Location: {}", res.location());
    let providers = linked_providers(&auth, "ada@acme.dk").await;
    assert!(
        !providers.contains(&"google".to_owned()),
        "mallory@evil.example's Google account was linked to ada@acme.dk: {providers:?}"
    );
    let landed = followed(res.location());
    assert!(
        landed.path() == "/oops" && landed.query().is_some_and(|q| q.starts_with("error=")),
        "{}",
        res.location()
    );
}

/// TOKENS-2b: `/link-social` attaches a provider identity whose email the provider does not
/// vouch for. Better Auth refuses with `unable_to_link_account` unless the provider is trusted.
#[tokio::test]
async fn sec_link_social_refuses_an_unverified_provider_email() {
    let (auth, mock) = app(AccountLinking::default());
    mock.google_user("google-unverified", "ada@acme.dk", false);
    let mut victim = Client::new(&auth);
    victim.sign_up("ada@acme.dk").await;

    let url = victim
        .start(
            "/link-social",
            json!({ "provider": "google", "callbackURL": "/settings", "errorCallbackURL": "/oops" }),
        )
        .await;
    let res = victim.callback("google", &url).await;
    println!("link callback Location: {}", res.location());
    let providers = linked_providers(&auth, "ada@acme.dk").await;
    assert!(
        !providers.contains(&"google".to_owned()),
        "an unverified provider email was linked: {providers:?}"
    );
}

/// TOKENS-2c: with `AccountLinking::Off`, `/link-social` still links. Better Auth's
/// `accountLinking.enabled: false` also refuses explicit links.
#[tokio::test]
async fn sec_link_social_respects_account_linking_off() {
    let (auth, mock) = app(AccountLinking::Off);
    mock.google_user("google-ada", "ada@acme.dk", true);
    let mut user = Client::new(&auth);
    user.sign_up("ada@acme.dk").await;

    let url = user
        .start(
            "/link-social",
            json!({ "provider": "google", "callbackURL": "/settings", "errorCallbackURL": "/oops" }),
        )
        .await;
    let res = user.callback("google", &url).await;
    println!("link callback Location: {}", res.location());
    let providers = linked_providers(&auth, "ada@acme.dk").await;
    assert!(
        !providers.contains(&"google".to_owned()),
        "linking is off but the account was linked: {providers:?}"
    );
}

/// TOKENS-2d: the user id to link to is frozen in the OAuth state. If the session that started
/// the link signs out (or is revoked) before the provider returns, the link still completes.
/// Better Auth re-checks that the starting session is still live (`isLinkSessionLive`).
#[tokio::test]
async fn sec_link_social_requires_the_starting_session_to_be_live() {
    let (auth, mock) = app(AccountLinking::default());
    mock.google_user("google-ada", "ada@acme.dk", true);
    let mut browser = Client::new(&auth);
    browser.sign_up("ada@acme.dk").await;

    let url = browser
        .start(
            "/link-social",
            json!({ "provider": "google", "callbackURL": "/settings", "errorCallbackURL": "/oops" }),
        )
        .await;
    let out = browser.post("/sign-out", json!({})).await;
    assert_eq!(out.status, 200, "{}", out.json);

    let res = browser.callback("google", &url).await;
    println!("link callback after sign-out, Location: {}", res.location());
    let providers = linked_providers(&auth, "ada@acme.dk").await;
    assert!(
        !providers.contains(&"google".to_owned()),
        "linked after the starting session signed out: {providers:?}"
    );
}

/// TOKENS-5: the token endpoint's `expires_in` is added to `now` without a range check, so a
/// provider answering a huge value panics the callback handler instead of redirecting with an
/// error.
#[tokio::test]
async fn sec_huge_expires_in_from_the_provider_does_not_panic() {
    let (auth, mock) = app(AccountLinking::default());
    mock.google_user("google-ada", "ada@acme.dk", true);
    mock.google_token(json!({ "access_token": "ya29.google-access", "expires_in": i64::MAX }));
    let mut browser = Client::new(&auth);
    let url = browser
        .start(
            "/sign-in/social",
            json!({ "provider": "google", "callbackURL": "/dashboard", "errorCallbackURL": "/error" }),
        )
        .await;
    let outcome = tokio::spawn(async move { browser.callback("google", &url).await.status }).await;
    match &outcome {
        Ok(status) => println!("callback answered {status}"),
        Err(err) => println!("callback task failed: {err}"),
    }
    assert!(
        outcome.is_ok(),
        "the callback handler panicked on expires_in = i64::MAX"
    );
}

/// TOKENS-1 (account takeover chain): the same unsafe relative URL, given as `redirectTo` to
/// `/request-password-reset` by an unauthenticated attacker, is embedded in the genuine reset
/// email. When the victim clicks it, `/reset-password/{token}` redirects to
/// `/\t/evil.example?token=<reset token>`, which the browser resolves off-site, handing the
/// attacker a live reset token.
#[tokio::test]
async fn sec_reset_password_link_does_not_leak_the_token_off_site() {
    use fastauth_core::mail::{AuthEmail, MemoryMailer};

    let mailer = MemoryMailer::new();
    let auth: AppAuth = FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(ORIGIN)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .mailer(mailer.clone())
        .rate_limit(RateLimit::disabled())
        .plugin(Social::with_http_client(MockHttp::default()))
        .build()
        .expect("valid config");
    Client::new(&auth).sign_up("victim@acme.dk").await;

    let mut attacker = Client::new(&auth);
    let res = attacker
        .post(
            "/request-password-reset",
            json!({ "email": "victim@acme.dk", "redirectTo": "/\t/evil.example/steal" }),
        )
        .await;
    println!(
        "request-password-reset answered {} {}",
        res.status, res.json
    );
    if res.status == 403 {
        return;
    }
    let Some(AuthEmail::ResetPassword(email)) = mailer.last() else {
        panic!("no reset email was sent");
    };
    println!("the victim's email links to {}", email.url);

    let mut victim = Client::new(&auth);
    let path = email.url.split_once("/api/auth").unwrap().1.to_owned();
    let clicked = victim.get(&path).await;
    let landed = followed(clicked.location());
    println!(
        "clicking it answers {} Location: {:?}; the browser lands on {landed}",
        clicked.status,
        clicked.location()
    );
    assert_eq!(
        landed.host_str(),
        Some("localhost"),
        "the reset token {} left the site: {landed}",
        email.token
    );
}
