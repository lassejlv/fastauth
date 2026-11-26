use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use fastauth_core::crypto::{Argon2id, Hash, Secret, base64url};
use fastauth_core::plugin_prelude::*;
use fastauth_core::prelude::{EmailPassword, FastAuth, MemoryAdapter, RateLimit};
use fastauth_core::query::Db;
use fastauth_core::{Auth, plugins};
use fastauth_oauth::http::MAX_RESPONSE_BYTES;
use fastauth_oauth::{
    AccountLinking, Github, Google, Http, HttpClient, HttpClientError, OAuthProviderExt, Social,
};
use http::{Request, Response, header};
use serde_json::{Value as Json, json};
use time::{Duration, OffsetDateTime};
use url::Url;

const ORIGIN: &str = "http://localhost:3000";

// ---------------------------------------------------------------- a mock provider backend

#[derive(Clone, Default)]
struct MockHttp {
    routes: Arc<Mutex<HashMap<String, (u16, String)>>>,
    requests: Arc<Mutex<Vec<(String, String)>>>,
}

impl MockHttp {
    fn respond(&self, url: &str, status: u16, body: Json) {
        self.routes
            .lock()
            .unwrap()
            .insert(url.to_owned(), (status, body.to_string()));
    }

    fn google_user(&self, email: &str, verified: bool) {
        self.respond(
            "https://oauth2.googleapis.com/token",
            200,
            json!({
                "access_token": "ya29.google-access",
                "refresh_token": "1//google-refresh",
                "expires_in": 3599,
                "scope": "openid email profile",
                "token_type": "Bearer",
                "id_token": "header.payload.signature"
            }),
        );
        self.respond(
            "https://openidconnect.googleapis.com/v1/userinfo",
            200,
            json!({
                "sub": format!("google-{email}"),
                "email": email,
                "email_verified": verified,
                "name": "Ada Lovelace",
                "picture": "https://lh3.googleusercontent.com/ada"
            }),
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
            json!([
                { "email": "old@acme.dk", "primary": false, "verified": false, "visibility": null },
                { "email": email, "primary": true, "verified": true, "visibility": "private" }
            ]),
        );
    }

    fn body_sent_to(&self, url: &str) -> Option<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(u, _)| u == url)
            .map(|(_, body)| body.clone())
    }
}

impl HttpClient for MockHttp {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpClientError> {
        assert!(request.headers().contains_key(header::USER_AGENT));
        let url = request.uri().to_string();
        let body = String::from_utf8(request.body().to_vec()).unwrap();
        self.requests.lock().unwrap().push((url.clone(), body));
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

// ---------------------------------------------------------------- a gate, like two-factor

struct Gatekeeper;

impl Plugin for Gatekeeper {
    const ID: &'static str = "gatekeeper";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.sign_in_gate(|ctx, attempt| async move {
            if attempt.method == "social" && attempt.user.email.starts_with("gated") {
                ctx.set_signed_cookie("pending_user", attempt.user.id.as_str(), None);
                return Ok(Gate::Challenge(
                    json!({ "twoFactorRedirect": true, "twoFactorMethods": ["totp", "otp"] }),
                ));
            }
            Ok(Gate::Allow)
        });
    }
}

type AppAuth<U = ()> = Auth<MemoryAdapter, U, plugins![Social, Gatekeeper]>;

fn build<U: Fields>(social: Social) -> AppAuth<U> {
    FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(ORIGIN)
        .trusted_origins(["https://app.acme.dk"])
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .user_fields::<U>()
        .plugin(social)
        .plugin(Gatekeeper)
        .build()
        .expect("valid config")
}

fn app(linking: AccountLinking) -> (AppAuth, MockHttp) {
    let mock = MockHttp::default();
    let social = Social::with_http_client(mock.clone())
        .provider(Github::new("gh-id", "gh-secret"))
        .provider(Google::new("google-id", "google-secret"))
        .account_linking(linking);
    (build(social), mock)
}

// ---------------------------------------------------------------- a browser

struct Client<U = ()> {
    auth: AppAuth<U>,
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

impl<U: Fields> Client<U> {
    fn new(auth: &AppAuth<U>) -> Self {
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

    async fn sign_up(&mut self, email: &str) -> Res {
        self.post(
            "/sign-up/email",
            json!({ "email": email, "password": "correct horse", "name": "Ada" }),
        )
        .await
    }

    /// Starts a flow and returns the provider's authorization URL.
    async fn start(&mut self, path: &str, body: Json) -> Url {
        let res = self.post(path, body).await;
        assert_eq!(res.status, 200, "{}", res.json);
        assert_eq!(res.json["redirect"], true);
        Url::parse(res.json["url"].as_str().unwrap()).unwrap()
    }

    /// The provider redirects the browser back with a code.
    async fn callback(&mut self, provider: &str, url: &Url) -> Res {
        let state = query(url, "state").unwrap();
        self.get(&format!(
            "/callback/{provider}?code=the-code&state={state}&scope=email"
        ))
        .await
    }

    fn has_session(&self) -> bool {
        self.jar.keys().any(|k| k.ends_with("session_token"))
    }
}

fn query(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

fn sign_in_body(provider: &str) -> Json {
    json!({
        "provider": provider,
        "callbackURL": "/dashboard",
        "newUserCallbackURL": "/welcome",
        "errorCallbackURL": "/error",
    })
}

fn db(auth: &AppAuth) -> Db<'_, MemoryAdapter> {
    Db::new(auth.adapter(), auth.schema())
}

async fn accounts(auth: &AppAuth, provider: &str) -> Vec<Account> {
    db(auth)
        .find::<Account>(Account::PROVIDER_ID.eq(provider))
        .all()
        .await
        .unwrap()
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn new_user_signs_up_with_pkce_and_encrypted_tokens() {
    let (auth, mock) = app(AccountLinking::default());
    mock.google_user("ada@acme.dk", true);
    let mut browser = Client::new(&auth);

    let url = browser
        .start("/sign-in/social", sign_in_body("google"))
        .await;
    assert_eq!(url.host_str(), Some("accounts.google.com"));
    assert_eq!(query(&url, "client_id").as_deref(), Some("google-id"));
    assert_eq!(
        query(&url, "scope").as_deref(),
        Some("openid email profile")
    );
    assert_eq!(
        query(&url, "code_challenge_method").as_deref(),
        Some("S256")
    );
    assert_eq!(
        query(&url, "redirect_uri").as_deref(),
        Some("http://localhost:3000/api/auth/callback/google")
    );
    assert!(browser.jar.contains_key("fastauth.oauth_state"));

    let res = browser.callback("google", &url).await;
    assert_eq!(res.status, 302);
    assert_eq!(
        res.location(),
        "http://localhost:3000/welcome",
        "new users go to newUserCallbackURL"
    );
    assert!(browser.has_session());
    assert!(
        !browser.jar.contains_key("fastauth.oauth_state"),
        "state cookie is cleared"
    );

    let token_request = mock
        .body_sent_to("https://oauth2.googleapis.com/token")
        .unwrap();
    let form: HashMap<String, String> = serde_urlencoded::from_str(&token_request).unwrap();
    assert_eq!(form["code"], "the-code");
    assert_eq!(
        form["redirect_uri"],
        "http://localhost:3000/api/auth/callback/google"
    );
    assert_eq!(
        base64url(Hash::sha256(&form["code_verifier"]).as_bytes()),
        query(&url, "code_challenge").unwrap(),
        "the verifier matches the S256 challenge"
    );

    let session = browser.get("/get-session").await.json;
    assert_eq!(session["user"]["email"], "ada@acme.dk");
    assert_eq!(session["user"]["emailVerified"], true);
    assert_eq!(
        session["user"]["image"],
        "https://lh3.googleusercontent.com/ada"
    );

    let account = accounts(&auth, "google").await.remove(0);
    assert_eq!(account.account_id, "google-ada@acme.dk");
    let sealed = account.access_token.unwrap();
    assert_ne!(sealed, b"ya29.google-access");
    assert_eq!(decrypt(&auth, sealed).await, "ya29.google-access");
}

/// Decrypts a sealed column with the auth instance's keys.
struct Decrypt;

impl<D: Adapter> Endpoint<D> for Decrypt {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/test/decrypt";
    type Access = Public;
    type Input = Vec<u8>;
    type Output = String;

    async fn call(&self, ctx: Ctx<D, Public>, sealed: Vec<u8>) -> Result<String, AuthError> {
        Ok(String::from_utf8(ctx.keys().decrypt(&sealed).unwrap()).unwrap())
    }
}

async fn decrypt(auth: &AppAuth, sealed: Vec<u8>) -> String {
    auth.api().call(&Decrypt, sealed).await.unwrap().data
}

#[tokio::test]
async fn returning_user_signs_in_and_tokens_are_refreshed() {
    let (auth, mock) = app(AccountLinking::default());
    mock.google_user("ada@acme.dk", true);
    let mut first = Client::new(&auth);
    let url = first.start("/sign-in/social", sign_in_body("google")).await;
    first.callback("google", &url).await;

    mock.respond(
        "https://oauth2.googleapis.com/token",
        200,
        json!({ "access_token": "ya29.second", "expires_in": 3599, "scope": "openid email profile" }),
    );
    let mut second = Client::new(&auth);
    let url = second
        .start("/sign-in/social", sign_in_body("google"))
        .await;
    let res = second.callback("google", &url).await;
    assert_eq!(
        res.location(),
        "http://localhost:3000/dashboard",
        "returning users go to callbackURL"
    );
    assert!(second.has_session());

    let users = db(&auth).find::<User>(Where::all()).all().await.unwrap();
    assert_eq!(users.len(), 1);
    let mut google = accounts(&auth, "google").await;
    assert_eq!(google.len(), 1);
    let account = google.remove(0);
    assert_eq!(
        decrypt(&auth, account.access_token.unwrap()).await,
        "ya29.second"
    );
    assert_eq!(
        decrypt(&auth, account.refresh_token.unwrap()).await,
        "1//google-refresh",
        "a missing refresh token keeps the old one"
    );
}

#[tokio::test]
async fn links_an_existing_user_by_verified_email() {
    let (auth, mock) = app(AccountLinking::default());
    let mut browser = Client::new(&auth);
    browser.sign_up("ada@acme.dk").await;
    browser.jar.clear();
    db(&auth)
        .update::<User>(User::EMAIL.eq("ada@acme.dk"))
        .set(User::EMAIL_VERIFIED, true)
        .exec()
        .await
        .unwrap();
    mock.google_user("Ada@Acme.dk", true);

    let url = browser
        .start("/sign-in/social", sign_in_body("google"))
        .await;
    let res = browser.callback("google", &url).await;
    assert_eq!(res.location(), "http://localhost:3000/dashboard");
    assert!(browser.has_session());

    let providers: Vec<Json> = browser
        .get("/list-accounts")
        .await
        .json
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["providerId"].clone())
        .collect();
    assert_eq!(providers, [json!("credential"), json!("google")]);
}

#[tokio::test]
async fn a_verified_sign_in_takes_over_a_pre_registered_unverified_account() {
    let (auth, mock) = app(AccountLinking::default());
    let mut attacker = Client::new(&auth);
    attacker.sign_up("ada@acme.dk").await;
    assert!(attacker.get("/get-session").await.json["user"].is_object());

    mock.google_user("ada@acme.dk", true);
    let mut ada = Client::new(&auth);
    let url = ada.start("/sign-in/social", sign_in_body("google")).await;
    let res = ada.callback("google", &url).await;
    assert_eq!(res.location(), "http://localhost:3000/dashboard");
    assert!(ada.has_session());

    let session = ada.get("/get-session").await.json;
    assert_eq!(session["user"]["emailVerified"], true);
    let providers: Vec<Json> = ada
        .get("/list-accounts")
        .await
        .json
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["providerId"].clone())
        .collect();
    assert_eq!(
        providers,
        [json!("google")],
        "the pre-registered password is gone"
    );

    assert_eq!(
        attacker.get("/get-session").await.json,
        Json::Null,
        "the attacker's session is revoked"
    );
    attacker.jar.clear();
    let res = attacker
        .post(
            "/sign-in/email",
            json!({ "email": "ada@acme.dk", "password": "correct horse" }),
        )
        .await;
    assert_eq!(res.status, 401);
    assert_eq!(res.json["code"], "INVALID_EMAIL_OR_PASSWORD");
}

#[tokio::test]
async fn refuses_to_link_by_an_unverified_email() {
    let (auth, mock) = app(AccountLinking::default());
    let mut browser = Client::new(&auth);
    browser.sign_up("ada@acme.dk").await;
    browser.jar.clear();
    mock.google_user("ada@acme.dk", false);

    let url = browser
        .start("/sign-in/social", sign_in_body("google"))
        .await;
    let res = browser.callback("google", &url).await;
    assert_eq!(
        res.location(),
        "http://localhost:3000/error?error=account_not_linked"
    );
    assert!(!browser.has_session());
    assert!(accounts(&auth, "google").await.is_empty());
}

#[tokio::test]
async fn linking_off_refuses_even_a_verified_email() {
    let (auth, mock) = app(AccountLinking::Off);
    let mut browser = Client::new(&auth);
    browser.sign_up("ada@acme.dk").await;
    browser.jar.clear();
    mock.google_user("ada@acme.dk", true);

    let url = browser
        .start("/sign-in/social", sign_in_body("google"))
        .await;
    let res = browser.callback("google", &url).await;
    assert_eq!(
        res.location(),
        "http://localhost:3000/error?error=account_not_linked"
    );
}

#[tokio::test]
async fn a_state_from_another_browser_is_rejected() {
    let (auth, mock) = app(AccountLinking::default());
    mock.google_user("ada@acme.dk", true);
    let mut victim = Client::new(&auth);
    let url = victim
        .start("/sign-in/social", sign_in_body("google"))
        .await;

    let mut attacker = Client::new(&auth);
    let res = attacker.callback("google", &url).await;
    assert_eq!(
        res.location(),
        "http://localhost:3000/error?error=state_mismatch"
    );
    assert!(!attacker.has_session());

    let res = victim.callback("google", &url).await;
    assert_eq!(
        res.location(),
        "http://localhost:3000/?error=please_restart_the_process",
        "a state is single use"
    );

    let res = Client::new(&auth).get("/callback/google?code=x").await;
    assert_eq!(
        res.location(),
        "http://localhost:3000/?error=state_not_found"
    );
    assert!(
        mock.body_sent_to("https://oauth2.googleapis.com/token")
            .is_none(),
        "no code was exchanged"
    );
}

#[tokio::test]
async fn an_expired_state_is_rejected() {
    let (auth, mock) = app(AccountLinking::default());
    mock.google_user("ada@acme.dk", true);
    let mut browser = Client::new(&auth);
    let url = browser
        .start("/sign-in/social", sign_in_body("google"))
        .await;

    let verification = db(&auth)
        .find::<Verification>(Verification::IDENTIFIER.eq("oauth-state:google"))
        .one()
        .await
        .unwrap()
        .unwrap();
    assert!(verification.expires_at - verification.created_at == Duration::minutes(10));
    db(&auth)
        .update::<Verification>(Verification::ID.eq(&verification.id))
        .set(
            Verification::EXPIRES_AT,
            OffsetDateTime::now_utc() - Duration::seconds(1),
        )
        .exec()
        .await
        .unwrap();

    let res = browser.callback("google", &url).await;
    assert_eq!(
        res.location(),
        "http://localhost:3000/?error=please_restart_the_process"
    );
    assert!(!browser.has_session());
}

#[tokio::test]
async fn untrusted_callback_urls_are_refused() {
    let (auth, _) = app(AccountLinking::default());
    let mut browser = Client::new(&auth);
    for field in ["callbackURL", "errorCallbackURL", "newUserCallbackURL"] {
        let res = browser
            .post(
                "/sign-in/social",
                json!({ "provider": "google", field: "https://evil.example/steal" }),
            )
            .await;
        assert_eq!(res.status, 403, "{field}");
        assert_eq!(res.json["code"], "INVALID_CALLBACK_URL");
    }
    let res = browser
        .post(
            "/sign-in/social",
            json!({ "provider": "google", "callbackURL": "https://app.acme.dk/home" }),
        )
        .await;
    assert_eq!(res.status, 200, "trusted origins are fine");

    let res = browser
        .post("/sign-in/social", json!({ "provider": "myspace" }))
        .await;
    assert_eq!(res.status, 404);
    assert_eq!(res.json["code"], "PROVIDER_NOT_FOUND");
}

#[tokio::test]
async fn a_gate_challenge_redirects_with_the_challenge_and_no_session() {
    let (auth, mock) = app(AccountLinking::default());
    mock.github_user(7, "gated@acme.dk");
    let mut browser = Client::new(&auth);
    let url = browser
        .start("/sign-in/social", sign_in_body("github"))
        .await;
    let res = browser.callback("github", &url).await;
    assert_eq!(
        res.location(),
        "http://localhost:3000/dashboard?twoFactorMethods=totp%2Cotp&twoFactorRedirect=true"
    );
    assert!(!browser.has_session());
    assert!(
        browser.jar.contains_key("fastauth.pending_user"),
        "the gate's cookie survives"
    );
}

#[tokio::test]
async fn github_takes_the_primary_verified_email_from_user_emails() {
    let (auth, mock) = app(AccountLinking::default());
    mock.github_user(42, "ada@acme.dk");
    let mut browser = Client::new(&auth);
    let url = browser
        .start("/sign-in/social", sign_in_body("github"))
        .await;
    assert_eq!(
        query(&url, "scope").as_deref(),
        Some("read:user user:email")
    );
    let res = browser.callback("github", &url).await;
    assert_eq!(res.location(), "http://localhost:3000/welcome");

    let session = browser.get("/get-session").await.json;
    assert_eq!(session["user"]["email"], "ada@acme.dk");
    assert_eq!(session["user"]["emailVerified"], true);
    assert_eq!(session["user"]["name"], "ada", "falls back to the login");
    let accounts = browser.get("/list-accounts").await.json;
    assert_eq!(accounts[0]["accountId"], "42");
    assert_eq!(accounts[0]["scopes"], json!(["read:user", "user:email"]));
    assert!(
        accounts[0].get("accessToken").is_none(),
        "tokens never leave the server"
    );
}

#[tokio::test]
async fn provider_errors_redirect_to_the_error_url() {
    let (auth, mock) = app(AccountLinking::default());
    mock.respond(
        "https://github.com/login/oauth/access_token",
        200,
        json!({ "error": "bad_verification_code", "error_description": "The code passed is incorrect or expired." }),
    );
    let mut browser = Client::new(&auth);
    let url = browser
        .start("/sign-in/social", sign_in_body("github"))
        .await;
    let res = browser.callback("github", &url).await;
    assert_eq!(
        res.location(),
        "http://localhost:3000/error?error=invalid_code"
    );

    let url = browser
        .start("/sign-in/social", sign_in_body("github"))
        .await;
    let state = query(&url, "state").unwrap();
    let res = browser
        .get(&format!(
            "/callback/github?error=access_denied&state={state}"
        ))
        .await;
    assert_eq!(
        res.location(),
        "http://localhost:3000/error?error=access_denied"
    );
}

#[tokio::test]
async fn link_social_adds_a_provider_to_the_signed_in_user() {
    let mock = MockHttp::default();
    let auth: AppAuth = build(
        Social::with_http_client(mock.clone())
            .provider(Github::new("gh-id", "gh-secret"))
            .allow_different_emails(true),
    );
    mock.github_user(42, "someone-else@users.noreply.github.com");
    let mut ada = Client::new(&auth);
    ada.sign_up("ada@acme.dk").await;
    let url = ada
        .start(
            "/link-social",
            json!({ "provider": "github", "callbackURL": "/settings", "scopes": ["repo"] }),
        )
        .await;
    assert_eq!(
        query(&url, "scope").as_deref(),
        Some("read:user user:email repo")
    );
    let res = ada.callback("github", &url).await;
    assert_eq!(res.location(), "http://localhost:3000/settings");
    let providers: Vec<Json> = ada
        .get("/list-accounts")
        .await
        .json
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["providerId"].clone())
        .collect();
    assert_eq!(providers, [json!("credential"), json!("github")]);

    let mut bob = Client::new(&auth);
    bob.sign_up("bob@acme.dk").await;
    let url = bob
        .start("/link-social", json!({ "provider": "github", "callbackURL": "/settings", "errorCallbackURL": "/oops" }))
        .await;
    let res = bob.callback("github", &url).await;
    assert_eq!(
        res.location(),
        "http://localhost:3000/oops?error=account_already_linked_to_different_user"
    );

    let res = Client::new(&auth)
        .post("/link-social", json!({ "provider": "github" }))
        .await;
    assert_eq!(res.status, 401);
}

#[tokio::test]
async fn the_last_account_cannot_be_unlinked() {
    let (auth, mock) = app(AccountLinking::default());
    mock.google_user("ada@acme.dk", true);
    let mut browser = Client::new(&auth);
    browser.sign_up("ada@acme.dk").await;
    let url = browser
        .start("/link-social", json!({ "provider": "google" }))
        .await;
    browser.callback("google", &url).await;

    let res = browser
        .post("/unlink-account", json!({ "providerId": "github" }))
        .await;
    assert_eq!(res.json["code"], "ACCOUNT_NOT_FOUND");

    let res = browser
        .post("/unlink-account", json!({ "providerId": "credential" }))
        .await;
    assert_eq!(res.json, json!({ "status": true }));

    let res = browser
        .post("/unlink-account", json!({ "providerId": "google" }))
        .await;
    assert_eq!(res.status, 400);
    assert_eq!(res.json["code"], "FAILED_TO_UNLINK_LAST_ACCOUNT");
    assert_eq!(accounts(&auth, "google").await.len(), 1);
}

#[tokio::test]
async fn disable_redirect_is_passed_through() {
    let (auth, _) = app(AccountLinking::default());
    let res = Client::new(&auth)
        .post(
            "/sign-in/social",
            json!({ "provider": "google", "disableRedirect": true }),
        )
        .await;
    assert_eq!(res.json["redirect"], false);
}

// ---------------------------------------------------------------- the HTTP limits

struct Slow;

impl HttpClient for Slow {
    async fn send(&self, _: Request<Bytes>) -> Result<Response<Bytes>, HttpClientError> {
        tokio::time::sleep(std::time::Duration::from_secs(11)).await;
        Ok(Response::new(Bytes::new()))
    }
}

struct Huge;

impl HttpClient for Huge {
    async fn send(&self, _: Request<Bytes>) -> Result<Response<Bytes>, HttpClientError> {
        Ok(Response::new(Bytes::from(vec![
            b' ';
            MAX_RESPONSE_BYTES + 1
        ])))
    }
}

#[tokio::test(start_paused = true)]
async fn outgoing_calls_time_out_after_ten_seconds() {
    let err = Http::new(&Slow)
        .send(Request::new(Bytes::new()))
        .await
        .unwrap_err();
    assert!(matches!(err, HttpClientError::Timeout), "{err}");
}

#[tokio::test]
async fn responses_over_one_mebibyte_are_refused() {
    let err = Http::new(&Huge)
        .send(Request::new(Bytes::new()))
        .await
        .unwrap_err();
    assert!(matches!(err, HttpClientError::TooLarge), "{err}");
}

// ---------------------------------------------------------------- profile mapping

/// An app with a required column that has no default and isn't client input.
#[derive(Clone, Debug)]
struct Plan {
    plan: String,
}

impl Fields for Plan {
    fn columns() -> &'static [ColumnDef] {
        const COLUMNS: &[ColumnDef] = &[ColumnDef::new("plan", ColumnType::Text)];
        COLUMNS
    }
    fn decode(row: &Row) -> Result<Self, DecodeError> {
        Ok(Self {
            plan: row.get("plan")?,
        })
    }
}

impl OnTable for Plan {
    type Table = User;
}

impl Plan {
    const PLAN: Col<Plan, String> = Col::new("plan");
}

fn plan_app(social: impl FnOnce(Social) -> Social) -> (AppAuth<Plan>, MockHttp) {
    let mock = MockHttp::default();
    let social = social(Social::with_http_client(mock.clone()));
    (build(social), mock)
}

async fn user_plans(auth: &AppAuth<Plan>) -> Vec<String> {
    let rows = Db::new(auth.adapter(), auth.schema())
        .find::<User>(Where::all())
        .all_rows()
        .await
        .unwrap();
    rows.iter()
        .map(|row| Plan::decode(row).unwrap().plan)
        .collect()
}

/// Captures this thread's log output for the rest of the test.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Logs;
    fn make_writer(&'a self) -> Logs {
        self.clone()
    }
}

impl Logs {
    fn capture() -> (Self, tracing::subscriber::DefaultGuard) {
        let logs = Logs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .finish();
        (logs, tracing::subscriber::set_default(subscriber))
    }

    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

#[tokio::test]
async fn map_profile_sets_a_required_field_for_new_users_only() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let (auth, mock) = plan_app(|social| {
        social
            .provider(Github::new("gh-id", "gh-secret"))
            .map_profile(move |profile, provider| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(vec![Plan::PLAN.value(format!("{provider}-{}", profile.id))])
            })
    });
    mock.github_user(7, "ada@acme.dk");

    let mut browser = Client::new(&auth);
    let url = browser
        .start("/sign-in/social", sign_in_body("github"))
        .await;
    let res = browser.callback("github", &url).await;
    assert_eq!(res.location(), "http://localhost:3000/welcome");
    assert!(browser.has_session());
    let session = browser.get("/get-session").await.json;
    assert_eq!(session["user"]["plan"], "github-7");

    let mut again = Client::new(&auth);
    let url = again.start("/sign-in/social", sign_in_body("github")).await;
    assert_eq!(
        again.callback("github", &url).await.location(),
        "http://localhost:3000/dashboard"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "only new users are mapped");
    assert_eq!(user_plans(&auth).await, ["github-7"]);
}

#[tokio::test]
async fn a_provider_mapping_wins_over_the_social_one() {
    let (auth, mock) = plan_app(|social| {
        social
            .provider(
                Github::new("gh-id", "gh-secret")
                    .map_profile(|_, _| Ok(vec![Plan::PLAN.value("from-github")])),
            )
            .provider(Google::new("google-id", "google-secret"))
            .map_profile(|_, _| Ok(vec![Plan::PLAN.value("from-social")]))
    });
    mock.github_user(7, "ada@acme.dk");
    mock.google_user("grace@acme.dk", true);

    for provider in ["github", "google"] {
        let mut browser = Client::new(&auth);
        let url = browser
            .start("/sign-in/social", sign_in_body(provider))
            .await;
        assert_eq!(
            browser.callback(provider, &url).await.location(),
            "http://localhost:3000/welcome"
        );
    }
    let mut plans = user_plans(&auth).await;
    plans.sort();
    assert_eq!(plans, ["from-github", "from-social"]);
}

#[tokio::test]
async fn without_a_mapping_a_required_field_fails_with_a_clear_error() {
    let (logs, _guard) = Logs::capture();
    let (auth, mock) = plan_app(|social| social.provider(Github::new("gh-id", "gh-secret")));
    mock.github_user(7, "ada@acme.dk");

    let mut browser = Client::new(&auth);
    let url = browser
        .start("/sign-in/social", sign_in_body("github"))
        .await;
    let res = browser.callback("github", &url).await;
    assert_eq!(res.status, 500);
    assert_eq!(res.json["code"], "INTERNAL_SERVER_ERROR");
    assert!(!browser.has_session());
    assert!(user_plans(&auth).await.is_empty());
    let logs = logs.text();
    assert!(
        logs.contains("`user.plan` is required and has no default, but social sign-up through `github` doesn't set it; return it from `Social::map_profile`"),
        "{logs}"
    );
}

#[tokio::test]
async fn a_mapping_with_the_wrong_type_fails_with_a_clear_error() {
    let (logs, _guard) = Logs::capture();
    let (auth, mock) = plan_app(|social| {
        social
            .provider(Github::new("gh-id", "gh-secret"))
            .map_profile(|_, _| Ok(vec![("plan", Value::Int(1))]))
    });
    mock.github_user(7, "ada@acme.dk");

    let mut browser = Client::new(&auth);
    let url = browser
        .start("/sign-in/social", sign_in_body("github"))
        .await;
    assert_eq!(browser.callback("github", &url).await.status, 500);
    assert!(user_plans(&auth).await.is_empty());
    let logs = logs.text();
    assert!(
        logs.contains(
            "the profile mapping for `github` sets `user.plan` to Int, but the column is Text"
        ),
        "{logs}"
    );
}

#[tokio::test]
async fn a_mapping_may_not_set_unknown_or_core_columns() {
    let (logs, _guard) = Logs::capture();
    for (column, value) in [
        ("plann", Value::Text("pro".into())),
        ("email_verified", Value::Bool(true)),
    ] {
        let (auth, mock) = plan_app(|social| {
            social
                .provider(Github::new("gh-id", "gh-secret"))
                .map_profile(move |_, _| Ok(vec![Plan::PLAN.value("pro"), (column, value.clone())]))
        });
        mock.github_user(7, "ada@acme.dk");
        let mut browser = Client::new(&auth);
        let url = browser
            .start("/sign-in/social", sign_in_body("github"))
            .await;
        assert_eq!(browser.callback("github", &url).await.status, 500);
        assert!(user_plans(&auth).await.is_empty());
        let logs = logs.text();
        assert!(
            logs.contains(&format!(
                "sets `user.{column}`, which is not an app or plugin column"
            )),
            "{logs}"
        );
    }
}

#[tokio::test]
async fn a_mapping_error_redirects_with_its_code() {
    let (auth, mock) = plan_app(|social| {
        social
            .provider(Github::new("gh-id", "gh-secret"))
            .map_profile(|profile, _| match profile.email.as_deref() {
                Some(email) if email.ends_with("@acme.dk") => Ok(vec![Plan::PLAN.value("staff")]),
                _ => Err(AuthError::forbidden()),
            })
    });
    mock.github_user(7, "ada@example.com");

    let mut browser = Client::new(&auth);
    let url = browser
        .start("/sign-in/social", sign_in_body("github"))
        .await;
    let res = browser.callback("github", &url).await;
    assert_eq!(
        res.location(),
        "http://localhost:3000/error?error=FORBIDDEN"
    );
    assert!(user_plans(&auth).await.is_empty());
}

#[tokio::test]
async fn disable_sign_up_refuses_new_users_but_signs_in_existing_ones() {
    let mock = MockHttp::default();
    let auth: AppAuth = build(
        Social::with_http_client(mock.clone())
            .provider(Github::new("gh-id", "gh-secret").disable_sign_up(true))
            .provider(Google::new("google-id", "google-secret")),
    );

    mock.github_user(7, "ada@acme.dk");
    let mut browser = Client::new(&auth);
    let url = browser
        .start("/sign-in/social", sign_in_body("github"))
        .await;
    let res = browser.callback("github", &url).await;
    assert_eq!(
        res.location(),
        "http://localhost:3000/error?error=signup_disabled"
    );
    assert!(!browser.has_session());
    let users = db(&auth).find::<User>(Where::all()).all().await.unwrap();
    assert!(users.is_empty());

    mock.google_user("ada@acme.dk", true);
    let mut browser = Client::new(&auth);
    let url = browser
        .start("/sign-in/social", sign_in_body("google"))
        .await;
    assert_eq!(
        browser.callback("google", &url).await.location(),
        "http://localhost:3000/welcome"
    );

    for _ in 0..2 {
        let mut browser = Client::new(&auth);
        let url = browser
            .start("/sign-in/social", sign_in_body("github"))
            .await;
        assert_eq!(
            browser.callback("github", &url).await.location(),
            "http://localhost:3000/dashboard",
            "an existing user links by verified email, then signs in with the account"
        );
        assert!(browser.has_session());
    }
    assert_eq!(accounts(&auth, "github").await.len(), 1);
}
