//! A real actix-web server on a local port, driven over HTTP: sign-up, sign-out, sign-in,
//! a protected route, session refresh through the middleware, bearer tokens (a response
//! hook) and two-factor sign-in.

use std::collections::BTreeMap;
use std::net::TcpListener;
use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::{App, HttpResponse, HttpServer, web};
use fastauth_actix::{AuthScope, Session};
use fastauth_core::crypto::{Argon2id, Secret};
use fastauth_core::prelude::*;
use fastauth_plugin_bearer::{Bearer, SET_AUTH_TOKEN};
use fastauth_plugin_two_factor::{TwoFactor, totp};
use reqwest::StatusCode;
use serde_json::{Value, json};

type AppAuth = Auth<MemoryAdapter, (), plugins![TwoFactor, Bearer]>;

const EMAIL: &str = "ada@acme.dk";
const PASSWORD: &str = "correct horse";

async fn me(session: Session<AppAuth>) -> HttpResponse {
    HttpResponse::Ok().json(json!({ "email": session.user.email }))
}

/// Starts the app on a free port and returns its origin.
fn start() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let auth: AppAuth = FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(origin.clone())
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .session(SessionConfig::default().update_age(Duration::ZERO))
        .rate_limit(RateLimit::disabled())
        .plugin(TwoFactor::new().issuer("Acme"))
        .plugin(Bearer::new())
        .build()
        .expect("valid config");
    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(auth.clone()))
            .wrap(auth.session_middleware())
            .service(auth.scope())
            .route("/me", web::get().to(me))
    })
    .workers(1)
    .listen(listener)
    .unwrap()
    .run();
    actix_web::rt::spawn(server);
    origin
}

struct Res {
    status: StatusCode,
    headers: reqwest::header::HeaderMap,
    json: Value,
}

impl Res {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    fn set_cookies(&self) -> Vec<&str> {
        self.headers
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect()
    }
}

/// A browser tab: keeps the cookies the server sets and sends Origin.
struct Browser {
    origin: String,
    http: reqwest::Client,
    jar: BTreeMap<String, String>,
}

impl Browser {
    fn new(origin: &str) -> Self {
        Self {
            origin: origin.to_owned(),
            http: reqwest::Client::new(),
            jar: BTreeMap::new(),
        }
    }

    async fn send(&mut self, request: reqwest::RequestBuilder) -> Res {
        let mut request = request.header("origin", &self.origin);
        if !self.jar.is_empty() {
            let cookies: Vec<String> = self.jar.iter().map(|(k, v)| format!("{k}={v}")).collect();
            request = request.header("cookie", cookies.join("; "));
        }
        let response = request.send().await.expect("server answers");
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await.unwrap();
        let res = Res {
            status,
            headers,
            json: serde_json::from_str(&body).unwrap_or(Value::Null),
        };
        for cookie in res.set_cookies() {
            let (pair, attributes) = cookie.split_once(';').unwrap_or((cookie, ""));
            let (name, value) = pair.split_once('=').unwrap();
            if attributes.contains("Max-Age=0") || value.is_empty() {
                self.jar.remove(name);
            } else {
                self.jar.insert(name.to_owned(), value.to_owned());
            }
        }
        res
    }

    async fn post(&mut self, path: &str, body: Value) -> Res {
        let request = self
            .http
            .post(format!("{}/api/auth{path}", self.origin))
            .header("content-type", "application/json")
            .body(body.to_string());
        self.send(request).await
    }

    async fn get(&mut self, path: &str) -> Res {
        let request = self.http.get(format!("{}{path}", self.origin));
        self.send(request).await
    }
}

/// An authenticator app: reads the secret from the URI and never reuses a time step.
struct Authenticator {
    secret: Vec<u8>,
    last_step: Option<u64>,
}

impl Authenticator {
    fn from_uri(uri: &str) -> Self {
        let secret = uri
            .split(['?', '&'])
            .find_map(|p| p.strip_prefix("secret="))
            .expect("secret in the TOTP URI");
        Self {
            secret: base32_decode(secret),
            last_step: None,
        }
    }

    fn code(&mut self) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 30;
        let step = self
            .last_step
            .map_or(now - 1, |last| (last + 1).max(now - 1));
        self.last_step = Some(step);
        totp::hotp(&self.secret, step, 6)
    }
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

#[actix_web::test]
async fn sign_up_sign_out_sign_in_and_a_protected_route() {
    let origin = start();
    let mut browser = Browser::new(&origin);

    let res = browser
        .post(
            "/sign-up/email",
            json!({ "email": EMAIL, "password": PASSWORD, "name": "Ada" }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let res = browser.get("/me").await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json["email"], EMAIL);

    let res = browser.post("/sign-out", json!({})).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert!(!browser.jar.contains_key("fastauth.session_token"));
    let res = browser.get("/me").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json["code"], "UNAUTHORIZED");

    let res = browser
        .post(
            "/sign-in/email",
            json!({ "email": EMAIL, "password": PASSWORD }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let res = browser.get("/me").await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json["email"], EMAIL);
}

#[actix_web::test]
async fn the_session_middleware_refreshes_the_cookie() {
    let origin = start();
    let mut browser = Browser::new(&origin);
    browser
        .post(
            "/sign-up/email",
            json!({ "email": EMAIL, "password": PASSWORD, "name": "Ada" }),
        )
        .await;
    let before = browser.jar["fastauth.session_token"].clone();

    let res = browser.get("/me").await;
    assert_eq!(res.status, StatusCode::OK);
    let refreshed = res.set_cookies();
    assert_eq!(refreshed.len(), 1, "{refreshed:?}");
    assert!(
        refreshed[0].starts_with("fastauth.session_token=") && refreshed[0].contains("Max-Age=")
    );
    assert_eq!(
        browser.jar["fastauth.session_token"], before,
        "same session, new expiry"
    );

    let res = browser.get("/api/auth/get-session").await;
    assert_eq!(res.json["user"]["email"], EMAIL);
}

#[actix_web::test]
async fn bearer_tokens_from_the_response_hook_work_on_app_routes() {
    let origin = start();
    let mut browser = Browser::new(&origin);
    let res = browser
        .post(
            "/sign-up/email",
            json!({ "email": EMAIL, "password": PASSWORD, "name": "Ada" }),
        )
        .await;
    let token = res
        .header(SET_AUTH_TOKEN)
        .expect("set-auth-token")
        .to_owned();
    let exposed = res
        .header("access-control-expose-headers")
        .unwrap_or_default();
    assert!(exposed.contains(SET_AUTH_TOKEN), "{exposed}");

    let client = reqwest::Client::new();
    let res = client
        .get(format!("{origin}/me"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let json: Value = serde_json::from_str(&res.text().await.unwrap()).unwrap();
    assert_eq!(json["email"], EMAIL);

    let res = client
        .get(format!("{origin}/me"))
        .header("authorization", "Bearer forged")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn two_factor_sign_in() {
    let origin = start();
    let mut browser = Browser::new(&origin);
    browser
        .post(
            "/sign-up/email",
            json!({ "email": EMAIL, "password": PASSWORD, "name": "Ada" }),
        )
        .await;

    let res = browser
        .post("/two-factor/enable", json!({ "password": PASSWORD }))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let mut authenticator = Authenticator::from_uri(res.json["totpURI"].as_str().unwrap());
    let res = browser
        .post(
            "/two-factor/verify-totp",
            json!({ "code": authenticator.code() }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let res = browser.get("/api/auth/get-session").await;
    assert_eq!(res.json["user"]["twoFactorEnabled"], true);

    browser.post("/sign-out", json!({})).await;
    let res = browser
        .post(
            "/sign-in/email",
            json!({ "email": EMAIL, "password": PASSWORD }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["twoFactorRedirect"], true);
    assert!(!browser.jar.contains_key("fastauth.session_token"));
    assert_eq!(browser.get("/me").await.status, StatusCode::UNAUTHORIZED);

    let res = browser
        .post(
            "/two-factor/verify-totp",
            json!({ "code": authenticator.code() }),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let res = browser.get("/me").await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json["email"], EMAIL);
}
