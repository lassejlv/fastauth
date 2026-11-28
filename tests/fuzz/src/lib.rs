//! Shared fixtures for the fuzz targets: one auth instance with every plugin whose routes
//! take request input, a signed-in user, and a runtime to drive async calls.

use std::sync::LazyLock;

use bytes::Bytes;
use fastauth_core::crypto::{Argon2id, Secret};
use fastauth_core::endpoint::Response;
use fastauth_core::mail::MemoryMailer;
use fastauth_core::prelude::*;
use fastauth_plugin_admin::Admin;
use fastauth_plugin_api_key::ApiKeys;
use fastauth_plugin_bearer::Bearer;
use fastauth_plugin_email_otp::EmailOtp;
use fastauth_plugin_jwt::Jwt;
use fastauth_plugin_magic_link::MagicLink;
use fastauth_plugin_organization::Organization;
use fastauth_plugin_two_factor::TwoFactor;
use http::{HeaderMap, Request, header};
use tokio::runtime::Runtime;

pub type FuzzAuth = Auth<
    MemoryAdapter,
    (),
    plugins![
        EmailOtp,
        MagicLink,
        TwoFactor,
        Organization,
        Admin,
        ApiKeys,
        Jwt,
        Bearer
    ],
>;

pub const BASE_URL: &str = "http://localhost:3000";
pub const TRUSTED: &str = "https://trusted.example";

pub struct Fixture {
    pub auth: FuzzAuth,
    /// The raw session token of the signed-in user.
    pub token: String,
    /// name=value of the signed session cookie.
    pub session_cookie: String,
    /// The signed cookie value alone, which is what set-auth-token carries.
    pub signed_token: String,
    /// name=value of the session cache cookie.
    pub cache_cookie: Option<String>,
}

pub static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
});

pub fn build_auth() -> FuzzAuth {
    FastAuth::builder()
        .secret(Secret::from_bytes(SECRET.to_vec()))
        .base_url(BASE_URL)
        .trusted_origins([TRUSTED])
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(256, 1, 1)))
        .session(SessionConfig::default().cookie_cache(Duration::minutes(5)))
        .mailer(MemoryMailer::new())
        .rate_limit(RateLimit::disabled())
        .plugin(EmailOtp::new())
        .plugin(MagicLink::new())
        .plugin(TwoFactor::new())
        .plugin(Organization::default())
        .plugin(Admin::new())
        .plugin(ApiKeys::new())
        .plugin(Jwt::new())
        .plugin(Bearer::new())
        .build()
        .expect("valid fuzz config")
}

pub fn send(auth: &FuzzAuth, request: Request<Bytes>) -> Response {
    RUNTIME.block_on(auth.handle(request))
}

pub fn cookies_of(response: &Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|c| c.split(';').next().unwrap_or_default().to_owned())
        .collect()
}

/// Signs a fresh user up on auth and returns (raw token, name=value session cookie).
pub fn sign_up(auth: &FuzzAuth, email: &str) -> (String, String) {
    let body = serde_json::json!({ "email": email, "password": "correct horse", "name": "Fuzz" });
    let response = send(
        auth,
        Request::post("/api/auth/sign-up/email")
            .header(header::ORIGIN, BASE_URL)
            .body(Bytes::from(body.to_string()))
            .unwrap(),
    );
    let json: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    let token = json["token"]
        .as_str()
        .expect("sign-up returns a token")
        .to_owned();
    let cookie = cookies_of(&response)
        .into_iter()
        .find(|c| c.starts_with("fastauth.session_token="))
        .expect("session cookie");
    (token, cookie)
}

pub static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
    let auth = build_auth();
    let (token, session_cookie) = sign_up(&auth, "fuzz@acme.dk");
    let signed_token = session_cookie
        .split_once('=')
        .map(|(_, v)| v.to_owned())
        .unwrap();
    let response = send(
        &auth,
        Request::get("/api/auth/get-session")
            .header(header::COOKIE, &session_cookie)
            .body(Bytes::new())
            .unwrap(),
    );
    let cache_cookie = cookies_of(&response)
        .into_iter()
        .find(|c| c.starts_with("fastauth.session_data="));
    Fixture {
        auth,
        token,
        session_cookie,
        signed_token,
        cache_cookie,
    }
});

/// The email of the session these headers resolve to, through the cookie, the cookie cache
/// and the bearer resolver.
pub fn session_user(headers: &HeaderMap) -> Option<String> {
    let (session, _) = RUNTIME.block_on(FIXTURE.auth.session_with_cookies(headers));
    session.ok().flatten().map(|s| s.user.email.clone())
}

pub mod authenticator;
pub mod client;
pub mod json;
pub mod mock_http;

/// The secret every fuzz auth instance is built with.
pub const SECRET: [u8; 32] = [7u8; 32];

/// Signs `value` the way fastauth signs the session cookie cache (HMAC-SHA256 under an HKDF
/// key from the secret). The fuzzer knows the secret, so forged payloads get past the
/// signature and reach the decoder behind it.
pub fn sign_cache(value: &str) -> String {
    use hmac::{KeyInit, Mac};
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"fastauth"), &SECRET);
    let mut key = [0u8; 32];
    hk.expand(b"fastauth/v1/cookie-cache", &mut key)
        .expect("32 bytes is a valid HKDF output length");
    let mut mac = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&key).expect("any key");
    mac.update(value.as_bytes());
    format!(
        "{value}.{}",
        fastauth_core::crypto::base64url(&mac.finalize().into_bytes())
    )
}

/// A value rebuilt every `every` uses, so the rows a long run piles up (sessions, users)
/// can't grow without bound.
pub struct Rotating<T> {
    make: fn() -> T,
    every: u32,
    state: std::sync::Mutex<(u32, Option<std::sync::Arc<T>>)>,
}

impl<T> Rotating<T> {
    pub const fn new(make: fn() -> T, every: u32) -> Self {
        Self {
            make,
            every,
            state: std::sync::Mutex::new((0, None)),
        }
    }

    pub fn get(&self) -> std::sync::Arc<T> {
        let mut state = self.state.lock().unwrap();
        if state.1.is_none() || state.0 >= self.every {
            *state = (0, Some(std::sync::Arc::new((self.make)())));
        }
        state.0 += 1;
        state.1.clone().unwrap()
    }
}
