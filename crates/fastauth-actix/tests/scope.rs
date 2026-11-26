//! The scope, extractors and middleware, driven in process with `actix_web::test`.

use std::net::SocketAddr;

use actix_http::Request;
use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::StatusCode;
use actix_web::http::header::{self, HeaderMap};
use actix_web::middleware::Condition;
use actix_web::test::{self, TestRequest};
use actix_web::{App, HttpResponse, web};
use fastauth_actix::{AuthScope, FreshSession, OptionalSession, Session};
use fastauth_core::config::ClientIp;
use fastauth_core::crypto::{Argon2id, Secret};
use fastauth_core::prelude::*;
use serde_json::{Value, json};

type AppAuth = Auth<MemoryAdapter>;

const ORIGIN: &str = "http://localhost:3000";

struct Options {
    session: SessionConfig,
    client_ip: ClientIp,
    base_path: &'static str,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            session: SessionConfig::default(),
            client_ip: ClientIp::Socket,
            base_path: "/api/auth",
        }
    }
}

fn auth_with(options: Options) -> AppAuth {
    FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(ORIGIN)
        .base_path(options.base_path)
        .client_ip(options.client_ip)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .session(options.session)
        .rate_limit(RateLimit::disabled())
        .build()
        .expect("valid config")
}

fn auth() -> AppAuth {
    auth_with(Options::default())
}

fn refreshing() -> Options {
    Options {
        session: SessionConfig::default().update_age(Duration::ZERO),
        ..Options::default()
    }
}

/// An app with the auth scope, the instance in app data, the session middleware when
/// `$middleware` is true, and the routes `$routes` adds.
macro_rules! app {
    ($auth:expr, $middleware:expr, $routes:expr) => {{
        let auth: AppAuth = $auth;
        test::init_service(
            App::new()
                .app_data(web::Data::new(auth.clone()))
                .wrap(Condition::new($middleware, auth.session_middleware()))
                .service(auth.scope())
                .configure($routes),
        )
        .await
    }};
}

struct Res {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
    json: Value,
}

impl Res {
    fn set_cookies(&self) -> Vec<&str> {
        self.headers
            .get_all(header::SET_COOKIE)
            .map(|v| v.to_str().unwrap())
            .collect()
    }

    /// `name=value` of the session cookie, for the next request's `Cookie` header.
    fn session_cookie(&self) -> String {
        let cookie = self
            .set_cookies()
            .into_iter()
            .find(|c| c.starts_with("fastauth.session_token="))
            .expect("session cookie");
        cookie.split(';').next().unwrap().to_owned()
    }
}

async fn send<S, B>(app: &S, request: TestRequest) -> Res
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let response = test::call_service(app, request.to_request()).await;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = test::read_body(response).await;
    let body = String::from_utf8_lossy(&bytes).into_owned();
    Res {
        status,
        headers,
        json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        body,
    }
}

fn sign_up_request(path: &str) -> TestRequest {
    TestRequest::post()
        .uri(path)
        .insert_header((header::ORIGIN, ORIGIN))
        .set_json(json!({ "email": "lasse@acme.dk", "password": "correct horse", "name": "Lasse" }))
}

async fn sign_up<S, B>(app: &S) -> String
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let res = send(app, sign_up_request("/api/auth/sign-up/email")).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    res.session_cookie()
}

fn get_with(path: &str, cookie: Option<&str>) -> TestRequest {
    let request = TestRequest::get().uri(path);
    match cookie {
        Some(cookie) => request.insert_header((header::COOKIE, cookie)),
        None => request,
    }
}

async fn me(session: Session<AppAuth>) -> HttpResponse {
    HttpResponse::Ok()
        .json(json!({ "email": session.user.email, "ip": session.session.ip_address }))
}

async fn home(OptionalSession(session): OptionalSession<AppAuth>) -> String {
    session.map_or_else(|| "anonymous".into(), |s| s.user.email.clone())
}

async fn lenient_home(session: Option<Session<AppAuth>>) -> String {
    session.map_or_else(|| "anonymous".into(), |s| s.user.email.clone())
}

fn routes(config: &mut web::ServiceConfig) {
    config
        .route("/me", web::get().to(me))
        .route("/home", web::get().to(home))
        .route("/lenient-home", web::get().to(lenient_home));
}

#[actix_web::test]
async fn sign_up_through_the_scope_then_a_protected_route() {
    let app = app!(auth(), false, routes);
    let cookie = sign_up(&app).await;

    let res = send(&app, get_with("/me", Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json["email"], "lasse@acme.dk");

    let res = send(&app, get_with("/api/auth/get-session", Some(&cookie))).await;
    assert_eq!(res.json["user"]["email"], "lasse@acme.dk");
}

#[actix_web::test]
async fn missing_session_is_a_401_json_error() {
    let app = app!(auth(), false, routes);
    let res = send(&app, get_with("/me", None)).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        res.headers.get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(res.json["code"], "UNAUTHORIZED");
}

#[actix_web::test]
async fn optional_session_works_signed_in_and_out() {
    let app = app!(auth(), false, routes);
    assert_eq!(send(&app, get_with("/home", None)).await.body, "anonymous");

    let cookie = sign_up(&app).await;
    let res = send(&app, get_with("/home", Some(&cookie))).await;
    assert_eq!(res.body, "lasse@acme.dk");
}

#[actix_web::test]
async fn optional_session_rejects_a_failed_lookup_and_option_reads_it_as_signed_out() {
    let auth = auth();
    let app = test::init_service(App::new().service(auth.scope()).configure(routes)).await;
    let cookie = sign_up(&app).await;

    let res = send(&app, get_with("/home", Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::INTERNAL_SERVER_ERROR, "no app data");
    let res = send(&app, get_with("/lenient-home", Some(&cookie))).await;
    assert_eq!(
        (res.status, res.body.as_str()),
        (StatusCode::OK, "anonymous")
    );
}

#[actix_web::test]
async fn optional_session_rejects_an_invalid_api_key() {
    use fastauth_plugin_api_key::ApiKeys;
    type KeyAuth = Auth<MemoryAdapter, (), plugins![ApiKeys]>;

    async fn page(OptionalSession(session): OptionalSession<KeyAuth>) -> String {
        session.map_or_else(|| "anonymous".into(), |s| s.user.email.clone())
    }
    let auth: KeyAuth = FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(ORIGIN)
        .database(MemoryAdapter::new())
        .rate_limit(RateLimit::disabled())
        .plugin(ApiKeys::new().sessions(true))
        .build()
        .expect("valid config");
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(auth.clone()))
            .route("/page", web::get().to(page)),
    )
    .await;

    assert_eq!(send(&app, get_with("/page", None)).await.body, "anonymous");
    let res = send(
        &app,
        get_with("/page", None).insert_header(("x-api-key", "forged")),
    )
    .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.body);
    assert_eq!(res.json["code"], "INVALID_API_KEY");
}

#[actix_web::test]
async fn two_extractors_share_one_lookup() {
    async fn twice(a: Session<AppAuth>, b: Option<Session<AppAuth>>) -> HttpResponse {
        let b = b.expect("same session");
        HttpResponse::Ok().json(json!({ "same": a.session.updated_at == b.session.updated_at }))
    }
    let app = app!(
        auth_with(refreshing()),
        false,
        |config: &mut web::ServiceConfig| {
            config.route("/twice", web::get().to(twice));
        }
    );
    let cookie = sign_up(&app).await;

    let res = send(&app, get_with("/twice", Some(&cookie))).await;
    assert_eq!(res.json, json!({ "same": true }));
}

#[actix_web::test]
async fn session_middleware_passes_refreshed_cookies_through() {
    let auth = auth_with(refreshing());
    let without = app!(auth.clone(), false, routes);
    let with = app!(auth.clone(), true, routes);
    let cookie = sign_up(&with).await;

    let res = send(&without, get_with("/me", Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.set_cookies().is_empty());

    let res = send(&with, get_with("/me", Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::OK);
    let refreshed = res.set_cookies();
    assert_eq!(refreshed.len(), 1, "{refreshed:?}");
    assert!(
        refreshed[0].starts_with("fastauth.session_token=") && refreshed[0].contains("Max-Age=")
    );
}

#[actix_web::test]
async fn session_middleware_clears_a_forged_cookie() {
    let app = app!(auth(), true, routes);
    let res = send(
        &app,
        get_with("/home", Some("fastauth.session_token=forged.value")),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(
        res.set_cookies()
            .iter()
            .any(|c| c.starts_with("fastauth.session_token=;") && c.contains("Max-Age=0")),
        "{:?}",
        res.set_cookies()
    );
}

#[actix_web::test]
async fn session_middleware_does_not_resolve_unless_asked() {
    let app = app!(
        auth_with(refreshing()),
        true,
        |config: &mut web::ServiceConfig| {
            config.route("/plain", web::get().to(|| async { "plain" }));
        }
    );
    let cookie = sign_up(&app).await;

    let res = send(&app, get_with("/plain", Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.set_cookies().is_empty());
}

#[actix_web::test]
async fn fresh_session_follows_fresh_age() {
    async fn danger(session: FreshSession<AppAuth>) -> String {
        session.user.email.clone()
    }
    for (fresh_age, expected) in [
        (Duration::days(1), StatusCode::OK),
        (Duration::ZERO, StatusCode::OK),
        (Duration::nanoseconds(1), StatusCode::FORBIDDEN),
    ] {
        let auth = auth_with(Options {
            session: SessionConfig::default().fresh_age(fresh_age),
            ..Options::default()
        });
        let app = app!(auth, false, |config: &mut web::ServiceConfig| {
            config.route("/danger", web::get().to(danger));
        });
        let cookie = sign_up(&app).await;

        let res = send(&app, get_with("/danger", Some(&cookie))).await;
        assert_eq!(res.status, expected, "fresh_age {fresh_age}");
        if expected == StatusCode::FORBIDDEN {
            assert_eq!(res.json["code"], "SESSION_NOT_FRESH");
        }
        let res = send(&app, get_with("/danger", None)).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    }
}

#[actix_web::test]
async fn handlers_can_return_auth_error() {
    async fn admin_only(session: Session<AppAuth>) -> Result<String, AuthError> {
        if session.user.email != "root@acme.dk" {
            return Err(AuthError::forbidden());
        }
        Ok("welcome".into())
    }
    let app = app!(auth(), false, |config: &mut web::ServiceConfig| {
        config.route("/admin", web::get().to(admin_only));
    });
    let cookie = sign_up(&app).await;

    let res = send(&app, get_with("/admin", Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(
        res.json,
        json!({ "code": "FORBIDDEN", "message": "not allowed" })
    );
}

#[actix_web::test]
async fn auth_instance_as_plain_app_data() {
    let auth = auth();
    let app = test::init_service(
        App::new()
            .app_data(auth.clone())
            .service(auth.scope())
            .configure(routes),
    )
    .await;
    let cookie = sign_up(&app).await;

    let res = send(&app, get_with("/me", Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json["email"], "lasse@acme.dk");
}

#[actix_web::test]
async fn missing_app_data_is_a_500_json_error() {
    let auth = auth();
    let app = test::init_service(App::new().service(auth.scope()).configure(routes)).await;
    let cookie = sign_up(&app).await;

    let res = send(&app, get_with("/me", Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(res.json["code"], "INTERNAL_SERVER_ERROR");
}

#[actix_web::test]
async fn peer_address_reaches_the_session_row() {
    let app = app!(auth(), false, routes);
    let request = sign_up_request("/api/auth/sign-up/email")
        .peer_addr(SocketAddr::from(([10, 0, 0, 7], 51000)));
    let cookie = send(&app, request).await.session_cookie();

    let res = send(&app, get_with("/me", Some(&cookie))).await;
    assert_eq!(res.json["ip"], "10.0.0.7");
}

#[actix_web::test]
async fn client_ip_header_replaces_the_peer_address() {
    let auth = auth_with(Options {
        client_ip: ClientIp::Header("fly-client-ip".into()),
        ..Options::default()
    });
    let app = app!(auth, false, routes);
    let request = sign_up_request("/api/auth/sign-up/email")
        .peer_addr(SocketAddr::from(([10, 0, 0, 7], 51000)))
        .insert_header(("fly-client-ip", "203.0.113.9"));
    let cookie = send(&app, request).await.session_cookie();

    let res = send(&app, get_with("/me", Some(&cookie))).await;
    assert_eq!(res.json["ip"], "203.0.113.9");
}

#[actix_web::test]
async fn body_over_64_kib_is_rejected() {
    let app = app!(auth(), false, routes);
    let request = TestRequest::post()
        .uri("/api/auth/sign-up/email")
        .insert_header((header::ORIGIN, ORIGIN))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(vec![b' '; 64 * 1024 + 1]);
    let res = send(&app, request).await;
    assert_eq!(res.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(res.json["code"], "INVALID_REQUEST_BODY");
}

#[actix_web::test]
async fn scope_follows_base_path() {
    let auth = auth_with(Options {
        base_path: "/auth",
        ..Options::default()
    });
    let app = app!(auth, false, routes);

    let res = send(&app, sign_up_request("/auth/sign-up/email")).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let cookie = res.session_cookie();

    let res = send(&app, get_with("/auth/get-session", Some(&cookie))).await;
    assert_eq!(res.json["user"]["email"], "lasse@acme.dk");
    let res = send(&app, get_with("/api/auth/get-session", Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn unknown_auth_route_is_a_404_json_error() {
    let app = app!(auth(), false, routes);
    let res = send(&app, get_with("/api/auth/nope", None)).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(res.json["code"], "NOT_FOUND");
}

#[actix_web::test]
async fn handlers_can_return_server_api_responses() {
    async fn custom_sign_up(
        auth: web::Data<AppAuth>,
        request: actix_web::HttpRequest,
    ) -> Result<fastauth_core::ApiResponse<fastauth_core::routes::SignUpOutput>, AuthError> {
        let input = serde_json::from_value(json!({
            "email": "custom@acme.dk",
            "password": "correct horse",
            "name": "Custom"
        }))
        .expect("valid input");
        auth.api()
            .headers(&fastauth_actix::headers(&request))
            .sign_up_email(input)
            .await
    }
    let app = app!(auth(), false, |config: &mut web::ServiceConfig| {
        config.route("/custom-sign-up", web::post().to(custom_sign_up));
    });
    let res = send(&app, TestRequest::post().uri("/custom-sign-up")).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(res.json["user"]["email"], "custom@acme.dk");
    assert!(res.session_cookie().starts_with("fastauth.session_token="));
}
