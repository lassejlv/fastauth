use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{ConnectInfo, FromRef};
use axum::routing::get;
use axum::{Json, Router};
use fastauth_axum::{AuthRouter, FreshSession, Session};
use fastauth_core::crypto::{Argon2id, Secret};
use fastauth_core::prelude::*;
use http::{HeaderMap, Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type AppAuth = Auth<MemoryAdapter>;

const ORIGIN: &str = "http://localhost:3000";

fn auth_with(session: SessionConfig) -> AppAuth {
    FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(ORIGIN)
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .session(session)
        .rate_limit(RateLimit::disabled())
        .build()
        .expect("valid config")
}

fn auth() -> AppAuth {
    auth_with(SessionConfig::default())
}

struct Res {
    status: StatusCode,
    headers: HeaderMap,
    json: Value,
}

impl Res {
    fn set_cookies(&self) -> Vec<&str> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
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

async fn send(app: &Router, request: Request<Body>) -> Res {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Res {
        status,
        headers,
        json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

fn sign_up_request(path: &str) -> Request<Body> {
    let body = json!({ "email": "lasse@acme.dk", "password": "correct horse", "name": "Lasse" });
    Request::post(path)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn sign_up(app: &Router) -> String {
    let res = send(app, sign_up_request("/api/auth/sign-up/email")).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    res.session_cookie()
}

fn get_with(path: &str, cookie: Option<&str>) -> Request<Body> {
    let mut request = Request::get(path);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    request.body(Body::empty()).unwrap()
}

async fn me(session: Session<AppAuth>) -> Json<Value> {
    Json(json!({ "email": session.user.email, "ip": session.session.ip_address }))
}

async fn home(session: Option<Session<AppAuth>>) -> String {
    session.map_or_else(|| "anonymous".into(), |s| s.user.email.clone())
}

fn app(auth: AppAuth) -> Router {
    Router::new()
        .route("/me", get(me))
        .route("/home", get(home))
        .merge(auth.router())
        .with_state(auth)
}

#[tokio::test]
async fn sign_up_through_the_router_then_a_protected_route() {
    let app = app(auth());
    let cookie = sign_up(&app).await;

    let res = send(&app, get_with("/me", Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json["email"], "lasse@acme.dk");

    let res = send(&app, get_with("/api/auth/get-session", Some(&cookie))).await;
    assert_eq!(res.json["user"]["email"], "lasse@acme.dk");
}

#[tokio::test]
async fn missing_session_is_a_401_json_error() {
    let res = send(&app(auth()), get_with("/me", None)).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        res.headers[header::CONTENT_TYPE],
        "application/json",
        "{:?}",
        res.headers
    );
    assert_eq!(res.json["code"], "UNAUTHORIZED");
}

#[tokio::test]
async fn optional_session_works_signed_in_and_out() {
    let app = app(auth());
    let anonymous = app.clone().oneshot(get_with("/home", None)).await.unwrap();
    let body = anonymous.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "anonymous");

    let cookie = sign_up(&app).await;
    let signed_in = app
        .clone()
        .oneshot(get_with("/home", Some(&cookie)))
        .await
        .unwrap();
    let body = signed_in.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "lasse@acme.dk");
}

#[tokio::test]
async fn two_extractors_share_one_lookup() {
    async fn twice(a: Session<AppAuth>, b: Option<Session<AppAuth>>) -> Json<Value> {
        let b = b.expect("same session");
        Json(json!({ "same": a.session.updated_at == b.session.updated_at }))
    }
    let auth = auth_with(SessionConfig::default().update_age(Duration::ZERO));
    let app = Router::new()
        .route("/twice", get(twice))
        .merge(auth.router())
        .with_state(auth);
    let cookie = sign_up(&app).await;

    let res = send(&app, get_with("/twice", Some(&cookie))).await;
    assert_eq!(res.json, json!({ "same": true }));
}

#[tokio::test]
async fn session_layer_passes_refreshed_cookies_through() {
    let auth = auth_with(SessionConfig::default().update_age(Duration::ZERO));
    let without_layer = app(auth.clone());
    let with_layer = app(auth.clone()).layer(auth.session_layer());
    let cookie = sign_up(&with_layer).await;

    let res = send(&without_layer, get_with("/me", Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.set_cookies().is_empty());

    let res = send(&with_layer, get_with("/me", Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::OK);
    let refreshed = res.set_cookies();
    assert_eq!(refreshed.len(), 1, "{refreshed:?}");
    assert!(
        refreshed[0].starts_with("fastauth.session_token=") && refreshed[0].contains("Max-Age=")
    );
}

#[tokio::test]
async fn session_layer_clears_a_forged_cookie() {
    let auth = auth();
    let app = app(auth.clone()).layer(auth.session_layer());

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

#[tokio::test]
async fn session_layer_does_not_resolve_unless_asked() {
    let auth = auth_with(SessionConfig::default().update_age(Duration::ZERO));
    let app = Router::new()
        .route("/plain", get(|| async { "plain" }))
        .merge(auth.router())
        .layer(auth.session_layer())
        .with_state(auth);
    let cookie = sign_up(&app).await;

    let res = send(&app, get_with("/plain", Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.set_cookies().is_empty());
}

#[tokio::test]
async fn fresh_session_follows_fresh_age() {
    async fn danger(session: FreshSession<AppAuth>) -> String {
        session.user.email.clone()
    }
    for (fresh_age, expected) in [
        (Duration::days(1), StatusCode::OK),
        (Duration::ZERO, StatusCode::OK),
        (Duration::nanoseconds(1), StatusCode::FORBIDDEN),
    ] {
        let auth = auth_with(SessionConfig::default().fresh_age(fresh_age));
        let app = Router::new()
            .route("/danger", get(danger))
            .merge(auth.router())
            .with_state(auth);
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

#[tokio::test]
async fn handlers_can_return_auth_error() {
    async fn admin_only(session: Session<AppAuth>) -> Result<String, AuthError> {
        if session.user.email != "root@acme.dk" {
            return Err(AuthError::forbidden());
        }
        Ok("welcome".into())
    }
    let auth = auth();
    let app = Router::new()
        .route("/admin", get(admin_only))
        .merge(auth.router())
        .with_state(auth);
    let cookie = sign_up(&app).await;

    let res = send(&app, get_with("/admin", Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(
        res.json,
        json!({ "code": "FORBIDDEN", "message": "not allowed" })
    );
}

#[derive(Clone, FromRef)]
struct AppState {
    auth: AppAuth,
    greeting: &'static str,
}

#[tokio::test]
async fn state_struct_with_from_ref() {
    async fn greet(
        axum::extract::State(greeting): axum::extract::State<&'static str>,
        session: Session<AppAuth>,
    ) -> String {
        format!("{greeting}, {}", session.user.name)
    }
    let auth = auth();
    let app = Router::new()
        .route("/greet", get(greet))
        .merge(auth.router())
        .layer(auth.session_layer())
        .with_state(AppState {
            auth,
            greeting: "Hej",
        });
    let cookie = sign_up(&app).await;

    let response = app
        .clone()
        .oneshot(get_with("/greet", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "Hej, Lasse");
}

#[tokio::test]
async fn socket_address_reaches_the_session_row() {
    let app = app(auth());
    let mut request = sign_up_request("/api/auth/sign-up/email");
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 7], 51000))));
    let res = send(&app, request).await;
    let cookie = res.session_cookie();

    let res = send(&app, get_with("/me", Some(&cookie))).await;
    assert_eq!(res.json["ip"], "10.0.0.7");
}

#[tokio::test]
async fn body_over_64_kib_is_rejected() {
    let app = app(auth());
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/sign-up/email")
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(vec![b' '; 64 * 1024 + 1]))
        .unwrap();
    let res = send(&app, request).await;
    assert_eq!(res.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(res.json["code"], "INVALID_REQUEST_BODY");
}

#[tokio::test]
async fn service_under_nest_service() {
    let auth = FastAuth::builder()
        .secret(Secret::from_bytes(vec![42u8; 32]))
        .base_url(ORIGIN)
        .base_path("/auth")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .build()
        .expect("valid config");
    let app = Router::new().nest_service("/auth", auth.service());

    let res = send(&app, sign_up_request("/auth/sign-up/email")).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let cookie = res.session_cookie();

    let res = send(&app, get_with("/auth/get-session", Some(&cookie))).await;
    assert_eq!(res.json["user"]["email"], "lasse@acme.dk");
}

#[tokio::test]
async fn unknown_auth_route_is_a_404_json_error() {
    let res = send(&app(auth()), get_with("/api/auth/nope", None)).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(res.json["code"], "NOT_FOUND");
}
