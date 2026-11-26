mod common;

use axum::Router;
use axum::body::Body;
use axum::routing::get;
use common::{Res, bearer, mysql, postgres, secret, send, sqlite};
use fastauth_axum::{AuthRouter, Session};
use fastauth_core::adapter::Adapter;
use fastauth_core::crypto::Argon2id;
use fastauth_core::plugin::{Plugin, PluginBuilder};
use fastauth_core::prelude::*;
use fastauth_plugin_bearer::{Bearer, SET_AUTH_TOKEN};
use http::{Method, Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

type BearerAuth<D> = Auth<D, (), plugins![Bearer]>;

fn build<D: Adapter>(db: D, bearer: Bearer, session: SessionConfig) -> BearerAuth<D> {
    FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(db)
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .rate_limit(RateLimit::disabled())
        .session(session)
        .plugin(bearer)
        .build()
        .expect("valid config")
}

async fn sign_up<D: Adapter>(auth: &BearerAuth<D>, email: &str) -> Res {
    let res = send(
        auth,
        Method::POST,
        "/sign-up/email",
        &[],
        Some(json!({ "email": email, "password": "correct horse", "name": "Ada" })),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    res
}

async fn session_email<D: Adapter>(auth: &BearerAuth<D>, authorization: &str) -> Option<String> {
    let res = send(
        auth,
        Method::GET,
        "/get-session",
        &[("authorization", authorization)],
        None,
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    res.json["user"]["email"].as_str().map(str::to_owned)
}

/// The whole bearer flow, run on every adapter.
async fn bearer_flow<D: Adapter>(db: D) {
    let auth = build(db, Bearer::new(), SessionConfig::default());
    auth.migrator().run().await.expect("migrations");

    let signed_up = sign_up(&auth, "ada@acme.dk").await;
    let signed = signed_up
        .header(SET_AUTH_TOKEN)
        .expect("sign-up sets set-auth-token")
        .to_owned();
    assert_eq!(Some(signed.clone()), signed_up.session_cookie());
    assert_eq!(
        signed_up.header("access-control-expose-headers"),
        Some(SET_AUTH_TOKEN)
    );
    let raw = signed_up.json["token"].as_str().unwrap().to_owned();
    assert!(
        signed.starts_with(&format!("{raw}.")),
        "{signed} signs {raw}"
    );

    assert_eq!(
        session_email(&auth, &bearer(&signed)).await.as_deref(),
        Some("ada@acme.dk")
    );
    assert_eq!(
        session_email(&auth, &bearer(&raw)).await.as_deref(),
        Some("ada@acme.dk"),
        "unsigned tokens are accepted by default"
    );
    assert_eq!(
        session_email(&auth, &format!("bEaReR {signed}"))
            .await
            .as_deref(),
        Some("ada@acme.dk"),
        "the scheme is case-insensitive"
    );
    let encoded = format!("%{:02X}{}", signed.as_bytes()[0], &signed[1..]);
    assert_eq!(
        session_email(&auth, &bearer(&encoded)).await.as_deref(),
        Some("ada@acme.dk"),
        "a percent-encoded token is decoded"
    );
    for refused in [
        bearer(&format!("{raw}.AAAA")),
        bearer(&format!("{}x", &raw[..raw.len() - 1])),
        format!("Basic {raw}"),
        "Bearer ".to_owned(),
    ] {
        assert_eq!(session_email(&auth, &refused).await, None, "{refused}");
    }

    let signed_in = send(
        &auth,
        Method::POST,
        "/sign-in/email",
        &[],
        Some(json!({ "email": "ada@acme.dk", "password": "correct horse" })),
    )
    .await;
    assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.json);
    let second = signed_in
        .header(SET_AUTH_TOKEN)
        .expect("sign-in sets set-auth-token")
        .to_owned();
    assert_ne!(second, signed);

    let list = send(
        &auth,
        Method::GET,
        "/list-sessions",
        &[("authorization", &bearer(&second))],
        None,
    )
    .await;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(list.json.as_array().unwrap().len(), 2);
    assert_eq!(
        list.header(SET_AUTH_TOKEN),
        None,
        "no cookie set, no header"
    );

    let out = send(
        &auth,
        Method::POST,
        "/sign-out",
        &[("authorization", &bearer(&signed))],
        Some(json!({})),
    )
    .await;
    assert_eq!(out.status, StatusCode::OK, "{}", out.json);
    assert_eq!(out.json["success"], true);
    assert_eq!(
        out.header(SET_AUTH_TOKEN),
        None,
        "a cleared cookie is not exposed"
    );
    assert_eq!(session_email(&auth, &bearer(&signed)).await, None);
    assert_eq!(
        session_email(&auth, &bearer(&second)).await.as_deref(),
        Some("ada@acme.dk")
    );

    let api = auth
        .api()
        .headers(
            &[(header::AUTHORIZATION, bearer(&second).parse().unwrap())]
                .into_iter()
                .collect(),
        )
        .list_sessions()
        .await
        .expect("server API calls accept bearer headers");
    assert_eq!(api.data.len(), 1);
}

#[tokio::test]
async fn bearer_flow_on_memory() {
    bearer_flow(MemoryAdapter::new()).await;
}

#[tokio::test]
async fn bearer_flow_on_sqlite() {
    bearer_flow(sqlite().await).await;
}

#[tokio::test]
async fn bearer_flow_on_postgres() {
    let Some((db, cleanup)) = postgres().await else {
        return;
    };
    bearer_flow(db).await;
    cleanup.drop_schema().await;
}

#[tokio::test]
async fn bearer_flow_on_mysql() {
    let Some((db, cleanup)) = mysql().await else {
        return;
    };
    bearer_flow(db).await;
    cleanup.drop_database().await;
}

#[tokio::test]
async fn require_signature_refuses_raw_tokens() {
    let auth = build(
        MemoryAdapter::new(),
        Bearer::new().require_signature(true),
        SessionConfig::default(),
    );
    let res = sign_up(&auth, "ada@acme.dk").await;
    let raw = res.json["token"].as_str().unwrap();
    let signed = res.header(SET_AUTH_TOKEN).unwrap();
    assert_eq!(session_email(&auth, &bearer(raw)).await, None);
    assert_eq!(
        session_email(&auth, &bearer(signed)).await.as_deref(),
        Some("ada@acme.dk")
    );
}

#[tokio::test]
async fn a_signature_from_another_secret_is_refused() {
    let other: BearerAuth<MemoryAdapter> = FastAuth::builder()
        .secret(Secret::from_bytes(vec![7u8; 32]))
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .plugin(Bearer::new())
        .build()
        .unwrap();
    let foreign = sign_up(&other, "eve@acme.dk").await;
    let auth = build(
        MemoryAdapter::new(),
        Bearer::new(),
        SessionConfig::default(),
    );
    sign_up(&auth, "ada@acme.dk").await;
    let forged = foreign.header(SET_AUTH_TOKEN).unwrap();
    assert_eq!(session_email(&auth, &bearer(forged)).await, None);
}

#[tokio::test]
async fn a_refreshed_bearer_session_gets_a_new_header() {
    let auth = build(
        MemoryAdapter::new(),
        Bearer::new(),
        SessionConfig::default().update_age(Duration::ZERO),
    );
    let signed = sign_up(&auth, "ada@acme.dk")
        .await
        .header(SET_AUTH_TOKEN)
        .unwrap()
        .to_owned();
    let res = send(
        &auth,
        Method::GET,
        "/get-session",
        &[("authorization", &bearer(&signed))],
        None,
    )
    .await;
    assert_eq!(res.json["user"]["email"], "ada@acme.dk");
    assert_eq!(
        res.header(SET_AUTH_TOKEN),
        Some(signed.as_str()),
        "the refresh sets the session cookie again, so the header comes with it"
    );
}

/// A plugin registered before `Bearer` that exposes its own header.
struct RequestId;

impl Plugin for RequestId {
    const ID: &'static str = "request-id";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &std::sync::Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.on_response(|_, response| {
            response.headers_mut().insert(
                header::ACCESS_CONTROL_EXPOSE_HEADERS,
                "x-request-id".parse().unwrap(),
            );
        });
    }
}

#[tokio::test]
async fn existing_expose_headers_are_kept() {
    let auth: Auth<MemoryAdapter, (), plugins![RequestId, Bearer]> = FastAuth::builder()
        .secret(secret())
        .base_url("http://localhost:3000")
        .database(MemoryAdapter::new())
        .email_password(EmailPassword::default().hasher(Argon2id::with_params(1024, 1, 1)))
        .plugin(RequestId)
        .plugin(Bearer::new())
        .build()
        .unwrap();
    let res = send(
        &auth,
        Method::POST,
        "/sign-up/email",
        &[],
        Some(json!({ "email": "ada@acme.dk", "password": "correct horse", "name": "Ada" })),
    )
    .await;
    assert!(res.header(SET_AUTH_TOKEN).is_some());
    assert_eq!(
        res.header("access-control-expose-headers"),
        Some("x-request-id, set-auth-token")
    );
}

type AppAuth = BearerAuth<MemoryAdapter>;

async fn me(session: Session<AppAuth>) -> String {
    session.user.email.clone()
}

async fn maybe_me(session: Option<Session<AppAuth>>) -> String {
    session.map_or_else(|| "anonymous".to_owned(), |s| s.user.email.clone())
}

#[tokio::test]
async fn axum_extractors_accept_bearer_tokens() {
    let auth = build(
        MemoryAdapter::new(),
        Bearer::new(),
        SessionConfig::default(),
    );
    let app = Router::new()
        .route("/me", get(me))
        .route("/maybe", get(maybe_me))
        .merge(auth.router())
        .layer(auth.session_layer())
        .with_state(auth.clone());

    let sign_up = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-up/email")
                .header(header::ORIGIN, common::ORIGIN)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "email": "ada@acme.dk", "password": "correct horse", "name": "Ada" })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sign_up.status(), StatusCode::OK);
    let token = sign_up.headers()[SET_AUTH_TOKEN]
        .to_str()
        .unwrap()
        .to_owned();

    let call = |path: &'static str, authorization: Option<String>| {
        let app = app.clone();
        async move {
            let mut request = Request::get(path);
            if let Some(value) = authorization {
                request = request.header(header::AUTHORIZATION, value);
            }
            let response = app
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, String::from_utf8(body.to_vec()).unwrap())
        }
    };
    assert_eq!(
        call("/me", Some(bearer(&token))).await,
        (StatusCode::OK, "ada@acme.dk".to_owned())
    );
    assert_eq!(call("/me", None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        call("/me", Some(bearer("nope.nope"))).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(call("/maybe", Some(bearer(&token))).await.1, "ada@acme.dk");
    assert_eq!(call("/maybe", None).await.1, "anonymous");
}
