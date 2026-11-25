# Testing

Tests run on `MemoryAdapter` (no database, no migrations) with `MemoryMailer` to read the
emails fastauth sends. All samples here pass against `main`.

## Share the config between the app and its tests

Make the build function and router generic over the adapter, so tests build the same
auth instance on `MemoryAdapter` and production on `Sqlx<Postgres>`:

```rust
use axum::Router;
use axum::routing::get;
use fastauth::adapter::Adapter;
use fastauth::endpoint::Before;
use fastauth::prelude::*;
use fastauth::routes::{SignUpEmail, SignUpEmailInput};

use crate::api_keys::{ApiKeys, Bans, KeyAudit};

#[derive(Fields, Clone, Debug)]
pub struct Profile {
    #[field(default = "free", input)]
    pub plan: String,
    pub stripe_customer_id: Option<String>,
}

pub type AppAuth<D> = Auth<D, Profile, plugins![ApiKeys, KeyAudit, Bans]>;

pub fn build<D: Adapter>(db: D, secret: Secret, mailer: impl Mailer) -> Result<AppAuth<D>, BuildError> {
    FastAuth::builder()
        .secret(secret)
        .base_url("http://localhost:3000")
        .database(db)
        .email_password(EmailPassword::default())
        .mailer(mailer)
        .user_fields::<Profile>()
        .plugin(ApiKeys::new().ttl(Duration::days(90)))
        .plugin(KeyAudit)
        .plugin(Bans)
        .configure(|app| {
            app.hook::<SignUpEmail>()
                .before(|_ctx, mut input: SignUpEmailInput| async move {
                    if input.email.ends_with("@mailinator.com") {
                        return Err(AuthError::bad_request("DISPOSABLE_EMAIL", "use a real email address"));
                    }
                    input.name = input.name.trim().to_owned();
                    Ok(Before::Continue(input))
                });
        })
        .on(|e: UserCreated, _ctx| async move {
            println!("welcome, {}", e.email);
            Ok(())
        })
        .build()
}

async fn plan<D: Adapter>(session: Session<AppAuth<D>>) -> String {
    session.user.fields.plan.clone()
}

pub fn app<D: Adapter>(auth: AppAuth<D>) -> Router {
    Router::new()
        .route("/plan", get(plan::<D>))
        .merge(auth.router())
        .layer(auth.session_layer())
        .with_state(auth)
}
```

## Through the router

`tower::ServiceExt::oneshot` (`tower = { version = "0.5", features = ["util"] }` in
dev-dependencies) sends requests through the real router. Copy `Set-Cookie` values into the
next request's `Cookie` header, and set `Origin`, which non-GET requests with cookies need:

```rust
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use fastauth::crypto::Argon2id;
use fastauth::models::User;
use fastauth::prelude::*;
use fastauth::query::Db;
use fastauth::routes::{SignInEmailInput, SignUpEmailInput};
use serde_json::{Value, json};
use tower::ServiceExt;
use use_fastauth_check::api_keys::{ApiKeysExt, BanFields, CreateKeyInput};
use use_fastauth_check::testable::{app, build};

const ORIGIN: &str = "http://localhost:3000";

fn post(path: &str, body: Value) -> Request<Body> {
    Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, ORIGIN)
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn cookies(set_cookies: impl IntoIterator<Item = HeaderValue>) -> String {
    set_cookies
        .into_iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
        .collect::<Vec<_>>()
        .join("; ")
}
#[tokio::test]
async fn sign_up_over_http_sets_input_fields() {
    let auth = build(MemoryAdapter::new(), secret(), MemoryMailer::new()).unwrap();
    let app = app(auth);

    let res = app
        .clone()
        .oneshot(post(
            "/api/auth/sign-up/email",
            json!({ "email": "lasse@acme.dk", "password": "correct horse battery", "name": "Lasse", "plan": "pro" }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let cookie = cookies(res.headers().get_all(header::SET_COOKIE).iter().cloned());

    let res = app
        .oneshot(Request::get("/plan").header(header::COOKIE, cookie).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(to_bytes(res.into_body(), usize::MAX).await.unwrap(), "pro");
}
```

## Emails, server API and plugins

```rust
#[tokio::test]
async fn email_verification_with_memory_mailer() {
    let mailer = MemoryMailer::new();
    let auth: Auth<MemoryAdapter> = FastAuth::builder()
        .secret(secret())
        .base_url(ORIGIN)
        .database(MemoryAdapter::new())
        .email_password(
            EmailPassword::default()
                .require_email_verification(true)
                .hasher(Argon2id::with_params(1024, 1, 1)),
        )
        .mailer(mailer.clone())
        .rate_limit(RateLimit::disabled())
        .build()
        .unwrap();

    auth.api().sign_up_email(sign_up("v@acme.dk")).await.unwrap();
    let Some(AuthEmail::VerifyEmail(email)) = mailer.last() else {
        panic!("expected a verification email, got {:?}", mailer.sent());
    };
    println!("verify url: {}", email.url);

    let err = sign_in(&auth, "v@acme.dk").await.unwrap_err();
    assert_eq!(err.code(), "EMAIL_NOT_VERIFIED");

    let router: Router = auth.router().with_state(auth.clone());
    let res = router
        .oneshot(
            Request::get(format!("/api/auth/verify-email?token={}", email.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(sign_in(&auth, "v@acme.dk").await.is_ok());
}
```

- `Argon2id::with_params(1024, 1, 1)` (in `fastauth::crypto`) makes password hashing fast in
  tests; the default is OWASP's cost. `RateLimit::disabled()` stops many sign-ins in one
  test from hitting the limit.
- `mailer.last()` and `mailer.sent()` return `AuthEmail`s; `AuthEmail::VerifyEmail` and
  `ResetPassword` carry `url` and `token`, and two-factor codes arrive as
  `AuthEmail::Plugin` with `code`.
- Assert on `err.code()` (`"EMAIL_NOT_VERIFIED"`, `"INVALID_ORIGIN"`, your plugin's codes).
- For a plugin, build an instance with only that plugin, call its endpoints through
  `auth.api().headers(..).call(..)` or its extension trait, and check resolvers with
  `auth.get_session(&headers)`. The `plugins_hooks_gates_and_resolvers` test in the scratch
  crate behind this skill does exactly that for the API-key plugin.
- A test against a real database uses the same `build` with `Sqlx::new(pool)` and calls
  `auth.migrator().run()` first. `SqlitePool::connect("sqlite::memory:")` needs no server.
