# axum

## Mounting

```rust
let app = Router::new()
    .route("/me", get(me))
    .merge(auth.router())
    .layer(auth.session_layer())
    .with_state(auth);
```

- `auth.router()` serves every auth route under the base path (`/api/auth`), for any router
  state `S` with `AppAuth: FromRef<S>`.
- `auth.session_layer()` resolves the session at most once per request, on first use, and
  appends the refreshed or cleared session cookies to your own routes' responses. Without
  it extractors still work, but sliding expiry only reaches the browser on auth routes. A
  cookie your handler sets wins over the layer's.
- Serve with `app.into_make_service_with_connect_info::<SocketAddr>()`. The default
  `ClientIp::Socket` reads the socket address from there, and rate limits key on it. With
  plain `axum::serve(listener, app)` there is no client IP, and rate limits fall back to one
  bucket per account named in the body, or one bucket for everyone.
- Behind proxies, set `.client_ip(..)` on the builder instead
  ([below](#session-cookie-and-origin-settings)). Use `ClientIp::Header(name)` only for a header
  your proxy overwrites with exactly one address (`fly-client-ip`, `cf-connecting-ip`). For
  `x-forwarded-for`, which every proxy appends to, use
  `ClientIp::TrustedProxies { header: "x-forwarded-for".into(), proxies: 1 }`, where
  `proxies` counts the proxies in front of the app. Never use
  `ClientIp::Header("x-forwarded-for")`: a client could pick its own IP and dodge every limit.
- `router` and `session_layer` are methods of the `AuthRouter` trait, in
  `fastauth::prelude`.

## State

When the state is more than the auth instance, derive `FromRef` (axum feature `macros`)
so the extractors find the instance. This sample shows every extractor:

```rust
use axum::extract::{FromRef, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use fastauth::prelude::*;
use serde::Serialize;

pub type AppAuth = Auth<Sqlx<Sqlite>>;

#[derive(Clone, FromRef)]
pub struct AppState {
    pub auth: AppAuth,
    pub pool: SqlitePool,
}

async fn home(session: Option<Session<AppAuth>>) -> String {
    match session {
        Some(session) => format!("Hi {}", session.user.name),
        None => "Hi, stranger".into(),
    }
}

#[derive(Serialize)]
struct Me {
    id: String,
    email: String,
    email_verified: bool,
}

async fn me(session: Session<AppAuth>) -> Json<Me> {
    Json(Me {
        id: session.user.id.to_string(),
        email: session.user.email.clone(),
        email_verified: session.user.email_verified,
    })
}

async fn sign_out_elsewhere(
    _fresh: FreshSession<AppAuth>,
    State(auth): State<AppAuth>,
    headers: HeaderMap,
) -> Result<StatusCode, AuthError> {
    auth.api().headers(&headers).revoke_other_sessions().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn pool_size(_session: Session<AppAuth>, State(pool): State<SqlitePool>) -> String {
    pool.size().to_string()
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/me", get(me))
        .route("/sign-out-elsewhere", post(sign_out_elsewhere))
        .route("/pool", get(pool_size))
        .merge(state.auth.router())
        .layer(state.auth.session_layer())
        .with_state(state)
}
```

## Extractors

| Extractor | Without a session | Notes |
|---|---|---|
| `Session<AppAuth>` | `401 UNAUTHORIZED` | |
| `Option<Session<AppAuth>>` | `None` | a storage error is still a `500` |
| `FreshSession<AppAuth>` | `401` | `403 SESSION_NOT_FRESH` when the session is older than `fresh_age` (default 1 day) |

Rejections are `AuthError`, which implements `IntoResponse` as `{ "code", "message" }`
JSON. Handlers can return `Result<T, AuthError>` and build their own with
`AuthError::bad_request("CODE", "message")` or `AuthError::new(StatusCode::.., "CODE", "message")`.

`Session<A>` derefs to `SessionData`:

| Expression | What it is |
|---|---|
| `session.user.id`, `.email`, `.email_verified`, `.name`, `.image`, `.created_at` | core user columns |
| `session.user.fields` | your `.user_fields::<U>()` struct, typed |
| `session.user.plugin::<P, _>()` | the columns plugin `P` adds to `user`; the `_` is inferred |
| `session.session.id`, `.expires_at`, `.ip_address`, `.user_agent`, `.created_at` | the session row |
| `session.token` | the raw session token, when the request carried it |
| `session.view().ephemeral` | true for a session a resolver built for this request (an API key) |

Outside an extractor (middleware, WebSockets), use `auth.get_session(&headers).await?` or
`auth.get_session_by_token(&token).await?`; both return `Option<SessionData<..>>`.

## Session, cookie and origin settings

```rust
pub fn build(pool: PgPool) -> Result<AppAuth, BuildError> {
    FastAuth::builder()
        .secret(Secret::from_env("FASTAUTH_SECRET")?)
        .base_url("https://acme.dk")
        .trusted_origins(["https://app.acme.dk"])
        .client_ip(ClientIp::Header("fly-client-ip".into()))
        .database(Sqlx::new(pool))
        .email_password(EmailPassword::default())
        .session(
            SessionConfig::default()
                .expires_in(Duration::days(7))
                .update_age(Duration::days(1))
                .fresh_age(Duration::days(1))
                .cookie_cache(Duration::minutes(5)),
        )
        .cookies(CookieConfig::default().prefix("acme"))
        .build()
}
```

The session values shown are the defaults. `cookie_cache` is off by default: it saves a
database read per request, but a revoked session keeps working until the cache cookie
expires. Cookies are named `{prefix}.session_token` (`fastauth` by default), with a
`__Secure-` prefix when `base_url` is https.

## Origins, CSRF and CORS

Every non-GET auth request that carries cookies must come from a trusted origin, judged
by `Origin`, then `Referer`; otherwise it answers `403 INVALID_ORIGIN`. `base_url`'s origin
is always trusted; add others with `.trusted_origins(["https://app.acme.dk"])`. The same
list decides which absolute `callbackURL`s are allowed. Browsers send `Origin` on their
own; curl and server-to-server callers must set it.

fastauth sends no CORS headers. A frontend on another origin needs a CORS layer on the
router that allows that origin with credentials, plus the origin in `trusted_origins`.
