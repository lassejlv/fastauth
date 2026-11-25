# HTTP integrations

`fastauth-core` handles requests as `http::Request` and returns `http::Response`. A
framework integration converts to and from those types, mounts the handler, and gives
handlers a way to get the session. axum is the default and the reference integration.

## axum

```rust
use fastauth::axum::{AuthRouter, Session};

let app = Router::new()
    .route("/me", get(me))
    .merge(auth.router())                   // all auth routes under base_path (/api/auth)
    .layer(auth.session_layer())            // optional: resolve the session once per request
    .with_state(state);
```

`auth.router()` returns `Router<S>` for any state `S` with `AppAuth: FromRef<S>`. You
can also nest it yourself if you want auth somewhere else:

```rust
.nest_service("/auth", auth.service())     // set .base_path("/auth") on the builder to match
```

Extractors (all implement `FromRequestParts`, so they compose with `Json` bodies):

| Extractor | Rejection |
|---|---|
| `Session<A>` | `401 UNAUTHORIZED` |
| `Option<Session<A>>` | none |
| `FreshSession<A>` | `401` or `403 SESSION_NOT_FRESH` |
| `RequireRole<A, R>` (admin plugin) | `401` or `403 FORBIDDEN` |
| `RequireMember<A, O>`, `RequirePermission<A, P>` (organization plugin) | `401`, `403` or `404` |

Rejections are `AuthError`, which implements `IntoResponse` as the same JSON body the auth
routes use. Your handlers can return `Result<T, AuthError>` and get consistent errors.

## actix-web

```rust
use fastauth::actix::{Session, AuthScope};

HttpServer::new(move || {
    App::new()
        .app_data(web::Data::new(auth.clone()))
        .service(auth.scope())                 // /api/auth/*
        .route("/me", web::get().to(me))
})

async fn me(session: Session<AppAuth>) -> impl Responder {
    HttpResponse::Ok().json(&session.user.email)
}
```

## Any tower-based server

`auth.service()` is a `tower::Service<http::Request<B>>` for any body `B: http_body::Body`.
That covers hyper directly, axum, tonic (gRPC handlers can call `auth.get_session` on the
metadata), and frameworks built on them.

```rust
let svc = auth.service();
hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
    .serve_connection(io, TowerToHyperService::new(svc))
    .await?;
```

## Without a framework

```rust
let response: http::Response<Body> = auth.handle(request).await;
let session: Option<SessionData<AppAuth>> = auth.get_session(request.headers()).await?;
```

Those two calls are all an integration needs.

## Writing an integration

An integration crate has three parts. Here's the actual size of each for a hypothetical
framework `foo`:

```rust
// 1. Mount: route everything under base_path to auth.handle.
pub trait AuthFoo {
    fn foo_routes(&self) -> foo::Scope;
}

impl<A: AuthInstance> AuthFoo for A {
    fn foo_routes(&self) -> foo::Scope {
        let auth = self.clone();
        foo::Scope::new(self.base_path()).wildcard(move |req: foo::Request| {
            let auth = auth.clone();
            async move { into_foo(auth.handle(from_foo(req)).await) }
        })
    }
}

// 2. Convert: foo::Request <-> http::Request. Usually zero-copy on the body.
fn from_foo(req: foo::Request) -> http::Request<foo::Body> { /* ... */ }
fn into_foo(res: http::Response<fastauth::Body>) -> foo::Response { /* ... */ }

// 3. Extract: the framework's extractor trait, backed by get_session.
pub struct Session<A: AuthInstance>(pub SessionData<A>);

impl<A: AuthInstance> foo::FromRequest for Session<A> {
    type Error = AuthError;
    async fn from_request(req: &foo::Request) -> Result<Self, AuthError> {
        if let Some(cached) = req.extensions().get::<SessionData<A>>() {
            return Ok(Session(cached.clone()));
        }
        let auth = req.app_data::<A>().expect("auth instance not registered");
        let data = auth.get_session(req.headers()).await?.ok_or_else(AuthError::unauthorized)?;
        req.extensions_mut().insert(data.clone());
        Ok(Session(data))
    }
}
```

`AuthInstance` is the object-safe-ish handle trait that `Auth<D, U, P>` implements and that
`AppAuth` names, with associated types for the user fields and plugin list. Integrations
are generic over it, so they never mention adapters or plugins.

## Request metadata

Endpoints see the client IP and user agent through `ctx.meta()`. The IP comes from the
socket address by default. Behind a proxy, configure the header to trust
(`RateLimit::client_ip`, [Configuration](03-configuration.md#rate-limits)); integrations
pass the socket address along through `http` extensions (`ConnectInfo` in axum).

## The outgoing HTTP client

OAuth token exchange, OIDC discovery and JWKS fetching need an HTTP client. That's a trait
too, so apps that already use one client don't compile two:

```rust
pub trait HttpClient: Send + Sync + 'static {
    fn send(&self, req: http::Request<Bytes>) -> impl Future<Output = Result<http::Response<Bytes>, HttpClientError>> + Send;
}

.http_client(ReqwestClient::new(my_reqwest_client))   // default with the reqwest feature
```

Every outgoing call has a timeout (10 s default) and a response size cap, so a slow or
hostile provider can't tie up sign-in.

## OpenAPI

With the `openapi` feature, `auth.openapi()` returns an OpenAPI 3.1 document built from every
registered endpoint's `Input`, `Output` and error codes (endpoint types derive `ToSchema`).
Merge it into your own utoipa document, or serve it at `/api/auth/openapi.json` with
`.serve_openapi(true)`. A frontend can generate a typed client from it, which is the
Rust-backend equivalent of Better Auth's inferred client types.
