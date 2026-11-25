# HTTP integrations

`fastauth-core` handles requests as `http::Request` and returns `http::Response`. A
framework integration converts to and from those types, mounts the handler, and gives
handlers a way to get the session. axum is the integration that ships; others are
[planned](01-overview.md#planned).

## axum

```rust
use fastauth::axum::{AuthRouter, Session};

let app = Router::new()
    .route("/me", get(me))
    .merge(auth.router())                   // all auth routes under base_path (/api/auth)
    .layer(auth.session_layer())            // optional: resolve the session once per request
    .with_state(state);

let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
```

`AuthRouter` is also in `fastauth::prelude`. `auth.router()` returns `Router<S>` for any
state `S` with `AppAuth: FromRef<S>`. `into_make_service_with_connect_info` passes the
socket address along, which rate limiting and the session's `ip_address` use; without it
every client shares one rate-limit bucket. You can also nest the routes yourself if you
want auth somewhere else:

```rust
.nest_service("/auth", auth.service())     // set .base_path("/auth") on the builder to match
```

Request bodies are capped at 64 KiB. Extractors (all implement `FromRequestParts`, so they
compose with `Json` bodies):

| Extractor | Rejection |
|---|---|
| `Session<A>` | `401 UNAUTHORIZED` |
| `Option<Session<A>>` | none (a storage error, or an invalid API key with key sessions on, still rejects) |
| `FreshSession<A>` | `401` or `403 SESSION_NOT_FRESH` |
| `RequireRole<A, R>` (admin plugin) | `401 UNAUTHORIZED` or `403 FORBIDDEN` |
| `ActiveMember<A>`, `OrgMember<A, S>` (organization plugin) | `401 UNAUTHORIZED`, `403 NO_ACTIVE_ORGANIZATION` or `403 YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION` |
| `RequirePermission<A, P, S>` (organization plugin) | the same, or `403 PERMISSION_DENIED` |

Rejections are `AuthError`, which implements `IntoResponse` as the same JSON body the auth
routes use. Your handlers can return `Result<T, AuthError>` and get consistent errors. The
plugin extractors are described on the [admin](13-admin.md#axum-extractor) and
[organization](12-organization.md#axum-extractors) pages.

## Any tower-based server

`auth.service()` is a `tower::Service` for any request body. It expects the full path,
`base_path` included (under `nest_service` it reads the original URI). That covers hyper
directly, through `hyper_util`'s `TowerToHyperService`, and frameworks built on tower.

## Without a framework

```rust
let session = auth.get_session(request.headers()).await?;  // Option<SessionData<..>>
let response: http::Response<Bytes> = auth.handle(request).await;
```

Those two calls, plus `session_with_cookies` for refreshed cookies, are all an integration
needs.

## Writing an integration

An integration is generic over `AuthInstance`, the trait `Auth<D, U, P>` implements, with
associated types for the adapter, user fields and plugin list. So it never mentions
adapters or plugins. It has three jobs:

1. **Mount:** route every request under `auth.config().base_path` to `auth.handle(..)`,
   after collecting the body into `Bytes` (cap its size).
2. **Pass the client address:** put `ClientAddr(ip)` in the request's extensions, so rate
   limiting and the session's `ip_address` see it.
3. **Extract:** give handlers the session through the framework's extractor trait, backed
   by `session_with_cookies`, and add the cookies it returns to the response.

```rust
/// Serves the auth routes for any `AuthInstance`. `peer` is the client's socket address.
pub async fn handle<A: AuthInstance>(auth: &A, mut request: http::Request<Bytes>, peer: IpAddr) -> http::Response<Bytes> {
    request.extensions_mut().insert(ClientAddr(peer));
    auth.handle(request).await
}

/// The session for a request, plus the Set-Cookie values to add to the response.
pub async fn session_of<A: AuthInstance>(auth: &A, headers: &http::HeaderMap) -> Result<Option<String>, AuthError> {
    let (session, set_cookies) = auth.session_with_cookies(headers).await;
    // append set_cookies to your response, then:
    Ok(session?.map(|s| s.user.email.clone()))
}
```

`crates/fastauth-axum` is about 400 lines and the reference for the rest: one session
lookup per request shared by every extractor, and the layer that adds refreshed cookies.

## Request metadata

Endpoints see the client IP and user agent through `ctx.ip()` and `ctx.user_agent()`. The
IP comes from the socket address by default (`ClientIp::Socket`). Behind a proxy, configure
the header to trust with `.client_ip(ClientIp::Header(..))`
([Configuration](03-configuration.md#rate-limits)).

## The outgoing HTTP client

OAuth token exchange and profile fetching need an HTTP client. That's a trait in
`fastauth-oauth`, so apps that already use one client don't compile two:

```rust
impl HttpClient for MyClient {
    async fn send(&self, request: http::Request<Bytes>) -> Result<http::Response<Bytes>, HttpClientError> {
        Err(HttpClientError::transport(std::io::Error::other("not wired up")))
    }
}

Social::new();                                                        // ReqwestClient, with the oauth feature
Social::with_http_client(ReqwestClient::from_client(my_reqwest_client));
Social::with_http_client(MyClient);                                   // any HttpClient
```

Every outgoing call has a 10 s timeout and a 1 MiB response cap, enforced on top of
whatever client you pass, so a slow or hostile provider can't tie up sign-in.
