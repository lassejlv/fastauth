# actix-web

`fastauth-actix` mounts the auth routes in an [actix-web](https://actix.rs) 4 app and gives
your handlers the same extractors as the axum integration, with the same `401` and `403`
answers. It is the facade's `actix` feature, as `fastauth::actix`.

## Setup

```toml
[dependencies]
actix-web = "4"
# actix-web without axum: turn the defaults off and pick the database yourself.
fastauth = { version = "0.8", default-features = false, features = ["actix", "postgres", "macros"] }
```

The `actix` and `axum` features can be on together. The prelude's `Session` is axum's, so the
actix types are never in the prelude: import them from `fastauth::actix`.

## Mounting

```rust
use actix_web::{App, HttpResponse, HttpServer, web};
use fastauth::actix::{AuthScope, Session};

async fn me(session: Session<AppAuth>) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "email": session.user.email }))
}

let auth = auth::build(pool)?;
HttpServer::new(move || {
    App::new()
        .app_data(web::Data::new(auth.clone()))  // the extractors find the instance here
        .wrap(auth.session_middleware())         // optional: resolve the session once per request
        .service(auth.scope())                   // all auth routes under base_path (/api/auth)
        .route("/me", web::get().to(me))
})
.bind(("0.0.0.0", 3000))?
.run()
.await?;
```

| axum | actix-web |
|---|---|
| `AuthRouter` | `AuthScope` |
| `.merge(auth.router())` | `.service(auth.scope())` |
| `.layer(auth.session_layer())` | `.wrap(auth.session_middleware())` |
| `.with_state(auth)`, `AppAuth: FromRef<S>` | `.app_data(web::Data::new(auth.clone()))` |
| `into_make_service_with_connect_info` | nothing: actix passes the peer address itself |

`auth.scope()` is an actix `Scope` at `base_path`. Register it on the `App` itself, not
inside another scope: the auth routes match on the full request path, so to serve them under
`/v1/auth`, set `.base_path("/v1/auth")` on the builder. Request bodies are capped at 64 KiB.

The extractors look the auth instance up in app data, as `web::Data<AppAuth>` or as plain
`AppAuth` (`.app_data(auth.clone())`; the instance is two `Arc`s, so either is cheap).
Without it they answer `500` and log why. `fastauth::actix::auth::<AppAuth>(&request)` does
the same lookup for your own extractors.

## Extractors

| Extractor | Rejection |
|---|---|
| `Session<A>` | `401 UNAUTHORIZED` |
| `OptionalSession<A>` | none (a storage error, or an invalid API key with key sessions on, still rejects) |
| `Option<Session<A>>` | none, ever: actix turns every rejection into `None` |
| `FreshSession<A>` | `401` or `403 SESSION_NOT_FRESH` |
| `actix::RequireRole<A, R>` (admin plugin) | `401 UNAUTHORIZED` or `403 FORBIDDEN` |
| `ActiveMember<A>`, `OrgMember<A, S>` (organization plugin) | `401 UNAUTHORIZED`, `403 NO_ACTIVE_ORGANIZATION` or `403 YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION` |
| `RequirePermission<A, P, S>` (organization plugin) | the same, or `403 PERMISSION_DENIED` |

`OptionalSession` is the actix spelling of axum's `Option<Session<A>>`; destructure it in the
signature:

```rust
use fastauth::actix::OptionalSession;

async fn home(OptionalSession(session): OptionalSession<AppAuth>) -> String {
    session.map_or_else(|| "hello, stranger".into(), |s| format!("hello, {}", s.user.name))
}
```

actix-web implements `FromRequest` for every `Option<T>` and maps any error to `None`, so
`Option<Session<A>>` compiles too, but a database outage or a forged API key then reads as
"signed out" instead of an error.

Every extractor in a request shares one session lookup, and rejections are `AuthError`, which
implements actix's `ResponseError` as the same JSON body the auth routes use. Your handlers
can return `Result<T, AuthError>`:

```rust
async fn admin_only(session: Session<AppAuth>) -> Result<String, AuthError> {
    if session.user.email != "root@acme.dk" {
        return Err(AuthError::forbidden());
    }
    Ok("welcome".into())
}
```

## Plugin extractors

The organization plugin's extractors are the same types in both frameworks, so a handler's
signature doesn't change. With the facade's `actix` and `organization` features (or
`fastauth-plugin-organization`'s `actix` feature), `OrgMember`, `ActiveMember` and
`RequirePermission` implement actix's `FromRequest`. `FromPath<P>` reads actix's
`{org_id}` route segment:

```rust
use fastauth::plugins::organization::access::MemberDelete;
use fastauth::plugins::organization::extract::{FromPath, OrgMember, RequirePermission};
use fastauth::plugins::organization::path_param;

path_param!(pub OrgId = "org_id");

async fn org_page(member: OrgMember<AppAuth, FromPath<OrgId>>) -> String {
    member.role.clone()
}

async fn remove(member: RequirePermission<AppAuth, MemberDelete, FromPath<OrgId>>) -> String {
    member.user_id.to_string()
}

App::new()
    .route("/orgs/{org_id}", web::get().to(org_page))
    .route("/orgs/{org_id}/members", web::delete().to(remove))
```

The admin plugin's `RequireRole` derefs to the framework's `Session`, so actix has its own:
`fastauth::plugins::admin::actix::RequireRole`. The roles (`role::Admin`, `role::User`,
`role!`) are shared:

```rust
use fastauth::plugins::admin::actix::RequireRole;
use fastauth::plugins::admin::role;

async fn dashboard(admin: RequireRole<AppAuth, role::Admin>) -> String {
    format!("hello {}", admin.user.email)
}
```

## The session middleware

Sliding expiry renews a session when it's used, and a cookie that no longer matches a
session should be cleared. On the auth routes fastauth sets those cookies itself. On your
own routes, `auth.session_middleware()` adds them: it resolves the session only when an
extractor asks for it, at most once per request, and appends the refreshed or cleared
cookies to the response unless the handler already set a cookie of the same name. Without
it, your routes still work; the browser's cookie just isn't renewed until the next auth
route call.

## Client IP

The scope puts the connection's peer address in the request as `ClientAddr`, which is what
`ClientIp::Socket` (the default) reads for rate limits and the session's `ip_address`.
Behind a proxy the peer is the proxy, so configure `.client_ip(ClientIp::Header(..))` or
`ClientIp::TrustedProxies { .. }` exactly as with axum
([Configuration](../get-started/03-configuration.md#rate-limits)). fastauth reads those
headers itself; actix's `ConnectionInfo::realip_remote_addr` isn't consulted.

## Bearer tokens and response hooks

Plugins that answer through response hooks, such as the [bearer](../plugins/tokens/01-bearer.md)
plugin's `set-auth-token` header, work unchanged: hooks run inside the auth routes, before
the scope hands the response to actix. Sessions from `Authorization: Bearer` or an
[API key](../plugins/tokens/03-api-keys.md) reach `Session<A>` on your own routes like
cookie sessions do.

## Calling the server API

The [server API](../concepts/01-sessions.md#the-server-api) takes `http` 1 headers. actix-web 4 is built on
`http` 0.2, so convert with `fastauth::actix::headers`. `ApiResponse<T>` implements actix's
`Responder`, so a handler can return a server API result as the HTTP route would answer it,
cookies included:

```rust
use fastauth::ApiResponse;
use fastauth::routes::SignOutOutput;

async fn log_out(
    auth: web::Data<AppAuth>,
    request: HttpRequest,
) -> Result<ApiResponse<SignOutOutput>, AuthError> {
    auth.api().headers(&fastauth::actix::headers(&request)).sign_out().await
}
```

`crates/fastauth/examples/actix_sqlite.rs` is the `axum_sqlite` example on actix-web, and
the Better Auth client suite runs against it: `SERVER=actix tests/compat/better-auth/run.sh`.
