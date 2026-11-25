use std::convert::Infallible;
use std::net::SocketAddr;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::{ConnectInfo, OriginalUri};
use axum::response::Response;
use fastauth_core::endpoint::BoxFuture;
use fastauth_core::error::codes;
use fastauth_core::{AuthError, AuthInstance, ClientAddr};
use http::StatusCode;
use http_body_util::{BodyExt, LengthLimitError, Limited};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const MAX_BODY: usize = 64 * 1024;

/// Collects the body (64 KiB cap), passes the socket address and original URI along, and
/// hands the request to `AuthInstance::handle`.
pub(crate) async fn serve<A, B>(auth: A, request: http::Request<B>) -> Response
where
    A: AuthInstance,
    B: http_body::Body,
    B::Error: Into<BoxError>,
{
    let (mut parts, body) = request.into_parts();
    let body = match Limited::new(body, MAX_BODY).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) if err.is::<LengthLimitError>() => {
            return error(AuthError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                codes::INVALID_BODY,
                "request body is too large",
            ));
        }
        Err(_) => {
            return error(AuthError::bad_request(
                codes::INVALID_BODY,
                "could not read the request body",
            ));
        }
    };
    if let Some(OriginalUri(uri)) = parts.extensions.get::<OriginalUri>() {
        parts.uri = uri.clone();
    }
    if let Some(ConnectInfo(addr)) = parts.extensions.get::<ConnectInfo<SocketAddr>>() {
        let ip = addr.ip();
        parts.extensions.insert(ClientAddr(ip));
    }
    auth.handle(http::Request::from_parts(parts, body))
        .await
        .map(Body::from)
}

fn error(err: AuthError) -> Response {
    err.into_response().map(Body::from)
}

/// The auth routes as a `tower::Service`. Build it with `AuthRouter::service`.
#[derive(Clone)]
pub struct AuthService<A> {
    auth: A,
}

impl<A> AuthService<A> {
    pub(crate) fn new(auth: A) -> Self {
        Self { auth }
    }
}

impl<A, B> tower_service::Service<http::Request<B>> for AuthService<A>
where
    A: AuthInstance,
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Response, Infallible>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let auth = self.auth.clone();
        Box::pin(async move { Ok(serve(auth, request).await) })
    }
}
