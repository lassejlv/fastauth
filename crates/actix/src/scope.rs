use actix_web::{HttpRequest, HttpResponse, web};
use fastauth_core::error::codes;
use fastauth_core::{AuthError, AuthInstance, ClientAddr};
use http::StatusCode;

use crate::convert;

const MAX_BODY: usize = 64 * 1024;

/// Collects the body (64 KiB cap), passes the peer address along, and hands the request to
/// `AuthInstance::handle`.
pub(crate) async fn serve<A: AuthInstance>(
    auth: A,
    request: HttpRequest,
    payload: web::Payload,
) -> HttpResponse {
    let body = match payload.to_bytes_limited(MAX_BODY).await {
        Ok(Ok(body)) => body,
        Err(_) => {
            return convert::response(
                AuthError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    codes::INVALID_BODY,
                    "request body is too large",
                )
                .into_response(),
            );
        }
        Ok(Err(_)) => {
            return convert::response(
                AuthError::bad_request(codes::INVALID_BODY, "could not read the request body")
                    .into_response(),
            );
        }
    };
    let mut builder = http::Request::builder()
        .method(request.method().as_str())
        .uri(request.uri().to_string());
    if let Some(headers) = builder.headers_mut() {
        *headers = convert::headers(request.headers());
    }
    if let Some(peer) = request.peer_addr() {
        builder = builder.extension(ClientAddr(peer.ip()));
    }
    let request = match builder.body(body) {
        Ok(request) => request,
        Err(err) => return convert::response(AuthError::internal(err).into_response()),
    };
    convert::response(auth.handle(request).await)
}
