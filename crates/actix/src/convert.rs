//! actix-web 4 is built on `http` 0.2 and fastauth on `http` 1, so headers and responses
//! are copied across at the boundary.

use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use bytes::Bytes;

pub(crate) fn headers(from: &actix_web::http::header::HeaderMap) -> http::HeaderMap {
    let mut headers = http::HeaderMap::with_capacity(from.len());
    for (name, value) in from {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_str().as_bytes()),
            http::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            headers.append(name, value);
        }
    }
    headers
}

pub(crate) fn response(response: http::Response<Bytes>) -> HttpResponse {
    let (parts, body) = response.into_parts();
    let status =
        StatusCode::from_u16(parts.status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = HttpResponse::build(status);
    for (name, value) in &parts.headers {
        builder.append_header((name.as_str(), value.as_bytes()));
    }
    builder.body(body)
}
