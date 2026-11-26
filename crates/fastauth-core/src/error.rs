use std::borrow::Cow;
use std::fmt;

use bytes::Bytes;
use http::{HeaderValue, StatusCode, header};
use serde::Serialize;

/// Error codes shared with Better Auth's client, so its `error.code` checks keep working.
pub mod codes {
    pub const UNAUTHORIZED: &str = "UNAUTHORIZED";
    pub const FORBIDDEN: &str = "FORBIDDEN";
    pub const NOT_FOUND: &str = "NOT_FOUND";
    pub const METHOD_NOT_ALLOWED: &str = "METHOD_NOT_ALLOWED";
    pub const INTERNAL: &str = "INTERNAL_SERVER_ERROR";
    pub const INVALID_BODY: &str = "INVALID_REQUEST_BODY";
    pub const TOO_MANY_REQUESTS: &str = "TOO_MANY_REQUESTS";
    pub const INVALID_ORIGIN: &str = "INVALID_ORIGIN";
    pub const MISSING_OR_NULL_ORIGIN: &str = "MISSING_OR_NULL_ORIGIN";
    pub const INVALID_CALLBACK_URL: &str = "INVALID_CALLBACK_URL";
    pub const SESSION_NOT_FRESH: &str = "SESSION_NOT_FRESH";
    pub const INVALID_EMAIL: &str = "INVALID_EMAIL";
    pub const INVALID_EMAIL_OR_PASSWORD: &str = "INVALID_EMAIL_OR_PASSWORD";
    pub const INVALID_PASSWORD: &str = "INVALID_PASSWORD";
    pub const PASSWORD_TOO_SHORT: &str = "PASSWORD_TOO_SHORT";
    pub const PASSWORD_TOO_LONG: &str = "PASSWORD_TOO_LONG";
    pub const PASSWORD_TOO_WEAK: &str = "PASSWORD_TOO_WEAK";
    pub const USER_ALREADY_EXISTS: &str = "USER_ALREADY_EXISTS";
    pub const USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL: &str = "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL";
    pub const USER_NOT_FOUND: &str = "USER_NOT_FOUND";
    pub const EMAIL_NOT_VERIFIED: &str = "EMAIL_NOT_VERIFIED";
    pub const EMAIL_ALREADY_VERIFIED: &str = "EMAIL_ALREADY_VERIFIED";
    pub const INVALID_TOKEN: &str = "INVALID_TOKEN";
    pub const CREDENTIAL_ACCOUNT_NOT_FOUND: &str = "CREDENTIAL_ACCOUNT_NOT_FOUND";
    pub const SOCIAL_ACCOUNT_ALREADY_LINKED: &str = "SOCIAL_ACCOUNT_ALREADY_LINKED";
    pub const SESSION_NOT_FOUND: &str = "SESSION_NOT_FOUND";
    pub const INVALID_FIELD: &str = "INVALID_FIELD";
    pub const FEATURE_DISABLED: &str = "FEATURE_DISABLED";
}

/// The one error type every endpoint, hook and extractor returns. It leaves the server as
/// `{ "code": "...", "message": "..." }` with `status`.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthError {
    status: StatusCode,
    code: Cow<'static, str>,
    message: Cow<'static, str>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: &'a str,
}

impl AuthError {
    pub const fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code: Cow::Borrowed(code),
            message: Cow::Borrowed(message),
        }
    }

    pub fn with_message(
        status: StatusCode,
        code: impl Into<Cow<'static, str>>,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn bad_request(
        code: impl Into<Cow<'static, str>>,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::with_message(StatusCode::BAD_REQUEST, code, message)
    }

    pub const fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            codes::UNAUTHORIZED,
            "a valid session is required",
        )
    }

    pub const fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, codes::FORBIDDEN, "not allowed")
    }

    pub const fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, codes::NOT_FOUND, "not found")
    }

    /// 403 `SESSION_NOT_FRESH`: the session is older than `fresh_age`.
    pub const fn not_fresh() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            codes::SESSION_NOT_FRESH,
            "sign in again to continue",
        )
    }

    pub const fn too_many_requests() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            codes::TOO_MANY_REQUESTS,
            "too many requests, try again later",
        )
    }

    /// Logs `detail` server-side and returns a generic 500, so internals never reach clients.
    pub fn internal(detail: impl fmt::Display) -> Self {
        tracing::error!(error = %detail, "fastauth internal error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            "internal server error",
        )
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn to_json(&self) -> Bytes {
        let body = ErrorBody {
            code: &self.code,
            message: &self.message,
        };
        Bytes::from(serde_json::to_vec(&body).expect("error body serializes"))
    }

    pub fn into_response(self) -> http::Response<Bytes> {
        let mut response = http::Response::new(self.to_json());
        *response.status_mut() = self.status;
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if self.status == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("10"));
        }
        response
    }
}

/// Lets axum handlers return `Result<T, AuthError>`: the same JSON body the auth routes use.
#[cfg(feature = "axum")]
impl axum_core::response::IntoResponse for AuthError {
    fn into_response(self) -> axum_core::response::Response {
        AuthError::into_response(self).map(axum_core::body::Body::from)
    }
}

/// Lets actix-web handlers and extractors return `AuthError`: the same JSON body the auth
/// routes use.
#[cfg(feature = "actix")]
impl actix_web::ResponseError for AuthError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        actix_web::http::StatusCode::from_u16(self.status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn error_response(&self) -> actix_web::HttpResponse {
        to_actix(self.clone().into_response())
    }
}

/// An `http` 1.x response as an actix-web response, which is built on `http` 0.2.
#[cfg(feature = "actix")]
pub(crate) fn to_actix(response: http::Response<Bytes>) -> actix_web::HttpResponse {
    let (parts, body) = response.into_parts();
    let status = actix_web::http::StatusCode::from_u16(parts.status.as_u16())
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = actix_web::HttpResponse::build(status);
    for (name, value) in &parts.headers {
        builder.append_header((name.as_str(), value.as_bytes()));
    }
    builder.body(body)
}

impl fmt::Debug for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AuthError({} {}: {})",
            self.status.as_u16(),
            self.code,
            self.message
        )
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AuthError {}

/// Lets a plugin register its error codes at build time, so two plugins can't claim one code.
pub trait ErrorCodes: Into<AuthError> {
    const CODES: &'static [&'static str];
}

/// Configuration problems found by `.build()`, all reported at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildError {
    pub problems: Vec<String>,
}

impl BuildError {
    pub fn new(problem: impl Into<String>) -> Self {
        Self {
            problems: vec![problem.into()],
        }
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid fastauth configuration")?;
        for problem in &self.problems {
            write!(f, "\n  - {problem}")?;
        }
        Ok(())
    }
}

impl std::error::Error for BuildError {}
