//! The error code the multi-session plugin answers with.

use fastauth_core::plugin_prelude::*;

/// Why a multi-session request failed. Matches Better Auth's `MULTI_SESSION_ERROR_CODES`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultiSessionError {
    /// `INVALID_SESSION_TOKEN` (401): the browser holds no signed device-session cookie for
    /// the token, or its session expired or was revoked.
    InvalidSessionToken,
}

impl MultiSessionError {
    /// The machine-readable code clients see.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidSessionToken => "INVALID_SESSION_TOKEN",
        }
    }
}

impl From<MultiSessionError> for AuthError {
    fn from(err: MultiSessionError) -> Self {
        match err {
            MultiSessionError::InvalidSessionToken => AuthError::new(
                StatusCode::UNAUTHORIZED,
                err.code(),
                "Invalid session token",
            ),
        }
    }
}

impl ErrorCodes for MultiSessionError {
    const CODES: &'static [&'static str] = &[Self::InvalidSessionToken.code()];
}
