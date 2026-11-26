//! The error codes magic links answer with.

use fastauth_core::plugin_prelude::*;

/// Why a magic link request failed before any redirect. Codes and statuses match Better
/// Auth's origin check; a bad or used token redirects with `?error=INVALID_TOKEN` instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MagicLinkError {
    /// `INVALID_ERROR_CALLBACK_URL` (403): `errorCallbackURL` isn't on a trusted origin.
    InvalidErrorCallbackUrl,
    /// `INVALID_NEW_USER_CALLBACK_URL` (403): `newUserCallbackURL` isn't on a trusted origin.
    InvalidNewUserCallbackUrl,
}

impl MagicLinkError {
    const fn parts(self) -> (StatusCode, &'static str, &'static str) {
        match self {
            Self::InvalidErrorCallbackUrl => (
                StatusCode::FORBIDDEN,
                "INVALID_ERROR_CALLBACK_URL",
                "Invalid errorCallbackURL",
            ),
            Self::InvalidNewUserCallbackUrl => (
                StatusCode::FORBIDDEN,
                "INVALID_NEW_USER_CALLBACK_URL",
                "Invalid newUserCallbackURL",
            ),
        }
    }

    /// The machine-readable code clients see.
    pub const fn code(self) -> &'static str {
        self.parts().1
    }
}

impl From<MagicLinkError> for AuthError {
    fn from(err: MagicLinkError) -> Self {
        let (status, code, message) = err.parts();
        AuthError::new(status, code, message)
    }
}

impl ErrorCodes for MagicLinkError {
    const CODES: &'static [&'static str] = &[
        Self::InvalidErrorCallbackUrl.code(),
        Self::InvalidNewUserCallbackUrl.code(),
    ];
}
