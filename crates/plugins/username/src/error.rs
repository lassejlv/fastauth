//! The error codes the username plugin answers with.

use fastauth_core::plugin_prelude::*;

/// Why a username request failed. Codes and messages match Better Auth's
/// `USERNAME_ERROR_CODES`. A bad username is a 400 on sign-up and update-user, and a 422 on
/// `/sign-in/username` and `/is-username-available`, as in Better Auth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsernameError {
    /// `INVALID_USERNAME_OR_PASSWORD` (401).
    InvalidUsernameOrPassword,
    /// `USERNAME_IS_ALREADY_TAKEN` (400).
    UsernameIsAlreadyTaken,
    /// `USERNAME_TOO_SHORT` (400 or 422).
    UsernameTooShort,
    /// `USERNAME_TOO_LONG` (400 or 422).
    UsernameTooLong,
    /// `INVALID_USERNAME` (400 or 422): the validator refused it.
    InvalidUsername,
    /// `INVALID_DISPLAY_USERNAME` (400): the display username validator refused it.
    InvalidDisplayUsername,
    /// `USERNAME_IS_IMMUTABLE` (400): `immutable_username` is on and the user has one.
    UsernameIsImmutable,
}

impl UsernameError {
    const fn parts(self) -> (StatusCode, &'static str, &'static str) {
        match self {
            Self::InvalidUsernameOrPassword => (
                StatusCode::UNAUTHORIZED,
                "INVALID_USERNAME_OR_PASSWORD",
                "Invalid username or password",
            ),
            Self::UsernameIsAlreadyTaken => (
                StatusCode::BAD_REQUEST,
                "USERNAME_IS_ALREADY_TAKEN",
                "Username is already taken. Please try another.",
            ),
            Self::UsernameTooShort => (
                StatusCode::BAD_REQUEST,
                "USERNAME_TOO_SHORT",
                "Username is too short",
            ),
            Self::UsernameTooLong => (
                StatusCode::BAD_REQUEST,
                "USERNAME_TOO_LONG",
                "Username is too long",
            ),
            Self::InvalidUsername => (
                StatusCode::BAD_REQUEST,
                "INVALID_USERNAME",
                "Username is invalid",
            ),
            Self::InvalidDisplayUsername => (
                StatusCode::BAD_REQUEST,
                "INVALID_DISPLAY_USERNAME",
                "Display username is invalid",
            ),
            Self::UsernameIsImmutable => (
                StatusCode::BAD_REQUEST,
                "USERNAME_IS_IMMUTABLE",
                "Username cannot be updated",
            ),
        }
    }

    /// The machine-readable code clients see.
    pub const fn code(self) -> &'static str {
        self.parts().1
    }

    /// The same error answered with 422, as sign-in and the availability check do.
    pub(crate) fn unprocessable(self) -> AuthError {
        let (_, code, message) = self.parts();
        AuthError::new(StatusCode::UNPROCESSABLE_ENTITY, code, message)
    }
}

impl From<UsernameError> for AuthError {
    fn from(err: UsernameError) -> Self {
        let (status, code, message) = err.parts();
        AuthError::new(status, code, message)
    }
}

impl ErrorCodes for UsernameError {
    const CODES: &'static [&'static str] = &[
        Self::InvalidUsernameOrPassword.code(),
        Self::UsernameIsAlreadyTaken.code(),
        Self::UsernameTooShort.code(),
        Self::UsernameTooLong.code(),
        Self::InvalidUsername.code(),
        Self::InvalidDisplayUsername.code(),
        Self::UsernameIsImmutable.code(),
    ];
}
