//! The error codes the anonymous plugin answers with.

use fastauth_core::plugin_prelude::*;

/// Why an anonymous request failed. Codes, statuses and messages match Better Auth's
/// `ANONYMOUS_ERROR_CODES`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnonymousError {
    /// `INVALID_EMAIL_FORMAT` (400): `generate_random_email` returned something that isn't one.
    InvalidEmailFormat,
    /// `ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY` (400).
    AnonymousUsersCannotSignInAgainAnonymously,
    /// `USER_IS_NOT_ANONYMOUS` (403): `/delete-anonymous-user` by a real user.
    UserIsNotAnonymous,
    /// `DELETE_ANONYMOUS_USER_DISABLED` (400): `disable_delete_anonymous_user` is on.
    DeleteAnonymousUserDisabled,
}

impl AnonymousError {
    const fn parts(self) -> (StatusCode, &'static str, &'static str) {
        match self {
            Self::InvalidEmailFormat => (
                StatusCode::BAD_REQUEST,
                "INVALID_EMAIL_FORMAT",
                "Email was not generated in a valid format",
            ),
            Self::AnonymousUsersCannotSignInAgainAnonymously => (
                StatusCode::BAD_REQUEST,
                "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
                "Anonymous users cannot sign in again anonymously",
            ),
            Self::UserIsNotAnonymous => (
                StatusCode::FORBIDDEN,
                "USER_IS_NOT_ANONYMOUS",
                "User is not anonymous",
            ),
            Self::DeleteAnonymousUserDisabled => (
                StatusCode::BAD_REQUEST,
                "DELETE_ANONYMOUS_USER_DISABLED",
                "Deleting anonymous users is disabled",
            ),
        }
    }

    /// The machine-readable code clients see.
    pub const fn code(self) -> &'static str {
        self.parts().1
    }
}

impl From<AnonymousError> for AuthError {
    fn from(err: AnonymousError) -> Self {
        let (status, code, message) = err.parts();
        AuthError::new(status, code, message)
    }
}

impl ErrorCodes for AnonymousError {
    const CODES: &'static [&'static str] = &[
        Self::InvalidEmailFormat.code(),
        Self::AnonymousUsersCannotSignInAgainAnonymously.code(),
        Self::UserIsNotAnonymous.code(),
        Self::DeleteAnonymousUserDisabled.code(),
    ];
}
