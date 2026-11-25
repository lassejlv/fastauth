//! The error codes two-factor answers with.

use fastauth_core::plugin_prelude::*;

/// Why a two-factor request failed. Codes and statuses match Better Auth's two-factor plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwoFactorError {
    /// `INVALID_CODE`: the TOTP or email code is wrong, expired or already used.
    InvalidCode,
    /// `INVALID_BACKUP_CODE`: the backup code is wrong or already used.
    InvalidBackupCode,
    /// `OTP_HAS_EXPIRED`: the email code is past its lifetime; send a new one.
    OtpHasExpired,
    /// `TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE`: five wrong email codes burn the code.
    TooManyAttempts,
    /// `TOTP_NOT_ENABLED`: the user never called `/two-factor/enable`.
    TotpNotEnabled,
    /// `TWO_FACTOR_NOT_ENABLED`: two-factor isn't on for this user yet.
    TwoFactorNotEnabled,
    /// `INVALID_TWO_FACTOR_COOKIE`: no session, and no valid pending sign-in cookie.
    InvalidTwoFactorCookie,
}

impl TwoFactorError {
    const fn parts(self) -> (StatusCode, &'static str, &'static str) {
        match self {
            Self::InvalidCode => (StatusCode::UNAUTHORIZED, "INVALID_CODE", "invalid code"),
            Self::InvalidBackupCode => (
                StatusCode::UNAUTHORIZED,
                "INVALID_BACKUP_CODE",
                "invalid backup code",
            ),
            Self::OtpHasExpired => (
                StatusCode::BAD_REQUEST,
                "OTP_HAS_EXPIRED",
                "the code has expired, request a new one",
            ),
            Self::TooManyAttempts => (
                StatusCode::BAD_REQUEST,
                "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
                "too many attempts, request a new code",
            ),
            Self::TotpNotEnabled => (
                StatusCode::BAD_REQUEST,
                "TOTP_NOT_ENABLED",
                "TOTP is not enabled",
            ),
            Self::TwoFactorNotEnabled => (
                StatusCode::BAD_REQUEST,
                "TWO_FACTOR_NOT_ENABLED",
                "two-factor authentication is not enabled",
            ),
            Self::InvalidTwoFactorCookie => (
                StatusCode::UNAUTHORIZED,
                "INVALID_TWO_FACTOR_COOKIE",
                "the two-factor sign-in has expired, sign in again",
            ),
        }
    }

    /// The machine-readable code clients see.
    pub const fn code(self) -> &'static str {
        self.parts().1
    }
}

impl From<TwoFactorError> for AuthError {
    fn from(err: TwoFactorError) -> Self {
        let (status, code, message) = err.parts();
        AuthError::new(status, code, message)
    }
}

impl ErrorCodes for TwoFactorError {
    const CODES: &'static [&'static str] = &[
        Self::InvalidCode.code(),
        Self::InvalidBackupCode.code(),
        Self::OtpHasExpired.code(),
        Self::TooManyAttempts.code(),
        Self::TotpNotEnabled.code(),
        Self::TwoFactorNotEnabled.code(),
        Self::InvalidTwoFactorCookie.code(),
    ];
}
