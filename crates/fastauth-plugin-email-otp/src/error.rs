//! The error codes email OTP answers with.

use fastauth_core::plugin_prelude::*;

/// Why an email OTP request failed. Codes, statuses and messages match Better Auth's
/// `emailOTP` plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmailOtpError {
    /// `OTP_EXPIRED` (400): the code is past its lifetime; send a new one.
    OtpExpired,
    /// `INVALID_OTP` (400): the code is wrong, used, or was never sent.
    InvalidOtp,
    /// `TOO_MANY_ATTEMPTS` (403): the code took too many wrong guesses and is burnt.
    TooManyAttempts,
    /// `INVALID_OTP_TYPE` (400): `change-email` isn't supported by this route.
    InvalidOtpType,
}

impl EmailOtpError {
    const fn parts(self) -> (StatusCode, &'static str, &'static str) {
        match self {
            Self::OtpExpired => (StatusCode::BAD_REQUEST, "OTP_EXPIRED", "OTP expired"),
            Self::InvalidOtp => (StatusCode::BAD_REQUEST, "INVALID_OTP", "Invalid OTP"),
            Self::TooManyAttempts => (
                StatusCode::FORBIDDEN,
                "TOO_MANY_ATTEMPTS",
                "Too many attempts",
            ),
            Self::InvalidOtpType => (
                StatusCode::BAD_REQUEST,
                "INVALID_OTP_TYPE",
                "Invalid OTP type",
            ),
        }
    }

    /// The machine-readable code clients see.
    pub const fn code(self) -> &'static str {
        self.parts().1
    }
}

impl From<EmailOtpError> for AuthError {
    fn from(err: EmailOtpError) -> Self {
        let (status, code, message) = err.parts();
        AuthError::new(status, code, message)
    }
}

impl ErrorCodes for EmailOtpError {
    const CODES: &'static [&'static str] = &[
        Self::OtpExpired.code(),
        Self::InvalidOtp.code(),
        Self::TooManyAttempts.code(),
        Self::InvalidOtpType.code(),
    ];
}
