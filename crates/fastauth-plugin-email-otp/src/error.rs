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
    /// `CHANGE_EMAIL_WITH_OTP_IS_DISABLED` (400): the change-email flow is off.
    ChangeEmailDisabled,
    /// `EMAIL_IS_THE_SAME` (400): the new email is the user's current one.
    EmailIsTheSame,
    /// `OTP_IS_REQUIRED_TO_VERIFY_CURRENT_EMAIL` (400): `verify_current_email` is on and the
    /// request has no code for the current address.
    CurrentEmailOtpRequired,
    /// `EMAIL_ALREADY_IN_USE` (400): another user has the new email. Only answered after a
    /// right code, so it reveals nothing to someone who doesn't own the address.
    EmailAlreadyInUse,
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
            Self::ChangeEmailDisabled => (
                StatusCode::BAD_REQUEST,
                "CHANGE_EMAIL_WITH_OTP_IS_DISABLED",
                "Change email with OTP is disabled",
            ),
            Self::EmailIsTheSame => (
                StatusCode::BAD_REQUEST,
                "EMAIL_IS_THE_SAME",
                "Email is the same",
            ),
            Self::CurrentEmailOtpRequired => (
                StatusCode::BAD_REQUEST,
                "OTP_IS_REQUIRED_TO_VERIFY_CURRENT_EMAIL",
                "OTP is required to verify current email",
            ),
            Self::EmailAlreadyInUse => (
                StatusCode::BAD_REQUEST,
                "EMAIL_ALREADY_IN_USE",
                "Email already in use",
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
        Self::ChangeEmailDisabled.code(),
        Self::EmailIsTheSame.code(),
        Self::CurrentEmailOtpRequired.code(),
        Self::EmailAlreadyInUse.code(),
    ];
}
