//! The error codes passkeys answer with.

use fastauth_core::plugin_prelude::*;

/// Why a passkey request failed. Codes and statuses match Better Auth's passkey plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasskeyError {
    /// `CHALLENGE_NOT_FOUND` (400): no challenge cookie, or its challenge expired, was used
    /// already, or belongs to the other ceremony.
    ChallengeNotFound,
    /// `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY` (401): the challenge was issued to
    /// another user, or the passkey being renamed isn't the caller's.
    NotAllowed,
    /// `FAILED_TO_VERIFY_REGISTRATION` (400): the attestation doesn't check out, or the
    /// credential is registered already.
    FailedToVerifyRegistration,
    /// `PASSKEY_NOT_FOUND` (401): no passkey has the credential that signed in.
    UnknownCredential,
    /// `PASSKEY_NOT_FOUND` (404): no passkey has this id.
    PasskeyNotFound,
    /// `AUTHENTICATION_FAILED` (401): the assertion's signature is wrong.
    AuthenticationFailed,
    /// `AUTHENTICATION_FAILED` (400): the assertion is malformed, answers another challenge
    /// or origin, lacks user verification, or its signature counter didn't advance.
    InvalidAssertion,
    /// `ORIGIN_NOT_CONFIGURED` (500): the rpID and origins don't make a valid relying party.
    OriginNotConfigured,
}

impl PasskeyError {
    const fn parts(self) -> (StatusCode, &'static str, &'static str) {
        match self {
            Self::ChallengeNotFound => (
                StatusCode::BAD_REQUEST,
                "CHALLENGE_NOT_FOUND",
                "Challenge not found",
            ),
            Self::NotAllowed => (
                StatusCode::UNAUTHORIZED,
                "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
                "You are not allowed to register this passkey",
            ),
            Self::FailedToVerifyRegistration => (
                StatusCode::BAD_REQUEST,
                "FAILED_TO_VERIFY_REGISTRATION",
                "Failed to verify registration",
            ),
            Self::UnknownCredential => (
                StatusCode::UNAUTHORIZED,
                "PASSKEY_NOT_FOUND",
                "Passkey not found",
            ),
            Self::PasskeyNotFound => (
                StatusCode::NOT_FOUND,
                "PASSKEY_NOT_FOUND",
                "Passkey not found",
            ),
            Self::AuthenticationFailed => (
                StatusCode::UNAUTHORIZED,
                "AUTHENTICATION_FAILED",
                "Authentication failed",
            ),
            Self::InvalidAssertion => (
                StatusCode::BAD_REQUEST,
                "AUTHENTICATION_FAILED",
                "Authentication failed",
            ),
            Self::OriginNotConfigured => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "ORIGIN_NOT_CONFIGURED",
                "Passkey origin is not configured. Set the passkey plugin's `rp_id` and `origin` \
                 to match `base_url`.",
            ),
        }
    }

    /// The machine-readable code clients see.
    pub const fn code(self) -> &'static str {
        self.parts().1
    }
}

impl From<PasskeyError> for AuthError {
    fn from(err: PasskeyError) -> Self {
        let (status, code, message) = err.parts();
        AuthError::new(status, code, message)
    }
}

impl ErrorCodes for PasskeyError {
    const CODES: &'static [&'static str] = &[
        Self::ChallengeNotFound.code(),
        Self::NotAllowed.code(),
        Self::FailedToVerifyRegistration.code(),
        Self::PasskeyNotFound.code(),
        Self::AuthenticationFailed.code(),
        Self::OriginNotConfigured.code(),
    ];
}
