//! The error codes the API key plugin answers with.

use fastauth_core::plugin_prelude::*;

/// Why an API key request failed. Codes, messages and statuses match Better Auth's
/// `apiKey` plugin.
#[derive(AuthError, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiKeyError {
    #[auth_error(status = 400, message = "metadata must be an object or undefined")]
    InvalidMetadataType,
    #[auth_error(
        status = 400,
        message = "refillAmount is required when refillInterval is provided"
    )]
    RefillAmountAndIntervalRequired,
    #[auth_error(
        status = 400,
        message = "refillInterval is required when refillAmount is provided"
    )]
    RefillIntervalAndAmountRequired,
    #[auth_error(status = 401, message = "Unauthorized or invalid session")]
    UnauthorizedSession,
    /// Also what verification answers when the key lacks a requested permission.
    #[auth_error(status = 404, message = "API Key not found")]
    KeyNotFound,
    #[auth_error(status = 401, message = "API Key is disabled")]
    KeyDisabled,
    #[auth_error(status = 401, message = "API Key has expired")]
    KeyExpired,
    #[auth_error(status = 429, message = "API Key has reached its usage limit")]
    UsageExceeded,
    #[auth_error(
        status = 400,
        message = "The expiresIn is smaller than the predefined minimum value."
    )]
    ExpiresInIsTooSmall,
    #[auth_error(
        status = 400,
        message = "The expiresIn is larger than the predefined maximum value."
    )]
    ExpiresInIsTooLarge,
    #[auth_error(
        status = 400,
        message = "The prefix length is either too large or too small."
    )]
    InvalidPrefixLength,
    #[auth_error(
        status = 400,
        message = "The name length is either too large or too small."
    )]
    InvalidNameLength,
    #[auth_error(status = 400, message = "Metadata is disabled.")]
    MetadataDisabled,
    /// The per-key rate limit. Verification adds `details.tryAgainIn` in milliseconds.
    #[auth_error(status = 429, message = "Rate limit exceeded.")]
    RateLimited,
    #[auth_error(status = 400, message = "No values to update.")]
    NoValuesToUpdate,
    #[auth_error(status = 401, message = "Invalid API key.")]
    InvalidApiKey,
    #[auth_error(
        status = 400,
        message = "The property you're trying to set can only be set from the server auth instance only."
    )]
    ServerOnlyProperty,
    #[auth_error(status = 500, message = "Failed to update API key")]
    FailedToUpdateApiKey,
    #[auth_error(status = 400, message = "API Key name is required.")]
    NameRequired,
}
