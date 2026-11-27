//! The provider contract, and the standard OAuth 2.0 steps most providers share.

use std::future::Future;

use bytes::Bytes;
use fastauth_core::endpoint::BoxFuture;
use http::Request;
use http::header::{ACCEPT, CONTENT_TYPE};
use serde::Deserialize;
use time::{Duration, OffsetDateTime};
use url::Url;

use crate::http::{Http, HttpClientError};

/// What a provider needs to build its authorization URL.
#[derive(Clone, Copy, Debug)]
pub struct AuthorizationRequest<'a> {
    pub state: &'a str,
    /// `BASE64URL(SHA256(code_verifier))`, sent with `code_challenge_method=S256`.
    pub code_challenge: &'a str,
    /// `{base_url}{base_path}/callback/{id}`.
    pub redirect_uri: &'a str,
    /// Scopes the caller asked for on top of the provider's own.
    pub scopes: &'a [String],
}

/// What a provider needs to trade the callback's code for tokens.
#[derive(Clone, Copy, Debug)]
pub struct TokenRequest<'a> {
    pub code: &'a str,
    pub code_verifier: &'a str,
    pub redirect_uri: &'a str,
}

/// Tokens from the provider. Access and refresh tokens are stored encrypted, unless
/// `Builder::store_oauth_tokens_in_plaintext` is on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<OffsetDateTime>,
    pub refresh_token_expires_at: Option<OffsetDateTime>,
    pub scope: Option<String>,
}

/// The provider's user, mapped to what fastauth needs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OAuthProfile {
    /// The provider's stable user id, stored as `account.account_id`.
    pub id: String,
    pub email: Option<String>,
    /// Whether the provider vouches for `email`. Linking by email requires it.
    pub email_verified: bool,
    pub name: Option<String>,
    pub image: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error(transparent)]
    Http(#[from] HttpClientError),
    #[error("provider answered {status}: {body}")]
    Status {
        status: http::StatusCode,
        body: String,
    },
    #[error("provider error `{error}`{}", description.as_deref().map(|d| format!(": {d}")).unwrap_or_default())]
    Provider {
        error: String,
        description: Option<String>,
    },
    #[error("unexpected provider response: {0}")]
    Decode(String),
}

/// A social sign-in provider: an authorization URL, a code exchange and a profile mapping.
pub trait OAuthProvider: Send + Sync + 'static {
    /// The path segment in `/callback/{id}` and `account.provider_id`: `"github"`.
    fn id(&self) -> &str;

    fn authorization_url(&self, request: &AuthorizationRequest<'_>) -> Url;

    fn exchange_code(
        &self,
        http: &Http<'_>,
        request: &TokenRequest<'_>,
    ) -> impl Future<Output = Result<OAuthTokens, OAuthError>> + Send;

    fn profile(
        &self,
        http: &Http<'_>,
        tokens: &OAuthTokens,
    ) -> impl Future<Output = Result<OAuthProfile, OAuthError>> + Send;
}

pub(crate) trait DynProvider: Send + Sync {
    fn id(&self) -> &str;
    fn authorization_url(&self, request: &AuthorizationRequest<'_>) -> Url;
    fn exchange_code<'a>(
        &'a self,
        http: &'a Http<'a>,
        request: &'a TokenRequest<'a>,
    ) -> BoxFuture<'a, Result<OAuthTokens, OAuthError>>;
    fn profile<'a>(
        &'a self,
        http: &'a Http<'a>,
        tokens: &'a OAuthTokens,
    ) -> BoxFuture<'a, Result<OAuthProfile, OAuthError>>;
}

impl<P: OAuthProvider> DynProvider for P {
    fn id(&self) -> &str {
        OAuthProvider::id(self)
    }

    fn authorization_url(&self, request: &AuthorizationRequest<'_>) -> Url {
        OAuthProvider::authorization_url(self, request)
    }

    fn exchange_code<'a>(
        &'a self,
        http: &'a Http<'a>,
        request: &'a TokenRequest<'a>,
    ) -> BoxFuture<'a, Result<OAuthTokens, OAuthError>> {
        Box::pin(OAuthProvider::exchange_code(self, http, request))
    }

    fn profile<'a>(
        &'a self,
        http: &'a Http<'a>,
        tokens: &'a OAuthTokens,
    ) -> BoxFuture<'a, Result<OAuthProfile, OAuthError>> {
        Box::pin(OAuthProvider::profile(self, http, tokens))
    }
}

/// The standard authorization URL: `response_type=code`, client id, redirect URI, the
/// provider's scopes plus the requested ones, state, and an S256 PKCE challenge.
///
/// # Panics
///
/// If `endpoint` is not a valid URL.
pub fn authorization_url(
    endpoint: &str,
    client_id: &str,
    scopes: &[String],
    request: &AuthorizationRequest<'_>,
) -> Url {
    let mut url = Url::parse(endpoint).expect("provider endpoints are valid URLs");
    let mut all: Vec<&str> = Vec::new();
    for scope in scopes.iter().chain(request.scopes) {
        if !all.contains(&scope.as_str()) {
            all.push(scope);
        }
    }
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", request.redirect_uri)
        .append_pair("scope", &all.join(" "))
        .append_pair("state", request.state)
        .append_pair("code_challenge", request.code_challenge)
        .append_pair("code_challenge_method", "S256");
    url
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    expires_in: Option<i64>,
    refresh_token_expires_in: Option<i64>,
    scope: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Trades a code for tokens at a standard token endpoint: client credentials and the PKCE
/// verifier in the form body, a JSON answer.
pub async fn exchange_code(
    http: &Http<'_>,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    request: &TokenRequest<'_>,
) -> Result<OAuthTokens, OAuthError> {
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", request.code),
        ("code_verifier", request.code_verifier),
        ("redirect_uri", request.redirect_uri),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ])
    .map_err(|e| OAuthError::Decode(e.to_string()))?;
    let request = Request::post(token_url)
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Bytes::from(form))
        .map_err(|e| OAuthError::Decode(e.to_string()))?;
    let token: TokenResponse = http.json(request).await?;
    if let Some(error) = token.error {
        return Err(OAuthError::Provider {
            error,
            description: token.error_description,
        });
    }
    let access_token = token
        .access_token
        .ok_or_else(|| OAuthError::Decode("token response has no access_token".into()))?;
    let now = OffsetDateTime::now_utc();
    Ok(OAuthTokens {
        access_token,
        refresh_token: token.refresh_token,
        id_token: token.id_token,
        access_token_expires_at: expires_at(now, token.expires_in),
        refresh_token_expires_at: expires_at(now, token.refresh_token_expires_in),
        scope: token.scope,
    })
}

/// The longest token lifetime taken from a provider's `expires_in`; larger values are clamped
/// to it, so a hostile or broken token endpoint can't overflow the date.
const MAX_EXPIRES_IN: Duration = Duration::days(3650);

/// `now + seconds`, clamped to [`MAX_EXPIRES_IN`]. A negative lifetime counts as unknown.
fn expires_at(now: OffsetDateTime, seconds: Option<i64>) -> Option<OffsetDateTime> {
    let seconds = seconds.filter(|s| *s >= 0)?;
    Some(now + Duration::seconds(seconds).min(MAX_EXPIRES_IN))
}
