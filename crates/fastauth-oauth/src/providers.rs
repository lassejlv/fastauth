//! Built-in providers.

use std::fmt;

use fastauth_core::BuildError;
use serde::Deserialize;
use url::Url;

use crate::http::Http;
use crate::provider::{
    self, AuthorizationRequest, OAuthError, OAuthProfile, OAuthProvider, OAuthTokens, TokenRequest,
};

fn env(var: &str) -> Result<String, BuildError> {
    std::env::var(var)
        .map_err(|_| BuildError::new(format!("environment variable `{var}` is not set")))
}

fn owned(scopes: impl IntoIterator<Item = impl Into<String>>) -> Vec<String> {
    scopes.into_iter().map(Into::into).collect()
}

/// GitHub. The profile's email comes from `/user`, or from `/user/emails` (the primary
/// address) when it isn't public; `/user/emails` also says whether it is verified.
#[derive(Clone)]
pub struct Github {
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
}

impl fmt::Debug for Github {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Github")
            .field("client_id", &self.client_id)
            .field("scopes", &self.scopes)
            .finish_non_exhaustive()
    }
}

impl Github {
    const AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";
    const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
    const USER_URL: &str = "https://api.github.com/user";
    const EMAILS_URL: &str = "https://api.github.com/user/emails";

    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scopes: owned(["read:user", "user:email"]),
        }
    }

    /// From `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`.
    pub fn from_env() -> Result<Self, BuildError> {
        Ok(Self::new(
            env("GITHUB_CLIENT_ID")?,
            env("GITHUB_CLIENT_SECRET")?,
        ))
    }

    /// Replaces the default scopes, `read:user` and `user:email`.
    pub fn scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes = owned(scopes);
        self
    }
}

#[derive(Deserialize)]
struct GithubUser {
    id: u64,
    login: String,
    name: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

impl OAuthProvider for Github {
    fn id(&self) -> &str {
        "github"
    }

    fn authorization_url(&self, request: &AuthorizationRequest<'_>) -> Url {
        provider::authorization_url(Self::AUTHORIZE_URL, &self.client_id, &self.scopes, request)
    }

    async fn exchange_code(
        &self,
        http: &Http<'_>,
        request: &TokenRequest<'_>,
    ) -> Result<OAuthTokens, OAuthError> {
        provider::exchange_code(
            http,
            Self::TOKEN_URL,
            &self.client_id,
            &self.client_secret,
            request,
        )
        .await
    }

    async fn profile(
        &self,
        http: &Http<'_>,
        tokens: &OAuthTokens,
    ) -> Result<OAuthProfile, OAuthError> {
        let user: GithubUser = http.get_json(Self::USER_URL, &tokens.access_token).await?;
        let emails: Vec<GithubEmail> = match http
            .get_json(Self::EMAILS_URL, &tokens.access_token)
            .await
        {
            Ok(emails) => emails,
            Err(err) if user.email.is_some() => {
                tracing::debug!(error = %err, "GitHub /user/emails failed; using the public email as unverified");
                Vec::new()
            }
            Err(err) => return Err(err),
        };
        let email = user.email.or_else(|| {
            emails
                .iter()
                .find(|e| e.primary)
                .or(emails.first())
                .map(|e| e.email.clone())
        });
        let email_verified = email.as_deref().is_some_and(|email| {
            emails
                .iter()
                .any(|e| e.verified && e.email.eq_ignore_ascii_case(email))
        });
        Ok(OAuthProfile {
            id: user.id.to_string(),
            email,
            email_verified,
            name: user.name.or(Some(user.login)),
            image: user.avatar_url,
        })
    }
}

/// Google, with the profile from the OpenID Connect userinfo endpoint.
#[derive(Clone)]
pub struct Google {
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
}

impl fmt::Debug for Google {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Google")
            .field("client_id", &self.client_id)
            .field("scopes", &self.scopes)
            .finish_non_exhaustive()
    }
}

impl Google {
    const AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
    const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
    const USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";

    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scopes: owned(["openid", "email", "profile"]),
        }
    }

    /// From `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`.
    pub fn from_env() -> Result<Self, BuildError> {
        Ok(Self::new(
            env("GOOGLE_CLIENT_ID")?,
            env("GOOGLE_CLIENT_SECRET")?,
        ))
    }

    /// Replaces the default scopes, `openid`, `email` and `profile`.
    pub fn scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes = owned(scopes);
        self
    }
}

#[derive(Deserialize)]
struct GoogleUser {
    sub: String,
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
    name: Option<String>,
    picture: Option<String>,
}

impl OAuthProvider for Google {
    fn id(&self) -> &str {
        "google"
    }

    fn authorization_url(&self, request: &AuthorizationRequest<'_>) -> Url {
        provider::authorization_url(Self::AUTHORIZE_URL, &self.client_id, &self.scopes, request)
    }

    async fn exchange_code(
        &self,
        http: &Http<'_>,
        request: &TokenRequest<'_>,
    ) -> Result<OAuthTokens, OAuthError> {
        provider::exchange_code(
            http,
            Self::TOKEN_URL,
            &self.client_id,
            &self.client_secret,
            request,
        )
        .await
    }

    async fn profile(
        &self,
        http: &Http<'_>,
        tokens: &OAuthTokens,
    ) -> Result<OAuthProfile, OAuthError> {
        let user: GoogleUser = http
            .get_json(Self::USERINFO_URL, &tokens.access_token)
            .await?;
        Ok(OAuthProfile {
            id: user.sub,
            email: user.email,
            email_verified: user.email_verified,
            name: user.name,
            image: user.picture,
        })
    }
}
