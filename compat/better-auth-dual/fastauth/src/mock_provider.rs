//! A social provider for the suite's mock OAuth server (`suite/mock-oauth.ts`), standing in
//! for a provider both apps configure. Better Auth reaches the same server through its
//! `genericOAuth` plugin under the same provider id, so both apps write the same account rows.

use fastauth::social::provider::{
    self, AuthorizationRequest, OAuthError, OAuthProfile, OAuthTokens, TokenRequest,
};
use fastauth::social::{Http, OAuthProvider};
use serde::Deserialize;

pub const ID: &str = "mock";
pub const CLIENT_ID: &str = "dual-suite";
pub const CLIENT_SECRET: &str = "dual-suite-secret";

#[derive(Clone, Debug)]
pub struct MockProvider {
    base: String,
}

impl MockProvider {
    pub fn new(base: impl Into<String>) -> Self {
        Self { base: base.into() }
    }
}

#[derive(Deserialize)]
struct UserInfo {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    picture: Option<String>,
}

impl OAuthProvider for MockProvider {
    fn id(&self) -> &str {
        ID
    }

    fn authorization_url(&self, request: &AuthorizationRequest<'_>) -> url::Url {
        provider::authorization_url(
            &format!("{}/authorize", self.base),
            CLIENT_ID,
            &["openid".into(), "email".into()],
            request,
        )
    }

    async fn exchange_code(
        &self,
        http: &Http<'_>,
        request: &TokenRequest<'_>,
    ) -> Result<OAuthTokens, OAuthError> {
        provider::exchange_code(
            http,
            &format!("{}/token", self.base),
            CLIENT_ID,
            CLIENT_SECRET,
            request,
        )
        .await
    }

    async fn profile(
        &self,
        http: &Http<'_>,
        tokens: &OAuthTokens,
    ) -> Result<OAuthProfile, OAuthError> {
        let info: UserInfo = http
            .get_json(&format!("{}/userinfo", self.base), &tokens.access_token)
            .await?;
        Ok(OAuthProfile {
            id: info.sub,
            email: info.email,
            email_verified: info.email_verified.unwrap_or(false),
            name: info.name,
            image: info.picture,
        })
    }
}
