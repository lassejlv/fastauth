//! The `Social` plugin value and its configuration.

use std::fmt;
use std::sync::Arc;

use fastauth_core::AuthError;
use fastauth_core::adapter::Adapter;
use fastauth_core::error::ErrorCodes;
use fastauth_core::plugin::{Plugin, PluginBuilder};
use http::StatusCode;

use crate::http::{DynHttpClient, Http, HttpClient};
use crate::provider::{DynProvider, OAuthProvider};
use crate::routes::{LinkSocial, ListAccounts, SignInSocial, SocialCallback, UnlinkAccount};

/// Whether a social sign-in may attach to an existing user with the same email.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AccountLinking {
    /// Link when the provider reports the email as verified (default).
    #[default]
    ByVerifiedEmail,
    /// Never link by email; the sign-in fails with `account_not_linked`. Signed-in users can
    /// still link through `/link-social`.
    Off,
}

/// Social sign-in as a plugin: `.plugin(Social::new().provider(Github::from_env()?))`.
pub struct Social {
    pub(crate) providers: Vec<Arc<dyn DynProvider>>,
    pub(crate) http: Arc<dyn DynHttpClient>,
    pub(crate) account_linking: AccountLinking,
}

impl fmt::Debug for Social {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Social")
            .field(
                "providers",
                &self.providers.iter().map(|p| p.id()).collect::<Vec<_>>(),
            )
            .field("account_linking", &self.account_linking)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "reqwest")]
impl Default for Social {
    fn default() -> Self {
        Self::new()
    }
}

impl Social {
    /// No providers yet, and the reqwest client.
    #[cfg(feature = "reqwest")]
    pub fn new() -> Self {
        Self::with_http_client(crate::http::ReqwestClient::new())
    }

    /// No providers yet, and your own HTTP client.
    pub fn with_http_client(client: impl HttpClient) -> Self {
        Self {
            providers: Vec::new(),
            http: Arc::new(client),
            account_linking: AccountLinking::default(),
        }
    }

    /// Adds a provider. A provider with the same id replaces the earlier one.
    pub fn provider(mut self, provider: impl OAuthProvider) -> Self {
        self.providers.retain(|p| p.id() != provider.id());
        self.providers.push(Arc::new(provider));
        self
    }

    pub fn account_linking(mut self, linking: AccountLinking) -> Self {
        self.account_linking = linking;
        self
    }

    pub(crate) fn find(&self, id: &str) -> Option<&dyn DynProvider> {
        self.providers.iter().find(|p| p.id() == id).map(|p| &**p)
    }

    pub(crate) fn http(&self) -> Http<'_> {
        Http::from_dyn(&*self.http)
    }
}

impl Plugin for Social {
    const ID: &'static str = "social";
    type Requires = ();
    type UserFields = ();
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.endpoint(SignInSocial(self.clone()))
            .endpoint(SocialCallback(self.clone()))
            .endpoint(LinkSocial(self.clone()))
            .endpoint(ListAccounts)
            .endpoint(UnlinkAccount)
            .errors::<SocialError>();
    }
}

/// Errors the social endpoints answer with as JSON. Callback failures redirect instead,
/// with `?error=` set to one of Better Auth's callback error strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocialError {
    /// 404 `PROVIDER_NOT_FOUND`.
    ProviderNotFound,
    /// 400 `ACCOUNT_NOT_FOUND`.
    AccountNotFound,
    /// 400 `FAILED_TO_UNLINK_LAST_ACCOUNT`: it is the user's only way to sign in.
    LastAccount,
}

impl From<SocialError> for AuthError {
    fn from(err: SocialError) -> Self {
        match err {
            SocialError::ProviderNotFound => AuthError::new(
                StatusCode::NOT_FOUND,
                "PROVIDER_NOT_FOUND",
                "provider not found",
            ),
            SocialError::AccountNotFound => AuthError::new(
                StatusCode::BAD_REQUEST,
                "ACCOUNT_NOT_FOUND",
                "account not found",
            ),
            SocialError::LastAccount => AuthError::new(
                StatusCode::BAD_REQUEST,
                "FAILED_TO_UNLINK_LAST_ACCOUNT",
                "you can't unlink your last account",
            ),
        }
    }
}

impl ErrorCodes for SocialError {
    const CODES: &'static [&'static str] = &[
        "PROVIDER_NOT_FOUND",
        "ACCOUNT_NOT_FOUND",
        "FAILED_TO_UNLINK_LAST_ACCOUNT",
    ];
}
