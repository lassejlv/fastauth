//! The `Social` plugin value and its configuration.

use std::fmt;
use std::sync::Arc;

use fastauth_core::AuthError;
use fastauth_core::adapter::Adapter;
use fastauth_core::error::ErrorCodes;
use fastauth_core::plugin::{Plugin, PluginBuilder};
use fastauth_core::value::Value;
use http::StatusCode;

use crate::http::{DynHttpClient, Http, HttpClient};
use crate::provider::{DynProvider, OAuthProfile, OAuthProvider};
use crate::routes::{LinkSocial, ListAccounts, SignInSocial, SocialCallback, UnlinkAccount};

/// Whether a social sign-in may attach to an existing user with the same email.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AccountLinking {
    /// Link when the provider reports the email as verified (default).
    #[default]
    ByVerifiedEmail,
    /// Never link: a sign-in by email fails with `account_not_linked`, and `/link-social`
    /// fails with `unable_to_link_account`, like Better Auth's `accountLinking.enabled: false`.
    Off,
}

/// Extra `user` columns for a user created by a social sign-in, from the provider's profile
/// and the provider id. See [`Social::map_profile`].
pub type MapProfile =
    dyn Fn(&OAuthProfile, &str) -> Result<Vec<(&'static str, Value)>, AuthError> + Send + Sync;

/// A provider with its own sign-up options, from [`OAuthProviderExt`]:
/// `Github::new(..).map_profile(..)` or `Github::new(..).disable_sign_up(true)`.
pub struct ConfiguredProvider {
    pub(crate) provider: Arc<dyn DynProvider>,
    pub(crate) map_profile: Option<Arc<MapProfile>>,
    pub(crate) disable_sign_up: bool,
}

impl fmt::Debug for ConfiguredProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfiguredProvider")
            .field("id", &self.provider.id())
            .field("map_profile", &self.map_profile.is_some())
            .field("disable_sign_up", &self.disable_sign_up)
            .finish()
    }
}

impl<P: OAuthProvider> From<P> for ConfiguredProvider {
    fn from(provider: P) -> Self {
        Self {
            provider: Arc::new(provider),
            map_profile: None,
            disable_sign_up: false,
        }
    }
}

impl ConfiguredProvider {
    /// Maps the profile to extra `user` columns for users created through this provider. It
    /// replaces [`Social::map_profile`] for this provider; the two are not merged.
    pub fn map_profile<F>(mut self, map: F) -> Self
    where
        F: Fn(&OAuthProfile, &str) -> Result<Vec<(&'static str, Value)>, AuthError>
            + Send
            + Sync
            + 'static,
    {
        self.map_profile = Some(Arc::new(map));
        self
    }

    /// Refuses to create users through this provider (`?error=signup_disabled`). Existing
    /// users still sign in with it, including ones linked by verified email.
    pub fn disable_sign_up(mut self, disable: bool) -> Self {
        self.disable_sign_up = disable;
        self
    }
}

/// Per-provider sign-up options on every [`OAuthProvider`], built-in or your own.
pub trait OAuthProviderExt: OAuthProvider + Sized {
    /// See [`ConfiguredProvider::map_profile`].
    fn map_profile<F>(self, map: F) -> ConfiguredProvider
    where
        F: Fn(&OAuthProfile, &str) -> Result<Vec<(&'static str, Value)>, AuthError>
            + Send
            + Sync
            + 'static,
    {
        ConfiguredProvider::from(self).map_profile(map)
    }

    /// See [`ConfiguredProvider::disable_sign_up`].
    fn disable_sign_up(self, disable: bool) -> ConfiguredProvider {
        ConfiguredProvider::from(self).disable_sign_up(disable)
    }
}

impl<P: OAuthProvider> OAuthProviderExt for P {}

/// Social sign-in as a plugin: `.plugin(Social::new().provider(Github::from_env()?))`.
pub struct Social {
    pub(crate) providers: Vec<ConfiguredProvider>,
    pub(crate) http: Arc<dyn DynHttpClient>,
    pub(crate) account_linking: AccountLinking,
    pub(crate) allow_different_emails: bool,
    pub(crate) map_profile: Option<Arc<MapProfile>>,
}

impl fmt::Debug for Social {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Social")
            .field("providers", &self.providers)
            .field("account_linking", &self.account_linking)
            .field("allow_different_emails", &self.allow_different_emails)
            .field("map_profile", &self.map_profile.is_some())
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
            allow_different_emails: false,
            map_profile: None,
        }
    }

    /// Adds a provider, plain or with its own options from [`OAuthProviderExt`]. A provider
    /// with the same id replaces the earlier one.
    pub fn provider(mut self, provider: impl Into<ConfiguredProvider>) -> Self {
        let provider = provider.into();
        self.providers
            .retain(|p| p.provider.id() != provider.provider.id());
        self.providers.push(provider);
        self
    }

    /// Maps the provider's profile to extra `user` columns when a social sign-in creates a
    /// user, so app and plugin columns without a default get a value. It runs only for new
    /// users. A provider's own mapping ([`OAuthProviderExt::map_profile`]) wins over this one.
    ///
    /// The columns are checked against `user`: each must be an app or plugin column, set once,
    /// with the column's type. Server-only columns are allowed. A mistake is a 500 with the
    /// reason logged. An error you return is passed on: a 4xx redirects to the error callback
    /// URL with `?error=` set to its code, so a mapping can also refuse a sign-up.
    pub fn map_profile<F>(mut self, map: F) -> Self
    where
        F: Fn(&OAuthProfile, &str) -> Result<Vec<(&'static str, Value)>, AuthError>
            + Send
            + Sync
            + 'static,
    {
        self.map_profile = Some(Arc::new(map));
        self
    }

    pub fn account_linking(mut self, linking: AccountLinking) -> Self {
        self.account_linking = linking;
        self
    }

    /// Lets `/link-social` link a provider account whose email differs from the signed-in
    /// user's. Off by default: such a link fails with `?error=email_doesn't_match`. Better
    /// Auth's `accountLinking.allowDifferentEmails`.
    pub fn allow_different_emails(mut self, allow: bool) -> Self {
        self.allow_different_emails = allow;
        self
    }

    pub(crate) fn find(&self, id: &str) -> Option<&ConfiguredProvider> {
        self.providers.iter().find(|p| p.provider.id() == id)
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
        for configured in &self.providers {
            app.account_provider(configured.provider.id());
        }
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
