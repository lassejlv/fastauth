//! Social sign-in for [fastauth](https://github.com/lassejlv/fastauth), as a plugin.
//!
//! ```no_run
//! # #[cfg(feature = "reqwest")]
//! # fn social() -> Result<fastauth_oauth::Social, fastauth_core::BuildError> {
//! use fastauth_core::value::Value;
//! use fastauth_oauth::{Github, Google, OAuthProviderExt, Social};
//!
//! let social = Social::new()
//!     .provider(Github::new("client-id", "client-secret"))
//!     .provider(Google::from_env()?.disable_sign_up(true))
//!     .map_profile(|_profile, _provider| Ok(vec![("plan", Value::Text("free".into()))]));
//! # Ok(social)
//! # }
//! ```
//!
//! `map_profile` sets `user` columns that have no default when a sign-in creates a user;
//! `disable_sign_up` lets a provider sign existing users in without creating new ones.
//!
//! Register it with `.plugin(social)` and list it in the alias: `plugins![Social, ..]`. It serves
//! `POST /sign-in/social`, `GET /callback/{id}`, `POST /link-social`, `GET /list-accounts` and
//! `POST /unlink-account`, with the same paths and JSON as Better Auth.

pub mod http;
pub mod provider;
mod providers;
mod routes;
mod social;

#[cfg(feature = "reqwest")]
pub use http::ReqwestClient;
pub use http::{Http, HttpClient, HttpClientError};
pub use provider::{
    AuthorizationRequest, OAuthError, OAuthProfile, OAuthProvider, OAuthTokens, TokenRequest,
};
pub use providers::{Github, Google};
pub use routes::{
    AccountInfo, AuthorizationUrl, CallbackQuery, LinkSocial, LinkSocialInput, ListAccounts,
    SignInSocial, SignInSocialInput, SocialCallback, UnlinkAccount, UnlinkAccountInput,
};
pub use social::{
    AccountLinking, ConfiguredProvider, MapProfile, OAuthProviderExt, Social, SocialError,
};
