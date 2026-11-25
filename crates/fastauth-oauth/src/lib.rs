//! Social sign-in for [fastauth](https://github.com/lassejlv/fastauth), as a plugin.
//!
//! ```no_run
//! # #[cfg(feature = "reqwest")]
//! # fn social() -> Result<fastauth_oauth::Social, fastauth_core::BuildError> {
//! use fastauth_oauth::{Github, Google, Social};
//!
//! let social = Social::new()
//!     .provider(Github::new("client-id", "client-secret"))
//!     .provider(Google::from_env()?);
//! # Ok(social)
//! # }
//! ```
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
pub use social::{AccountLinking, Social, SocialError};
