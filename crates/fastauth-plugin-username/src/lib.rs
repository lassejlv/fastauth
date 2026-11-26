//! Username sign-in for [fastauth](https://github.com/lassejlv/fastauth). The routes, fields and
//! JSON match Better Auth's `username` plugin, so its `usernameClient` works unchanged.
//!
//! It adds `username` (unique, normalized) and `display_username` to `user`, both settable
//! on `/sign-up/email` and `/update-user`, and serves `POST /sign-in/username` and
//! `POST /is-username-available`. Usernames are checked for length and characters, then
//! normalized (lowercased by default) before they are stored or looked up, so `Ada` and
//! `ada` are the same user.
//!
//! ```
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_username::{Username, UsernameExt};
//!
//! let auth: Auth<MemoryAdapter, (), plugins![Username]> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .email_password(EmailPassword::default())
//!     .plugin(Username::new().min_username_length(4))
//!     .build()?;
//! let _username = auth.username();
//! # Ok::<(), BuildError>(())
//! ```
//!
//! Without the plugin registered, `auth.username()` doesn't compile:
//!
//! ```compile_fail
//! use fastauth_core::prelude::*;
//! use fastauth_plugin_username::UsernameExt;
//!
//! let auth: Auth<MemoryAdapter> = FastAuth::builder()
//!     .secret(Secret::from_bytes(vec![1u8; 32]))
//!     .base_url("http://localhost:3000")
//!     .database(MemoryAdapter::new())
//!     .build()
//!     .unwrap();
//! let _username = auth.username();
//! ```

mod endpoints;
mod error;
mod model;

use fastauth_core::ApiResponse;
use fastauth_core::plugin_prelude::*;
use fastauth_core::routes::SignInOutput;

pub use endpoints::{
    Availability, IsUsernameAvailable, IsUsernameAvailableInput, SignInUsername,
    SignInUsernameInput,
};
pub use error::UsernameError;
pub use model::UsernameUser;

type Validator = Arc<dyn Fn(&str) -> bool + Send + Sync>;
type Normalizer = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Whether a validator sees the value as sent or after normalization.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ValidationOrder {
    /// The value as the client sent it (the default).
    #[default]
    PreNormalization,
    /// The value after normalization.
    PostNormalization,
}

#[derive(Clone)]
enum Normalization {
    Lowercase,
    Off,
    Custom(Normalizer),
}

/// The username plugin: `.plugin(Username::new())`.
#[derive(Clone)]
pub struct Username {
    min_length: usize,
    max_length: usize,
    validator: Option<Validator>,
    display_validator: Option<Validator>,
    normalization: Normalization,
    display_normalization: Option<Normalizer>,
    username_order: ValidationOrder,
    display_order: ValidationOrder,
    immutable: bool,
}

impl std::fmt::Debug for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Username")
            .field("min_length", &self.min_length)
            .field("max_length", &self.max_length)
            .field("username_order", &self.username_order)
            .field("display_order", &self.display_order)
            .field("immutable", &self.immutable)
            .finish_non_exhaustive()
    }
}

impl Default for Username {
    fn default() -> Self {
        Self {
            min_length: 3,
            max_length: 30,
            validator: None,
            display_validator: None,
            normalization: Normalization::Lowercase,
            display_normalization: None,
            username_order: ValidationOrder::PreNormalization,
            display_order: ValidationOrder::PreNormalization,
            immutable: false,
        }
    }
}

/// Better Auth's default validator: ASCII letters, digits, `_` and `.`.
fn default_validator(username: &str) -> bool {
    !username.is_empty()
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

impl Username {
    pub fn new() -> Self {
        Self::default()
    }

    /// Shortest allowed username, in characters (default 3).
    pub fn min_username_length(mut self, length: usize) -> Self {
        self.min_length = length;
        self
    }

    /// Longest allowed username, in characters (default 30).
    pub fn max_username_length(mut self, length: usize) -> Self {
        self.max_length = length;
        self
    }

    /// Replaces the default validator (ASCII letters, digits, `_` and `.`). Runs after the
    /// length checks; `false` answers `INVALID_USERNAME`.
    pub fn username_validator(
        mut self,
        validator: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.validator = Some(Arc::new(validator));
        self
    }

    /// Checks `displayUsername` when a client sets it; `false` answers
    /// `INVALID_DISPLAY_USERNAME`. By default any display username is accepted.
    pub fn display_username_validator(
        mut self,
        validator: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.display_validator = Some(Arc::new(validator));
        self
    }

    /// Replaces the default normalization (lowercase) for stored and looked-up usernames.
    pub fn username_normalization(
        mut self,
        normalize: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> Self {
        self.normalization = Normalization::Custom(Arc::new(normalize));
        self
    }

    /// Stores and looks up usernames exactly as sent (Better Auth's
    /// `usernameNormalization: false`).
    pub fn disable_username_normalization(mut self) -> Self {
        self.normalization = Normalization::Off;
        self
    }

    /// Normalizes `displayUsername` before it is stored. By default it is kept as sent.
    pub fn display_username_normalization(
        mut self,
        normalize: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> Self {
        self.display_normalization = Some(Arc::new(normalize));
        self
    }

    /// Whether the length checks and validator see the username before or after
    /// normalization (default before).
    pub fn username_validation_order(mut self, order: ValidationOrder) -> Self {
        self.username_order = order;
        self
    }

    /// Whether the display username validator sees the value before or after normalization
    /// (default before).
    pub fn display_username_validation_order(mut self, order: ValidationOrder) -> Self {
        self.display_order = order;
        self
    }

    /// Once a user has a username, `/update-user` can't change it
    /// (`USERNAME_IS_IMMUTABLE`). Off by default.
    pub fn immutable_username(mut self, immutable: bool) -> Self {
        self.immutable = immutable;
        self
    }

    /// The username as it is stored and looked up.
    pub fn normalize(&self, username: &str) -> String {
        match &self.normalization {
            Normalization::Lowercase => username.to_lowercase(),
            Normalization::Off => username.to_owned(),
            Normalization::Custom(normalize) => normalize(username),
        }
    }

    /// The display username as it is stored.
    pub fn normalize_display(&self, display_username: &str) -> String {
        match &self.display_normalization {
            Some(normalize) => normalize(display_username),
            None => display_username.to_owned(),
        }
    }

    /// Checks length and characters, in the configured validation order.
    pub fn validate(&self, username: &str) -> Result<(), UsernameError> {
        let normalized;
        let username = match self.username_order {
            ValidationOrder::PreNormalization => username,
            ValidationOrder::PostNormalization => {
                normalized = self.normalize(username);
                &normalized
            }
        };
        let length = username.chars().count();
        if length < self.min_length {
            return Err(UsernameError::UsernameTooShort);
        }
        if length > self.max_length {
            return Err(UsernameError::UsernameTooLong);
        }
        let valid = match &self.validator {
            Some(validator) => validator(username),
            None => default_validator(username),
        };
        if !valid {
            return Err(UsernameError::InvalidUsername);
        }
        Ok(())
    }

    fn validate_display(&self, display_username: &str) -> Result<(), UsernameError> {
        let Some(validator) = &self.display_validator else {
            return Ok(());
        };
        let valid = match self.display_order {
            ValidationOrder::PreNormalization => validator(display_username),
            ValidationOrder::PostNormalization => {
                validator(&self.normalize_display(display_username))
            }
        };
        if valid {
            Ok(())
        } else {
            Err(UsernameError::InvalidDisplayUsername)
        }
    }
}

impl Plugin for Username {
    const ID: &'static str = "username";
    type Requires = ();
    type UserFields = UsernameUser;
    type SessionFields = ();

    fn init<D: Adapter>(self: &Arc<Self>, app: &mut PluginBuilder<'_, D>) {
        app.endpoint(SignInUsername(self.clone()))
            .endpoint(IsUsernameAvailable(self.clone()))
            .errors::<UsernameError>();
        let plugin = self.clone();
        app.prepare_user_input(move |ctx, mut body, input| {
            let plugin = plugin.clone();
            async move {
                match input {
                    UserInput::SignUp => {
                        endpoints::prepare_new_user(&plugin, &ctx, &mut body, true).await?
                    }
                    UserInput::Create => {
                        endpoints::prepare_new_user(&plugin, &ctx, &mut body, false).await?
                    }
                    UserInput::Update => {
                        endpoints::prepare_update(&plugin, &ctx, &mut body).await?
                    }
                }
                Ok(body)
            }
        });
    }
}

/// `auth.username()`: the server API. Only compiles on an `Auth` with `Username` registered.
pub trait UsernameExt: AuthInstance + Sized {
    fn username<I>(&self) -> UsernameApi<'_, Self>
    where
        Self: HasPlugin<Username, I>,
    {
        UsernameApi {
            auth: self,
            plugin: self.plugin_arc().clone(),
        }
    }
}

impl<A: AuthInstance> UsernameExt for A {}

/// Calls the username endpoints without HTTP.
pub struct UsernameApi<'a, A> {
    auth: &'a A,
    plugin: Arc<Username>,
}

impl<A: AuthInstance> UsernameApi<'_, A> {
    /// `POST /sign-in/username`. The response's cookies carry the new session.
    pub async fn sign_in(
        &self,
        headers: &HeaderMap,
        input: SignInUsernameInput,
    ) -> Result<ApiResponse<SignInOutput>, AuthError> {
        self.auth
            .api()
            .headers(headers)
            .call(&SignInUsername(self.plugin.clone()), input)
            .await
    }

    /// `POST /is-username-available`.
    pub async fn is_available(
        &self,
        username: impl Into<String>,
    ) -> Result<ApiResponse<Availability>, AuthError> {
        self.auth
            .api()
            .call(
                &IsUsernameAvailable(self.plugin.clone()),
                IsUsernameAvailableInput {
                    username: username.into(),
                },
            )
            .await
    }

    /// The user with this username (normalized first), if any.
    pub async fn find_user(&self, username: &str) -> Result<Option<UserView>, AuthError> {
        let row = self
            .auth
            .api()
            .db()
            .find::<User>(UsernameUser::USERNAME.eq(Some(self.plugin.normalize(username))))
            .one_row()
            .await?;
        row.map(UserView::from_row)
            .transpose()
            .map_err(AuthError::internal)
    }
}
