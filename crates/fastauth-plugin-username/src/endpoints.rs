//! `POST /sign-in/username`, `POST /is-username-available`, and the checks on sign-up,
//! update-user and server-side user creation.

use fastauth_core::plugin_prelude::*;
use fastauth_core::routes::SignInOutput;
use serde_json::{Map, Value as Json};

use crate::{Username, UsernameError, UsernameUser};

const USERNAME: &str = "username";
const DISPLAY_USERNAME: &str = "displayUsername";

async fn username_owner<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    normalized: &str,
) -> Result<Option<UserView>, AuthError> {
    let row = ctx
        .db()
        .find::<User>(UsernameUser::USERNAME.eq(Some(normalized.to_owned())))
        .one_row()
        .await?;
    row.map(UserView::from_row)
        .transpose()
        .map_err(AuthError::internal)
}

fn string<'m>(body: &'m Map<String, Json>, key: &str) -> Option<&'m str> {
    body.get(key).and_then(Json::as_str)
}

/// Sign-up (`from_sign_up`) and server-side user creation: Better Auth's sign-up hooks and
/// its user-create database hook. Validates the username, refuses a taken one, defaults the
/// display username to it, and stores both normalized.
pub(crate) async fn prepare_new_user<D: Adapter, A>(
    plugin: &Username,
    ctx: &Ctx<D, A>,
    body: &mut Map<String, Json>,
    from_sign_up: bool,
) -> Result<(), AuthError> {
    if from_sign_up
        && !body.contains_key(USERNAME)
        && let Some(display) = string(body, DISPLAY_USERNAME)
        && plugin.validate(display).is_ok()
    {
        body.insert(USERNAME.into(), display.into());
    }
    if let Some(display) = string(body, DISPLAY_USERNAME) {
        plugin.validate_display(display)?;
    }
    let Some(username) = string(body, USERNAME).map(str::to_owned) else {
        if let Some(display) = string(body, DISPLAY_USERNAME) {
            let display = plugin.normalize_display(display);
            body.insert(DISPLAY_USERNAME.into(), display.into());
        }
        return Ok(());
    };
    plugin.validate(&username)?;
    let normalized = plugin.normalize(&username);
    if username_owner(ctx, &normalized).await?.is_some() {
        return Err(UsernameError::UsernameIsAlreadyTaken.into());
    }
    let display = match string(body, DISPLAY_USERNAME) {
        Some(display) => plugin.normalize_display(display),
        None if from_sign_up => plugin.normalize_display(&username),
        None => username,
    };
    body.insert(USERNAME.into(), normalized.into());
    body.insert(DISPLAY_USERNAME.into(), display.into());
    Ok(())
}

/// `/update-user`: Better Auth's update-user hook and its user-update database hook.
pub(crate) async fn prepare_update<D: Adapter>(
    plugin: &Username,
    ctx: &HookCtx<D>,
    body: &mut Map<String, Json>,
) -> Result<(), AuthError> {
    if let Some(username) = string(body, USERNAME).map(str::to_owned) {
        plugin.validate(&username)?;
        let normalized = plugin.normalize(&username);
        let session = ctx.session();
        let current = session
            .map(|s| s.user.fields::<UsernameUser>())
            .transpose()
            .map_err(AuthError::internal)?
            .and_then(|fields| fields.username);
        if plugin.immutable && current.as_ref().is_some_and(|c| *c != normalized) {
            return Err(UsernameError::UsernameIsImmutable.into());
        }
        if let Some(owner) = username_owner(ctx, &normalized).await?
            && session.is_none_or(|s| s.user.id != owner.id)
        {
            return Err(UsernameError::UsernameIsAlreadyTaken.into());
        }
        body.insert(USERNAME.into(), normalized.into());
    }
    if let Some(display) = string(body, DISPLAY_USERNAME) {
        plugin.validate_display(display)?;
        let display = plugin.normalize_display(display);
        body.insert(DISPLAY_USERNAME.into(), display.into());
    }
    Ok(())
}

/// `POST /sign-in/username`: signs in with a username and password. Answers like
/// `/sign-in/email`: `{ redirect, token, url, user }`, a sign-in gate's challenge (such as
/// `{"twoFactorRedirect": true}`), or 401 `INVALID_USERNAME_OR_PASSWORD`.
pub struct SignInUsername(pub(crate) Arc<Username>);

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInUsernameInput {
    pub username: String,
    pub password: String,
    /// `false` makes the session cookie last for the browser session.
    #[serde(default)]
    pub remember_me: Option<bool>,
    /// Where to send the user after signing in; also the target of the verification email
    /// when the email isn't verified yet.
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
}

impl<D: Adapter> Endpoint<D> for SignInUsername {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/sign-in/username";
    type Access = Public;
    type Input = SignInUsernameInput;
    type Output = SignInOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: SignInUsernameInput,
    ) -> Result<SignInOutput, AuthError> {
        let invalid = || AuthError::from(UsernameError::InvalidUsernameOrPassword);
        if input.username.is_empty() || input.password.is_empty() {
            return Err(invalid());
        }
        self.0
            .validate(&input.username)
            .map_err(UsernameError::unprocessable)?;
        if ctx
            .config()
            .email_password
            .as_ref()
            .is_some_and(|config| input.password.chars().count() > config.max_password_len())
        {
            return Err(AuthError::bad_request(
                codes::PASSWORD_TOO_LONG,
                "Password too long",
            ));
        }
        if let Some(url) = input.callback_url.as_deref()
            && !ctx.config().is_safe_redirect(url)
        {
            return Err(AuthError::new(
                StatusCode::FORBIDDEN,
                codes::INVALID_CALLBACK_URL,
                "Invalid callbackURL",
            ));
        }
        let internal = ctx.internal();
        let passwords = ctx.passwords();
        let Some(user) = username_owner(&ctx, &self.0.normalize(&input.username)).await? else {
            passwords.verify_dummy(&input.password).await;
            return Err(invalid());
        };
        let Some(hash) = internal
            .credential_account(&user.id)
            .await?
            .and_then(|account| account.password_hash)
        else {
            passwords.verify_dummy(&input.password).await;
            return Err(invalid());
        };
        if !passwords
            .verify(&input.password, &hash)
            .await
            .map_err(AuthError::internal)?
        {
            return Err(invalid());
        }
        if passwords.needs_rehash(&hash) {
            internal.set_password(&user.id, &input.password).await?;
        }
        let require_verification = ctx
            .config()
            .email_password
            .as_ref()
            .is_some_and(|config| config.requires_email_verification());
        if require_verification && !user.email_verified {
            if internal.can_send_email() {
                internal
                    .send_verification_email(&user, input.callback_url.as_deref())
                    .await?;
            }
            return Err(AuthError::new(
                StatusCode::FORBIDDEN,
                codes::EMAIL_NOT_VERIFIED,
                "Email not verified",
            ));
        }
        let result = internal
            .sign_in(user, "username", input.remember_me.unwrap_or(true))
            .await?;
        Ok(SignInOutput::from_result(&ctx, result, input.callback_url))
    }
}

/// `POST /is-username-available`: `{ "available": bool }` for a valid username, 422 for an
/// invalid one.
pub struct IsUsernameAvailable(pub(crate) Arc<Username>);

#[derive(Debug, Default, Deserialize)]
pub struct IsUsernameAvailableInput {
    pub username: String,
}

/// `{ "available": bool }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Availability {
    pub available: bool,
}

impl<D: Adapter> Endpoint<D> for IsUsernameAvailable {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/is-username-available";
    type Access = Public;
    type Input = IsUsernameAvailableInput;
    type Output = Availability;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: IsUsernameAvailableInput,
    ) -> Result<Availability, AuthError> {
        if input.username.is_empty() {
            return Err(UsernameError::InvalidUsername.unprocessable());
        }
        self.0
            .validate(&input.username)
            .map_err(UsernameError::unprocessable)?;
        let taken = username_owner(&ctx, &self.0.normalize(&input.username))
            .await?
            .is_some();
        Ok(Availability { available: !taken })
    }
}
