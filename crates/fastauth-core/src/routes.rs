//! Core endpoints. Paths and JSON shapes follow Better Auth, so its client works unchanged.

use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};

use crate::adapter::Adapter;
use crate::endpoint::{Authenticated, Ctx, Empty, Endpoint, MaybeAuthenticated, Public};
use crate::error::{AuthError, codes};
use crate::events::{EmailVerified, PasswordChanged, UserUpdated};
use crate::internal::{NewAccount, NewUser, SignInResult, url_encode};
use crate::mail::{AuthEmail, ResetPassword as ResetPasswordEmail};
use crate::model::Model;
use crate::models::{Session, User};
use crate::plugin::PluginBuilder;
use crate::session::UserView;
use crate::value::{Id, Value, camel_case};

pub(crate) fn register<D: Adapter>(app: &mut PluginBuilder<'_, D>, email_password: bool) {
    app.endpoint(GetSession)
        .endpoint(SignOut)
        .endpoint(ListSessions)
        .endpoint(RevokeSession)
        .endpoint(RevokeSessions)
        .endpoint(RevokeOtherSessions)
        .endpoint(UpdateUser)
        .endpoint(SendVerificationEmail)
        .endpoint(VerifyEmail)
        .server_endpoint::<CreateUser>();
    if email_password {
        app.endpoint(SignUpEmail)
            .endpoint(SignInEmail)
            .endpoint(ChangePassword)
            .endpoint(RequestPasswordReset)
            .endpoint(ForgetPassword)
            .endpoint(ResetPasswordCallback)
            .endpoint(ResetPassword);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Status {
    pub status: bool,
}

const OK: Status = Status { status: true };

fn check_callback<D: Adapter, A>(ctx: &Ctx<D, A>, url: Option<&str>) -> Result<(), AuthError> {
    match url {
        Some(url) if !ctx.config().is_safe_redirect(url) => Err(AuthError::new(
            StatusCode::FORBIDDEN,
            codes::INVALID_CALLBACK_URL,
            "callback URL is not on a trusted origin",
        )),
        _ => Ok(()),
    }
}

fn with_query(url: &str, key: &str, value: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}{key}={}", url_encode(value))
}

/// Trims and lowercases an email, answering 400 `INVALID_EMAIL` when it isn't one. Every
/// email route normalizes this way, so plugins that take an email should too.
pub fn normalize_email(email: &str) -> Result<String, AuthError> {
    let email = email.trim().to_lowercase();
    let valid = email.len() <= 254
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.')
        });
    if !valid {
        return Err(AuthError::bad_request(
            codes::INVALID_EMAIL,
            "invalid email",
        ));
    }
    Ok(email)
}

/// Turns extra JSON body keys into user columns, as sign-up does. Only app and plugin `input`
/// columns are accepted; with `require_all`, every required one without a default must be
/// there. Answers 400 `INVALID_FIELD` otherwise.
pub fn user_input_fields<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    extra: &Map<String, Json>,
    require_all: bool,
) -> Result<Vec<(&'static str, Value)>, AuthError> {
    let table = ctx.schema().expect(User::TABLE);
    let mut out = Vec::new();
    for (key, json) in extra {
        let column = table
            .columns
            .iter()
            .find(|c| c.input && c.owner != "core" && camel_case(c.name) == *key)
            .ok_or_else(|| {
                AuthError::bad_request(codes::INVALID_FIELD, format!("field `{key}` can't be set"))
            })?;
        let value = Value::from_json(column.ty, json)
            .filter(|v| !v.is_null() || column.nullable)
            .ok_or_else(|| {
                AuthError::bad_request(
                    codes::INVALID_FIELD,
                    format!("field `{key}` has the wrong type"),
                )
            })?;
        out.push((column.name, value));
    }
    if require_all {
        for column in table
            .columns
            .iter()
            .filter(|c| c.input && c.owner != "core" && !c.nullable && c.default.is_none())
        {
            if !out.iter().any(|(name, _)| *name == column.name) {
                return Err(AuthError::bad_request(
                    codes::INVALID_FIELD,
                    format!("field `{}` is required", camel_case(column.name)),
                ));
            }
        }
    }
    Ok(out)
}

fn email_password<D: Adapter, A>(ctx: &Ctx<D, A>) -> &crate::config::EmailPassword {
    ctx.config()
        .email_password
        .as_ref()
        .expect("route only registered with email_password")
}

// ---------------------------------------------------------------------------- sign-up

pub struct SignUpEmail;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignUpEmailInput {
    pub name: String,
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(default)]
    pub remember_me: Option<bool>,
    /// App and plugin `input` columns, by camelCase name.
    #[serde(flatten)]
    pub extra: Map<String, Json>,
}

#[derive(Debug, Serialize)]
pub struct SignUpOutput {
    pub token: Option<String>,
    pub user: Map<String, Json>,
}

impl<D: Adapter> Endpoint<D> for SignUpEmail {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/sign-up/email";
    type Access = Public;
    type Input = SignUpEmailInput;
    type Output = SignUpOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: SignUpEmailInput,
    ) -> Result<SignUpOutput, AuthError> {
        let config = email_password(&ctx);
        let email = normalize_email(&input.email)?;
        check_callback(&ctx, input.callback_url.as_deref())?;
        let internal = ctx.internal();
        internal.validate_new_password(&input.password)?;
        let extra = user_input_fields(&ctx, &input.extra, true)?;

        if config.require_email_verification && internal.find_user_by_email(&email).await?.is_some()
        {
            // Answer as if it worked, so sign-up can't be used to discover accounts.
            ctx.passwords().verify_dummy(&input.password).await;
            let now = time::OffsetDateTime::now_utc();
            let ghost = User {
                id: ctx.new_id()?,
                email,
                email_verified: false,
                name: input.name,
                image: input.image,
                created_at: now,
                updated_at: now,
            };
            let user = serde_json::to_value(ghost)
                .ok()
                .and_then(|v| v.as_object().cloned())
                .unwrap_or_default();
            return Ok(SignUpOutput { token: None, user });
        }

        let hash = ctx
            .passwords()
            .hash(&input.password)
            .await
            .map_err(AuthError::internal)?;
        let new_user = NewUser {
            email,
            name: input.name,
            image: input.image,
            email_verified: false,
            extra,
        };
        let user = internal
            .create_user(new_user, Some(NewAccount::credential(hash)))
            .await?;

        if config.require_email_verification
            || ctx.config().email_verification.send_on_sign_up && ctx.mailer().is_some()
        {
            internal
                .send_verification_email(&user, input.callback_url.as_deref())
                .await?;
        }
        if config.require_email_verification || !config.auto_sign_in {
            return Ok(SignUpOutput {
                token: None,
                user: user.to_json(),
            });
        }
        match internal
            .sign_in(user.clone(), "email", input.remember_me.unwrap_or(true))
            .await?
        {
            SignInResult::SignedIn(session) => Ok(SignUpOutput {
                token: session.token,
                user: user.to_json(),
            }),
            SignInResult::Challenge(_) => Ok(SignUpOutput {
                token: None,
                user: user.to_json(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------- create-user

/// Server-only: `auth.api().create_user(..)`. Never registered as a route, but hooks
/// can target it.
pub struct CreateUser;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserInput {
    pub email: String,
    pub name: String,
    /// Creates a credential account with this password. `None` creates the user alone.
    #[serde(default)]
    pub password: Option<String>,
    /// App and plugin `input` columns, by camelCase name, as on sign-up.
    #[serde(default)]
    pub fields: Map<String, Json>,
}

impl<D: Adapter> Endpoint<D> for CreateUser {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/create-user";
    type Access = Public;
    type Input = CreateUserInput;
    type Output = UserView;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: CreateUserInput,
    ) -> Result<UserView, AuthError> {
        let email = normalize_email(&input.email)?;
        let internal = ctx.internal();
        let extra = user_input_fields(&ctx, &input.fields, true)?;
        let account = match &input.password {
            Some(password) => {
                internal.validate_new_password(password)?;
                let hash = ctx
                    .passwords()
                    .hash(password)
                    .await
                    .map_err(AuthError::internal)?;
                Some(NewAccount::credential(hash))
            }
            None => None,
        };
        let new_user = NewUser {
            email,
            name: input.name,
            extra,
            ..NewUser::default()
        };
        internal.create_user(new_user, account).await
    }
}

// ---------------------------------------------------------------------------- sign-in

pub struct SignInEmail;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInEmailInput {
    pub email: String,
    pub password: String,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(default)]
    pub remember_me: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum SignInOutput {
    SignedIn {
        redirect: bool,
        token: String,
        url: Option<String>,
        user: Map<String, Json>,
    },
    /// A sign-in gate's answer, e.g. `{"twoFactorRedirect": true}`.
    Challenge(Json),
}

impl SignInOutput {
    pub fn from_result<D: Adapter, A>(
        ctx: &Ctx<D, A>,
        result: SignInResult,
        callback_url: Option<String>,
    ) -> Self {
        match result {
            SignInResult::SignedIn(session) => {
                if let Some(url) = &callback_url {
                    ctx.redirect(url.clone());
                }
                SignInOutput::SignedIn {
                    redirect: callback_url.is_some(),
                    token: session.token.clone().unwrap_or_default(),
                    url: callback_url,
                    user: session.user.to_json(),
                }
            }
            SignInResult::Challenge(body) => SignInOutput::Challenge(body),
        }
    }
}

fn invalid_credentials() -> AuthError {
    AuthError::new(
        StatusCode::UNAUTHORIZED,
        codes::INVALID_EMAIL_OR_PASSWORD,
        "invalid email or password",
    )
}

impl<D: Adapter> Endpoint<D> for SignInEmail {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/sign-in/email";
    type Access = Public;
    type Input = SignInEmailInput;
    type Output = SignInOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: SignInEmailInput,
    ) -> Result<SignInOutput, AuthError> {
        let config = email_password(&ctx);
        let email = normalize_email(&input.email)?;
        check_callback(&ctx, input.callback_url.as_deref())?;
        let internal = ctx.internal();
        let passwords = ctx.passwords();

        let Some(user) = internal.find_user_by_email(&email).await? else {
            passwords.verify_dummy(&input.password).await;
            return Err(invalid_credentials());
        };
        let Some(hash) = internal
            .credential_account(&user.id)
            .await?
            .and_then(|a| a.password_hash)
        else {
            passwords.verify_dummy(&input.password).await;
            return Err(invalid_credentials());
        };
        if !passwords
            .verify(&input.password, &hash)
            .await
            .map_err(AuthError::internal)?
        {
            return Err(invalid_credentials());
        }
        if passwords.needs_rehash(&hash) {
            internal.set_password(&user.id, &input.password).await?;
        }
        if config.require_email_verification && !user.email_verified {
            if ctx.mailer().is_some() {
                internal
                    .send_verification_email(&user, input.callback_url.as_deref())
                    .await?;
            }
            return Err(AuthError::new(
                StatusCode::FORBIDDEN,
                codes::EMAIL_NOT_VERIFIED,
                "email is not verified",
            ));
        }
        let result = internal
            .sign_in(user, "email", input.remember_me.unwrap_or(true))
            .await?;
        Ok(SignInOutput::from_result(&ctx, result, input.callback_url))
    }
}

// ---------------------------------------------------------------------------- sessions

pub struct SignOut;

#[derive(Debug, Serialize)]
pub struct SignOutOutput {
    pub success: bool,
}

impl<D: Adapter> Endpoint<D> for SignOut {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/sign-out";
    type Access = MaybeAuthenticated;
    type Input = Empty;
    type Output = SignOutOutput;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        _: Empty,
    ) -> Result<SignOutOutput, AuthError> {
        if let Some(session) = ctx.session().filter(|s| !s.ephemeral) {
            ctx.internal()
                .revoke_session(&session.user.id, &session.session.id)
                .await?;
        }
        ctx.internal().clear_session_cookies();
        Ok(SignOutOutput { success: true })
    }
}

pub struct GetSession;

impl<D: Adapter> Endpoint<D> for GetSession {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/get-session";
    type Access = MaybeAuthenticated;
    type Input = Map<String, Json>;
    type Output = Option<Json>;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        _: Map<String, Json>,
    ) -> Result<Option<Json>, AuthError> {
        Ok(ctx.session().map(|s| s.to_response_json()))
    }
}

pub struct ListSessions;

impl<D: Adapter> Endpoint<D> for ListSessions {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/list-sessions";
    type Access = Authenticated;
    type Input = Map<String, Json>;
    type Output = Vec<Map<String, Json>>;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        _: Map<String, Json>,
    ) -> Result<Self::Output, AuthError> {
        let rows = ctx
            .db()
            .find::<Session>(
                Session::USER_ID
                    .eq(&ctx.session().user.id)
                    .and(Session::EXPIRES_AT.gt(ctx.now())),
            )
            .order_by(Session::CREATED_AT.desc())
            .all_rows()
            .await?;
        Ok(rows.iter().map(|r| r.to_client_json()).collect())
    }
}

pub struct RevokeSession;

#[derive(Debug, Deserialize)]
pub struct RevokeSessionInput {
    /// Better Auth clients send the token; it is hashed to find the session.
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub id: Option<Id>,
}

impl<D: Adapter> Endpoint<D> for RevokeSession {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/revoke-session";
    type Access = Authenticated;
    type Input = RevokeSessionInput;
    type Output = Status;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: RevokeSessionInput,
    ) -> Result<Status, AuthError> {
        let current = ctx.authoritative_session().await?;
        let user_id = &current.user.id;
        let target = match (input.id, input.token) {
            (Some(id), _) => Some(id),
            (None, Some(token)) => ctx
                .db()
                .find::<Session>(Session::TOKEN_HASH.eq(crate::crypto::Hash::sha256(token)))
                .one()
                .await?
                .map(|s| s.id),
            (None, None) => {
                return Err(AuthError::bad_request(
                    codes::INVALID_BODY,
                    "send `id` or `token`",
                ));
            }
        };
        let Some(target) = target else {
            return Err(AuthError::new(
                StatusCode::NOT_FOUND,
                codes::SESSION_NOT_FOUND,
                "session not found",
            ));
        };
        if !ctx.internal().revoke_session(user_id, &target).await? {
            return Err(AuthError::new(
                StatusCode::NOT_FOUND,
                codes::SESSION_NOT_FOUND,
                "session not found",
            ));
        }
        if target == current.session.id {
            ctx.internal().clear_session_cookies();
        }
        Ok(OK)
    }
}

pub struct RevokeSessions;

impl<D: Adapter> Endpoint<D> for RevokeSessions {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/revoke-sessions";
    type Access = Authenticated;
    type Input = Empty;
    type Output = Status;

    async fn call(&self, ctx: Ctx<D, Authenticated>, _: Empty) -> Result<Status, AuthError> {
        let current = ctx.authoritative_session().await?;
        ctx.internal()
            .revoke_user_sessions(&current.user.id, None)
            .await?;
        ctx.internal().clear_session_cookies();
        Ok(OK)
    }
}

pub struct RevokeOtherSessions;

impl<D: Adapter> Endpoint<D> for RevokeOtherSessions {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/revoke-other-sessions";
    type Access = Authenticated;
    type Input = Empty;
    type Output = Status;

    async fn call(&self, ctx: Ctx<D, Authenticated>, _: Empty) -> Result<Status, AuthError> {
        let session = ctx.authoritative_session().await?;
        ctx.internal()
            .revoke_user_sessions(&session.user.id, Some(&session.session.id))
            .await?;
        Ok(OK)
    }
}

// ---------------------------------------------------------------------------- user

pub struct UpdateUser;

#[derive(Debug, Deserialize)]
pub struct UpdateUserInput {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, with = "double_option")]
    pub image: Option<Option<String>>,
    #[serde(flatten)]
    pub extra: Map<String, Json>,
}

mod double_option {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Option<String>>, D::Error> {
        Option::<String>::deserialize(d).map(Some)
    }
}

impl<D: Adapter> Endpoint<D> for UpdateUser {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/update-user";
    type Access = Authenticated;
    type Input = UpdateUserInput;
    type Output = Status;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: UpdateUserInput,
    ) -> Result<Status, AuthError> {
        if input.extra.contains_key("email") {
            return Err(AuthError::bad_request(
                codes::INVALID_FIELD,
                "email can't be changed here",
            ));
        }
        let user_id = ctx.session().user.id.clone();
        let mut update = ctx.db().update::<User>(User::ID.eq(&user_id));
        if let Some(name) = input.name {
            update = update.set(User::NAME, name);
        }
        if let Some(image) = input.image {
            update = update.set(User::IMAGE, image);
        }
        for (column, value) in user_input_fields(&ctx, &input.extra, false)? {
            update = update.set_raw(column, value);
        }
        update.exec().await?;
        ctx.emit(UserUpdated { user_id });
        Ok(OK)
    }
}

pub struct ChangePassword;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordInput {
    pub new_password: String,
    pub current_password: String,
    #[serde(default)]
    pub revoke_other_sessions: bool,
}

#[derive(Debug, Serialize)]
pub struct ChangePasswordOutput {
    pub token: Option<String>,
    pub user: Map<String, Json>,
}

impl<D: Adapter> Endpoint<D> for ChangePassword {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/change-password";
    type Access = Authenticated;
    type Input = ChangePasswordInput;
    type Output = ChangePasswordOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: ChangePasswordInput,
    ) -> Result<ChangePasswordOutput, AuthError> {
        let session = &ctx.sensitive_session().await?;
        let internal = ctx.internal();
        let Some(hash) = internal
            .credential_account(&session.user.id)
            .await?
            .and_then(|a| a.password_hash)
        else {
            return Err(AuthError::bad_request(
                codes::CREDENTIAL_ACCOUNT_NOT_FOUND,
                "this user has no password",
            ));
        };
        if !ctx
            .passwords()
            .verify(&input.current_password, &hash)
            .await
            .map_err(AuthError::internal)?
        {
            return Err(AuthError::bad_request(
                codes::INVALID_PASSWORD,
                "invalid password",
            ));
        }
        internal
            .set_password(&session.user.id, &input.new_password)
            .await?;
        if input.revoke_other_sessions && !session.ephemeral {
            internal
                .revoke_user_sessions(&session.user.id, Some(&session.session.id))
                .await?;
        }
        ctx.emit(PasswordChanged {
            user_id: session.user.id.clone(),
        });
        Ok(ChangePasswordOutput {
            token: session.token.clone(),
            user: session.user.to_json(),
        })
    }
}

// ---------------------------------------------------------------------------- email verification

pub struct SendVerificationEmail;

#[derive(Debug, Deserialize)]
pub struct SendVerificationEmailInput {
    pub email: String,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
}

impl<D: Adapter> Endpoint<D> for SendVerificationEmail {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/send-verification-email";
    type Access = Public;
    type Input = SendVerificationEmailInput;
    type Output = Status;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: SendVerificationEmailInput,
    ) -> Result<Status, AuthError> {
        check_callback(&ctx, input.callback_url.as_deref())?;
        let internal = ctx.internal();
        if let Some(user) = internal
            .find_user_by_email(&normalize_email(&input.email)?)
            .await?
            && !user.email_verified
        {
            internal
                .send_verification_email(&user, input.callback_url.as_deref())
                .await?;
        } else {
            internal.simulate_verification().await?;
        }
        Ok(OK)
    }
}

pub struct VerifyEmail;

#[derive(Debug, Deserialize)]
pub struct VerifyEmailInput {
    pub token: String,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyEmailOutput {
    pub status: bool,
    pub user: Option<Map<String, Json>>,
}

impl<D: Adapter> Endpoint<D> for VerifyEmail {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/verify-email";
    type Access = Public;
    type Input = VerifyEmailInput;
    type Output = VerifyEmailOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: VerifyEmailInput,
    ) -> Result<VerifyEmailOutput, AuthError> {
        check_callback(&ctx, input.callback_url.as_deref())?;
        let internal = ctx.internal();
        let invalid = || AuthError::bad_request(codes::INVALID_TOKEN, "invalid or expired token");
        let verification = internal.consume_verification(&input.token).await?;
        let user_id = verification
            .as_ref()
            .and_then(|v| v.identifier.strip_prefix("email-verification:"))
            .map(Id::from);
        let user = match user_id {
            Some(id) => internal.find_user_by_id(&id).await?,
            None => None,
        };
        let Some(user) = user else {
            if let Some(callback) = &input.callback_url {
                ctx.redirect(with_query(callback, "error", codes::INVALID_TOKEN));
                return Ok(VerifyEmailOutput {
                    status: false,
                    user: None,
                });
            }
            return Err(invalid());
        };
        ctx.db()
            .update::<User>(User::ID.eq(&user.id))
            .set(User::EMAIL_VERIFIED, true)
            .exec()
            .await?;
        ctx.emit(EmailVerified {
            user_id: user.id.clone(),
        });
        if ctx
            .config()
            .email_verification
            .auto_sign_in_after_verification
        {
            internal
                .sign_in(user.clone(), "email-verification", true)
                .await?;
        }
        if let Some(callback) = input.callback_url {
            ctx.redirect(callback);
        }
        let user = internal
            .find_user_by_id(&user.id)
            .await?
            .map(|u: UserView| u.to_json());
        Ok(VerifyEmailOutput { status: true, user })
    }
}

// ---------------------------------------------------------------------------- password reset

pub struct RequestPasswordReset;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestPasswordResetInput {
    pub email: String,
    #[serde(default)]
    pub redirect_to: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RequestPasswordResetOutput {
    pub status: bool,
    pub message: &'static str,
}

async fn request_reset<D: Adapter>(
    ctx: &Ctx<D, Public>,
    input: RequestPasswordResetInput,
) -> Result<RequestPasswordResetOutput, AuthError> {
    check_callback(ctx, input.redirect_to.as_deref())?;
    let internal = ctx.internal();
    let ttl = email_password(ctx).reset_password_ttl;
    if let Some(user) = internal
        .find_user_by_email(&normalize_email(&input.email)?)
        .await?
    {
        let token = internal
            .create_verification(&format!("reset-password:{}", user.id), ttl, None)
            .await?;
        let mut url = format!("{}/reset-password/{token}", ctx.config().auth_url());
        if let Some(redirect) = &input.redirect_to {
            url = with_query(&url, "callbackURL", redirect);
        }
        internal
            .send_email_in_background(AuthEmail::ResetPassword(ResetPasswordEmail {
                to: user.email.clone(),
                name: user.name.clone(),
                url,
                token,
            }))
            .await?;
    } else {
        internal.simulate_verification().await?;
    }
    Ok(RequestPasswordResetOutput {
        status: true,
        message: "If this email exists in our system, check your email for the reset link",
    })
}

impl<D: Adapter> Endpoint<D> for RequestPasswordReset {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/request-password-reset";
    type Access = Public;
    type Input = RequestPasswordResetInput;
    type Output = RequestPasswordResetOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: RequestPasswordResetInput,
    ) -> Result<Self::Output, AuthError> {
        request_reset(&ctx, input).await
    }
}

/// The older Better Auth name for `/request-password-reset`.
pub struct ForgetPassword;

impl<D: Adapter> Endpoint<D> for ForgetPassword {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/forget-password";
    type Access = Public;
    type Input = RequestPasswordResetInput;
    type Output = RequestPasswordResetOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: RequestPasswordResetInput,
    ) -> Result<Self::Output, AuthError> {
        request_reset(&ctx, input).await
    }
}

/// The link in the reset email. Redirects to the app's reset page with the token.
pub struct ResetPasswordCallback;

#[derive(Debug, Deserialize)]
pub struct ResetPasswordCallbackInput {
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
}

impl<D: Adapter> Endpoint<D> for ResetPasswordCallback {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/reset-password/{token}";
    type Access = Public;
    type Input = ResetPasswordCallbackInput;
    type Output = Status;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: ResetPasswordCallbackInput,
    ) -> Result<Status, AuthError> {
        let Some(callback) = input.callback_url else {
            return Err(AuthError::bad_request(
                codes::INVALID_CALLBACK_URL,
                "callbackURL is required",
            ));
        };
        check_callback(&ctx, Some(&callback))?;
        let token = ctx.param("token").unwrap_or_default().to_owned();
        let valid = ctx
            .internal()
            .find_verification(&token)
            .await?
            .is_some_and(|v| v.identifier.starts_with("reset-password:"));
        ctx.redirect(if valid {
            with_query(&callback, "token", &token)
        } else {
            with_query(&callback, "error", codes::INVALID_TOKEN)
        });
        Ok(Status { status: valid })
    }
}

pub struct ResetPassword;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordInput {
    pub new_password: String,
    pub token: String,
}

impl<D: Adapter> Endpoint<D> for ResetPassword {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/reset-password";
    type Access = Public;
    type Input = ResetPasswordInput;
    type Output = Status;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: ResetPasswordInput,
    ) -> Result<Status, AuthError> {
        let internal = ctx.internal();
        internal.validate_new_password(&input.new_password)?;
        let user_id = internal
            .consume_verification(&input.token)
            .await?
            .and_then(|v| v.identifier.strip_prefix("reset-password:").map(Id::from))
            .ok_or_else(|| {
                AuthError::bad_request(codes::INVALID_TOKEN, "invalid or expired token")
            })?;
        internal.set_password(&user_id, &input.new_password).await?;
        if email_password(&ctx).revoke_sessions_on_password_reset {
            internal.revoke_user_sessions(&user_id, None).await?;
        }
        ctx.emit(PasswordChanged { user_id });
        Ok(OK)
    }
}
