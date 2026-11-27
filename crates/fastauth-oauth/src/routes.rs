//! The social endpoints. Paths and JSON follow Better Auth.

use std::sync::Arc;

use fastauth_core::adapter::{Adapter, Order};
use fastauth_core::crypto::{Hash, base64url, ct_eq, random_token};
use fastauth_core::endpoint::{Authenticated, Ctx, Empty, Endpoint, Public};
use fastauth_core::error::codes;
use fastauth_core::internal::{NewAccount, NewUser, SignInResult};
use fastauth_core::model::Model;
use fastauth_core::models::{Account, Session, User};
use fastauth_core::routes::Status;
use fastauth_core::schema::ColumnType;
use fastauth_core::session::UserView;
use fastauth_core::value::{Id, Value};
use fastauth_core::{AuthError, Duration};
use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::provider::{AuthorizationRequest, OAuthProfile, OAuthTokens, TokenRequest};
use crate::social::{AccountLinking, ConfiguredProvider, Social, SocialError};

const STATE_TTL: Duration = Duration::minutes(10);
const STATE_COOKIE: &str = "oauth_state";

/// `{ url, redirect }`: where to send the browser to start the provider's consent screen.
#[derive(Clone, Debug, Serialize)]
pub struct AuthorizationUrl {
    pub url: String,
    pub redirect: bool,
}

/// What the callback needs, stored as JSON in `verification.data` under the state.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StateData {
    code_verifier: String,
    callback_url: String,
    error_callback_url: Option<String>,
    new_user_callback_url: Option<String>,
    link_user_id: Option<Id>,
    /// The session that started a link; the link completes only while it is live.
    #[serde(default)]
    link_session_id: Option<Id>,
}

struct Start<'a> {
    provider: &'a str,
    scopes: &'a [String],
    callback_url: Option<String>,
    error_callback_url: Option<String>,
    new_user_callback_url: Option<String>,
    link: Option<(Id, Id)>,
}

fn identifier(provider: &str) -> String {
    format!("oauth-state:{provider}")
}

fn with_query(url: &str, key: &str, value: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    let value: String = url::form_urlencoded::byte_serialize(value.as_bytes()).collect();
    format!("{url}{sep}{key}={value}")
}

/// Stores the state and PKCE verifier, binds the state to this browser, and builds the
/// provider's authorization URL.
async fn start<D: Adapter, A>(
    social: &Social,
    ctx: &Ctx<D, A>,
    start: Start<'_>,
) -> Result<String, AuthError> {
    let provider = social
        .find(start.provider)
        .ok_or(SocialError::ProviderNotFound)?;
    let config = ctx.config();
    for url in [
        &start.callback_url,
        &start.error_callback_url,
        &start.new_user_callback_url,
    ]
    .into_iter()
    .flatten()
    {
        if !config.is_safe_redirect(url) {
            return Err(AuthError::new(
                StatusCode::FORBIDDEN,
                codes::INVALID_CALLBACK_URL,
                "callback URL is not on a trusted origin",
            ));
        }
    }
    let code_verifier = random_token();
    let code_challenge = base64url(Hash::sha256(&code_verifier).as_bytes());
    let data = StateData {
        code_verifier,
        callback_url: start
            .callback_url
            .unwrap_or_else(|| config.base_url.to_string()),
        error_callback_url: start.error_callback_url,
        new_user_callback_url: start.new_user_callback_url,
        link_user_id: start.link.as_ref().map(|(user_id, _)| user_id.clone()),
        link_session_id: start.link.map(|(_, session_id)| session_id),
    };
    let data = serde_json::to_string(&data).map_err(AuthError::internal)?;
    let state = ctx
        .internal()
        .create_verification(&identifier(start.provider), STATE_TTL, Some(data))
        .await?;
    ctx.set_signed_cookie(STATE_COOKIE, &state, Some(STATE_TTL));
    let redirect_uri = format!("{}/callback/{}", config.auth_url(), start.provider);
    let url = provider.provider.authorization_url(&AuthorizationRequest {
        state: &state,
        code_challenge: &code_challenge,
        redirect_uri: &redirect_uri,
        scopes: start.scopes,
    });
    Ok(url.into())
}

// ---------------------------------------------------------------------------- sign-in

/// `POST /sign-in/social`.
pub struct SignInSocial(pub(crate) Arc<Social>);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInSocialInput {
    pub provider: String,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(default, rename = "errorCallbackURL")]
    pub error_callback_url: Option<String>,
    #[serde(default, rename = "newUserCallbackURL")]
    pub new_user_callback_url: Option<String>,
    #[serde(default)]
    pub disable_redirect: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl<D: Adapter> Endpoint<D> for SignInSocial {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/sign-in/social";
    type Access = Public;
    type Input = SignInSocialInput;
    type Output = AuthorizationUrl;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: SignInSocialInput,
    ) -> Result<AuthorizationUrl, AuthError> {
        let url = start(
            &self.0,
            &ctx,
            Start {
                provider: &input.provider,
                scopes: &input.scopes,
                callback_url: input.callback_url,
                error_callback_url: input.error_callback_url,
                new_user_callback_url: input.new_user_callback_url,
                link: None,
            },
        )
        .await?;
        Ok(AuthorizationUrl {
            url,
            redirect: !input.disable_redirect,
        })
    }
}

// ---------------------------------------------------------------------------- link

/// `POST /link-social`: link another provider to the signed-in user. Needs a session read
/// from the database (`Ctx::sensitive_session`), so API-key and impersonation sessions can't
/// link accounts.
pub struct LinkSocial(pub(crate) Arc<Social>);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkSocialInput {
    pub provider: String,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(default, rename = "errorCallbackURL")]
    pub error_callback_url: Option<String>,
    #[serde(default)]
    pub disable_redirect: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl<D: Adapter> Endpoint<D> for LinkSocial {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/link-social";
    type Access = Authenticated;
    type Input = LinkSocialInput;
    type Output = AuthorizationUrl;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: LinkSocialInput,
    ) -> Result<AuthorizationUrl, AuthError> {
        let session = ctx.sensitive_session().await?;
        let url = start(
            &self.0,
            &ctx,
            Start {
                provider: &input.provider,
                scopes: &input.scopes,
                callback_url: input.callback_url,
                error_callback_url: input.error_callback_url,
                new_user_callback_url: None,
                link: Some((session.user.id.clone(), session.session.id.clone())),
            },
        )
        .await?;
        Ok(AuthorizationUrl {
            url,
            redirect: !input.disable_redirect,
        })
    }
}

// ---------------------------------------------------------------------------- callback

/// `GET /callback/{id}`: the provider sends the browser back here. Always answers with a
/// redirect: to the callback URL on success, to the error callback URL with `?error=` on
/// failure.
pub struct SocialCallback(pub(crate) Arc<Social>);

#[derive(Debug, Default, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

enum Fail {
    Code(String),
    Auth(AuthError),
}

impl From<AuthError> for Fail {
    fn from(err: AuthError) -> Self {
        Fail::Auth(err)
    }
}

fn fail(code: &str) -> Fail {
    Fail::Code(code.to_owned())
}

impl<D: Adapter> Endpoint<D> for SocialCallback {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/callback/{id}";
    type Access = Public;
    type Input = CallbackQuery;
    type Output = Empty;

    async fn call(&self, ctx: Ctx<D, Public>, input: CallbackQuery) -> Result<Empty, AuthError> {
        ctx.delete_cookie(STATE_COOKIE);
        let provider = ctx.param("id").unwrap_or_default().to_owned();
        let fallback = ctx.config().base_url.to_string();
        let verification = match &input.state {
            Some(state) => ctx.internal().consume_verification(state).await?,
            None => None,
        };
        let data = verification
            .filter(|v| v.identifier == identifier(&provider))
            .and_then(|v| v.data)
            .and_then(|data| serde_json::from_str::<StateData>(&data).ok());
        let Some(data) = data else {
            let code = if input.state.is_some() {
                "please_restart_the_process"
            } else {
                "state_not_found"
            };
            ctx.redirect(with_query(&fallback, "error", code));
            return Ok(Empty {});
        };
        let error_url = data
            .error_callback_url
            .clone()
            .unwrap_or_else(|| data.callback_url.clone());
        let target = match self.finish(&ctx, &provider, input, data).await {
            Ok(target) => target,
            Err(Fail::Code(code)) => with_query(&error_url, "error", &code),
            Err(Fail::Auth(err)) if err.status().is_client_error() => {
                with_query(&error_url, "error", err.code())
            }
            Err(Fail::Auth(err)) => return Err(err),
        };
        ctx.redirect(target);
        Ok(Empty {})
    }
}

impl SocialCallback {
    async fn finish<D: Adapter>(
        &self,
        ctx: &Ctx<D, Public>,
        provider_id: &str,
        input: CallbackQuery,
        data: StateData,
    ) -> Result<String, Fail> {
        let state = input.state.as_deref().unwrap_or_default();
        let bound = ctx
            .signed_cookie(STATE_COOKIE)
            .is_some_and(|cookie| ct_eq(cookie.as_bytes(), state.as_bytes()));
        if !bound {
            return Err(fail("state_mismatch"));
        }
        if let Some(error) = input.error {
            return Err(Fail::Code(error));
        }
        let code = input.code.ok_or_else(|| fail("no_code"))?;
        let configured = self
            .0
            .find(provider_id)
            .ok_or_else(|| fail("oauth_provider_not_found"))?;
        let provider = &configured.provider;
        let http = self.0.http();
        let redirect_uri = format!("{}/callback/{provider_id}", ctx.config().auth_url());
        let tokens = provider
            .exchange_code(
                &http,
                &TokenRequest {
                    code: &code,
                    code_verifier: &data.code_verifier,
                    redirect_uri: &redirect_uri,
                },
            )
            .await
            .map_err(|err| {
                tracing::warn!(provider = provider_id, error = %err, "OAuth code exchange failed");
                fail("invalid_code")
            })?;
        let profile = provider.profile(&http, &tokens).await.map_err(|err| {
            tracing::warn!(provider = provider_id, error = %err, "OAuth profile fetch failed");
            fail("unable_to_get_user_info")
        })?;
        let account = new_account(provider_id, &profile, tokens);
        let internal = ctx.internal();
        let existing = internal.find_account(provider_id, &profile.id).await?;

        if let Some(user_id) = data.link_user_id {
            // The user is read before the session that started the link is checked, so a
            // claim after this read refuses the link (see `link_account_unless_claimed`) and a
            // claim before it has already deleted that session.
            let user = internal
                .find_user_by_id(&user_id)
                .await?
                .ok_or_else(|| fail("unable_to_link_account"))?;
            self.check_link(ctx, &user, data.link_session_id.as_ref(), &profile)
                .await?;
            match existing {
                Some(found) if found.user_id != user_id => {
                    return Err(fail("account_already_linked_to_different_user"));
                }
                Some(found) => {
                    update_tokens(ctx, &found.id, &account).await?;
                }
                None => {
                    internal.link_account_unless_claimed(&user, account).await?;
                }
            }
            return Ok(data.callback_url);
        }

        let (user, created) = match existing {
            Some(found) => {
                let user = internal
                    .find_user_by_id(&found.user_id)
                    .await?
                    .ok_or_else(|| AuthError::internal("account without a user"))?;
                // Read after the user, so a claim that deleted the link after this point
                // changed the stamp the sign-in checks, and one before it left no link here.
                if update_tokens(ctx, &found.id, &account).await? == 0 {
                    return Err(fail("account_not_linked"));
                }
                (user, false)
            }
            None => {
                let email = profile
                    .email
                    .clone()
                    .ok_or_else(|| fail("email_not_found"))?;
                match internal.find_user_by_email(&email).await? {
                    Some(user) => {
                        if self.0.account_linking == AccountLinking::Off || !profile.email_verified
                        {
                            return Err(fail("account_not_linked"));
                        }
                        (internal.claim_user(user, Some(account)).await?, false)
                    }
                    None => {
                        if configured.disable_sign_up {
                            return Err(fail("signup_disabled"));
                        }
                        let user = NewUser {
                            email,
                            name: profile.name.clone().unwrap_or_default(),
                            image: profile.image.clone(),
                            email_verified: profile.email_verified,
                            extra: self.new_user_columns(ctx, configured, provider_id, &profile)?,
                        };
                        (internal.create_user(user, Some(account)).await?, true)
                    }
                }
            }
        };

        match internal.sign_in(user, "social", true).await? {
            SignInResult::SignedIn(_) if created => {
                Ok(data.new_user_callback_url.unwrap_or(data.callback_url))
            }
            SignInResult::SignedIn(_) => Ok(data.callback_url),
            SignInResult::Challenge(body) => Ok(with_challenge(data.callback_url, &body)),
        }
    }

    /// The checks of Better Auth's `linkOAuthAccount`: the session that started the link is
    /// still live and the user's, linking isn't off, the provider verified the email, and the
    /// email is the user's unless [`Social::allow_different_emails`] is set.
    async fn check_link<D: Adapter>(
        &self,
        ctx: &Ctx<D, Public>,
        user: &UserView,
        session_id: Option<&Id>,
        profile: &OAuthProfile,
    ) -> Result<(), Fail> {
        let session = match session_id {
            Some(id) => ctx
                .db()
                .find::<Session>(Session::ID.eq(id))
                .one()
                .await
                .map_err(AuthError::from)?,
            None => None,
        };
        let live = session.is_some_and(|s| s.user_id == user.id && s.expires_at > ctx.now());
        if !live || self.0.account_linking == AccountLinking::Off || !profile.email_verified {
            return Err(fail("unable_to_link_account"));
        }
        if self.0.allow_different_emails {
            return Ok(());
        }
        let same_email = profile
            .email
            .as_deref()
            .is_some_and(|email| email.eq_ignore_ascii_case(&user.email));
        if !same_email {
            return Err(fail("email_doesn't_match"));
        }
        Ok(())
    }

    /// Runs the profile mapping for a new user and checks its columns against `user`, like
    /// sign-up checks its input fields, except that server-only columns are allowed. Mistakes
    /// are the app's, so they are 500s with the reason logged.
    fn new_user_columns<D: Adapter>(
        &self,
        ctx: &Ctx<D, Public>,
        configured: &ConfiguredProvider,
        provider_id: &str,
        profile: &OAuthProfile,
    ) -> Result<Vec<(&'static str, Value)>, AuthError> {
        let columns = match configured
            .map_profile
            .as_ref()
            .or(self.0.map_profile.as_ref())
        {
            Some(map) => map(profile, provider_id)?,
            None => Vec::new(),
        };
        let table = ctx.schema().expect(User::TABLE);
        for (i, (name, value)) in columns.iter().enumerate() {
            let Some(column) = table.column(name).filter(|c| c.owner != "core") else {
                return Err(AuthError::internal(format!(
                    "the profile mapping for `{provider_id}` sets `user.{name}`, which is not an app or plugin column"
                )));
            };
            if columns[..i].iter().any(|(earlier, _)| earlier == name) {
                return Err(AuthError::internal(format!(
                    "the profile mapping for `{provider_id}` sets `user.{name}` twice"
                )));
            }
            let fits = match value_type(value) {
                None => column.nullable,
                Some(ty) => {
                    ty == column.ty || (ty == ColumnType::Text && column.ty == ColumnType::Id)
                }
            };
            if !fits {
                let got = value_type(value).map_or("null".to_owned(), |ty| format!("{ty:?}"));
                let nullable = if column.nullable { "nullable " } else { "" };
                return Err(AuthError::internal(format!(
                    "the profile mapping for `{provider_id}` sets `user.{name}` to {got}, but the column is {nullable}{:?}",
                    column.ty
                )));
            }
        }
        let missing = table.columns.iter().find(|c| {
            c.owner != "core"
                && !c.nullable
                && c.default.is_none()
                && !columns.iter().any(|(name, _)| *name == c.name)
        });
        if let Some(column) = missing {
            return Err(AuthError::internal(format!(
                "`user.{}` is required and has no default, but social sign-up through `{provider_id}` doesn't set it; return it from `Social::map_profile`",
                column.name
            )));
        }
        Ok(columns)
    }
}

/// The column type a value belongs to, or `None` for null.
fn value_type(value: &Value) -> Option<ColumnType> {
    Some(match value {
        Value::Null => return None,
        Value::Bool(_) => ColumnType::Bool,
        Value::Int(_) => ColumnType::Int,
        Value::Text(_) => ColumnType::Text,
        Value::Bytes(_) => ColumnType::Bytes,
        Value::Timestamp(_) => ColumnType::Timestamp,
        Value::Json(_) => ColumnType::Json,
    })
}

/// The callback URL with a gate's challenge as query parameters, e.g.
/// `?twoFactorRedirect=true&twoFactorMethods=totp,otp`. Arrays become comma-separated lists.
fn with_challenge(url: String, challenge: &serde_json::Value) -> String {
    let Some(fields) = challenge.as_object() else {
        return url;
    };
    fields.iter().fold(url, |url, (key, value)| match value {
        serde_json::Value::String(s) => with_query(&url, key, s),
        serde_json::Value::Array(items) => {
            let items: Vec<String> = items
                .iter()
                .map(|item| match item {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect();
            with_query(&url, key, &items.join(","))
        }
        other => with_query(&url, key, &other.to_string()),
    })
}

fn new_account(provider_id: &str, profile: &OAuthProfile, tokens: OAuthTokens) -> NewAccount {
    NewAccount {
        access_token: Some(tokens.access_token),
        refresh_token: tokens.refresh_token,
        id_token: tokens.id_token,
        access_token_expires_at: tokens.access_token_expires_at,
        refresh_token_expires_at: tokens.refresh_token_expires_at,
        scope: tokens.scope,
        ..NewAccount::oauth(provider_id, &profile.id)
    }
}

/// Stores fresh tokens on an existing account. A missing refresh or id token keeps the old one,
/// since providers only send those on some sign-ins.
async fn update_tokens<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    account_id: &Id,
    account: &NewAccount,
) -> Result<u64, AuthError> {
    let seal = |token: &String| Some(ctx.oauth_token_bytes(token));
    let mut update = ctx
        .db()
        .update::<Account>(Account::ID.eq(account_id))
        .set(
            Account::ACCESS_TOKEN,
            account.access_token.as_ref().and_then(seal),
        )
        .set(
            Account::ACCESS_TOKEN_EXPIRES_AT,
            account.access_token_expires_at,
        )
        .set(Account::SCOPE, account.scope.clone());
    if let Some(refresh_token) = &account.refresh_token {
        update = update.set(Account::REFRESH_TOKEN, seal(refresh_token)).set(
            Account::REFRESH_TOKEN_EXPIRES_AT,
            account.refresh_token_expires_at,
        );
    }
    if let Some(id_token) = &account.id_token {
        update = update.set(Account::ID_TOKEN, Some(id_token.clone()));
    }
    Ok(update.exec().await?)
}

// ---------------------------------------------------------------------------- accounts

/// `GET /list-accounts`: the signed-in user's ways to sign in, without tokens.
pub struct ListAccounts;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub id: Id,
    pub provider_id: String,
    pub account_id: String,
    pub user_id: Id,
    pub scopes: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<Account> for AccountInfo {
    fn from(account: Account) -> Self {
        let scopes = account
            .scope
            .as_deref()
            .unwrap_or_default()
            .split([',', ' '])
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        Self {
            id: account.id,
            provider_id: account.provider_id,
            account_id: account.account_id,
            user_id: account.user_id,
            scopes,
            created_at: account.created_at,
            updated_at: account.updated_at,
        }
    }
}

async fn user_accounts<D: Adapter>(ctx: &Ctx<D, Authenticated>) -> Result<Vec<Account>, AuthError> {
    Ok(ctx
        .db()
        .find::<Account>(ctx.internal().accounts_of(&ctx.session().user.id))
        .order_by(("created_at", Order::Asc))
        .all()
        .await?)
}

impl<D: Adapter> Endpoint<D> for ListAccounts {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/list-accounts";
    type Access = Authenticated;
    type Input = Empty;
    type Output = Vec<AccountInfo>;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        _: Empty,
    ) -> Result<Vec<AccountInfo>, AuthError> {
        Ok(user_accounts(&ctx)
            .await?
            .into_iter()
            .map(AccountInfo::from)
            .collect())
    }
}

/// `POST /unlink-account`. Refuses to remove the user's last account.
pub struct UnlinkAccount;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlinkAccountInput {
    pub provider_id: String,
    #[serde(default)]
    pub account_id: Option<String>,
}

impl<D: Adapter> Endpoint<D> for UnlinkAccount {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/unlink-account";
    type Access = Authenticated;
    type Input = UnlinkAccountInput;
    type Output = Status;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: UnlinkAccountInput,
    ) -> Result<Status, AuthError> {
        ctx.sensitive_session().await?;
        let accounts = user_accounts(&ctx).await?;
        let target = accounts
            .iter()
            .find(|a| {
                a.provider_id == input.provider_id
                    && input
                        .account_id
                        .as_ref()
                        .is_none_or(|id| *id == a.account_id)
            })
            .ok_or(SocialError::AccountNotFound)?;
        if accounts.len() == 1 {
            return Err(SocialError::LastAccount.into());
        }
        ctx.db()
            .delete::<Account>(Account::ID.eq(&target.id))
            .await?;
        Ok(Status { status: true })
    }
}
