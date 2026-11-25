//! The social endpoints. Paths and JSON follow Better Auth.

use std::sync::Arc;

use fastauth_core::adapter::{Adapter, Order, Transaction};
use fastauth_core::crypto::{Hash, base64url, ct_eq, random_token};
use fastauth_core::endpoint::{Authenticated, Ctx, Empty, Endpoint, Public};
use fastauth_core::error::codes;
use fastauth_core::events::{AccountLinked, EmailVerified, SessionRevoked};
use fastauth_core::internal::{NewAccount, NewUser, SignInResult};
use fastauth_core::models::{Account, Session, User};
use fastauth_core::routes::Status;
use fastauth_core::value::Id;
use fastauth_core::{AuthError, Duration};
use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::provider::{AuthorizationRequest, OAuthProfile, OAuthTokens, TokenRequest};
use crate::social::{AccountLinking, Social, SocialError};

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
}

struct Start<'a> {
    provider: &'a str,
    scopes: &'a [String],
    callback_url: Option<String>,
    error_callback_url: Option<String>,
    new_user_callback_url: Option<String>,
    link_user_id: Option<Id>,
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
        link_user_id: start.link_user_id,
    };
    let data = serde_json::to_string(&data).map_err(AuthError::internal)?;
    let state = ctx
        .internal()
        .create_verification(&identifier(start.provider), STATE_TTL, Some(data))
        .await?;
    ctx.set_signed_cookie(STATE_COOKIE, &state, Some(STATE_TTL));
    let redirect_uri = format!("{}/callback/{}", config.auth_url(), start.provider);
    let url = provider.authorization_url(&AuthorizationRequest {
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
                link_user_id: None,
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

/// `POST /link-social`: link another provider to the signed-in user.
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
        let url = start(
            &self.0,
            &ctx,
            Start {
                provider: &input.provider,
                scopes: &input.scopes,
                callback_url: input.callback_url,
                error_callback_url: input.error_callback_url,
                new_user_callback_url: None,
                link_user_id: Some(ctx.session().user.id.clone()),
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
        let provider = self
            .0
            .find(provider_id)
            .ok_or_else(|| fail("oauth_provider_not_found"))?;
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
            match existing {
                Some(found) if found.user_id != user_id => {
                    return Err(fail("account_already_linked_to_different_user"));
                }
                Some(found) => update_tokens(ctx, &found.id, &account).await?,
                None => {
                    internal.link_account(&user_id, account).await?;
                }
            }
            return Ok(data.callback_url);
        }

        let (user, created) = match existing {
            Some(found) => {
                update_tokens(ctx, &found.id, &account).await?;
                let user = internal
                    .find_user_by_id(&found.user_id)
                    .await?
                    .ok_or_else(|| AuthError::internal("account without a user"))?;
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
                        if user.email_verified {
                            internal.link_account(&user.id, account).await?;
                        } else {
                            claim_unverified_user(ctx, &user.id, account).await?;
                        }
                        (user, false)
                    }
                    None => {
                        let user = NewUser {
                            email,
                            name: profile.name.clone().unwrap_or_default(),
                            image: profile.image.clone(),
                            email_verified: profile.email_verified,
                            extra: Vec::new(),
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
}

/// The callback URL with a gate's challenge as query parameters, e.g. `?twoFactorRedirect=true`.
fn with_challenge(url: String, challenge: &serde_json::Value) -> String {
    let Some(fields) = challenge.as_object() else {
        return url;
    };
    fields.iter().fold(url, |url, (key, value)| match value {
        serde_json::Value::String(s) => with_query(&url, key, s),
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

/// Links a verified social account to a user whose email was never verified. Whoever
/// registered that email first may not own it, so in one transaction their password and
/// sessions go, the email becomes verified, and the account is linked.
async fn claim_unverified_user<D: Adapter>(
    ctx: &Ctx<D, Public>,
    user_id: &Id,
    account: NewAccount,
) -> Result<(), AuthError> {
    let keys = ctx.keys();
    let seal = |token: Option<String>| token.map(|t| keys.encrypt(t.as_bytes()));
    let now = ctx.now();
    let provider_id = account.provider_id.clone();
    let row = Account {
        id: ctx.new_id(),
        user_id: user_id.clone(),
        provider_id: account.provider_id,
        account_id: account.account_id.unwrap_or_else(|| user_id.to_string()),
        password_hash: None,
        access_token: seal(account.access_token),
        refresh_token: seal(account.refresh_token),
        id_token: account.id_token,
        access_token_expires_at: account.access_token_expires_at,
        refresh_token_expires_at: account.refresh_token_expires_at,
        scope: account.scope,
        created_at: now,
        updated_at: now,
    };
    let tx = ctx.adapter().begin().await?;
    let db = ctx.db_on(&tx);
    db.delete::<Account>(
        Account::USER_ID
            .eq(user_id)
            .and(Account::PROVIDER_ID.eq(Account::CREDENTIAL)),
    )
    .await?;
    let revoked = db.delete::<Session>(Session::USER_ID.eq(user_id)).await?;
    db.update::<User>(User::ID.eq(user_id))
        .set(User::EMAIL_VERIFIED, true)
        .exec()
        .await?;
    db.insert(&row).await?;
    tx.commit().await?;
    if revoked > 0 {
        ctx.emit(SessionRevoked {
            user_id: user_id.clone(),
            session_id: None,
        });
    }
    ctx.emit(EmailVerified {
        user_id: user_id.clone(),
    });
    ctx.emit(AccountLinked {
        user_id: user_id.clone(),
        provider_id,
    });
    Ok(())
}

/// Stores fresh tokens on an existing account. A missing refresh or id token keeps the old one,
/// since providers only send those on some sign-ins.
async fn update_tokens<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    account_id: &Id,
    account: &NewAccount,
) -> Result<(), AuthError> {
    let keys = ctx.keys();
    let seal = |token: &String| Some(keys.encrypt(token.as_bytes()));
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
    update.exec().await?;
    Ok(())
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
        .find::<Account>(Account::USER_ID.eq(&ctx.session().user.id))
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
