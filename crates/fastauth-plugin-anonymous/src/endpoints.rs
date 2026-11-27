//! `POST /sign-in/anonymous`, `POST /delete-anonymous-user`, and linking an anonymous user
//! to the real one that signs in after it.

use fastauth_core::events::UserDeleted;
use fastauth_core::plugin_prelude::*;
use fastauth_core::routes::normalize_email;
use serde_json::{Map, Value as Json};

use crate::model::{AnonymousUser, is_anonymous};
use crate::{Anonymous, AnonymousError, LinkAccount};

/// Better Auth's placeholder domain: `{id}@anonymous.placeholder.invalid`.
const PLACEHOLDER_DOMAIN: &str = "anonymous.placeholder.invalid";

/// The request's own session from its cookie, without refreshing it. Sign-in endpoints are
/// public, so their context carries no session.
async fn cookie_session<D: Adapter, A>(ctx: &Ctx<D, A>) -> Result<Option<SessionView>, AuthError> {
    let Some(token) = ctx.signed_token_cookie("session_token") else {
        return Ok(None);
    };
    ctx.internal().find_session_by_token(&token).await
}

/// Deletes a user with their sessions and accounts.
async fn delete_user<D: Adapter, A>(ctx: &Ctx<D, A>, user: &UserView) -> Result<(), AuthError> {
    ctx.internal().revoke_user_sessions(&user.id, None).await?;
    ctx.db()
        .delete::<Account>(Account::USER_ID.eq(&user.id))
        .await?;
    ctx.db().delete::<User>(User::ID.eq(&user.id)).await?;
    ctx.emit(UserDeleted {
        user_id: user.id.clone(),
        email: user.email.clone(),
    });
    Ok(())
}

/// Runs after every new session (see `PluginBuilder::on_session_created`): when the request
/// came from an anonymous session, hands both users to `on_link_account`, then deletes the
/// anonymous one unless it is the same user, the new user is anonymous too, or deletion is off.
pub(crate) async fn link<D: Adapter>(
    plugin: &Anonymous,
    ctx: HookCtx<D>,
    new_user: SessionView,
) -> Result<(), AuthError> {
    let Some(anonymous) = cookie_session(&ctx).await? else {
        return Ok(());
    };
    if !is_anonymous(&anonymous.user) {
        return Ok(());
    }
    let same_user = anonymous.user.id == new_user.user.id;
    let new_is_anonymous = is_anonymous(&new_user.user);
    if let Some(hook) = &plugin.on_link_account {
        hook(LinkAccount {
            anonymous_user: anonymous.clone(),
            new_user,
        })
        .await?;
    }
    if plugin.disable_delete_anonymous_user || same_user || new_is_anonymous {
        return Ok(());
    }
    if let Err(err) = delete_user(&ctx, &anonymous.user).await {
        tracing::error!(
            anonymous_user_id = %anonymous.user.id,
            error = %err,
            "failed to delete the anonymous user after linking"
        );
    }
    Ok(())
}

/// `POST /sign-in/anonymous`: creates an anonymous user and signs them in. Answers
/// `{ token, user }`, or 400 `ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY` when the
/// request already has an anonymous session.
pub struct SignInAnonymous(pub(crate) Arc<Anonymous>);

/// `{ token, user }`, or a sign-in gate's challenge.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum SignInAnonymousOutput {
    SignedIn {
        token: String,
        user: Map<String, Json>,
    },
    Challenge(Json),
}

impl<D: Adapter> Endpoint<D> for SignInAnonymous {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/sign-in/anonymous";
    type Access = Public;
    type Input = Empty;
    type Output = SignInAnonymousOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        _: Empty,
    ) -> Result<SignInAnonymousOutput, AuthError> {
        if cookie_session(&ctx)
            .await?
            .is_some_and(|session| is_anonymous(&session.user))
        {
            return Err(AnonymousError::AnonymousUsersCannotSignInAgainAnonymously.into());
        }
        let email = match &self.0.generate_random_email {
            Some(generate) => normalize_email(&generate())
                .map_err(|_| AuthError::from(AnonymousError::InvalidEmailFormat))?,
            None => {
                let id = ctx.new_id()?;
                let email = match &self.0.email_domain_name {
                    Some(domain) => format!("temp-{id}@{domain}"),
                    None => format!("{id}@{PLACEHOLDER_DOMAIN}"),
                };
                normalize_email(&email)
                    .map_err(|_| AuthError::from(AnonymousError::InvalidEmailFormat))?
            }
        };
        let name = self
            .0
            .generate_name
            .as_ref()
            .map(|generate| generate())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "Anonymous".to_owned());
        let internal = ctx.internal();
        let user = internal
            .create_user(
                NewUser {
                    email,
                    name,
                    extra: vec![AnonymousUser::IS_ANONYMOUS.value(true)],
                    ..NewUser::default()
                },
                None,
            )
            .await?;
        Ok(match internal.sign_in(user, "anonymous", true).await? {
            SignInResult::SignedIn(session) => SignInAnonymousOutput::SignedIn {
                token: session.token.clone().unwrap_or_default(),
                user: session.user.to_json(),
            },
            SignInResult::Challenge(body) => SignInAnonymousOutput::Challenge(body),
        })
    }
}

/// `POST /delete-anonymous-user`: deletes the signed-in anonymous user with their sessions
/// and clears the session cookies.
pub struct DeleteAnonymousUser(pub(crate) Arc<Anonymous>);

/// `{ "success": true }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Success {
    pub success: bool,
}

impl<D: Adapter> Endpoint<D> for DeleteAnonymousUser {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/delete-anonymous-user";
    type Access = Authenticated;
    type Input = Empty;
    type Output = Success;

    async fn call(&self, ctx: Ctx<D, Authenticated>, _: Empty) -> Result<Success, AuthError> {
        if self.0.disable_delete_anonymous_user {
            return Err(AnonymousError::DeleteAnonymousUserDisabled.into());
        }
        let user = &ctx.sensitive_session().await?.user;
        if !is_anonymous(user) {
            return Err(AnonymousError::UserIsNotAnonymous.into());
        }
        delete_user(&ctx, user).await?;
        ctx.internal().clear_session_cookies();
        Ok(Success { success: true })
    }
}
