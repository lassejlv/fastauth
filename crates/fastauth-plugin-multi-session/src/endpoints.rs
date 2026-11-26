//! The device-session cookies and the `/multi-session/*` endpoints.

use fastauth_core::cookies::SetCookie;
use fastauth_core::crypto::SignPurpose;
use fastauth_core::plugin_prelude::*;
use fastauth_core::routes::Status;
use serde_json::{Map, Value as Json};

use crate::{MultiSession, MultiSessionError};

/// Better Auth's marker: every cookie whose name contains it is a device-session cookie.
const MARKER: &str = "_multi-";

/// `session_token_multi-{token}`, before the cookie prefix. Better Auth lowercases the token.
fn cookie_suffix(token: &str) -> String {
    format!("session_token{MARKER}{}", token.to_lowercase())
}

/// Every device-session cookie on the request: its full name, and its token when the
/// signature checks out.
fn device_cookies<D: Adapter, A>(ctx: &Ctx<D, A>) -> Vec<(String, Option<String>)> {
    ctx.headers()
        .get_all("cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(name, _)| name.contains(MARKER))
        .map(|(name, value)| {
            let token = ctx
                .keys()
                .verify(SignPurpose::Cookie, value.trim_matches('"'))
                .map(str::to_owned);
            (name.to_owned(), token)
        })
        .collect()
}

/// Deletes the session `token` belongs to, if it still exists.
async fn revoke_token<D: Adapter, A>(ctx: &Ctx<D, A>, token: &str) -> Result<(), AuthError> {
    let internal = ctx.internal();
    if let Some(found) = internal.find_session_by_token(token).await? {
        internal
            .revoke_session(&found.user.id, &found.session.id)
            .await?;
    }
    Ok(())
}

fn invalid_token() -> AuthError {
    MultiSessionError::InvalidSessionToken.into()
}

/// Whether the browser asked not to be remembered, so a switched-to session cookie should
/// last for the browser session too.
fn remember_me<D: Adapter, A>(ctx: &Ctx<D, A>) -> bool {
    !ctx.dont_remember()
}

/// Runs after every new session: remembers it in a device-session cookie, after deleting the
/// browser's older sessions of the same user. A `rememberMe: false` session gets a cookie
/// that ends with the browser session, like its session cookie. Past `maximum_sessions` the new session stays
/// active but isn't remembered. Better Auth's after hook, rule for rule.
pub(crate) async fn remember<D: Adapter>(
    plugin: &MultiSession,
    ctx: HookCtx<D>,
    session: SessionView,
) -> Result<(), AuthError> {
    let Some(token) = session.token.as_deref() else {
        return Ok(());
    };
    let suffix = cookie_suffix(token);
    if ctx.cookie(&ctx.config().cookie_name(&suffix)).is_some() {
        return Ok(());
    }
    let cookies = device_cookies(&ctx);
    let internal = ctx.internal();
    let mut replaced = 0;
    for (name, held) in &cookies {
        let Some(held) = held else { continue };
        let Some(found) = internal.find_session_by_token(held).await? else {
            continue;
        };
        if found.user.id == session.user.id {
            internal
                .revoke_session(&found.user.id, &found.session.id)
                .await?;
            ctx.set_cookie(SetCookie::delete(name.clone()));
            replaced += 1;
        }
    }
    if cookies.len() - replaced + 1 > plugin.maximum_sessions {
        return Ok(());
    }
    let max_age = remember_me(&ctx).then(|| ctx.config().session.lifetime());
    ctx.set_signed_cookie(&suffix, token, max_age);
    Ok(())
}

/// After `/sign-out`: expires every device-session cookie and deletes their sessions.
pub(crate) async fn sign_out_all<D: Adapter>(ctx: &HookCtx<D>) -> Result<(), AuthError> {
    for (name, token) in device_cookies(ctx) {
        let Some(token) = token else { continue };
        ctx.set_cookie(SetCookie::delete(name));
        revoke_token(ctx, &token).await?;
    }
    Ok(())
}

/// `GET /multi-session/list-device-sessions`: `[{ session, user }]` for every unexpired
/// remembered session, one per user. Each `session` carries its `token`, which
/// `set-active` and `revoke` take.
pub struct ListDeviceSessions;

impl<D: Adapter> Endpoint<D> for ListDeviceSessions {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/multi-session/list-device-sessions";
    type Access = Public;
    type Input = Map<String, Json>;
    type Output = Vec<Json>;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        _: Map<String, Json>,
    ) -> Result<Vec<Json>, AuthError> {
        let internal = ctx.internal();
        let mut sessions: Vec<SessionView> = Vec::new();
        for token in device_cookies(&ctx)
            .into_iter()
            .filter_map(|(_, token)| token)
        {
            let Some(found) = internal.find_session_by_token(&token).await? else {
                continue;
            };
            if !sessions.iter().any(|s| s.user.id == found.user.id) {
                sessions.push(found);
            }
        }
        Ok(sessions.iter().map(SessionView::to_response_json).collect())
    }
}

/// The body of `set-active` and `revoke`: `{ "sessionToken": ".." }`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionTokenInput {
    pub session_token: String,
}

/// `POST /multi-session/set-active`: makes a remembered session the active one and answers
/// `{ session, user }`. 401 `INVALID_SESSION_TOKEN` when the browser doesn't hold it, or it
/// expired (its cookie is then cleared).
pub struct SetActiveSession;

impl<D: Adapter> Endpoint<D> for SetActiveSession {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/multi-session/set-active";
    type Access = Public;
    type Input = SessionTokenInput;
    type Output = Json;

    async fn call(&self, ctx: Ctx<D, Public>, input: SessionTokenInput) -> Result<Json, AuthError> {
        let suffix = cookie_suffix(&input.session_token);
        let token = ctx.signed_cookie(&suffix).ok_or_else(invalid_token)?;
        let internal = ctx.internal();
        let Some(found) = internal.find_session_by_token(&token).await? else {
            ctx.delete_cookie(&suffix);
            return Err(invalid_token());
        };
        internal.set_session_cookies(&token, remember_me(&ctx));
        Ok(found.to_response_json())
    }
}

/// `POST /multi-session/revoke`: signs one remembered session out and forgets it. Revoking
/// the active session makes the next remembered one active, or signs the browser out when
/// none is left. Needs a session; answers `{ "status": true }`.
pub struct RevokeDeviceSession;

impl<D: Adapter> Endpoint<D> for RevokeDeviceSession {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/multi-session/revoke";
    type Access = Authenticated;
    type Input = SessionTokenInput;
    type Output = Status;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: SessionTokenInput,
    ) -> Result<Status, AuthError> {
        let suffix = cookie_suffix(&input.session_token);
        let token = ctx.signed_cookie(&suffix).ok_or_else(invalid_token)?;
        revoke_token(&ctx, &token).await?;
        ctx.delete_cookie(&suffix);
        if ctx.session().token.as_deref() != Some(token.as_str()) {
            return Ok(Status { status: true });
        }
        let internal = ctx.internal();
        for held in device_cookies(&ctx)
            .into_iter()
            .filter_map(|(_, token)| token)
        {
            if internal.find_session_by_token(&held).await?.is_some() {
                internal.set_session_cookies(&held, remember_me(&ctx));
                return Ok(Status { status: true });
            }
        }
        internal.clear_session_cookies();
        Ok(Status { status: true })
    }
}
