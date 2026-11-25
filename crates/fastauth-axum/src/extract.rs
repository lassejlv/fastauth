use std::ops::Deref;
use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts, OptionalFromRequestParts};
use fastauth_core::prelude::SessionData;
use fastauth_core::{AuthError, AuthInstance};
use http::request::Parts;
use http::{HeaderMap, HeaderValue, header};
use tokio::sync::OnceCell;

type Data<A> = SessionData<<A as AuthInstance>::UserFields, <A as AuthInstance>::Plugins>;

struct Resolution<A: AuthInstance> {
    session: Result<Option<Arc<Data<A>>>, AuthError>,
    cookies: Vec<HeaderValue>,
}

/// The request's session, resolved at most once. Lives in request extensions, keyed by
/// the auth type, so every extractor and the session layer share one lookup.
pub(crate) struct SessionSlot<A: AuthInstance>(Arc<OnceCell<Resolution<A>>>);

impl<A: AuthInstance> Clone for SessionSlot<A> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<A: AuthInstance> Default for SessionSlot<A> {
    fn default() -> Self {
        Self(Arc::new(OnceCell::new()))
    }
}

impl<A: AuthInstance> SessionSlot<A> {
    /// Appends the cookies the lookup produced, unless the response already sets a cookie
    /// of the same name (a handler that signed in or out knows better).
    pub(crate) fn append_cookies(&self, headers: &mut HeaderMap) {
        let Some(resolution) = self.0.get() else {
            return;
        };
        let already_set: Vec<String> = headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| cookie_name(v).map(str::to_owned))
            .collect();
        for cookie in &resolution.cookies {
            if !cookie_name(cookie).is_some_and(|name| already_set.iter().any(|n| n == name)) {
                headers.append(header::SET_COOKIE, cookie.clone());
            }
        }
    }
}

fn cookie_name(value: &HeaderValue) -> Option<&str> {
    let (name, _) = value.to_str().ok()?.split_once('=')?;
    Some(name.trim())
}

async fn resolve<A, S>(parts: &mut Parts, state: &S) -> Result<Option<Session<A>>, AuthError>
where
    A: AuthInstance + FromRef<S>,
    S: Send + Sync,
{
    let slot = parts
        .extensions
        .get_or_insert_with(SessionSlot::<A>::default)
        .clone();
    let headers = &parts.headers;
    let resolution = slot
        .0
        .get_or_init(|| async {
            let (session, cookies) = A::from_ref(state).session_with_cookies(headers).await;
            Resolution {
                session: session.map(|s| s.map(Arc::new)),
                cookies,
            }
        })
        .await;
    resolution.session.clone().map(|s| s.map(Session))
}

/// The signed-in session. Rejects with `401 UNAUTHORIZED` when there is none; use
/// `Option<Session<A>>` for routes that work signed in or out.
///
/// Derefs to `SessionData`: `session.user.email`, `session.session.expires_at`.
pub struct Session<A: AuthInstance>(Arc<Data<A>>);

impl<A: AuthInstance> Clone for Session<A> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<A: AuthInstance> Deref for Session<A> {
    type Target = Data<A>;

    fn deref(&self) -> &Data<A> {
        &self.0
    }
}

impl<A, S> FromRequestParts<S> for Session<A>
where
    A: AuthInstance + FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, AuthError> {
        resolve(parts, state)
            .await?
            .ok_or(AuthError::unauthorized())
    }
}

impl<A, S> OptionalFromRequestParts<S> for Session<A>
where
    A: AuthInstance + FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Option<Self>, AuthError> {
        resolve(parts, state).await
    }
}

/// A session created within `fresh_age`, for sensitive actions. Rejects with `401` without
/// a session and `403 SESSION_NOT_FRESH` when it is older: the rule of core's `Fresh` access.
pub struct FreshSession<A: AuthInstance>(Session<A>);

impl<A: AuthInstance> Clone for FreshSession<A> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<A: AuthInstance> Deref for FreshSession<A> {
    type Target = Data<A>;

    fn deref(&self) -> &Data<A> {
        &self.0
    }
}

impl<A, S> FromRequestParts<S> for FreshSession<A>
where
    A: AuthInstance + FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, AuthError> {
        let session = resolve::<A, S>(parts, state)
            .await?
            .ok_or(AuthError::unauthorized())?;
        if !A::from_ref(state).config().is_fresh(&session.session) {
            return Err(AuthError::not_fresh());
        }
        Ok(Self(session))
    }
}
