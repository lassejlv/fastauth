use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;

use actix_web::dev::Payload;
use actix_web::http::header::{self, HeaderMap, HeaderValue};
use actix_web::{FromRequest, HttpMessage, HttpRequest};
use fastauth_core::prelude::SessionData;
use fastauth_core::{AuthError, AuthInstance};
use tokio::sync::OnceCell;

use crate::convert;

type Data<A> = SessionData<<A as AuthInstance>::UserFields, <A as AuthInstance>::Plugins>;
type LocalBoxFuture<T> = Pin<Box<dyn Future<Output = T>>>;

struct Resolution<A: AuthInstance> {
    session: Result<Option<Arc<Data<A>>>, AuthError>,
    cookies: Vec<http::HeaderValue>,
}

/// The request's session, resolved at most once. Lives in request extensions, keyed by
/// the auth type, so every extractor and the session middleware share one lookup.
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
            .filter_map(|v| cookie_name(v.as_bytes()).map(str::to_owned))
            .collect();
        for cookie in &resolution.cookies {
            if cookie_name(cookie.as_bytes())
                .is_some_and(|name| already_set.iter().any(|n| n == name))
            {
                continue;
            }
            if let Ok(value) = HeaderValue::from_bytes(cookie.as_bytes()) {
                headers.append(header::SET_COOKIE, value);
            }
        }
    }
}

fn cookie_name(value: &[u8]) -> Option<&str> {
    let (name, _) = std::str::from_utf8(value).ok()?.split_once('=')?;
    Some(name.trim())
}

async fn resolve<A: AuthInstance>(request: &HttpRequest) -> Result<Option<Session<A>>, AuthError> {
    let slot = request
        .extensions_mut()
        .get_or_insert_with(SessionSlot::<A>::default)
        .clone();
    let resolution = slot
        .0
        .get_or_init(|| async {
            let headers = convert::headers(request.headers());
            match crate::auth::<A>(request) {
                Ok(auth) => {
                    let (session, cookies) = auth.session_with_cookies(&headers).await;
                    Resolution {
                        session: session.map(|s| s.map(Arc::new)),
                        cookies,
                    }
                }
                Err(err) => Resolution {
                    session: Err(err),
                    cookies: Vec::new(),
                },
            }
        })
        .await;
    resolution.session.clone().map(|s| s.map(Session))
}

/// The signed-in session. Rejects with `401 UNAUTHORIZED` when there is none; use
/// [`OptionalSession<A>`] for routes that work signed in or out.
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

impl<A: AuthInstance> FromRequest for Session<A> {
    type Error = AuthError;
    type Future = LocalBoxFuture<Result<Self, AuthError>>;

    fn from_request(request: &HttpRequest, _: &mut Payload) -> Self::Future {
        let request = request.clone();
        Box::pin(async move {
            resolve::<A>(&request)
                .await?
                .ok_or(AuthError::unauthorized())
        })
    }
}

/// The session if there is one, for routes that work signed in or out:
/// `OptionalSession(session): OptionalSession<A>`. Like axum's `Option<Session<A>>`, a failed
/// lookup (a storage error, or an invalid API key with key sessions on) still rejects.
///
/// actix-web's own `Option<Session<A>>` works too, but actix turns every rejection into
/// `None`, so those failures read as signed out.
pub struct OptionalSession<A: AuthInstance>(pub Option<Session<A>>);

impl<A: AuthInstance> Clone for OptionalSession<A> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<A: AuthInstance> FromRequest for OptionalSession<A> {
    type Error = AuthError;
    type Future = LocalBoxFuture<Result<Self, AuthError>>;

    fn from_request(request: &HttpRequest, _: &mut Payload) -> Self::Future {
        let request = request.clone();
        Box::pin(async move { resolve::<A>(&request).await.map(Self) })
    }
}

/// A session created within `fresh_age`, for sensitive actions. Rejects with `401` without
/// a session and `403 SESSION_NOT_FRESH` when it is older or ephemeral (an API key's): the
/// rule of core's `Fresh` access.
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

impl<A: AuthInstance> FromRequest for FreshSession<A> {
    type Error = AuthError;
    type Future = LocalBoxFuture<Result<Self, AuthError>>;

    fn from_request(request: &HttpRequest, _: &mut Payload) -> Self::Future {
        let request = request.clone();
        Box::pin(async move {
            let session = resolve::<A>(&request)
                .await?
                .ok_or(AuthError::unauthorized())?;
            let auth = crate::auth::<A>(&request)?;
            if session.view().ephemeral || !auth.config().is_fresh(&session.session) {
                return Err(AuthError::not_fresh());
            }
            Ok(Self(session))
        })
    }
}
