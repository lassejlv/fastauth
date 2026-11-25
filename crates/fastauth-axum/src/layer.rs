use std::marker::PhantomData;
use std::task::{Context, Poll};

use fastauth_core::AuthInstance;
use fastauth_core::endpoint::BoxFuture;
use http::{Request, Response};

use crate::extract::SessionSlot;

/// Resolves the session at most once per request, on first use, and adds the refreshed
/// or cleared session cookies to the response, so sliding expiry reaches the browser on
/// your own routes too. Build it with `AuthRouter::session_layer`.
pub struct SessionLayer<A> {
    _auth: PhantomData<fn() -> A>,
}

impl<A> SessionLayer<A> {
    pub(crate) fn new() -> Self {
        Self { _auth: PhantomData }
    }
}

impl<A> Clone for SessionLayer<A> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<A, S> tower_layer::Layer<S> for SessionLayer<A> {
    type Service = SessionService<S, A>;

    fn layer(&self, inner: S) -> SessionService<S, A> {
        SessionService {
            inner,
            _auth: PhantomData,
        }
    }
}

/// The service `SessionLayer` wraps around each route.
pub struct SessionService<S, A> {
    inner: S,
    _auth: PhantomData<fn() -> A>,
}

impl<S: Clone, A> Clone for SessionService<S, A> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _auth: PhantomData,
        }
    }
}

impl<S, A, B, ResBody> tower_service::Service<Request<B>> for SessionService<S, A>
where
    S: tower_service::Service<Request<B>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    A: AuthInstance,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Response<ResBody>, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let slot = SessionSlot::<A>::default();
        request.extensions_mut().insert(slot.clone());
        let response = self.inner.call(request);
        Box::pin(async move {
            let mut response = response.await?;
            slot.append_cookies(response.headers_mut());
            Ok(response)
        })
    }
}
