use std::future::{Future, Ready, ready};
use std::marker::PhantomData;
use std::pin::Pin;

use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::{Error, HttpMessage};
use fastauth_core::AuthInstance;

use crate::extract::SessionSlot;

/// Resolves the session at most once per request, on first use, and adds the refreshed
/// or cleared session cookies to the response, so sliding expiry reaches the browser on
/// your own routes too. Build it with `AuthScope::session_middleware`.
pub struct SessionMiddleware<A> {
    _auth: PhantomData<fn() -> A>,
}

impl<A> SessionMiddleware<A> {
    pub(crate) fn new() -> Self {
        Self { _auth: PhantomData }
    }
}

impl<A> Clone for SessionMiddleware<A> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<S, B, A> Transform<S, ServiceRequest> for SessionMiddleware<A>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    A: AuthInstance,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SessionMiddlewareService<S, A>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, ()>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SessionMiddlewareService {
            service,
            _auth: PhantomData,
        }))
    }
}

/// The service `SessionMiddleware` wraps around each route.
pub struct SessionMiddlewareService<S, A> {
    service: S,
    _auth: PhantomData<fn() -> A>,
}

impl<S, B, A> Service<ServiceRequest> for SessionMiddlewareService<S, A>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    A: AuthInstance,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<ServiceResponse<B>, Error>>>>;

    forward_ready!(service);

    fn call(&self, request: ServiceRequest) -> Self::Future {
        let slot = SessionSlot::<A>::default();
        request.extensions_mut().insert(slot.clone());
        let response = self.service.call(request);
        Box::pin(async move {
            let mut response = response.await?;
            slot.append_cookies(response.headers_mut());
            Ok(response)
        })
    }
}
