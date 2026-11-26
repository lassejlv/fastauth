//! Endpoints, the request context, hooks, and the execution pipeline shared by HTTP
//! requests and server-side API calls.

use std::any::{Any, TypeId};
use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::header::{CONTENT_TYPE, LOCATION, SET_COOKIE};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use time::{Duration, OffsetDateTime};

use crate::adapter::{Adapter, Queries};
use crate::config::CoreConfig;
use crate::cookies::{self, SetCookie};
use crate::crypto::{Keys, Passwords, SignPurpose};
use crate::error::AuthError;
use crate::events::Event;
use crate::internal::Internal;
use crate::mail::DynMailer;
use crate::plugin::Plugin;
use crate::query::Db;
use crate::rate_limit::RateLimiter;
use crate::schema::Schema;
use crate::session::{SessionView, UserView};
use crate::value::Id;

pub type Response = http::Response<Bytes>;
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessLevel {
    Public,
    Optional,
    Required,
    Fresh,
}

/// How much session an endpoint needs. It decides what `Ctx::session` returns.
pub trait Access: Send + Sync + 'static {
    const LEVEL: AccessLevel;
}

/// No session lookup; `ctx.session()` doesn't exist.
#[derive(Debug)]
pub struct Public;
/// `ctx.session()` returns `Option<&SessionView>`.
#[derive(Debug)]
pub struct MaybeAuthenticated;
/// 401 without a session; `ctx.session()` returns `&SessionView`.
#[derive(Debug)]
pub struct Authenticated;
/// Like `Authenticated`, plus 403 `SESSION_NOT_FRESH` when the session is older than `fresh_age`.
#[derive(Debug)]
pub struct Fresh;

impl Access for Public {
    const LEVEL: AccessLevel = AccessLevel::Public;
}
impl Access for MaybeAuthenticated {
    const LEVEL: AccessLevel = AccessLevel::Optional;
}
impl Access for Authenticated {
    const LEVEL: AccessLevel = AccessLevel::Required;
}
impl Access for Fresh {
    const LEVEL: AccessLevel = AccessLevel::Fresh;
}

/// An auth endpoint: a typed function first, an HTTP route second.
///
/// `GET` endpoints read `Input` from the query string, everything else from the JSON body.
/// `PATH` is relative to the base path and uses `{name}` for parameters.
pub trait Endpoint<D: Adapter>: Send + Sync + 'static {
    const METHOD: Method;
    const PATH: &'static str;
    type Access: Access;
    type Input: DeserializeOwned + Send + 'static;
    type Output: Serialize + Send + 'static;

    fn call(
        &self,
        ctx: Ctx<D, Self::Access>,
        input: Self::Input,
    ) -> impl Future<Output = Result<Self::Output, AuthError>> + Send;
}

/// An empty input or output: `{}`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, Serialize)]
pub struct Empty {}

/// What the request looked like. For server API calls, headers are whatever the caller passed.
#[derive(Clone, Debug)]
pub struct RequestInfo {
    pub method: Method,
    pub path: String,
    pub params: Vec<(String, String)>,
    pub query: Option<String>,
    pub headers: HeaderMap,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

impl RequestInfo {
    pub(crate) fn synthetic(method: Method, path: &str, headers: HeaderMap) -> Self {
        let user_agent = header_str(&headers, http::header::USER_AGENT);
        Self {
            method,
            path: path.to_owned(),
            params: Vec::new(),
            query: None,
            headers,
            ip: None,
            user_agent,
        }
    }
}

pub(crate) fn header_str(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

pub(crate) struct PendingEvent {
    type_id: TypeId,
    event: Arc<dyn Any + Send + Sync>,
}

/// Side effects an endpoint asks for: cookies, a redirect, headers, events.
#[derive(Default)]
pub(crate) struct Effects {
    pub cookies: Vec<SetCookie>,
    pub redirect: Option<String>,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub events: Vec<PendingEvent>,
}

pub(crate) type ErasedBefore<D> = Arc<
    dyn Fn(
            HookCtx<D>,
            Box<dyn Any + Send>,
        ) -> BoxFuture<'static, Result<Before<Box<dyn Any + Send>>, AuthError>>
        + Send
        + Sync,
>;
pub(crate) type ErasedAfter<D> = Arc<
    dyn Fn(
            HookCtx<D>,
            Box<dyn Any + Send>,
        ) -> BoxFuture<'static, Result<After<Box<dyn Any + Send>>, AuthError>>
        + Send
        + Sync,
>;
pub(crate) type ErasedGate<D> = Arc<
    dyn Fn(HookCtx<D>, SignInAttempt) -> BoxFuture<'static, Result<Gate, AuthError>> + Send + Sync,
>;

/// A sign-in gate and the id of the plugin that registered it (`"app"` for the app's own).
pub(crate) struct OwnedGate<D> {
    pub owner: &'static str,
    pub gate: ErasedGate<D>,
}
pub(crate) type ErasedResponseHook<D> = Arc<dyn Fn(&Ctx<D>, &mut Response) + Send + Sync>;
pub(crate) type ErasedSessionHook<D> =
    Arc<dyn Fn(HookCtx<D>, SessionView) -> BoxFuture<'static, Result<(), AuthError>> + Send + Sync>;
pub(crate) type ErasedEventHandler<D> = Arc<
    dyn Fn(Arc<dyn Any + Send + Sync>, Ctx<D>) -> BoxFuture<'static, Result<(), AuthError>>
        + Send
        + Sync,
>;

pub(crate) struct EndpointHooks<D> {
    pub before: Vec<ErasedBefore<D>>,
    pub after: Vec<ErasedAfter<D>>,
}

impl<D> Default for EndpointHooks<D> {
    fn default() -> Self {
        Self {
            before: Vec::new(),
            after: Vec::new(),
        }
    }
}

/// What a before hook decides.
pub enum Before<I> {
    /// Run the endpoint with this (possibly changed) input.
    Continue(I),
    /// Skip the endpoint and answer with this response.
    Respond(Response),
}

/// What an after hook decides.
pub enum After<O> {
    Continue(O),
    Respond(Response),
}

/// What a sign-in gate decides, after credentials check out and before a session exists.
#[derive(Debug)]
pub enum Gate {
    Allow,
    Deny(AuthError),
    /// Answer the sign-in with this JSON (e.g. `{"twoFactorRedirect": true}`), no session.
    /// Gates registered after this one don't run yet: the plugin that challenged finishes the
    /// sign-in with [`Internal::complete_sign_in`], which runs every gate but its own.
    Challenge(serde_json::Value),
}

/// The sign-in a gate is judging.
#[derive(Clone, Debug)]
pub struct SignInAttempt {
    pub user: UserView,
    /// `"email"`, `"social"`, `"magic-link"`, ... A sign-in finished after a challenge keeps
    /// the method it started with.
    pub method: Cow<'static, str>,
    pub remember_me: bool,
}

/// The context hooks, gates and event handlers get.
pub type HookCtx<D> = Ctx<D, MaybeAuthenticated>;

/// What a session resolver found for a request without a session cookie.
#[derive(Clone, Debug)]
pub enum Resolved {
    /// A session token from somewhere other than the cookie (e.g. a bearer header).
    Token(String),
    /// A user, with a session that exists only for this request (e.g. an API key).
    User(Id),
}

/// Turns non-cookie credentials into a session. Tried in registration order.
pub trait SessionResolver<D: Adapter>: Send + Sync + 'static {
    fn resolve(
        &self,
        ctx: &Ctx<D>,
        headers: &HeaderMap,
    ) -> impl Future<Output = Result<Option<Resolved>, AuthError>> + Send;
}

pub(crate) trait ErasedResolver<D>: Send + Sync {
    fn resolve<'a>(
        &'a self,
        ctx: &'a Ctx<D>,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<Option<Resolved>, AuthError>>;
}

impl<D: Adapter, R: SessionResolver<D>> ErasedResolver<D> for R {
    fn resolve<'a>(
        &'a self,
        ctx: &'a Ctx<D>,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<Option<Resolved>, AuthError>> {
        Box::pin(SessionResolver::resolve(self, ctx, headers))
    }
}

pub(crate) type MethodTable<D> = Vec<(Method, Arc<dyn ErasedEndpoint<D>>)>;

/// Everything shared by all requests. Built once by `.build()`.
pub(crate) struct Shared<D> {
    pub db: D,
    pub schema: Schema,
    pub keys: Keys,
    pub config: CoreConfig,
    pub passwords: Passwords,
    pub mailer: Option<Arc<dyn DynMailer>>,
    pub plugins: HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
    pub hooks: HashMap<TypeId, EndpointHooks<D>>,
    pub gates: Vec<OwnedGate<D>>,
    pub resolvers: Vec<Arc<dyn ErasedResolver<D>>>,
    pub response_hooks: Vec<ErasedResponseHook<D>>,
    pub session_hooks: Vec<ErasedSessionHook<D>>,
    pub events: HashMap<TypeId, Vec<ErasedEventHandler<D>>>,
    pub router: matchit::Router<MethodTable<D>>,
    pub rate_limiter: RateLimiter,
    pub cache_fingerprint: u64,
}

/// The per-request context. Cheap to clone; hooks and event handlers get their own copy.
pub struct Ctx<D, A = Public> {
    pub(crate) shared: Arc<Shared<D>>,
    /// The adapter a server API call runs on instead of `shared.db` (`Api::within`).
    pub(crate) within: Option<Arc<D>>,
    pub(crate) request: Arc<RequestInfo>,
    pub(crate) session: Option<Arc<SessionView>>,
    pub(crate) effects: Arc<Mutex<Effects>>,
    _access: PhantomData<fn() -> A>,
}

impl<D, A> Clone for Ctx<D, A> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
            within: self.within.clone(),
            request: self.request.clone(),
            session: self.session.clone(),
            effects: self.effects.clone(),
            _access: PhantomData,
        }
    }
}

impl<D, A> std::fmt::Debug for Ctx<D, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ctx({} {})", self.request.method, self.request.path)
    }
}

impl<D: Adapter, A> Ctx<D, A> {
    pub(crate) fn new(
        shared: Arc<Shared<D>>,
        within: Option<Arc<D>>,
        request: Arc<RequestInfo>,
        session: Option<Arc<SessionView>>,
        effects: Arc<Mutex<Effects>>,
    ) -> Self {
        Self {
            shared,
            within,
            request,
            session,
            effects,
            _access: PhantomData,
        }
    }

    pub(crate) fn retype<B>(&self) -> Ctx<D, B> {
        Ctx::new(
            self.shared.clone(),
            self.within.clone(),
            self.request.clone(),
            self.session.clone(),
            self.effects.clone(),
        )
    }

    /// Typed queries on the adapter this call runs on.
    pub fn db(&self) -> Db<'_, D> {
        Db::new(self.adapter(), &self.shared.schema)
    }

    /// Typed queries inside a transaction: `let tx = ctx.adapter().begin().await?; ctx.db_on(&tx)`.
    pub fn db_on<'t, Q: Queries>(&'t self, queries: &'t Q) -> Db<'t, Q> {
        Db::new(queries, &self.shared.schema)
    }

    /// The adapter this call runs on: the configured one, or the one a server API call
    /// passed to `Api::within` (for sqlx, one bound to the app's transaction).
    pub fn adapter(&self) -> &D {
        self.within.as_deref().unwrap_or(&self.shared.db)
    }

    pub fn schema(&self) -> &Schema {
        &self.shared.schema
    }

    pub fn keys(&self) -> &Keys {
        &self.shared.keys
    }

    pub fn config(&self) -> &CoreConfig {
        &self.shared.config
    }

    pub fn passwords(&self) -> &Passwords {
        &self.shared.passwords
    }

    pub fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    /// A new id from the configured [`IdStrategy`](crate::config::IdStrategy). Fails only
    /// when a custom generator returns an invalid id: a 500 whose detail is logged.
    pub fn new_id(&self) -> Result<Id, AuthError> {
        self.shared.config.ids.generate()
    }

    pub fn request(&self) -> &RequestInfo {
        &self.request
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.request.headers
    }

    pub fn ip(&self) -> Option<&str> {
        self.request.ip.as_deref()
    }

    pub fn user_agent(&self) -> Option<&str> {
        self.request.user_agent.as_deref()
    }

    /// A path parameter, e.g. `{token}` in `/reset-password/{token}`.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.request
            .params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// A plugin's config. Panics if it isn't registered, which `Plugin::Requires` rules out
    /// for dependencies. Use `try_plugin` for optional ones.
    pub fn plugin<P: Plugin>(&self) -> &P {
        self.try_plugin::<P>().unwrap_or_else(|| {
            panic!(
                "plugin `{}` is not registered; list it in `Requires`",
                P::ID
            )
        })
    }

    pub fn try_plugin<P: Plugin>(&self) -> Option<&P> {
        self.shared
            .plugins
            .get(&TypeId::of::<P>())
            .and_then(|p| p.downcast_ref::<P>())
    }

    /// Queues an event; handlers run after the endpoint succeeds.
    pub fn emit<E: Event>(&self, event: E) {
        self.effects.lock().unwrap().events.push(PendingEvent {
            type_id: TypeId::of::<E>(),
            event: Arc::new(event),
        });
    }

    pub fn set_cookie(&self, cookie: SetCookie) {
        let mut effects = self.effects.lock().unwrap();
        effects.cookies.retain(|c| c.name != cookie.name);
        effects.cookies.push(cookie);
    }

    pub fn cookie(&self, name: &str) -> Option<&str> {
        cookies::read(&self.request.headers, name)
    }

    /// Sets `{prefix}.{name}`, signed with the cookie key.
    pub fn set_signed_cookie(&self, name: &str, value: &str, max_age: Option<Duration>) {
        let name = self.shared.config.cookie_name(name);
        let value = self.shared.keys.sign(SignPurpose::Cookie, value);
        self.set_cookie(SetCookie::new(name, value, max_age));
    }

    /// Reads `{prefix}.{name}` and checks its signature.
    pub fn signed_cookie(&self, name: &str) -> Option<String> {
        let raw = self.cookie(&self.shared.config.cookie_name(name))?;
        self.shared
            .keys
            .verify(SignPurpose::Cookie, raw)
            .map(str::to_owned)
    }

    pub fn delete_cookie(&self, name: &str) {
        self.set_cookie(SetCookie::delete(self.shared.config.cookie_name(name)));
    }

    /// Answer with a 302 to `url` instead of JSON.
    pub fn redirect(&self, url: impl Into<String>) {
        self.effects.lock().unwrap().redirect = Some(url.into());
    }

    pub fn set_header(&self, name: HeaderName, value: HeaderValue) {
        self.effects.lock().unwrap().headers.push((name, value));
    }

    /// Core operations plugins build on: users, sessions, sign-in, verification values, email.
    pub fn internal(&self) -> Internal<'_, D, A> {
        Internal::new(self)
    }

    pub(crate) fn mailer(&self) -> Option<&Arc<dyn DynMailer>> {
        self.shared.mailer.as_ref()
    }
}

impl<D: Adapter> Ctx<D, MaybeAuthenticated> {
    pub fn session(&self) -> Option<&SessionView> {
        self.session.as_deref()
    }
}

impl<D: Adapter> Ctx<D, Authenticated> {
    pub fn session(&self) -> &SessionView {
        self.session
            .as_deref()
            .expect("Authenticated endpoints only run with a session")
    }
}

impl<D: Adapter> Ctx<D, Fresh> {
    pub fn session(&self) -> &SessionView {
        self.session
            .as_deref()
            .expect("Fresh endpoints only run with a session")
    }
}

pub(crate) enum Outcome<O> {
    Output(O),
    Response(Response),
}

pub(crate) struct Executed<O> {
    pub result: Result<Outcome<O>, AuthError>,
    pub effects: Effects,
}

/// Runs one endpoint: session by access level, before hooks, the call, after hooks.
/// Events are left in the effects for the caller to dispatch or defer.
pub(crate) async fn execute<D: Adapter, E: Endpoint<D>>(
    shared: &Arc<Shared<D>>,
    within: Option<Arc<D>>,
    endpoint: &E,
    request: Arc<RequestInfo>,
    input: E::Input,
) -> Executed<E::Output> {
    let effects = Arc::new(Mutex::new(Effects::default()));
    let result = run::<D, E>(shared, within, endpoint, request, input, &effects).await;
    let effects = std::mem::take(&mut *effects.lock().unwrap());
    Executed { result, effects }
}

async fn run<D: Adapter, E: Endpoint<D>>(
    shared: &Arc<Shared<D>>,
    within: Option<Arc<D>>,
    endpoint: &E,
    request: Arc<RequestInfo>,
    input: E::Input,
    effects: &Arc<Mutex<Effects>>,
) -> Result<Outcome<E::Output>, AuthError> {
    let level = <E::Access as Access>::LEVEL;
    let session = match level {
        AccessLevel::Public => None,
        _ => crate::session::resolve(shared, within.as_ref(), &request, effects)
            .await?
            .map(Arc::new),
    };
    match (level, &session) {
        (AccessLevel::Required | AccessLevel::Fresh, None) => return Err(AuthError::unauthorized()),
        (AccessLevel::Fresh, Some(s)) if !shared.config.is_fresh(&s.session) => {
            return Err(AuthError::not_fresh());
        }
        _ => {}
    }

    let ctx: Ctx<D, E::Access> =
        Ctx::new(shared.clone(), within, request, session, effects.clone());
    let hooks = shared.hooks.get(&TypeId::of::<E>());
    let mut input = input;
    for before in hooks.map(|h| h.before.as_slice()).unwrap_or_default() {
        match before(ctx.retype(), Box::new(input)).await? {
            Before::Continue(next) => {
                input = *next
                    .downcast::<E::Input>()
                    .expect("hook keeps the input type")
            }
            Before::Respond(response) => return Ok(Outcome::Response(response)),
        }
    }
    let mut output = endpoint.call(ctx.clone(), input).await?;
    for after in hooks.map(|h| h.after.as_slice()).unwrap_or_default() {
        match after(ctx.retype(), Box::new(output)).await? {
            After::Continue(next) => {
                output = *next
                    .downcast::<E::Output>()
                    .expect("hook keeps the output type")
            }
            After::Respond(response) => return Ok(Outcome::Response(response)),
        }
    }
    Ok(Outcome::Output(output))
}

pub(crate) async fn dispatch_events<D: Adapter>(
    shared: &Arc<Shared<D>>,
    events: Vec<PendingEvent>,
) {
    for pending in events {
        let Some(handlers) = shared.events.get(&pending.type_id) else {
            continue;
        };
        for handler in handlers {
            let request = Arc::new(RequestInfo::synthetic(
                Method::POST,
                "/event",
                HeaderMap::new(),
            ));
            let ctx = Ctx::new(shared.clone(), None, request, None, Arc::default());
            if let Err(err) = handler(pending.event.clone(), ctx).await {
                tracing::error!(error = %err, "fastauth event handler failed");
            }
        }
    }
}

pub(crate) trait ErasedEndpoint<D>: Send + Sync {
    fn handle<'a>(
        &'a self,
        shared: &'a Arc<Shared<D>>,
        request: Arc<RequestInfo>,
        body: Bytes,
    ) -> BoxFuture<'a, Response>;
}

pub(crate) struct Erased<E>(pub E);

impl<D: Adapter, E: Endpoint<D>> ErasedEndpoint<D> for Erased<E> {
    fn handle<'a>(
        &'a self,
        shared: &'a Arc<Shared<D>>,
        request: Arc<RequestInfo>,
        body: Bytes,
    ) -> BoxFuture<'a, Response> {
        Box::pin(async move {
            let input = match decode_input::<E::Input>(&request, &body) {
                Ok(input) => input,
                Err(err) => return err.into_response(),
            };
            let mut executed = execute(shared, None, &self.0, request.clone(), input).await;
            if executed.result.is_ok() {
                let events = std::mem::take(&mut executed.effects.events);
                dispatch_events(shared, events).await;
            }
            let result = executed.result.and_then(|outcome| match outcome {
                Outcome::Output(output) => serde_json::to_vec(&output)
                    .map(|b| Outcome::Output(Bytes::from(b)))
                    .map_err(AuthError::internal),
                Outcome::Response(response) => Ok(Outcome::Response(response)),
            });
            let mut response = into_response(&shared.config, result, executed.effects);
            if !shared.response_hooks.is_empty() {
                let ctx: Ctx<D> = Ctx::new(shared.clone(), None, request, None, Arc::default());
                for hook in &shared.response_hooks {
                    hook(&ctx, &mut response);
                }
            }
            response
        })
    }
}

fn decode_input<I: DeserializeOwned>(request: &RequestInfo, body: &[u8]) -> Result<I, AuthError> {
    let invalid = |e: &dyn std::fmt::Display| {
        AuthError::bad_request(crate::error::codes::INVALID_BODY, e.to_string())
    };
    if request.method == Method::GET || request.method == Method::HEAD {
        return serde_urlencoded::from_str(request.query.as_deref().unwrap_or(""))
            .map_err(|e| invalid(&e));
    }
    if body.iter().all(u8::is_ascii_whitespace) {
        return serde_json::from_slice(b"{}")
            .or_else(|_| serde_json::from_slice(b"null"))
            .map_err(|e| invalid(&e));
    }
    serde_json::from_slice(body).map_err(|e| invalid(&e))
}

pub(crate) fn into_response(
    config: &CoreConfig,
    result: Result<Outcome<Bytes>, AuthError>,
    effects: Effects,
) -> Response {
    let mut response = match result {
        Ok(Outcome::Response(response)) => response,
        Ok(Outcome::Output(_)) if effects.redirect.is_some() => {
            let mut response = Response::new(Bytes::new());
            *response.status_mut() = StatusCode::FOUND;
            if let Ok(location) = HeaderValue::from_str(effects.redirect.as_deref().unwrap_or("/"))
            {
                response.headers_mut().insert(LOCATION, location);
            }
            response
        }
        Ok(Outcome::Output(body)) => {
            let mut response = Response::new(body);
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            response
        }
        Err(err) => err.into_response(),
    };
    for cookie in &effects.cookies {
        if let Ok(value) = HeaderValue::from_str(&cookie.to_header(config)) {
            response.headers_mut().append(SET_COOKIE, value);
        }
    }
    for (name, value) in effects.headers {
        response.headers_mut().append(name, value);
    }
    response
}
