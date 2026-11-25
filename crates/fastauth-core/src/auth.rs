//! The builder, the `Auth` instance, HTTP dispatch and the server API.

use std::collections::BTreeMap;
use std::future::Future;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::header::{COOKIE, ORIGIN, REFERER, USER_AGENT};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde::Serialize;
use url::Url;

use crate::adapter::{Adapter, Transaction};
use crate::config::{
    ClientIp, CookieConfig, CoreConfig, EmailPassword, EmailVerification, Secure, SessionConfig,
};
use crate::crypto::{Argon2id, Keys, Passwords, Secret, SignPurpose};
use crate::endpoint::{
    Effects, Endpoint, Executed, Outcome, RequestInfo, Response, Shared, dispatch_events, execute,
    header_str,
};
use crate::error::{AuthError, BuildError, codes};
use crate::events::{DeferredEvents, Event};
use crate::hlist::{Append, Has, Nil, PluginSet, Satisfied};
use crate::mail::{DynMailer, Mailer};
use crate::migrate::Migrator;
use crate::model::{Fields, Model};
use crate::models::{Session, User};
use crate::plugin::{Plugin, PluginBuilder, Registry};
use crate::rate_limit::{RateLimit, RateLimiter};
use crate::routes;
use crate::schema::Schema;
use crate::session::{self, SessionData, UserView};

/// Entry point: `FastAuth::builder()`.
#[derive(Debug)]
pub struct FastAuth;

/// Builder state: no database yet.
#[derive(Debug)]
pub struct NoDatabase;
/// Builder state: a required option is missing.
#[derive(Debug)]
pub struct Missing;
/// Builder state: a required option is set.
#[derive(Debug)]
pub struct Present;

impl FastAuth {
    pub fn builder() -> Builder<NoDatabase, (), Nil, Missing, Missing> {
        Builder {
            db: NoDatabase,
            plugins: Nil,
            secrets: Vec::new(),
            base_url: None,
            app_name: "fastauth".into(),
            base_path: "/api/auth".into(),
            trusted_origins: Vec::new(),
            session: SessionConfig::default(),
            cookies: CookieConfig::default(),
            email_password: None,
            email_verification: EmailVerification::default(),
            rate_limit: RateLimit::default(),
            client_ip: ClientIp::Socket,
            mailer: None,
            app_init: Vec::new(),
            _state: PhantomData,
        }
    }
}

type AppInit<D> = Box<dyn FnOnce(&mut PluginBuilder<'_, D>) + Send>;

/// Collects configuration. `.build()` only exists once `secret`, `base_url` and `database`
/// are set: the last three type parameters track that.
pub struct Builder<D, U, P, S, B> {
    db: D,
    plugins: P,
    secrets: Vec<Secret>,
    base_url: Option<String>,
    app_name: String,
    base_path: String,
    trusted_origins: Vec<String>,
    session: SessionConfig,
    cookies: CookieConfig,
    email_password: Option<EmailPassword>,
    email_verification: EmailVerification,
    rate_limit: RateLimit,
    client_ip: ClientIp,
    mailer: Option<Arc<dyn DynMailer>>,
    app_init: Vec<AppInit<D>>,
    _state: PhantomData<BuilderState<U, S, B>>,
}

type BuilderState<U, S, B> = fn() -> (U, S, B);

impl<D, U, P, S, B> std::fmt::Debug for Builder<D, U, P, S, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Builder")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl<D, U, P, S, B> Builder<D, U, P, S, B> {
    fn retype<U2, P2, S2, B2>(self, plugins: impl FnOnce(P) -> P2) -> Builder<D, U2, P2, S2, B2> {
        Builder {
            db: self.db,
            plugins: plugins(self.plugins),
            secrets: self.secrets,
            base_url: self.base_url,
            app_name: self.app_name,
            base_path: self.base_path,
            trusted_origins: self.trusted_origins,
            session: self.session,
            cookies: self.cookies,
            email_password: self.email_password,
            email_verification: self.email_verification,
            rate_limit: self.rate_limit,
            client_ip: self.client_ip,
            mailer: self.mailer,
            app_init: self.app_init,
            _state: PhantomData,
        }
    }

    /// The master secret (at least 32 bytes). See `Secret::from_env`.
    pub fn secret(mut self, secret: Secret) -> Builder<D, U, P, Present, B> {
        self.secrets = vec![secret];
        self.retype(|p| p)
    }

    /// Several secrets for rotation: the first signs, all verify.
    pub fn secrets(
        mut self,
        secrets: impl IntoIterator<Item = Secret>,
    ) -> Builder<D, U, P, Present, B> {
        self.secrets = secrets.into_iter().collect();
        self.retype(|p| p)
    }

    /// The public URL of the app, e.g. `https://acme.dk`.
    pub fn base_url(mut self, url: impl Into<String>) -> Builder<D, U, P, S, Present> {
        self.base_url = Some(url.into());
        self.retype(|p| p)
    }

    pub fn app_name(mut self, name: impl Into<String>) -> Self {
        self.app_name = name.into();
        self
    }

    /// Where auth routes live (default `/api/auth`).
    pub fn base_path(mut self, path: impl Into<String>) -> Self {
        self.base_path = path.into();
        self
    }

    /// Origins allowed to make cookie-carrying requests and to be redirect targets.
    pub fn trusted_origins(mut self, origins: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.trusted_origins.extend(
            origins
                .into_iter()
                .map(|o| o.into().trim_end_matches('/').to_owned()),
        );
        self
    }

    pub fn email_password(mut self, config: EmailPassword) -> Self {
        self.email_password = Some(config);
        self
    }

    pub fn email_verification(mut self, config: EmailVerification) -> Self {
        self.email_verification = config;
        self
    }

    pub fn session(mut self, config: SessionConfig) -> Self {
        self.session = config;
        self
    }

    pub fn cookies(mut self, config: CookieConfig) -> Self {
        self.cookies = config;
        self
    }

    pub fn rate_limit(mut self, config: RateLimit) -> Self {
        self.rate_limit = config;
        self
    }

    pub fn client_ip(mut self, source: ClientIp) -> Self {
        self.client_ip = source;
        self
    }

    pub fn mailer(mut self, mailer: impl Mailer) -> Self {
        self.mailer = Some(Arc::new(mailer));
        self
    }

    /// The app's own columns on `user`.
    pub fn user_fields<U2: Fields>(self) -> Builder<D, U2, P, S, B> {
        self.retype(|p| p)
    }

    /// Registers a plugin. Its `Requires` must already be registered.
    pub fn plugin<Pl: Plugin, I>(self, plugin: Pl) -> Builder<D, U, P::Out, S, B>
    where
        P: Append<Pl>,
        Pl::Requires: Satisfied<P, I>,
    {
        self.retype(|plugins| plugins.append(Arc::new(plugin)))
    }
}

impl<U, P, S, B> Builder<NoDatabase, U, P, S, B> {
    pub fn database<D: Adapter>(self, db: D) -> Builder<D, U, P, S, B> {
        Builder {
            db,
            plugins: self.plugins,
            secrets: self.secrets,
            base_url: self.base_url,
            app_name: self.app_name,
            base_path: self.base_path,
            trusted_origins: self.trusted_origins,
            session: self.session,
            cookies: self.cookies,
            email_password: self.email_password,
            email_verification: self.email_verification,
            rate_limit: self.rate_limit,
            client_ip: self.client_ip,
            mailer: self.mailer,
            app_init: Vec::new(),
            _state: PhantomData,
        }
    }
}

impl<D: Adapter, U, P, S, B> Builder<D, U, P, S, B> {
    /// Registers app-level hooks, gates, resolvers or endpoints, like a plugin's `init`.
    pub fn configure(
        mut self,
        init: impl FnOnce(&mut PluginBuilder<'_, D>) + Send + 'static,
    ) -> Self {
        self.app_init.push(Box::new(init));
        self
    }

    /// Runs `handler` after every endpoint that emits `Ev`.
    pub fn on<Ev, F, Fut>(self, handler: F) -> Self
    where
        Ev: Event,
        F: Fn(Ev, crate::endpoint::Ctx<D>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), AuthError>> + Send + 'static,
    {
        self.configure(move |app| {
            app.on(handler);
        })
    }
}

impl<D: Adapter, U: Fields, P: PluginSet> Builder<D, U, P, Present, Present> {
    pub fn build(self) -> Result<Auth<D, U, P>, BuildError> {
        let mut problems = Vec::new();
        if self.secrets.is_empty() || self.secrets.iter().any(|s| s.len() < Secret::MIN_LEN) {
            problems.push(format!(
                "every secret must be at least {} bytes; generate one with `fastauth secret`",
                Secret::MIN_LEN
            ));
        }
        let base_url = match Url::parse(self.base_url.as_deref().unwrap_or_default()) {
            Ok(url) if matches!(url.scheme(), "http" | "https") => url,
            _ => {
                problems.push(format!(
                    "base_url `{}` is not an http(s) URL",
                    self.base_url.unwrap_or_default()
                ));
                Url::parse("http://localhost").expect("valid URL")
            }
        };
        let base_path = format!("/{}", self.base_path.trim_matches('/'));
        if self
            .email_password
            .as_ref()
            .is_some_and(|e| e.require_email_verification)
            && self.mailer.is_none()
        {
            problems.push("require_email_verification needs a mailer: call .mailer(..)".into());
        }

        let mut registry = Registry::<D>::new();
        crate::models::register(&mut registry.schema);
        routes::register(
            &mut PluginBuilder {
                registry: &mut registry,
            },
            self.email_password.is_some(),
        );
        registry.set_owner("app");
        registry.schema.extend(User::TABLE, U::columns());
        self.plugins.register(&mut registry);
        registry.set_owner("app");
        for init in self.app_init {
            init(&mut PluginBuilder {
                registry: &mut registry,
            });
        }

        problems.append(&mut registry.errors);
        for (type_id, name, owner) in &registry.hook_targets {
            if !registry.routes.iter().any(|r| r.type_id == *type_id) {
                problems.push(format!(
                    "`{owner}` hooks endpoint `{name}`, which no plugin registers"
                ));
            }
        }

        let mut by_path: BTreeMap<&'static str, Vec<_>> = BTreeMap::new();
        for route in registry.routes {
            by_path
                .entry(route.path)
                .or_default()
                .push((route.method, route.endpoint));
        }
        let mut router = matchit::Router::new();
        for (path, methods) in by_path {
            if let Err(err) = router.insert(path, methods) {
                problems.push(format!("route {path}: {err}"));
            }
        }

        let schema = match registry.schema.finish() {
            Ok(schema) => schema,
            Err(mut errors) => {
                problems.append(&mut errors);
                Schema::default()
            }
        };
        if !problems.is_empty() {
            return Err(BuildError { problems });
        }

        let mut rate_limit = self.rate_limit;
        rate_limit.rules.extend(registry.rate_rules);
        rate_limit.rules.extend(RateLimit::core_rules());

        let secure_cookies = match self.cookies.secure {
            Secure::Always => true,
            Secure::Never => false,
            Secure::Auto => base_url.scheme() == "https",
        };
        let hasher = self.email_password.as_ref().map_or_else(
            || Arc::new(Argon2id::owasp()) as Arc<dyn crate::crypto::PasswordHasher>,
            |e| e.hasher.clone(),
        );
        let cache_fingerprint =
            session::fingerprint(schema.expect(Session::TABLE), schema.expect(User::TABLE));
        let config = CoreConfig {
            app_name: self.app_name,
            base_url,
            base_path,
            trusted_origins: self.trusted_origins,
            session: self.session,
            cookies: self.cookies,
            email_password: self.email_password,
            email_verification: self.email_verification,
            rate_limit: rate_limit.clone(),
            client_ip: self.client_ip,
            secure_cookies,
        };
        let shared = Shared {
            db: self.db,
            schema,
            keys: Keys::new(self.secrets),
            config,
            passwords: Passwords::new(hasher),
            mailer: self.mailer,
            plugins: registry.plugins,
            hooks: registry.hooks,
            gates: registry.gates,
            resolvers: registry.resolvers,
            events: registry.events,
            router,
            rate_limiter: RateLimiter::new(rate_limit),
            cache_fingerprint,
        };
        Ok(Auth {
            shared: Arc::new(shared),
            plugins: Arc::new(self.plugins),
            _user: PhantomData,
        })
    }
}

/// The client's socket address. Integrations put it in request extensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientAddr(pub IpAddr);

/// A configured auth instance. Cheap to clone (two `Arc`s).
///
/// `D` is the database adapter, `U` the app's user fields, `P` the plugin list
/// (`plugins![TwoFactor, Organization]`).
pub struct Auth<D, U = (), P = Nil> {
    shared: Arc<Shared<D>>,
    plugins: Arc<P>,
    _user: PhantomData<fn() -> U>,
}

impl<D, U, P> Clone for Auth<D, U, P> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
            plugins: self.plugins.clone(),
            _user: PhantomData,
        }
    }
}

impl<D, U, P> std::fmt::Debug for Auth<D, U, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auth")
            .field("base_path", &self.shared.config.base_path)
            .finish_non_exhaustive()
    }
}

const MAX_BODY: usize = 64 * 1024;

fn origin_of(value: &str) -> Option<String> {
    Url::parse(value)
        .ok()
        .map(|u| u.origin().ascii_serialization())
}

impl<D: Adapter, U: Fields, P: PluginSet> Auth<D, U, P> {
    pub fn config(&self) -> &CoreConfig {
        &self.shared.config
    }

    pub fn schema(&self) -> &Schema {
        &self.shared.schema
    }

    pub fn adapter(&self) -> &D {
        &self.shared.db
    }

    pub fn migrator(&self) -> Migrator<'_, D> {
        Migrator::new(&self.shared.db, &self.shared.schema)
    }

    /// A registered plugin's config. Doesn't compile when the plugin isn't registered.
    pub fn plugin<Pl: Plugin, I>(&self) -> &Pl
    where
        P: Has<Pl, I>,
    {
        self.plugins.get()
    }

    /// Server-side calls to endpoints: no HTTP, no JSON.
    pub fn api(&self) -> Api<'_, D> {
        Api {
            shared: &self.shared,
            headers: HeaderMap::new(),
            within: None,
        }
    }

    /// Handles a request under `base_path`. Integrations call this.
    pub async fn handle(&self, request: http::Request<Bytes>) -> Response {
        let shared = &self.shared;
        let config = &shared.config;
        let (parts, body) = request.into_parts();
        let Some(path) = parts.uri.path().strip_prefix(config.base_path.as_str()) else {
            return AuthError::not_found().into_response();
        };
        let path = if path.is_empty() { "/" } else { path };
        let Ok(matched) = shared.router.at(path) else {
            return AuthError::not_found().into_response();
        };
        let Some((_, endpoint)) = matched.value.iter().find(|(m, _)| *m == parts.method) else {
            return AuthError::new(
                StatusCode::METHOD_NOT_ALLOWED,
                codes::METHOD_NOT_ALLOWED,
                "method not allowed",
            )
            .into_response();
        };
        if body.len() > MAX_BODY {
            return AuthError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                codes::INVALID_BODY,
                "request body is too large",
            )
            .into_response();
        }

        let ip = match &config.client_ip {
            ClientIp::Socket => parts
                .extensions
                .get::<ClientAddr>()
                .map(|a| a.0.to_string()),
            ClientIp::Header(name) => parts
                .headers
                .get(name.as_str())
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(|v| v.trim().to_owned()),
        };
        if !shared
            .rate_limiter
            .check(ip.as_deref().unwrap_or("unknown"), path)
        {
            return AuthError::too_many_requests().into_response();
        }

        if !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS) {
            let origin = header_str(&parts.headers, ORIGIN)
                .filter(|o| o != "null")
                .or_else(|| header_str(&parts.headers, REFERER).and_then(|r| origin_of(&r)));
            let allowed = match &origin {
                Some(origin) => config.is_trusted_origin(origin),
                None => !parts.headers.contains_key(COOKIE),
            };
            if !allowed {
                return AuthError::new(
                    StatusCode::FORBIDDEN,
                    codes::INVALID_ORIGIN,
                    "invalid origin",
                )
                .into_response();
            }
        }

        let request = RequestInfo {
            method: parts.method.clone(),
            path: path.to_owned(),
            params: matched
                .params
                .iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            query: parts.uri.query().map(str::to_owned),
            user_agent: header_str(&parts.headers, USER_AGENT),
            headers: parts.headers,
            ip,
        };
        endpoint
            .clone()
            .handle(shared, Arc::new(request), body)
            .await
    }

    /// The session for these request headers, plus `Set-Cookie` values the caller should
    /// add to its response (refreshed or cleared cookies).
    pub async fn session_with_cookies(
        &self,
        headers: &HeaderMap,
    ) -> (
        Result<Option<SessionData<U, P>>, AuthError>,
        Vec<HeaderValue>,
    ) {
        let request = Arc::new(RequestInfo::synthetic(
            Method::GET,
            "/get-session",
            headers.clone(),
        ));
        let effects = Arc::new(Mutex::new(Effects::default()));
        let result = session::resolve(&self.shared, None, &request, &effects)
            .await
            .and_then(|view| {
                view.map(SessionData::from_view)
                    .transpose()
                    .map_err(AuthError::internal)
            });
        let cookies = effects
            .lock()
            .unwrap()
            .cookies
            .iter()
            .filter_map(|c| HeaderValue::from_str(&c.to_header(&self.shared.config)).ok())
            .collect();
        (result, cookies)
    }

    /// The session for these request headers (cookie, or any registered resolver).
    pub async fn get_session(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<SessionData<U, P>>, AuthError> {
        self.session_with_cookies(headers).await.0
    }

    /// The session for a raw token, e.g. from a WebSocket query string.
    pub async fn get_session_by_token(
        &self,
        token: &str,
    ) -> Result<Option<SessionData<U, P>>, AuthError> {
        let view = session::by_token(&self.shared, &self.shared.db, token).await?;
        view.map(SessionData::from_view)
            .transpose()
            .map_err(AuthError::internal)
    }
}

/// What integrations and plugin extension traits need from an auth instance, without
/// naming its type parameters.
pub trait AuthInstance: Clone + Send + Sync + 'static {
    type Db: Adapter;
    type UserFields: Fields;
    type Plugins: PluginSet;

    fn config(&self) -> &CoreConfig;
    fn api(&self) -> Api<'_, Self::Db>;
    fn handle(&self, request: http::Request<Bytes>) -> impl Future<Output = Response> + Send;
    #[allow(clippy::type_complexity)]
    fn session_with_cookies(
        &self,
        headers: &HeaderMap,
    ) -> impl Future<
        Output = (
            Result<Option<SessionData<Self::UserFields, Self::Plugins>>, AuthError>,
            Vec<HeaderValue>,
        ),
    > + Send;
}

impl<D: Adapter, U: Fields, P: PluginSet> AuthInstance for Auth<D, U, P> {
    type Db = D;
    type UserFields = U;
    type Plugins = P;

    fn config(&self) -> &CoreConfig {
        Auth::config(self)
    }

    fn api(&self) -> Api<'_, D> {
        Auth::api(self)
    }

    fn handle(&self, request: http::Request<Bytes>) -> impl Future<Output = Response> + Send {
        Auth::handle(self, request)
    }

    fn session_with_cookies(
        &self,
        headers: &HeaderMap,
    ) -> impl Future<
        Output = (
            Result<Option<SessionData<U, P>>, AuthError>,
            Vec<HeaderValue>,
        ),
    > + Send {
        Auth::session_with_cookies(self, headers)
    }
}

#[diagnostic::on_unimplemented(
    message = "plugin `{Pl}` is not registered on this auth instance",
    note = "register it with `.plugin(...)` on the builder and list it in your `plugins![..]` alias"
)]
/// For plugin extension traits: methods bounded by `Self: HasPlugin<MyPlugin, I>` only
/// compile on an `Auth` that registered the plugin.
pub trait HasPlugin<Pl, I>: AuthInstance {
    fn plugin_arc(&self) -> &Arc<Pl>;
}

impl<D: Adapter, U: Fields, P: Has<Pl, I>, Pl: Plugin, I> HasPlugin<Pl, I> for Auth<D, U, P> {
    fn plugin_arc(&self) -> &Arc<Pl> {
        self.plugins.get()
    }
}

/// Server-side endpoint calls. Pass the request's headers (or a session token) for
/// endpoints that need a session.
pub struct Api<'a, D> {
    shared: &'a Arc<Shared<D>>,
    headers: HeaderMap,
    within: Option<(Arc<D>, DeferredEvents)>,
}

impl<D> std::fmt::Debug for Api<'_, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Api")
    }
}

/// An endpoint's typed output plus the cookies it wants set.
#[derive(Debug)]
pub struct ApiResponse<T> {
    pub data: T,
    pub set_cookies: Vec<HeaderValue>,
}

impl<T: Serialize> ApiResponse<T> {
    /// The same response the HTTP route would give.
    pub fn into_http(self) -> Response {
        let body = serde_json::to_vec(&self.data).unwrap_or_default();
        let mut response = Response::new(Bytes::from(body));
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        for cookie in self.set_cookies {
            response
                .headers_mut()
                .append(http::header::SET_COOKIE, cookie);
        }
        response
    }
}

impl<D: Adapter> Api<'_, D> {
    /// The configured adapter.
    pub fn adapter(&self) -> &D {
        &self.shared.db
    }

    /// Runs every call on `db` instead of the configured adapter (its queries, session
    /// lookup, hooks and gates), and queues the calls' events on `events` instead of firing
    /// them.
    ///
    /// Each call runs inside its own `db.begin()`, committed when the call succeeds and
    /// rolled back when it fails, so a failed call leaves `db` as it was. That needs an
    /// adapter whose `begin` nests inside its own queries: with sqlx, use `.in_tx(&tx)` from
    /// `fastauth_sqlx::InTx`, which binds the adapter to a transaction and makes `begin` a
    /// savepoint.
    pub fn within(mut self, db: D, events: &DeferredEvents) -> Self {
        self.within = Some((Arc::new(db), events.clone()));
        self
    }

    /// Uses these request headers: cookies for the session, user agent and so on.
    pub fn headers(mut self, headers: &HeaderMap) -> Self {
        self.headers = headers.clone();
        self
    }

    /// Acts as the session with this raw token.
    pub fn session_token(mut self, token: &str) -> Self {
        let name = self.shared.config.cookie_name(session::SESSION_TOKEN);
        let signed = self.shared.keys.sign(SignPurpose::Cookie, token);
        if let Ok(value) = HeaderValue::from_str(&format!("{name}={signed}")) {
            self.headers.insert(COOKIE, value);
        }
        self
    }

    /// Runs any endpoint, with its access check, hooks and events.
    pub async fn call<E: Endpoint<D>>(
        &self,
        endpoint: &E,
        input: E::Input,
    ) -> Result<ApiResponse<E::Output>, AuthError> {
        let request = Arc::new(RequestInfo::synthetic(
            E::METHOD,
            E::PATH,
            self.headers.clone(),
        ));
        let Some((db, events)) = &self.within else {
            let mut executed = execute(self.shared, None, endpoint, request, input).await;
            if executed.result.is_ok() {
                let pending = std::mem::take(&mut executed.effects.events);
                dispatch_events(self.shared, pending).await;
            }
            return self.respond(executed);
        };
        let savepoint = db.begin().await?;
        let mut executed = execute(self.shared, Some(db.clone()), endpoint, request, input).await;
        if !matches!(executed.result, Ok(Outcome::Output(_))) {
            savepoint.rollback().await?;
            return self.respond(executed);
        }
        savepoint.commit().await?;
        let pending = std::mem::take(&mut executed.effects.events);
        let shared = self.shared.clone();
        events.push(Box::new(move || {
            Box::pin(async move { dispatch_events(&shared, pending).await })
        }));
        self.respond(executed)
    }

    fn respond<O>(&self, executed: Executed<O>) -> Result<ApiResponse<O>, AuthError> {
        let set_cookies = executed
            .effects
            .cookies
            .iter()
            .filter_map(|c| HeaderValue::from_str(&c.to_header(&self.shared.config)).ok())
            .collect();
        match executed.result? {
            Outcome::Output(data) => Ok(ApiResponse { data, set_cookies }),
            Outcome::Response(response) => Err(AuthError::with_message(
                response.status(),
                "HOOK_RESPONDED",
                String::from_utf8_lossy(response.body()).into_owned(),
            )),
        }
    }

    /// Creates a user, plus a credential account when `password` is set. Server-only: there
    /// is no HTTP route. Validates like sign-up and answers `USER_ALREADY_EXISTS` (422) when
    /// the email is taken.
    pub async fn create_user(&self, input: routes::CreateUserInput) -> Result<UserView, AuthError> {
        Ok(self.call(&routes::CreateUser, input).await?.data)
    }

    pub async fn sign_up_email(
        &self,
        input: routes::SignUpEmailInput,
    ) -> Result<ApiResponse<routes::SignUpOutput>, AuthError> {
        self.call(&routes::SignUpEmail, input).await
    }

    pub async fn sign_in_email(
        &self,
        input: routes::SignInEmailInput,
    ) -> Result<ApiResponse<routes::SignInOutput>, AuthError> {
        self.call(&routes::SignInEmail, input).await
    }

    pub async fn sign_out(&self) -> Result<ApiResponse<routes::SignOutOutput>, AuthError> {
        self.call(&routes::SignOut, crate::endpoint::Empty {}).await
    }

    pub async fn list_sessions(
        &self,
    ) -> Result<ApiResponse<Vec<serde_json::Map<String, serde_json::Value>>>, AuthError> {
        self.call(&routes::ListSessions, serde_json::Map::new())
            .await
    }

    pub async fn revoke_other_sessions(&self) -> Result<ApiResponse<routes::Status>, AuthError> {
        self.call(&routes::RevokeOtherSessions, crate::endpoint::Empty {})
            .await
    }

    pub async fn change_password(
        &self,
        input: routes::ChangePasswordInput,
    ) -> Result<ApiResponse<routes::ChangePasswordOutput>, AuthError> {
        self.call(&routes::ChangePassword, input).await
    }

    pub async fn request_password_reset(
        &self,
        input: routes::RequestPasswordResetInput,
    ) -> Result<ApiResponse<routes::RequestPasswordResetOutput>, AuthError> {
        self.call(&routes::RequestPasswordReset, input).await
    }

    pub async fn reset_password(
        &self,
        input: routes::ResetPasswordInput,
    ) -> Result<ApiResponse<routes::Status>, AuthError> {
        self.call(&routes::ResetPassword, input).await
    }
}
