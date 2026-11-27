//! The builder, the `Auth` instance, HTTP dispatch and the server API.

use std::collections::BTreeMap;
use std::future::Future;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CACHE_CONTROL, COOKIE, ORIGIN, REFERER, USER_AGENT};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde::Serialize;
use url::Url;

use crate::adapter::{Adapter, Transaction};
use crate::config::{
    ClientIp, CookieConfig, CoreConfig, EmailPassword, EmailVerification, IdStrategy, Secure,
    SessionConfig, SessionTokens,
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
use crate::migrate::{Migrations, Migrator};
use crate::model::{Fields, Model};
use crate::models::{Account, Session, User, Verification};
use crate::plugin::{Plugin, PluginBuilder, Registry};
use crate::query::Db;
use crate::rate_limit::{RateLimit, RateLimiter};
use crate::routes;
use crate::schema::{ColumnNaming, Schema, Storage};
use crate::session::{self, SessionData, UserView};
use crate::storage::{DEFAULT_STORAGE_TIMEOUT, DynStorage, GuardedStorage, SecondaryStorage};

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
            ids: IdStrategy::default(),
            mailer: None,
            secondary_storage: None,
            secondary_storage_timeout: DEFAULT_STORAGE_TIMEOUT,
            multi_instance: false,
            allow_insecure: false,
            storage: Storage::default(),
            session_tokens: SessionTokens::default(),
            only_owned_accounts: false,
            migrations: Migrations::default(),
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
    ids: IdStrategy,
    mailer: Option<Arc<dyn DynMailer>>,
    secondary_storage: Option<Arc<dyn DynStorage>>,
    secondary_storage_timeout: Duration,
    multi_instance: bool,
    allow_insecure: bool,
    storage: Storage,
    session_tokens: SessionTokens,
    only_owned_accounts: bool,
    migrations: Migrations,
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
            ids: self.ids,
            mailer: self.mailer,
            secondary_storage: self.secondary_storage,
            secondary_storage_timeout: self.secondary_storage_timeout,
            multi_instance: self.multi_instance,
            allow_insecure: self.allow_insecure,
            storage: self.storage,
            session_tokens: self.session_tokens,
            only_owned_accounts: self.only_owned_accounts,
            migrations: self.migrations,
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

    /// How ids are generated and stored; [`IdStrategy::Ulid`] unless set.
    ///
    /// Apps upgrading a Postgres database created by fastauth 0.1 (`uuid` id columns)
    /// keep it working with `.ids(IdStrategy::UuidV7)`.
    pub fn ids(mut self, strategy: IdStrategy) -> Self {
        self.ids = strategy;
        self
    }

    pub fn mailer(mut self, mailer: impl Mailer) -> Self {
        self.mailer = Some(Arc::new(mailer));
        self
    }

    /// A key-value store every instance of the app shares, such as Redis
    /// (`fastauth_redis::RedisStorage`). Rate limit counters live there, so a limit holds
    /// across all instances. Without it, each instance keeps its own counters in memory.
    ///
    /// Each call is bounded by [`secondary_storage_timeout`](Self::secondary_storage_timeout).
    /// A call that fails or times out falls back to this instance's in-memory limiter, and
    /// after 5 such calls in a row the storage is skipped for 5 seconds before one request
    /// probes it again, so a dead store doesn't slow every request down.
    pub fn secondary_storage(mut self, storage: impl SecondaryStorage) -> Self {
        self.secondary_storage = Some(Arc::new(storage));
        self
    }

    /// How long a request waits for one secondary storage call before its rate limit falls
    /// back to this instance's memory. Default: 100 ms
    /// ([`DEFAULT_STORAGE_TIMEOUT`](crate::storage::DEFAULT_STORAGE_TIMEOUT)).
    pub fn secondary_storage_timeout(mut self, timeout: Duration) -> Self {
        assert!(
            !timeout.is_zero(),
            "a secondary storage timeout is longer than zero"
        );
        self.secondary_storage_timeout = timeout;
        self
    }

    /// Says the app runs as several instances (processes, containers, machines) behind a
    /// load balancer. `.build()` then warns when rate limiting is on without
    /// [`secondary_storage`](Self::secondary_storage), since each instance would allow the
    /// full limit.
    pub fn multi_instance(mut self, multi_instance: bool) -> Self {
        self.multi_instance = multi_instance;
        self
    }

    /// Builds a configuration that `.build()` refuses for production, logging each problem
    /// as a warning instead: an `http://` `base_url` on a host other than localhost, or a
    /// current (first) secret with too little entropy. A weak retired secret is only ever
    /// logged, so rotating off one needs no opt-out. For local development, CI and staging setups on a
    /// private network only. A localhost `base_url` gets the same leniency without it.
    pub fn allow_insecure_config(mut self, allow: bool) -> Self {
        self.allow_insecure = allow;
        self
    }

    /// How column names are stored in the database, for every table: core's, the plugins'
    /// and the app's fields. [`ColumnNaming::CamelCase`] stores `email_verified` as
    /// `emailVerified`, as Better Auth does. Code keeps using the declared names
    /// (`User::EMAIL_VERIFIED`, `#[derive(Fields)]` field names); only the SQL changes.
    /// Default: [`ColumnNaming::SnakeCase`], the declared names.
    pub fn column_naming(mut self, naming: ColumnNaming) -> Self {
        self.storage.naming = naming;
        self
    }

    /// Stores `table.column` (declared names) as `to`, over the naming strategy:
    /// `.rename_column("account", "password_hash", "password")` keeps the password hash in
    /// Better Auth's `password` column. `.build()` fails on a column the schema doesn't have.
    pub fn rename_column(
        mut self,
        table: impl Into<String>,
        column: impl Into<String>,
        to: impl Into<String>,
    ) -> Self {
        self.storage
            .renames
            .push((table.into(), column.into(), to.into()));
        self
    }

    /// Stores the byte column `table.column` as lowercase hex text, for a text column
    /// another app created, such as Better Auth's `account.accessToken`. The values stay
    /// what they are (`access_token` is still encrypted); only their encoding changes.
    /// Text that isn't hex, which only the other app writes, reads as its UTF-8 bytes.
    pub fn bytes_as_hex_text(
        mut self,
        table: impl Into<String>,
        column: impl Into<String>,
    ) -> Self {
        self.storage.hex_text.push((table.into(), column.into()));
        self
    }

    /// How session tokens are stored: [`SessionTokens::Hashed`] (the default) or
    /// [`SessionTokens::Raw`], the token itself in `session.token`, as Better Auth stores
    /// it. Raw tokens let both apps resolve each other's sessions while they share a
    /// database, and give up the protection hashing gives a leaked table; see
    /// `docs/concepts/03-security.md`.
    pub fn session_tokens(mut self, tokens: SessionTokens) -> Self {
        self.session_tokens = tokens;
        self
    }

    /// Leaves `account` rows of providers fastauth doesn't own alone: it never reads them
    /// as a sign-in method, lists, changes, unlinks or deletes them, and refuses to delete a
    /// user that has one (409 `USER_HAS_FOREIGN_ACCOUNTS`, since the foreign key would
    /// delete it too). fastauth owns `credential` and the providers plugins register (each
    /// social provider). For a database another app writes accounts to, such as the
    /// `oidc` rows of an SSO integration. Off by default: fastauth manages every row.
    pub fn only_owned_accounts(mut self, on: bool) -> Self {
        self.only_owned_accounts = on;
        self
    }

    /// Whether `auth.migrator()` may change the database. [`Migrations::ReviewOnly`] makes
    /// `run` and `apply` (and `fastauth migrate`) refuse, for a schema another app's
    /// migrations own, and `fastauth generate` write each step as its own migration to
    /// review. Default: [`Migrations::Apply`].
    pub fn migrations(mut self, mode: Migrations) -> Self {
        self.migrations = mode;
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
            ids: self.ids,
            mailer: self.mailer,
            secondary_storage: self.secondary_storage,
            secondary_storage_timeout: self.secondary_storage_timeout,
            multi_instance: self.multi_instance,
            allow_insecure: self.allow_insecure,
            storage: self.storage,
            session_tokens: self.session_tokens,
            only_owned_accounts: self.only_owned_accounts,
            migrations: self.migrations,
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
        if !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            problems.push(format!(
                "base_url `{base_url}` has credentials, a query or a fragment; emailed links are \
                 built from it, so give only the scheme, host, port and path"
            ));
        }
        let local = is_local(&base_url);
        let mut unsafe_in_production = Vec::new();
        if let Some(bits) = self
            .secrets
            .first()
            .map(Secret::entropy_bits)
            .filter(|bits| *bits < Secret::MIN_ENTROPY_BITS)
        {
            unsafe_in_production.push(format!(
                "the current secret has about {bits:.0} bits of entropy, less than {:.0}; \
                 generate one with `fastauth secret`",
                Secret::MIN_ENTROPY_BITS
            ));
        }
        if self
            .secrets
            .iter()
            .skip(1)
            .any(|secret| secret.entropy_bits() < Secret::MIN_ENTROPY_BITS)
        {
            tracing::warn!(
                "fastauth: a retired secret has less than {:.0} bits of entropy; it still \
                 verifies session tokens and decrypts columns written under it, so drop it from \
                 `.secrets(..)` once those columns are rewritten",
                Secret::MIN_ENTROPY_BITS
            );
        }
        if base_url.scheme() == "http" && !local {
            unsafe_in_production.push(format!(
                "base_url `{base_url}` is http:// on a host other than localhost, so cookies \
                 would be sent without Secure; serve the app over https"
            ));
        }
        if local || self.allow_insecure {
            for problem in &unsafe_in_production {
                tracing::warn!("fastauth: {problem} (allowed outside production)");
            }
        } else {
            problems.extend(unsafe_in_production.into_iter().map(|problem| {
                format!("{problem} (for local development: .allow_insecure_config(true))")
            }));
        }
        let base_path = format!("/{}", self.base_path.trim_matches('/'));
        if self
            .email_password
            .as_ref()
            .is_some_and(|e| e.require_email_verification)
            && self.mailer.is_none()
        {
            problems.push("require_email_verification needs a mailer: call .mailer(..)".into());
        }
        if matches!(self.client_ip, ClientIp::TrustedProxies { proxies: 0, .. }) {
            problems.push("ClientIp::TrustedProxies needs at least one proxy".into());
        }

        let mut registry = Registry::<D>::new();
        crate::models::register_with(&mut registry.schema, self.session_tokens);
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
            if !registry.routes.iter().any(|r| r.type_id == *type_id)
                && !registry.server_endpoints.contains(type_id)
            {
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

        let schema = match registry.schema.finish(self.ids.storage(), &self.storage) {
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
        if self.multi_instance && rate_limit.enabled && self.secondary_storage.is_none() {
            tracing::warn!(
                "fastauth: the app runs several instances, but rate limits are counted in each \
                 instance's memory, so n instances allow n times every limit; configure \
                 .secondary_storage(..), such as fastauth_redis::RedisStorage"
            );
        }

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
            ids: self.ids,
            secure_cookies,
            session_tokens: self.session_tokens,
            owned_accounts: self.only_owned_accounts.then(|| {
                std::iter::once(Account::CREDENTIAL.to_owned())
                    .chain(registry.account_providers.iter().cloned())
                    .collect()
            }),
        };
        let keys = Keys::new(self.secrets);
        let rate_limiter = RateLimiter::new(
            rate_limit,
            !local && !self.allow_insecure,
            keys.rate_limit_key(),
            self.secondary_storage
                .map(|storage| GuardedStorage::new(storage, self.secondary_storage_timeout)),
        );
        let shared = Shared {
            migrations: self.migrations,
            db: self.db,
            schema,
            keys,
            config,
            passwords: Passwords::new(hasher),
            mailer: self.mailer,
            plugins: registry.plugins,
            hooks: registry.hooks,
            gates: registry.gates,
            resolvers: registry.resolvers,
            response_hooks: registry.response_hooks,
            session_hooks: registry.session_hooks,
            session_gates: registry.session_gates,
            fixed_expiry: registry.fixed_expiry,
            claim_hooks: registry.claim_hooks,
            user_input_hooks: registry.user_input_hooks,
            events: registry.events,
            router,
            rate_limiter,
            cache_fingerprint,
        };
        Ok(Auth {
            shared: Arc::new(shared),
            plugins: Arc::new(self.plugins),
            _user: PhantomData,
        })
    }
}

async fn prune_verifications<D: Adapter>(shared: &Shared<D>) -> Result<u64, AuthError> {
    let expired = Verification::EXPIRES_AT.lt(time::OffsetDateTime::now_utc());
    Ok(Db::new(&shared.db, &shared.schema)
        .delete::<Verification>(expired)
        .await?)
}

/// Whether `url` points at this machine: `localhost`, `*.localhost` or a loopback address.
fn is_local(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost" || domain.ends_with(".localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
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
        Migrator::new(&self.shared.db, &self.shared.schema).with_mode(self.shared.migrations)
    }

    /// Deletes every expired `verification` row (email verification and reset links,
    /// OAuth states, codes) and answers how many. fastauth already deletes expired rows
    /// before it stores a new one; call this, or
    /// [`prune_verifications_every`](Self::prune_verifications_every), to keep the table
    /// small when few new rows arrive.
    pub async fn prune_verifications(&self) -> Result<u64, AuthError> {
        prune_verifications(&self.shared).await
    }

    /// Runs [`prune_verifications`](Self::prune_verifications) every `every` on the
    /// current Tokio runtime, first after one interval, until every clone of this `Auth` is
    /// dropped or the handle is aborted. A failed run is logged and the next one runs on
    /// time. Panics outside a Tokio runtime, as `tokio::spawn` does.
    pub fn prune_verifications_every(&self, every: Duration) -> tokio::task::JoinHandle<()> {
        let shared = Arc::downgrade(&self.shared);
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticks.tick().await;
                let Some(shared) = shared.upgrade() else {
                    return;
                };
                match prune_verifications(&shared).await {
                    Ok(pruned) => tracing::debug!(pruned, "fastauth: pruned expired verifications"),
                    Err(err) => tracing::warn!("fastauth: pruning verifications failed: {err}"),
                }
            }
        })
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

        let client = config.client_ip.resolve(&parts);
        let allowed = match client {
            Some(client) => shared.rate_limiter.check(client, path, &body).await,
            None => {
                shared
                    .rate_limiter
                    .check_without_ip(&config.client_ip, path, &body)
                    .await
            }
        };
        let ip = client.map(|ip| ip.to_string());
        if !allowed {
            return AuthError::too_many_requests().into_response();
        }

        if !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS) {
            let origin = header_str(&parts.headers, ORIGIN)
                .filter(|o| o != "null")
                .or_else(|| header_str(&parts.headers, REFERER).and_then(|r| origin_of(&r)));
            let rejected = match &origin {
                Some(origin) if !config.is_trusted_origin(origin) => {
                    Some((codes::INVALID_ORIGIN, "invalid origin"))
                }
                None if parts.headers.contains_key(COOKIE) => {
                    Some((codes::MISSING_OR_NULL_ORIGIN, "missing or null origin"))
                }
                _ => None,
            };
            if let Some((code, message)) = rejected {
                return AuthError::new(StatusCode::FORBIDDEN, code, message).into_response();
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
        let mut response = endpoint
            .clone()
            .handle(shared, Arc::new(request), body)
            .await;
        response
            .headers_mut()
            .entry(CACHE_CONTROL)
            .or_insert(HeaderValue::from_static("no-store"));
        response
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
    /// A registered plugin's config, or `None` when `P` isn't registered. For code generic
    /// over `AuthInstance` (an axum extractor) that can't name the `HasPlugin` index; with a
    /// concrete `Auth`, a plugin's extension trait is the compile-checked way.
    fn try_plugin<P: Plugin>(&self) -> Option<&P>;
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

    fn try_plugin<Pl: Plugin>(&self) -> Option<&Pl> {
        self.shared
            .plugins
            .get(&std::any::TypeId::of::<Pl>())
            .and_then(|plugin| plugin.downcast_ref::<Pl>())
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

/// Lets a handler return a server API result as is: the JSON body plus the cookies the
/// endpoint set, like the HTTP route would answer.
#[cfg(feature = "axum")]
impl<T: Serialize> axum_core::response::IntoResponse for ApiResponse<T> {
    fn into_response(self) -> axum_core::response::Response {
        self.into_http().map(axum_core::body::Body::from)
    }
}

/// Lets an actix-web handler return a server API result as is: the JSON body plus the
/// cookies the endpoint set, like the HTTP route would answer.
#[cfg(feature = "actix")]
impl<T: Serialize> actix_web::Responder for ApiResponse<T> {
    type Body = actix_web::body::BoxBody;

    fn respond_to(self, _: &actix_web::HttpRequest) -> actix_web::HttpResponse {
        crate::error::to_actix(self.into_http())
    }
}

impl<D: Adapter> Api<'_, D> {
    /// The configured adapter.
    pub fn adapter(&self) -> &D {
        &self.shared.db
    }

    /// Typed queries on the configured adapter, for code outside an endpoint that has an
    /// `AuthInstance` but no `Ctx` (an axum extractor reading a plugin's table).
    pub fn db(&self) -> Db<'_, D> {
        Db::new(&self.shared.db, &self.shared.schema)
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
    /// is no HTTP route. Validates like sign-up and answers
    /// `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` (422) when the email is taken.
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
