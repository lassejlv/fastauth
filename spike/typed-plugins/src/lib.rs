//! Spike for the fastauth plugin type system. It proves four claims from
//! `docs/08-internals.md` with real rustc:
//!
//! 1. Plugins live in a type-level list, and `Has<P, I>` finds one by type with the
//!    index `I` inferred, so callers never name it.
//! 2. A plugin's `Requires` is checked when it is registered: a missing or later
//!    dependency is a compile error, not a runtime panic.
//! 3. Plugin crates add methods to `Auth` through extension traits that only compile
//!    when the plugin is registered.
//! 4. Columns a plugin adds to `user` decode into a typed struct reached with
//!    `user.plugin::<P, _>()`.
//!
//! Everything else (crypto, cookies, real HTTP, SQL) is stubbed. Do not ship this.
//!
//! A missing plugin does not compile:
//!
//! ```compile_fail
//! use fastauth_spike_typed_plugins::{*, plugins::*};
//! let auth = builder(MemoryAdapter::default()).plugin(TwoFactor::default()).build().unwrap();
//! let _org = auth.plugin::<Organization, _>();
//! ```
//!
//! A plugin whose dependency is absent does not compile:
//!
//! ```compile_fail
//! use fastauth_spike_typed_plugins::{*, plugins::*};
//! let _ = builder(MemoryAdapter::default()).plugin(OrgBilling).build();
//! ```
//!
//! Nor does one registered before its dependency:
//!
//! ```compile_fail
//! use fastauth_spike_typed_plugins::{*, plugins::*};
//! let _ = builder(MemoryAdapter::default())
//!     .plugin(OrgBilling)
//!     .plugin(Organization::default())
//!     .build();
//! ```
//!
//! The extension method only exists with its plugin:
//!
//! ```compile_fail
//! use fastauth_spike_typed_plugins::{*, plugins::*};
//! let auth = builder(MemoryAdapter::default()).build().unwrap();
//! let _api = auth.two_factor();
//! ```
//!
//! With the right plugins, the same calls compile:
//!
//! ```
//! use fastauth_spike_typed_plugins::{*, plugins::*};
//! type AppAuth = Auth<MemoryAdapter, (), plugins![TwoFactor, Organization, OrgBilling]>;
//! let auth: AppAuth = builder(MemoryAdapter::default())
//!     .plugin(TwoFactor::default())
//!     .plugin(Organization::default())
//!     .plugin(OrgBilling)
//!     .build()
//!     .unwrap();
//! assert_eq!(auth.plugin::<TwoFactor, _>().issuer, "fastauth");
//! let _api = auth.two_factor();
//! ```

pub mod plugins;

use std::any::{Any, TypeId};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ---------------------------------------------------------------------------
// Type-level plugin list
// ---------------------------------------------------------------------------

/// Empty plugin list.
pub struct Nil;

/// A plugin followed by the rest of the list.
pub struct Cons<H, T>(pub Arc<H>, pub T);

/// Index: the plugin is the head of the list.
pub struct Here;

/// Index: the plugin is somewhere in the tail.
pub struct There<I>(PhantomData<I>);

/// Builds the plugin list type: `plugins![A, B]` is `Cons<A, Cons<B, Nil>>`.
#[macro_export]
macro_rules! plugins {
    () => { $crate::Nil };
    ($head:ty $(, $tail:ty)* $(,)?) => { $crate::Cons<$head, $crate::plugins![$($tail),*]> };
}

#[diagnostic::on_unimplemented(
    message = "plugin `{P}` is not registered on this auth instance",
    label = "`{P}` is not in this plugin list",
    note = "register it with `.plugin(...)` on the builder, before any plugin that requires it"
)]
pub trait Has<P: Plugin, I>: PluginSet {
    fn get(&self) -> &Arc<P>;
    fn user_ext(ext: &Self::UserExt) -> &P::UserFields;
}

impl<P: Plugin, T: PluginSet> Has<P, Here> for Cons<P, T> {
    fn get(&self) -> &Arc<P> {
        &self.0
    }
    fn user_ext(ext: &Self::UserExt) -> &P::UserFields {
        &ext.0
    }
}

impl<P: Plugin, H: Plugin, T: Has<P, I>, I> Has<P, There<I>> for Cons<H, T> {
    fn get(&self) -> &Arc<P> {
        self.1.get()
    }
    fn user_ext(ext: &Self::UserExt) -> &P::UserFields {
        T::user_ext(&ext.1)
    }
}

/// A tuple of plugins that must all be present in list `L`.
pub trait Satisfied<L, I> {}
impl<L> Satisfied<L, ()> for () {}
impl<L, A: Plugin, IA> Satisfied<L, (IA,)> for (A,) where L: Has<A, IA> {}
impl<L, A: Plugin, B: Plugin, IA, IB> Satisfied<L, (IA, IB)> for (A, B) where
    L: Has<A, IA> + Has<B, IB>
{
}

/// Appends a plugin at the end so the list reads in registration order.
pub trait Append<T> {
    type Out;
    fn append(self, item: Arc<T>) -> Self::Out;
}
impl<T> Append<T> for Nil {
    type Out = Cons<T, Nil>;
    fn append(self, item: Arc<T>) -> Self::Out {
        Cons(item, Nil)
    }
}
impl<H, Tail: Append<T>, T> Append<T> for Cons<H, Tail> {
    type Out = Cons<H, Tail::Out>;
    fn append(self, item: Arc<T>) -> Self::Out {
        Cons(self.0, self.1.append(item))
    }
}

/// Walks the list at build time (registration) and on every session load (decoding).
pub trait PluginSet: Send + Sync + 'static {
    /// Nested tuple of each plugin's `UserFields`, parallel to the list.
    type UserExt: Send + Sync + 'static;
    fn register<D: Adapter>(&self, r: &mut Registry<D>);
    fn decode_user(record: &Record) -> Result<Self::UserExt, AuthError>;
}

impl PluginSet for Nil {
    type UserExt = ();
    fn register<D: Adapter>(&self, _: &mut Registry<D>) {}
    fn decode_user(_: &Record) -> Result<(), AuthError> {
        Ok(())
    }
}

impl<H: Plugin, T: PluginSet> PluginSet for Cons<H, T> {
    type UserExt = (H::UserFields, T::UserExt);
    fn register<D: Adapter>(&self, r: &mut Registry<D>) {
        r.plugins.insert(TypeId::of::<H>(), self.0.clone());
        r.schema.extend("user", H::ID, H::UserFields::columns());
        self.0.schema(&mut r.schema);
        self.0.endpoints(r);
        self.1.register(r);
    }
    fn decode_user(record: &Record) -> Result<Self::UserExt, AuthError> {
        Ok((H::UserFields::decode(record)?, T::decode_user(record)?))
    }
}

// ---------------------------------------------------------------------------
// Plugin, fields, schema
// ---------------------------------------------------------------------------

pub trait Plugin: Send + Sync + Sized + 'static {
    const ID: &'static str;
    /// Plugins that must be registered before this one, as a tuple.
    type Requires;
    /// Columns this plugin adds to `user`, decoded on every session load.
    type UserFields: Fields;
    fn schema(&self, _schema: &mut Schema) {}
    fn endpoints<D: Adapter>(self: &Arc<Self>, _routes: &mut Registry<D>) {}
}

/// A typed view over some columns of a table. `#[derive(Fields)]` writes this in the real crate.
pub trait Fields: Sized + Send + Sync + 'static {
    fn columns() -> &'static [Column];
    fn decode(record: &Record) -> Result<Self, AuthError>;
}

impl Fields for () {
    fn columns() -> &'static [Column] {
        &[]
    }
    fn decode(_: &Record) -> Result<(), AuthError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ColumnType {
    Text,
    Bool,
    Int,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DefaultValue {
    Text(&'static str),
    Bool(bool),
    Int(i64),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Column {
    pub name: &'static str,
    pub ty: ColumnType,
    pub default: Option<DefaultValue>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TableColumn {
    pub column: Column,
    pub owner: &'static str,
}

#[derive(Debug, Default)]
pub struct Schema {
    pub tables: BTreeMap<&'static str, Vec<TableColumn>>,
    pub errors: Vec<String>,
}

impl Schema {
    pub fn table(&mut self, name: &'static str, owner: &'static str, columns: &[Column]) {
        if self.tables.contains_key(name) {
            self.errors.push(format!(
                "table `{name}` is defined twice (second by `{owner}`)"
            ));
            return;
        }
        self.tables.insert(name, Vec::new());
        self.extend(name, owner, columns);
    }

    pub fn extend(&mut self, table: &'static str, owner: &'static str, columns: &[Column]) {
        let Some(existing) = self.tables.get_mut(table) else {
            self.errors
                .push(format!("`{owner}` extends unknown table `{table}`"));
            return;
        };
        for column in columns {
            if let Some(clash) = existing.iter().find(|c| c.column.name == column.name) {
                self.errors.push(format!(
                    "column `{table}.{}` is defined by both `{}` and `{owner}`",
                    column.name, clash.owner
                ));
                continue;
            }
            existing.push(TableColumn {
                column: *column,
                owner,
            });
        }
    }

    fn defaults(&self, table: &str, record: &mut Record) {
        for c in self.tables.get(table).into_iter().flatten() {
            if record.contains_key(c.column.name) {
                continue;
            }
            let value = match c.column.default {
                Some(DefaultValue::Text(s)) => Value::Text(s.to_owned()),
                Some(DefaultValue::Bool(b)) => Value::Bool(b),
                Some(DefaultValue::Int(i)) => Value::Int(i),
                None => Value::Null,
            };
            record.insert(c.column.name.to_owned(), value);
        }
    }
}

// ---------------------------------------------------------------------------
// Values and the adapter
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Text(String),
}

pub type Record = HashMap<String, Value>;

pub fn text(record: &Record, column: &str) -> Result<String, AuthError> {
    match record.get(column) {
        Some(Value::Text(s)) => Ok(s.clone()),
        other => Err(AuthError::internal(format!(
            "column {column}: expected text, got {other:?}"
        ))),
    }
}

pub fn boolean(record: &Record, column: &str) -> Result<bool, AuthError> {
    match record.get(column) {
        Some(Value::Bool(b)) => Ok(*b),
        other => Err(AuthError::internal(format!(
            "column {column}: expected bool, got {other:?}"
        ))),
    }
}

pub trait Adapter: Send + Sync + 'static {
    fn insert(
        &self,
        table: &'static str,
        record: Record,
    ) -> impl Future<Output = Result<Record, AuthError>> + Send;

    fn find_one(
        &self,
        table: &'static str,
        column: &'static str,
        equals: Value,
    ) -> impl Future<Output = Result<Option<Record>, AuthError>> + Send;

    fn update(
        &self,
        table: &'static str,
        column: &'static str,
        equals: Value,
        set: Record,
    ) -> impl Future<Output = Result<Option<Record>, AuthError>> + Send;
}

#[derive(Default)]
pub struct MemoryAdapter {
    tables: Mutex<HashMap<&'static str, Vec<Record>>>,
}

impl Adapter for MemoryAdapter {
    async fn insert(&self, table: &'static str, record: Record) -> Result<Record, AuthError> {
        self.tables
            .lock()
            .unwrap()
            .entry(table)
            .or_default()
            .push(record.clone());
        Ok(record)
    }

    async fn find_one(
        &self,
        table: &'static str,
        column: &'static str,
        equals: Value,
    ) -> Result<Option<Record>, AuthError> {
        let tables = self.tables.lock().unwrap();
        let rows = tables.get(table).map(Vec::as_slice).unwrap_or_default();
        Ok(rows
            .iter()
            .find(|r| r.get(column) == Some(&equals))
            .cloned())
    }

    async fn update(
        &self,
        table: &'static str,
        column: &'static str,
        equals: Value,
        set: Record,
    ) -> Result<Option<Record>, AuthError> {
        let mut tables = self.tables.lock().unwrap();
        let Some(row) = tables
            .get_mut(table)
            .and_then(|rows| rows.iter_mut().find(|r| r.get(column) == Some(&equals)))
        else {
            return Ok(None);
        };
        row.extend(set);
        Ok(Some(row.clone()))
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AuthError {
    #[serde(skip)]
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

impl AuthError {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
    pub fn unauthorized() -> Self {
        Self::new(401, "UNAUTHORIZED", "a valid session is required")
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(500, "INTERNAL", message)
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AuthError {}

// ---------------------------------------------------------------------------
// Endpoints and the registry
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    Get,
    Post,
}

pub trait Endpoint<D: Adapter>: Send + Sync + 'static {
    const METHOD: Method;
    const PATH: &'static str;
    type Input: DeserializeOwned + Send + 'static;
    type Output: Serialize + Send + 'static;

    fn call(
        &self,
        ctx: Ctx<D>,
        input: Self::Input,
    ) -> impl Future<Output = Result<Self::Output, AuthError>> + Send;
}

trait ErasedEndpoint<D>: Send + Sync {
    fn call_json<'a>(
        &'a self,
        ctx: Ctx<D>,
        body: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, AuthError>>;
}

struct Erased<E>(E);

impl<D: Adapter, E: Endpoint<D>> ErasedEndpoint<D> for Erased<E> {
    fn call_json<'a>(
        &'a self,
        ctx: Ctx<D>,
        body: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, AuthError>> {
        Box::pin(async move {
            let input: E::Input = serde_json::from_slice(body)
                .map_err(|e| AuthError::new(400, "INVALID_BODY", e.to_string()))?;
            let output = self.0.call(ctx, input).await?;
            serde_json::to_vec(&output).map_err(|e| AuthError::internal(e.to_string()))
        })
    }
}

type PluginMap = HashMap<TypeId, Arc<dyn Any + Send + Sync>>;
type RouteTable<D> = HashMap<(Method, &'static str), (&'static str, Arc<dyn ErasedEndpoint<D>>)>;

pub struct Registry<D> {
    routes: RouteTable<D>,
    plugins: PluginMap,
    pub schema: Schema,
    owner: &'static str,
}

impl<D: Adapter> Registry<D> {
    pub fn endpoint<E: Endpoint<D>>(&mut self, endpoint: E) {
        let key = (E::METHOD, E::PATH);
        if let Some((first, _)) = self.routes.get(&key) {
            self.schema.errors.push(format!(
                "route {} is registered by both `{first}` and `{}`",
                E::PATH,
                self.owner
            ));
            return;
        }
        self.routes
            .insert(key, (self.owner, Arc::new(Erased(endpoint))));
    }
}

/// Per-request context handed to endpoints.
pub struct Ctx<D> {
    pub db: Arc<D>,
    pub schema: Arc<Schema>,
    plugins: Arc<PluginMap>,
    bearer: Option<String>,
}

impl<D: Adapter> Ctx<D> {
    /// Runtime lookup for plugin-to-plugin calls. `Requires` made it infallible at compile time.
    pub fn plugin<P: Plugin>(&self) -> &P {
        self.plugins
            .get(&TypeId::of::<P>())
            .and_then(|p| p.downcast_ref::<P>())
            .expect("guaranteed by Plugin::Requires")
    }

    pub async fn require_session(&self) -> Result<SessionRow, AuthError> {
        let token = self.bearer.clone().ok_or_else(AuthError::unauthorized)?;
        let row = self
            .db
            .find_one("session", "token", Value::Text(token))
            .await?
            .ok_or_else(AuthError::unauthorized)?;
        Ok(SessionRow {
            token: text(&row, "token")?,
            user_id: text(&row, "user_id")?,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionRow {
    pub token: String,
    pub user_id: String,
}

// ---------------------------------------------------------------------------
// Auth, builder, sessions
// ---------------------------------------------------------------------------

pub struct Auth<D, U = (), P = Nil> {
    inner: Arc<Inner<D, P>>,
    _user: PhantomData<fn() -> U>,
}

impl<D, U, P> Clone for Auth<D, U, P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _user: PhantomData,
        }
    }
}

struct Inner<D, P> {
    db: Arc<D>,
    plugins: P,
    plugin_map: Arc<PluginMap>,
    routes: RouteTable<D>,
    schema: Arc<Schema>,
}

pub struct Builder<D, U, P> {
    db: D,
    plugins: P,
    _user: PhantomData<fn() -> U>,
}

pub fn builder<D: Adapter>(db: D) -> Builder<D, (), Nil> {
    Builder {
        db,
        plugins: Nil,
        _user: PhantomData,
    }
}

#[derive(Debug)]
pub struct BuildError(pub Vec<String>);

impl<D: Adapter, U, P: PluginSet> Builder<D, U, P> {
    pub fn user_fields<U2: Fields>(self) -> Builder<D, U2, P> {
        Builder {
            db: self.db,
            plugins: self.plugins,
            _user: PhantomData,
        }
    }

    pub fn plugin<Pl: Plugin, I>(self, plugin: Pl) -> Builder<D, U, P::Out>
    where
        P: Append<Pl>,
        Pl::Requires: Satisfied<P, I>,
    {
        Builder {
            db: self.db,
            plugins: self.plugins.append(Arc::new(plugin)),
            _user: PhantomData,
        }
    }
}

impl<D: Adapter, U: Fields, P: PluginSet> Builder<D, U, P> {
    pub fn build(self) -> Result<Auth<D, U, P>, BuildError> {
        let mut registry = Registry::<D> {
            routes: HashMap::new(),
            plugins: HashMap::new(),
            schema: Schema::default(),
            owner: "core",
        };
        core_schema(&mut registry.schema);
        registry.schema.extend("user", "app", U::columns());
        registry.endpoint(SignUpEmail);
        registry.owner = "plugins";
        self.plugins.register(&mut registry);
        if !registry.schema.errors.is_empty() {
            return Err(BuildError(registry.schema.errors));
        }
        Ok(Auth {
            inner: Arc::new(Inner {
                db: Arc::new(self.db),
                plugins: self.plugins,
                plugin_map: Arc::new(registry.plugins),
                routes: registry.routes,
                schema: Arc::new(registry.schema),
            }),
            _user: PhantomData,
        })
    }
}

fn core_schema(schema: &mut Schema) {
    const fn text(name: &'static str) -> Column {
        Column {
            name,
            ty: ColumnType::Text,
            default: None,
        }
    }
    schema.table("user", "core", &[text("id"), text("email"), text("name")]);
    schema.table("session", "core", &[text("token"), text("user_id")]);
}

pub struct Request {
    pub method: Method,
    pub path: String,
    pub bearer: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

pub struct User<U, P: PluginSet> {
    pub id: String,
    pub email: String,
    pub name: String,
    /// The app's own columns (`.user_fields::<U>()`).
    pub fields: U,
    ext: P::UserExt,
}

impl<U, P: PluginSet> User<U, P> {
    /// Columns a registered plugin added to `user`, fully typed.
    pub fn plugin<Pl: Plugin, I>(&self) -> &Pl::UserFields
    where
        P: Has<Pl, I>,
    {
        P::user_ext(&self.ext)
    }
}

pub struct Session<U, P: PluginSet> {
    pub token: String,
    pub user: User<U, P>,
}

impl<D: Adapter, U: Fields, P: PluginSet> Auth<D, U, P> {
    pub async fn handle(&self, req: Request) -> Response {
        let Some((_, endpoint)) = self.inner.routes.get(&(req.method, req.path.as_str())) else {
            return error_response(&AuthError::new(404, "NOT_FOUND", "no such auth route"));
        };
        match endpoint.call_json(self.ctx(req.bearer), &req.body).await {
            Ok(body) => Response { status: 200, body },
            Err(err) => error_response(&err),
        }
    }

    pub fn plugin<Pl: Plugin, I>(&self) -> &Pl
    where
        P: Has<Pl, I>,
    {
        self.inner.plugins.get()
    }

    pub fn schema(&self) -> &Schema {
        &self.inner.schema
    }

    pub async fn sign_up_email(
        &self,
        input: SignUpEmailInput,
    ) -> Result<SignUpEmailOutput, AuthError> {
        SignUpEmail.call(self.ctx(None), input).await
    }

    pub async fn get_session(&self, token: &str) -> Result<Option<Session<U, P>>, AuthError> {
        let db = &self.inner.db;
        let Some(session) = db
            .find_one("session", "token", Value::Text(token.to_owned()))
            .await?
        else {
            return Ok(None);
        };
        let user_id = text(&session, "user_id")?;
        let Some(row) = db.find_one("user", "id", Value::Text(user_id)).await? else {
            return Ok(None);
        };
        Ok(Some(Session {
            token: token.to_owned(),
            user: User {
                id: text(&row, "id")?,
                email: text(&row, "email")?,
                name: text(&row, "name")?,
                fields: U::decode(&row)?,
                ext: P::decode_user(&row)?,
            },
        }))
    }
}

fn error_response(err: &AuthError) -> Response {
    Response {
        status: err.status,
        body: serde_json::to_vec(err).unwrap_or_default(),
    }
}

/// Lets plugin crates reach into `Auth` without naming its type parameters.
pub trait AuthHandle {
    type Db: Adapter;
    fn ctx(&self, bearer: Option<String>) -> Ctx<Self::Db>;
}

impl<D: Adapter, U, P> AuthHandle for Auth<D, U, P> {
    type Db = D;
    fn ctx(&self, bearer: Option<String>) -> Ctx<D> {
        Ctx {
            db: self.inner.db.clone(),
            schema: self.inner.schema.clone(),
            plugins: self.inner.plugin_map.clone(),
            bearer,
        }
    }
}

#[diagnostic::on_unimplemented(
    message = "plugin `{Pl}` is not registered on this auth instance",
    note = "register it with `.plugin(...)` on the builder"
)]
pub trait HasPlugin<Pl, I>: AuthHandle {
    fn plugin_arc(&self) -> &Arc<Pl>;
}

impl<D: Adapter, U, P: Has<Pl, I>, Pl: Plugin, I> HasPlugin<Pl, I> for Auth<D, U, P> {
    fn plugin_arc(&self) -> &Arc<Pl> {
        self.inner.plugins.get()
    }
}

// ---------------------------------------------------------------------------
// One core endpoint (no credentials: this spike is about types, not auth)
// ---------------------------------------------------------------------------

pub struct SignUpEmail;

#[derive(Deserialize)]
pub struct SignUpEmailInput {
    pub email: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct SignUpEmailOutput {
    pub token: String,
    pub user_id: String,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn next_id(prefix: &str) -> String {
    format!("{prefix}_{}", NEXT_ID.fetch_add(1, Ordering::Relaxed))
}

impl<D: Adapter> Endpoint<D> for SignUpEmail {
    const METHOD: Method = Method::Post;
    const PATH: &'static str = "/sign-up/email";
    type Input = SignUpEmailInput;
    type Output = SignUpEmailOutput;

    async fn call(
        &self,
        ctx: Ctx<D>,
        input: SignUpEmailInput,
    ) -> Result<SignUpEmailOutput, AuthError> {
        let user_id = next_id("usr");
        let mut user = Record::from([
            ("id".to_owned(), Value::Text(user_id.clone())),
            ("email".to_owned(), Value::Text(input.email)),
            ("name".to_owned(), Value::Text(input.name)),
        ]);
        ctx.schema.defaults("user", &mut user);
        ctx.db.insert("user", user).await?;
        let token = next_id("tok");
        ctx.db
            .insert(
                "session",
                Record::from([
                    ("token".to_owned(), Value::Text(token.clone())),
                    ("user_id".to_owned(), Value::Text(user_id.clone())),
                ]),
            )
            .await?;
        Ok(SignUpEmailOutput { token, user_id })
    }
}
