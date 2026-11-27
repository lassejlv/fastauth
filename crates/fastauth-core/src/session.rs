//! Session lookup (cookie, cookie cache, resolvers), refresh, and the typed session the app sees.

use std::ops::Deref;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::adapter::{Adapter, Filter, Op, SessionWithUser, Update};
use crate::config::{CoreConfig, SlidingRefresh};
use crate::cookies::{self, SetCookie};
use crate::crypto::{Hash, Keys, SignPurpose, base64url, base64url_decode};
use crate::endpoint::{Ctx, Effects, RequestInfo, Resolved, SessionUse, Shared};
use crate::error::AuthError;
use crate::hlist::{Has, PluginSet};
use crate::model::{Fields, Model};
use crate::models::{Session, User};
use crate::plugin::Plugin;
use crate::query::Db;
use crate::value::{DecodeError, Row, Value};

/// A user row as plugins see it: core fields typed, everything else in `row`.
#[derive(Clone, Debug)]
pub struct UserView {
    pub user: User,
    pub row: Row,
}

impl Deref for UserView {
    type Target = User;
    fn deref(&self) -> &User {
        &self.user
    }
}

impl UserView {
    pub fn from_row(row: Row) -> Result<Self, DecodeError> {
        Ok(Self {
            user: User::decode(&row)?,
            row,
        })
    }

    /// Decodes a plugin's or the app's columns from this row.
    pub fn fields<F: Fields>(&self) -> Result<F, DecodeError> {
        F::decode(&self.row)
    }

    /// What clients see: every `returned` column, camelCase.
    pub fn to_json(&self) -> serde_json::Map<String, serde_json::Value> {
        self.row.to_client_json()
    }

    /// The user's security stamp ([`User::SECURITY_STAMP`]) when this row was read. A row
    /// without the column (an old cookie cache) reads as 0.
    pub fn security_stamp(&self) -> i64 {
        self.row
            .get(User::SECURITY_STAMP.name())
            .unwrap_or_default()
    }
}

/// Serializes as the client JSON of the row, the `user` of `/get-session`.
impl Serialize for UserView {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_json().serialize(serializer)
    }
}

/// A session as endpoints and plugins see it. Debug output never shows the raw token.
#[derive(Clone)]
pub struct SessionView {
    pub session: Session,
    pub row: Row,
    pub user: UserView,
    /// The raw token, when the request carried it. Never stored.
    pub token: Option<String>,
    /// Created for this request only by a resolver (e.g. an API key); not in the database.
    pub ephemeral: bool,
    /// Read from the cookie cache, so it may be stale; see `Ctx::authoritative_session`.
    pub(crate) from_cache: bool,
}

impl std::fmt::Debug for SessionView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionView")
            .field("session", &self.session)
            .field("row", &self.row)
            .field("user", &self.user)
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .field("ephemeral", &self.ephemeral)
            .finish()
    }
}

impl SessionView {
    pub fn fields<F: Fields>(&self) -> Result<F, DecodeError> {
        F::decode(&self.row)
    }

    pub fn to_json(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut json = self.row.to_client_json();
        if let Some(token) = &self.token {
            json.insert("token".into(), token.clone().into());
        }
        json
    }

    /// `{ "session": {..}, "user": {..} }`, the `/get-session` shape.
    pub fn to_response_json(&self) -> serde_json::Value {
        serde_json::json!({ "session": self.to_json(), "user": self.user.to_json() })
    }
}

/// The signed-in user with the app's fields and every plugin's fields, typed.
pub struct AuthUser<U, P: PluginSet> {
    user: User,
    /// The app's `.user_fields::<U>()`.
    pub fields: U,
    ext: P::UserExt,
}

impl<U: Clone, P: PluginSet> Clone for AuthUser<U, P> {
    fn clone(&self) -> Self {
        Self {
            user: self.user.clone(),
            fields: self.fields.clone(),
            ext: self.ext.clone(),
        }
    }
}

impl<U: std::fmt::Debug, P: PluginSet> std::fmt::Debug for AuthUser<U, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthUser")
            .field("user", &self.user)
            .field("fields", &self.fields)
            .finish_non_exhaustive()
    }
}

impl<U, P: PluginSet> Deref for AuthUser<U, P> {
    type Target = User;
    fn deref(&self) -> &User {
        &self.user
    }
}

impl<U, P: PluginSet> AuthUser<U, P> {
    /// Columns a registered plugin added to `user`. Doesn't compile without the plugin.
    pub fn plugin<Pl: Plugin, I>(&self) -> &Pl::UserFields
    where
        P: Has<Pl, I>,
    {
        P::user_ext(&self.ext)
    }

    pub fn core(&self) -> &User {
        &self.user
    }
}

/// The typed session handlers get (through `Session<AppAuth>` in axum).
pub struct SessionData<U, P: PluginSet> {
    pub session: Session,
    pub user: AuthUser<U, P>,
    pub token: Option<String>,
    ext: P::SessionExt,
    view: SessionView,
}

impl<U: Clone, P: PluginSet> Clone for SessionData<U, P> {
    fn clone(&self) -> Self {
        Self {
            session: self.session.clone(),
            user: self.user.clone(),
            token: self.token.clone(),
            ext: self.ext.clone(),
            view: self.view.clone(),
        }
    }
}

impl<U: std::fmt::Debug, P: PluginSet> std::fmt::Debug for SessionData<U, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionData")
            .field("session", &self.session)
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

impl<U: Fields, P: PluginSet> SessionData<U, P> {
    pub fn from_view(view: SessionView) -> Result<Self, DecodeError> {
        Ok(Self {
            session: view.session.clone(),
            user: AuthUser {
                user: view.user.user.clone(),
                fields: U::decode(&view.user.row)?,
                ext: P::decode_user(&view.user.row)?,
            },
            token: view.token.clone(),
            ext: P::decode_session(&view.row)?,
            view,
        })
    }
}

impl<U, P: PluginSet> SessionData<U, P> {
    /// Columns a registered plugin added to `session`.
    pub fn session_plugin<Pl: Plugin, I>(&self) -> &Pl::SessionFields
    where
        P: Has<Pl, I>,
    {
        P::session_ext(&self.ext)
    }

    pub fn view(&self) -> &SessionView {
        &self.view
    }
}

pub(crate) const SESSION_TOKEN: &str = "session_token";
pub(crate) const SESSION_DATA: &str = "session_data";
pub(crate) const DONT_REMEMBER: &str = "dont_remember";
/// How long a `rememberMe: false` session lives at most, as in Better Auth.
pub(crate) const DONT_REMEMBER_LIFETIME: time::Duration = time::Duration::days(1);

pub(crate) fn set_session_cookies(
    config: &CoreConfig,
    keys: &Keys,
    effects: &Mutex<Effects>,
    token: &str,
    remember_me: bool,
) {
    let max_age = remember_me.then_some(config.session.expires_in);
    let mut effects = effects.lock().unwrap();
    let mut push = |cookie: SetCookie| {
        effects.cookies.retain(|c| c.name != cookie.name);
        effects.cookies.push(cookie);
    };
    push(SetCookie::new(
        config.cookie_name(SESSION_TOKEN),
        keys.sign(SignPurpose::Cookie, token),
        max_age,
    ));
    if !remember_me {
        push(SetCookie::new(
            config.cookie_name(DONT_REMEMBER),
            keys.sign(SignPurpose::Cookie, "true"),
            None,
        ));
    }
}

pub(crate) fn clear_session_cookies(config: &CoreConfig, effects: &Mutex<Effects>) {
    let mut effects = effects.lock().unwrap();
    for name in [SESSION_TOKEN, SESSION_DATA, DONT_REMEMBER] {
        let name = config.cookie_name(name);
        effects.cookies.retain(|c| c.name != name);
        effects.cookies.push(SetCookie::delete(name));
    }
}

/// The cookie cache: the session and user rows with every column hidden from clients
/// (`returned = false`) set to null, and those columns' values encrypted in `h`.
#[derive(Serialize, Deserialize)]
struct CachePayload {
    s: Vec<Value>,
    u: Vec<Value>,
    h: String,
    t: Option<String>,
    e: i64,
    f: u64,
}

pub(crate) fn fingerprint(
    session: &crate::schema::TableDef,
    user: &crate::schema::TableDef,
) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for column in session.columns.iter().chain(&user.columns) {
        let hidden = if column.returned { "" } else { "!" };
        for byte in column.name.bytes().chain(hidden.bytes()).chain(*b"|") {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }
    hash
}

fn write_cache<D>(shared: &Shared<D>, effects: &Mutex<Effects>, view: &SessionView) {
    let Some(max_age) = shared.config.session.cookie_cache else {
        return;
    };
    let expires = OffsetDateTime::now_utc() + max_age;
    let (s, hidden_s) = split_hidden(&view.row);
    let (u, hidden_u) = split_hidden(&view.user.row);
    let Ok(hidden) = serde_json::to_vec(&(hidden_s, hidden_u)) else {
        return;
    };
    let payload = CachePayload {
        s,
        u,
        h: base64url(&shared.keys.encrypt(&hidden)),
        t: view
            .token
            .as_ref()
            .map(|t| base64url(Hash::sha256(t).as_bytes())),
        e: expires.unix_timestamp(),
        f: shared.cache_fingerprint,
    };
    let Ok(json) = serde_json::to_vec(&payload) else {
        return;
    };
    let value = shared
        .keys
        .sign(SignPurpose::CookieCache, &base64url(&json));
    if value.len() > 3800 {
        return;
    }
    let name = shared.config.cookie_name(SESSION_DATA);
    let mut effects = effects.lock().unwrap();
    effects.cookies.retain(|c| c.name != name);
    effects
        .cookies
        .push(SetCookie::new(name, value, Some(max_age)));
}

/// The row's values with the columns hidden from clients set to null, and those values.
fn split_hidden(row: &Row) -> (Vec<Value>, Vec<Value>) {
    let mut public = row.values().to_vec();
    let mut hidden = Vec::new();
    for (value, column) in public.iter_mut().zip(&row.table().columns) {
        if !column.returned {
            hidden.push(std::mem::replace(value, Value::Null));
        }
    }
    (public, hidden)
}

/// Puts the hidden values `split_hidden` took back in place. `None` when they don't fit.
fn join_hidden(
    table: &crate::schema::TableDef,
    mut public: Vec<Value>,
    hidden: Vec<Value>,
) -> Option<Vec<Value>> {
    if public.len() != table.columns.len() {
        return None;
    }
    let mut hidden = hidden.into_iter();
    for (value, column) in public.iter_mut().zip(&table.columns) {
        if !column.returned {
            *value = hidden.next()?;
        }
    }
    hidden.next().is_none().then_some(public)
}

fn read_cache<D>(shared: &Shared<D>, request: &RequestInfo, token: &str) -> Option<SessionView> {
    shared.config.session.cookie_cache?;
    let raw = cookies::read(&request.headers, &shared.config.cookie_name(SESSION_DATA))?;
    let encoded = shared.keys.verify(SignPurpose::CookieCache, raw)?;
    let payload: CachePayload = serde_json::from_slice(&base64url_decode(encoded)?).ok()?;
    let token_hash = base64url(Hash::sha256(token).as_bytes());
    if payload.f != shared.cache_fingerprint
        || payload.e < OffsetDateTime::now_utc().unix_timestamp()
        || payload.t.as_deref() != Some(token_hash.as_str())
    {
        return None;
    }
    let session_table = shared.schema.expect(Session::TABLE);
    let user_table = shared.schema.expect(User::TABLE);
    let hidden = shared.keys.decrypt(&base64url_decode(&payload.h)?)?;
    let (hidden_s, hidden_u): (Vec<Value>, Vec<Value>) = serde_json::from_slice(&hidden).ok()?;
    let row = Row::new(
        session_table.clone(),
        join_hidden(session_table, payload.s, hidden_s)?,
    );
    let user = UserView::from_row(Row::new(
        user_table.clone(),
        join_hidden(user_table, payload.u, hidden_u)?,
    ))
    .ok()?;
    let session = Session::decode(&row).ok()?;
    (session.expires_at > OffsetDateTime::now_utc()).then(|| SessionView {
        session,
        row,
        user,
        token: Some(token.to_owned()),
        ephemeral: false,
        from_cache: true,
    })
}

/// Looks a session up by its raw token. Deletes it if expired.
pub(crate) async fn by_token<D: Adapter>(
    shared: &Shared<D>,
    db: &D,
    token: &str,
) -> Result<Option<SessionView>, AuthError> {
    let token_hash = Hash::sha256(token);
    let session_table = shared.schema.expect(Session::TABLE);
    let user_table = shared.schema.expect(User::TABLE);
    let found = db
        .session_with_user(SessionWithUser {
            session: session_table,
            user: user_table,
            token_hash: &token_hash,
        })
        .await?;
    let Some((row, user_row)) = found else {
        return Ok(None);
    };
    let session = Session::decode(&row).map_err(AuthError::internal)?;
    if session.expires_at <= OffsetDateTime::now_utc() {
        Db::new(db, &shared.schema)
            .delete::<Session>(Session::ID.eq(&session.id))
            .await?;
        return Ok(None);
    }
    Ok(Some(SessionView {
        session,
        row,
        user: UserView::from_row(user_row).map_err(AuthError::internal)?,
        token: Some(token.to_owned()),
        ephemeral: false,
        from_cache: false,
    }))
}

/// Whether the request carries the signed cookie of a `rememberMe: false` sign-in.
fn dont_remember<D>(shared: &Shared<D>, request: &RequestInfo) -> bool {
    cookies::read(&request.headers, &shared.config.cookie_name(DONT_REMEMBER)).is_some_and(|v| {
        shared
            .keys
            .verify_token(&shared.keys.decode_cookie(v))
            .is_some()
    })
}

/// Whether `session` was created shorter than a remembered one: a `rememberMe: false`
/// session, or one a plugin gave a short expiry. Read from the stored row, so it holds when
/// the request carries the token without the `dont_remember` marker (a bearer token, a
/// cookie jar that dropped the marker). A remembered session's stored lifetime is
/// `expires_in` (from creation, or from its last refresh); a second of slack absorbs the
/// timestamp precision of the database. When `expires_in` is one day or less, a
/// `rememberMe: false` session is as long as any other and only the marker tells them apart.
///
/// With [`SlidingRefresh::ExpiresAt`] the lifetime is read from `created_at` instead: a session
/// that is never extended keeps the expiry it was created with, and Better Auth moves
/// `updated_at` on any change to the row.
fn created_short(session: &Session, config: &crate::config::SessionConfig) -> bool {
    let since = match config.sliding {
        SlidingRefresh::UpdatedAt => session.updated_at,
        SlidingRefresh::ExpiresAt => session.created_at,
    };
    let expires_in = config.expires_in;
    let lifetime = session.expires_at - since;
    lifetime <= DONT_REMEMBER_LIFETIME && lifetime < expires_in - time::Duration::seconds(1)
}

/// Extends the expiry at most once per `update_age`, counted from `updated_at` or, with
/// [`SlidingRefresh::ExpiresAt`], from when `expires_at` was last set. The conditional update makes
/// concurrent requests extend it once. Sessions a plugin marked with
/// `PluginBuilder::fixed_session_expiry` (impersonation sessions) and `rememberMe: false`
/// sessions (by their marker cookie or their stored lifetime, see `created_short`) are never
/// extended. `false` when the session is gone: it was revoked between the lookup and the
/// update.
async fn refresh<D: Adapter>(
    shared: &Shared<D>,
    db: &D,
    request: &RequestInfo,
    effects: &Mutex<Effects>,
    view: &mut SessionView,
) -> Result<bool, AuthError> {
    let now = OffsetDateTime::now_utc();
    let config = &shared.config.session;
    let (due, column, current) = match config.sliding {
        SlidingRefresh::UpdatedAt => (
            now - view.session.updated_at >= config.update_age,
            "updated_at",
            view.session.updated_at,
        ),
        SlidingRefresh::ExpiresAt => (
            view.session.expires_at - config.expires_in + config.update_age <= now,
            "expires_at",
            view.session.expires_at,
        ),
    };
    if !due
        || shared.fixed_expiry.iter().any(|fixed| fixed(view))
        || dont_remember(shared, request)
        || created_short(&view.session, config)
    {
        return Ok(true);
    }
    let Some(token) = view.token.clone() else {
        return Ok(true);
    };
    let table = shared.schema.expect(Session::TABLE);
    let position = |c: &str| table.position(c).expect("core session column");
    let expires_at = now + config.expires_in;
    let filter = Filter::And(vec![
        Filter::Cmp {
            column: position("id"),
            op: Op::Eq,
            value: Value::Text(view.session.id.to_string()),
        },
        Filter::Cmp {
            column: position(column),
            op: Op::Eq,
            value: Value::Timestamp(current),
        },
    ]);
    let set = vec![
        (position("expires_at"), Value::Timestamp(expires_at)),
        (position("updated_at"), Value::Timestamp(now)),
    ];
    if db.update(Update { table, filter, set }).await? == 0 {
        let Some(current) = by_token(shared, db, &token).await? else {
            return Ok(false);
        };
        *view = current;
        return Ok(true);
    }
    view.session.expires_at = expires_at;
    view.session.updated_at = now;
    view.row.set("expires_at", Value::Timestamp(expires_at));
    view.row.set("updated_at", Value::Timestamp(now));
    set_session_cookies(&shared.config, &shared.keys, effects, &token, true);
    Ok(true)
}

/// Finds the request's session: signed cookie (and cookie cache), then resolvers.
/// `within` is the adapter of an `Api::within` call; every lookup goes through it.
pub(crate) async fn resolve<D: Adapter>(
    shared: &Arc<Shared<D>>,
    within: Option<&Arc<D>>,
    request: &Arc<RequestInfo>,
    effects: &Arc<Mutex<Effects>>,
) -> Result<Option<SessionView>, AuthError> {
    let db = within.map_or(&shared.db, |db| &**db);
    let cookie_name = shared.config.cookie_name(SESSION_TOKEN);
    if let Some(raw) = cookies::read(&request.headers, &cookie_name) {
        let Some(token) = shared
            .keys
            .verify_token(&shared.keys.decode_cookie(raw))
            .map(str::to_owned)
        else {
            clear_session_cookies(&shared.config, effects);
            return Ok(None);
        };
        if let Some(view) = read_cache(shared, request, &token) {
            run_gates(shared, within, request, effects, &view, SessionUse::Request).await?;
            return Ok(Some(view));
        }
        let Some(mut view) = by_token(shared, db, &token).await? else {
            clear_session_cookies(&shared.config, effects);
            return Ok(None);
        };
        run_gates(shared, within, request, effects, &view, SessionUse::Request).await?;
        if !refresh(shared, db, request, effects, &mut view).await? {
            clear_session_cookies(&shared.config, effects);
            return Ok(None);
        }
        write_cache(shared, effects, &view);
        return Ok(Some(view));
    }

    for resolver in &shared.resolvers {
        let ctx: Ctx<D> = Ctx::new(
            shared.clone(),
            within.cloned(),
            request.clone(),
            None,
            effects.clone(),
        );
        match resolver.resolve(&ctx, &request.headers).await? {
            None => continue,
            Some(Resolved::Token(token)) => {
                let Some(mut view) = by_token(shared, db, &token).await? else {
                    return Ok(None);
                };
                run_gates(shared, within, request, effects, &view, SessionUse::Request).await?;
                if !refresh(shared, db, request, effects, &mut view).await? {
                    return Ok(None);
                }
                return Ok(Some(view));
            }
            Some(Resolved::User(user_id)) => {
                return for_user(shared, within, request, effects, &user_id).await;
            }
        }
    }
    Ok(None)
}

/// The ephemeral session of `Resolved::User`: the user's row, after the session gates.
pub(crate) async fn for_user<D: Adapter>(
    shared: &Arc<Shared<D>>,
    within: Option<&Arc<D>>,
    request: &Arc<RequestInfo>,
    effects: &Arc<Mutex<Effects>>,
    user_id: &crate::value::Id,
) -> Result<Option<SessionView>, AuthError> {
    let db = within.map_or(&shared.db, |db| &**db);
    let Some(user_row) = Db::new(db, &shared.schema)
        .find::<User>(User::ID.eq(user_id))
        .one_row()
        .await?
    else {
        return Ok(None);
    };
    let view = ephemeral(shared, user_row)?;
    run_gates(shared, within, request, effects, &view, SessionUse::Request).await?;
    Ok(Some(view))
}

/// `Ctx::sensitive_session`: the stored session behind `current`, read without the cookie
/// cache, after the session gates with `SessionUse::Sensitive`.
pub(crate) async fn sensitive<D: Adapter>(
    shared: &Arc<Shared<D>>,
    within: Option<&Arc<D>>,
    request: &Arc<RequestInfo>,
    effects: &Arc<Mutex<Effects>>,
    current: Option<&SessionView>,
) -> Result<SessionView, AuthError> {
    let Some(current) = current.filter(|s| !s.ephemeral) else {
        return Err(AuthError::unauthorized());
    };
    stored(
        shared,
        within,
        request,
        effects,
        current,
        SessionUse::Sensitive,
    )
    .await
}

/// `Ctx::authoritative_session`: `current` when this request read it from the database
/// (or a resolver made it); a session from the cookie cache read again, after the session
/// gates with `SessionUse::Request`.
pub(crate) async fn authoritative<D: Adapter>(
    shared: &Arc<Shared<D>>,
    within: Option<&Arc<D>>,
    request: &Arc<RequestInfo>,
    effects: &Arc<Mutex<Effects>>,
    current: Option<&SessionView>,
) -> Result<SessionView, AuthError> {
    let Some(current) = current else {
        return Err(AuthError::unauthorized());
    };
    if !current.from_cache {
        return Ok(current.clone());
    }
    stored(
        shared,
        within,
        request,
        effects,
        current,
        SessionUse::Request,
    )
    .await
}

/// The stored session behind `current`, read without the cookie cache, after the gates.
async fn stored<D: Adapter>(
    shared: &Arc<Shared<D>>,
    within: Option<&Arc<D>>,
    request: &Arc<RequestInfo>,
    effects: &Arc<Mutex<Effects>>,
    current: &SessionView,
    usage: SessionUse,
) -> Result<SessionView, AuthError> {
    let Some(token) = current.token.as_deref() else {
        return Err(AuthError::unauthorized());
    };
    let db = within.map_or(&shared.db, |db| &**db);
    let Some(view) = by_token(shared, db, token).await? else {
        clear_session_cookies(&shared.config, effects);
        return Err(AuthError::unauthorized());
    };
    run_gates(shared, within, request, effects, &view, usage).await?;
    Ok(view)
}

async fn run_gates<D: Adapter>(
    shared: &Arc<Shared<D>>,
    within: Option<&Arc<D>>,
    request: &Arc<RequestInfo>,
    effects: &Arc<Mutex<Effects>>,
    view: &SessionView,
    usage: SessionUse,
) -> Result<(), AuthError> {
    for gate in &shared.session_gates {
        let ctx = Ctx::new(
            shared.clone(),
            within.cloned(),
            request.clone(),
            None,
            effects.clone(),
        );
        gate(ctx, view.clone(), usage).await?;
    }
    Ok(())
}

fn ephemeral<D>(shared: &Shared<D>, user_row: Row) -> Result<SessionView, AuthError> {
    let user = UserView::from_row(user_row).map_err(AuthError::internal)?;
    let now = OffsetDateTime::now_utc();
    let session = Session {
        id: "ephemeral".into(),
        token_hash: Hash::sha256(b""),
        user_id: user.id.clone(),
        expires_at: now + time::Duration::hours(1),
        ip_address: None,
        user_agent: None,
        created_at: now,
        updated_at: now,
    };
    let table = shared.schema.expect(Session::TABLE);
    let values = crate::query::full_row(table, session.encode()).map_err(AuthError::internal)?;
    Ok(SessionView {
        session,
        row: Row::new(table.clone(), values),
        user,
        token: None,
        ephemeral: true,
        from_cache: false,
    })
}
