//! Session lookup (cookie, cookie cache, resolvers), refresh, and the typed session the app sees.

use std::ops::Deref;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::adapter::{Adapter, Filter, Op, SessionWithUser, Update};
use crate::config::CoreConfig;
use crate::cookies::{self, SetCookie};
use crate::crypto::{Hash, Keys, SignPurpose, base64url, base64url_decode};
use crate::endpoint::{Ctx, Effects, RequestInfo, Resolved, Shared};
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
}

/// Serializes as the client JSON of the row, the `user` of `/get-session`.
impl Serialize for UserView {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_json().serialize(serializer)
    }
}

/// A session as endpoints and plugins see it.
#[derive(Clone, Debug)]
pub struct SessionView {
    pub session: Session,
    pub row: Row,
    pub user: UserView,
    /// The raw token, when the request carried it. Never stored.
    pub token: Option<String>,
    /// Created for this request only by a resolver (e.g. an API key); not in the database.
    pub ephemeral: bool,
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

#[derive(Serialize, Deserialize)]
struct CachePayload {
    s: Vec<Value>,
    u: Vec<Value>,
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
        for byte in column.name.bytes().chain(*b"|") {
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
    let payload = CachePayload {
        s: view.row.values().to_vec(),
        u: view.user.row.values().to_vec(),
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
    if payload.s.len() != session_table.columns.len() || payload.u.len() != user_table.columns.len()
    {
        return None;
    }
    let row = Row::new(session_table.clone(), payload.s);
    let user = UserView::from_row(Row::new(user_table.clone(), payload.u)).ok()?;
    let session = Session::decode(&row).ok()?;
    (session.expires_at > OffsetDateTime::now_utc()).then(|| SessionView {
        session,
        row,
        user,
        token: Some(token.to_owned()),
        ephemeral: false,
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
    }))
}

/// Extends the expiry at most once per `update_age`. The conditional update makes
/// concurrent requests extend it once.
async fn refresh<D: Adapter>(
    shared: &Shared<D>,
    db: &D,
    request: &RequestInfo,
    effects: &Mutex<Effects>,
    view: &mut SessionView,
) -> Result<(), AuthError> {
    let now = OffsetDateTime::now_utc();
    let config = &shared.config.session;
    if now - view.session.updated_at < config.update_age {
        return Ok(());
    }
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
            column: position("updated_at"),
            op: Op::Eq,
            value: Value::Timestamp(view.session.updated_at),
        },
    ]);
    let set = vec![
        (position("expires_at"), Value::Timestamp(expires_at)),
        (position("updated_at"), Value::Timestamp(now)),
    ];
    db.update(Update { table, filter, set }).await?;
    view.session.expires_at = expires_at;
    view.session.updated_at = now;
    view.row.set("expires_at", Value::Timestamp(expires_at));
    view.row.set("updated_at", Value::Timestamp(now));
    if let Some(token) = &view.token {
        let remember = cookies::read(&request.headers, &shared.config.cookie_name(DONT_REMEMBER))
            .and_then(|v| shared.keys.verify(SignPurpose::Cookie, v))
            .is_none();
        set_session_cookies(&shared.config, &shared.keys, effects, token, remember);
    }
    Ok(())
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
            .verify(SignPurpose::Cookie, raw)
            .map(str::to_owned)
        else {
            clear_session_cookies(&shared.config, effects);
            return Ok(None);
        };
        if let Some(view) = read_cache(shared, request, &token) {
            return Ok(Some(view));
        }
        let Some(mut view) = by_token(shared, db, &token).await? else {
            clear_session_cookies(&shared.config, effects);
            return Ok(None);
        };
        refresh(shared, db, request, effects, &mut view).await?;
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
                refresh(shared, db, request, effects, &mut view).await?;
                return Ok(Some(view));
            }
            Some(Resolved::User(user_id)) => {
                let Some(user_row) = Db::new(db, &shared.schema)
                    .find::<User>(User::ID.eq(&user_id))
                    .one_row()
                    .await?
                else {
                    return Ok(None);
                };
                return ephemeral(shared, user_row).map(Some);
            }
        }
    }
    Ok(None)
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
    })
}
