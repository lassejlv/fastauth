//! Core operations shared by core endpoints and plugins: users, accounts, sessions,
//! sign-in with gates, verification values, email.

use std::any::Any;
use std::borrow::Cow;
use std::marker::PhantomData;

use http::StatusCode;
use time::{Duration, OffsetDateTime};

use crate::adapter::{Adapter, DbError, Queries, Transaction, Update};
use crate::crypto::{Hash, random_bytes, random_token};
use crate::endpoint::{Ctx, Gate, SignInAttempt};
use crate::error::{AuthError, codes};
use crate::events::{
    AccountLinked, EmailVerified, SessionCreated, SessionRevoked, UserClaimed, UserCreated,
};
use crate::mail::{AuthEmail, VerifyEmail};
use crate::model::{Col, Model, OnTable};
use crate::models::{Account, Session, User, Verification};
use crate::query::Db;
use crate::schema::Schema;
use crate::session::{
    SESSION_DATA, SessionView, UserView, clear_session_cookies, set_session_cookies,
};
use crate::value::{ColumnValue, Id, Value};

/// A user to create.
#[derive(Clone, Debug, Default)]
pub struct NewUser {
    pub email: String,
    pub name: String,
    pub image: Option<String>,
    pub email_verified: bool,
    /// App and plugin columns, already validated.
    pub extra: Vec<(&'static str, Value)>,
}

/// An account to create with a user or link to one.
#[derive(Clone, Debug, Default)]
pub struct NewAccount {
    pub provider_id: String,
    /// Defaults to the user id (what the credential account uses).
    pub account_id: Option<String>,
    pub password_hash: Option<String>,
    /// Plaintext; encrypted before it is stored.
    pub access_token: Option<String>,
    /// Plaintext; encrypted before it is stored.
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<OffsetDateTime>,
    pub refresh_token_expires_at: Option<OffsetDateTime>,
    pub scope: Option<String>,
}

/// What [`Internal::create_session_with`] stores beyond a default session: a different expiry
/// and plugin columns, written in the same insert.
#[derive(Clone, Debug, Default)]
pub struct NewSession {
    expires_at: Option<OffsetDateTime>,
    values: Vec<(&'static str, Value)>,
}

impl NewSession {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the expiry `remember_me` and the session config give.
    pub fn expires_at(mut self, expires_at: OffsetDateTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Sets a plugin's or the app's session column.
    pub fn set<O: OnTable<Table = Session>, T: ColumnValue>(
        mut self,
        column: Col<O, T>,
        value: impl Into<T>,
    ) -> Self {
        self.values.push((column.name(), value.into().into_value()));
        self
    }
}

/// How long a `rememberMe: false` session lives at most, as in Better Auth.
const DONT_REMEMBER_LIFETIME: Duration = Duration::days(1);

impl NewAccount {
    pub fn credential(password_hash: String) -> Self {
        Self {
            provider_id: Account::CREDENTIAL.into(),
            password_hash: Some(password_hash),
            ..Self::default()
        }
    }

    pub fn oauth(provider_id: impl Into<String>, account_id: impl Into<String>) -> Self {
        Self {
            provider_id: provider_id.into(),
            account_id: Some(account_id.into()),
            ..Self::default()
        }
    }
}

/// Which user write [`Internal::user_fields`] reads client input for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserInput {
    /// A client creating their own user: `/sign-up/email`, or an email code that signs up.
    SignUp,
    /// The server creating a user (`auth.api().create_user(..)`).
    Create,
    /// `/update-user`, for the signed-in user.
    Update,
}

#[derive(Clone, Debug)]
pub enum SignInResult {
    SignedIn(Box<SessionView>),
    /// A gate wants more (e.g. a TOTP code). Respond with this JSON; no session exists.
    Challenge(serde_json::Value),
}

fn user_exists(err: DbError) -> AuthError {
    match err {
        DbError::UniqueViolation { ref table, .. } if table == User::TABLE => AuthError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            codes::USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL,
            "user already exists, use another email",
        ),
        other => other.into(),
    }
}

fn account_linked(err: DbError) -> AuthError {
    match err {
        DbError::UniqueViolation {
            ref table,
            column: None,
        } if table == Account::TABLE => AuthError::new(
            StatusCode::CONFLICT,
            codes::SOCIAL_ACCOUNT_ALREADY_LINKED,
            "social account already linked",
        ),
        other => other.into(),
    }
}

/// The cookie that marks the browser which set or proved an unverified user's password.
const PENDING_VERIFICATION: &str = "pending_verification";

/// A fresh random security stamp.
fn new_security_stamp() -> i64 {
    i64::from_le_bytes(random_bytes::<8>())
}

pub(crate) fn url_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// A sign-in, link or session-authorised write that started before proof of the email
/// claimed the user.
fn claimed_meanwhile() -> AuthError {
    AuthError::new(
        StatusCode::UNAUTHORIZED,
        codes::UNAUTHORIZED,
        "the account changed meanwhile; sign in again",
    )
}

/// What a claim cleanup registered with
/// [`PluginBuilder::on_claim`](crate::plugin::PluginBuilder::on_claim) gets: the claimed
/// user and the claim's transaction. Every query on [`db`](Self::db) commits or rolls back
/// with the claim.
pub struct Claim<'a, D> {
    user_id: &'a Id,
    tx: &'a (dyn Any + Send + Sync),
    schema: &'a Schema,
    _adapter: PhantomData<fn() -> D>,
}

impl<'a, D: Adapter> Claim<'a, D> {
    /// The user that was claimed. Its email is verified now.
    pub fn user_id(&self) -> &'a Id {
        self.user_id
    }

    /// Typed queries inside the claim's transaction.
    pub fn db(&self) -> Db<'a, D::Tx> {
        let tx = self
            .tx
            .downcast_ref::<D::Tx>()
            .expect("a claim runs in its adapter's transaction");
        Db::new(tx, self.schema)
    }
}

impl<D> std::fmt::Debug for Claim<'_, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Claim")
            .field("user_id", self.user_id)
            .finish_non_exhaustive()
    }
}

/// The verification identifiers core keeps per user, which a claim retires.
fn user_verification_identifiers(user_id: &Id) -> [String; 2] {
    [
        format!("email-verification:{user_id}"),
        format!("reset-password:{user_id}"),
    ]
}

/// What a token bound to a user carries: the user's security stamp and email when it was
/// minted, so a claim or a change of email retires it.
fn user_binding(user: &UserView) -> String {
    format!("{}:{}", user.security_stamp(), user.email)
}

pub struct Internal<'a, D, A> {
    ctx: &'a Ctx<D, A>,
}

impl<'a, D: Adapter, A> Internal<'a, D, A> {
    pub(crate) fn new(ctx: &'a Ctx<D, A>) -> Self {
        Self { ctx }
    }

    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<UserView>, AuthError> {
        let row = self
            .ctx
            .db()
            .find::<User>(User::EMAIL.eq(email.trim().to_lowercase()))
            .one_row()
            .await?;
        row.map(UserView::from_row)
            .transpose()
            .map_err(AuthError::internal)
    }

    pub async fn find_user_by_id(&self, id: &Id) -> Result<Option<UserView>, AuthError> {
        let row = self
            .ctx
            .db()
            .find::<User>(User::ID.eq(id))
            .one_row()
            .await?;
        row.map(UserView::from_row)
            .transpose()
            .map_err(AuthError::internal)
    }

    fn account_values(
        &self,
        user_id: &Id,
        account: NewAccount,
    ) -> Result<Vec<(&'static str, Value)>, AuthError> {
        let keys = self.ctx.keys();
        let seal = |t: Option<String>| t.map(|t| keys.encrypt(t.as_bytes()));
        Ok(vec![
            ("id", self.ctx.new_id()?.into_value()),
            ("user_id", user_id.clone().into_value()),
            ("provider_id", account.provider_id.into_value()),
            (
                "account_id",
                account
                    .account_id
                    .unwrap_or_else(|| user_id.to_string())
                    .into_value(),
            ),
            ("password_hash", account.password_hash.into_value()),
            ("access_token", seal(account.access_token).into_value()),
            ("refresh_token", seal(account.refresh_token).into_value()),
            ("id_token", account.id_token.into_value()),
            (
                "access_token_expires_at",
                account.access_token_expires_at.into_value(),
            ),
            (
                "refresh_token_expires_at",
                account.refresh_token_expires_at.into_value(),
            ),
            ("scope", account.scope.into_value()),
        ])
    }

    /// Creates a user (and optionally its first account) in one transaction.
    /// Answers `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` (422) when the email is taken.
    pub async fn create_user(
        &self,
        user: NewUser,
        account: Option<NewAccount>,
    ) -> Result<UserView, AuthError> {
        let id = self.ctx.new_id()?;
        let mut values = vec![
            ("id", id.clone().into_value()),
            ("email", user.email.trim().to_lowercase().into_value()),
            ("email_verified", user.email_verified.into_value()),
            ("name", user.name.into_value()),
            ("image", user.image.into_value()),
        ];
        values.extend(user.extra);
        let account = account
            .map(|account| self.account_values(&id, account))
            .transpose()?;
        let tx = self.ctx.adapter().begin().await?;
        let db = self.ctx.db_on(&tx);
        let row = db.insert_row::<User>(values).await.map_err(user_exists)?;
        if let Some(account) = account {
            db.insert_row::<Account>(account)
                .await
                .map_err(account_linked)?;
        }
        tx.commit().await?;
        let view = UserView::from_row(row).map_err(AuthError::internal)?;
        self.ctx.emit(UserCreated {
            user_id: view.id.clone(),
            email: view.email.clone(),
        });
        Ok(view)
    }

    pub async fn link_account(
        &self,
        user_id: &Id,
        account: NewAccount,
    ) -> Result<Account, AuthError> {
        let provider_id = account.provider_id.clone();
        let row = self
            .ctx
            .db()
            .insert_row::<Account>(self.account_values(user_id, account)?)
            .await
            .map_err(account_linked)?;
        self.ctx.emit(AccountLinked {
            user_id: user_id.clone(),
            provider_id,
        });
        Account::decode(&row).map_err(AuthError::internal)
    }

    /// Links an account like [`link_account`](Self::link_account), unless proof of the email
    /// claimed the user after `user` was read: then nothing is linked and the call answers 401.
    /// For links that a session or an earlier request started, such as linking a social
    /// account, so a link the previous holder started can't land on a claimed user. The insert
    /// runs under [`lock_user_unless_claimed`](Self::lock_user_unless_claimed).
    pub async fn link_account_unless_claimed(
        &self,
        user: &UserView,
        account: NewAccount,
    ) -> Result<Account, AuthError> {
        let provider_id = account.provider_id.clone();
        let values = self.account_values(&user.id, account)?;
        let tx = self.lock_user_unless_claimed(user).await?;
        let row = self
            .ctx
            .db_on(&tx)
            .insert_row::<Account>(values)
            .await
            .map_err(account_linked)?;
        tx.commit().await?;
        self.ctx.emit(AccountLinked {
            user_id: user.id.clone(),
            provider_id,
        });
        Account::decode(&row).map_err(AuthError::internal)
    }

    /// Begins a transaction that holds `user`'s row locked, for a write that a session or an
    /// earlier read of `user` authorised: a password, a passkey, an API key, a two-factor
    /// enrollment, a linked account, a new email or profile fields. When proof of the email
    /// claimed the user since `user` was read (its security stamp moved), the transaction is
    /// rolled back and the call answers 401, so the write can't land on the claimed user.
    ///
    /// Make the write through [`Ctx::db_on`] on the transaction and commit it; dropping it
    /// rolls back. The lock is the transaction's first statement, as it is in a claim, which
    /// locks the user row before it deletes anything: the two serialise, and with the user row
    /// always first they can't deadlock. Hash passwords and send mail before calling this, not
    /// while holding the lock.
    pub async fn lock_user_unless_claimed(&self, user: &UserView) -> Result<D::Tx, AuthError> {
        let tx = self.ctx.adapter().begin().await?;
        match self
            .stamp_holds_on(&tx, &user.id, user.security_stamp())
            .await
        {
            Ok(true) => Ok(tx),
            Ok(false) => {
                tx.rollback().await?;
                Err(claimed_meanwhile())
            }
            Err(err) => {
                let _ = tx.rollback().await;
                Err(err)
            }
        }
    }

    /// Whether `user_id`'s security stamp still is `stamp`. A locking no-op write, so it waits
    /// for a claim in progress and then sees its stamp: anything inserted before this check
    /// and after a claim began is either deleted by the claim or refused here.
    async fn stamp_holds(&self, user_id: &Id, stamp: i64) -> Result<bool, AuthError> {
        self.stamp_holds_on(self.ctx.adapter(), user_id, stamp)
            .await
    }

    /// [`stamp_holds`](Self::stamp_holds) on `db`, a transaction that then keeps the user
    /// row locked until it ends.
    async fn stamp_holds_on<Q: Queries>(
        &self,
        db: &Q,
        user_id: &Id,
        stamp: i64,
    ) -> Result<bool, AuthError> {
        let table = self.ctx.schema().expect(User::TABLE);
        let filter = User::ID
            .eq(user_id)
            .and(User::SECURITY_STAMP.eq(stamp))
            .resolve(table)?;
        let column = table
            .position(User::SECURITY_STAMP.name())
            .ok_or_else(|| AuthError::internal("user.security_stamp missing"))?;
        let matched = db
            .update(Update {
                table,
                filter,
                set: vec![(column, Value::Int(stamp))],
            })
            .await?;
        Ok(matched == 1)
    }

    pub async fn find_account(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> Result<Option<Account>, AuthError> {
        let filter = Account::PROVIDER_ID
            .eq(provider_id)
            .and(Account::ACCOUNT_ID.eq(account_id));
        Ok(self.ctx.db().find::<Account>(filter).one().await?)
    }

    pub async fn credential_account(&self, user_id: &Id) -> Result<Option<Account>, AuthError> {
        let filter = Account::USER_ID
            .eq(user_id)
            .and(Account::PROVIDER_ID.eq(Account::CREDENTIAL));
        Ok(self.ctx.db().find::<Account>(filter).one().await?)
    }

    /// The app and plugin columns in `extra` (a body's extra camelCase keys), after every
    /// [`prepare_user_input`](crate::plugin::PluginBuilder::prepare_user_input) hook, parsed
    /// like [`user_input_fields`](crate::routes::user_input_fields). Creating a user needs every
    /// required column; an update doesn't.
    pub async fn user_fields(
        &self,
        extra: &serde_json::Map<String, serde_json::Value>,
        input: UserInput,
    ) -> Result<Vec<(&'static str, Value)>, AuthError> {
        let mut extra = extra.clone();
        for hook in &self.ctx.shared.user_input_hooks {
            extra = hook(self.ctx.retype(), extra, input).await?;
        }
        crate::routes::user_input_fields(self.ctx, &extra, input != UserInput::Update)
    }

    /// Checks a new password against the configured length limits and policy.
    pub fn validate_new_password(&self, password: &str) -> Result<(), AuthError> {
        let Some(config) = &self.ctx.config().email_password else {
            return Ok(());
        };
        let length = password.chars().count();
        if length < config.min_password_length {
            return Err(AuthError::bad_request(
                codes::PASSWORD_TOO_SHORT,
                "password is too short",
            ));
        }
        if length > config.max_password_length {
            return Err(AuthError::bad_request(
                codes::PASSWORD_TOO_LONG,
                "password is too long",
            ));
        }
        if config
            .password_policy
            .as_ref()
            .is_some_and(|policy| !policy(password))
        {
            return Err(AuthError::bad_request(
                codes::PASSWORD_TOO_WEAK,
                "password is too weak",
            ));
        }
        Ok(())
    }

    /// Validates, hashes and stores `user`'s password, creating the credential account if
    /// needed. Pass the user as the request authorised it (the session's user, or the user a
    /// sign-in or a token was read for): the write runs under
    /// [`lock_user_unless_claimed`](Self::lock_user_unless_claimed), so when proof of the email
    /// claimed the user since, nothing is stored and the call answers 401.
    pub async fn set_password(&self, user: &UserView, password: &str) -> Result<(), AuthError> {
        self.validate_new_password(password)?;
        let hash = self
            .ctx
            .passwords()
            .hash(password)
            .await
            .map_err(AuthError::internal)?;
        let credential = || {
            Account::USER_ID
                .eq(&user.id)
                .and(Account::PROVIDER_ID.eq(Account::CREDENTIAL))
        };
        let tx = self.lock_user_unless_claimed(user).await?;
        let db = self.ctx.db_on(&tx);
        if db.find::<Account>(credential()).one().await?.is_some() {
            db.update::<Account>(credential())
                .set(Account::PASSWORD_HASH, Some(hash))
                .exec()
                .await?;
            tx.commit().await?;
            return Ok(());
        }
        db.insert_row::<Account>(self.account_values(&user.id, NewAccount::credential(hash))?)
            .await
            .map_err(account_linked)?;
        tx.commit().await?;
        self.ctx.emit(AccountLinked {
            user_id: user.id.clone(),
            provider_id: Account::CREDENTIAL.into(),
        });
        Ok(())
    }

    /// Creates a session and sets its cookies, running no sign-in gate at all. This is the
    /// low-level primitive: sign a user in with [`sign_in`](Self::sign_in), and finish a
    /// challenged sign-in with [`complete_sign_in`](Self::complete_sign_in). Finishing one
    /// with this would skip every other plugin's gates, so a banned user would get a session.
    ///
    /// A `remember_me: false` session lives one day at most and is never extended. The session
    /// hooks run before the response gets the session: when one fails, the session is deleted
    /// and the response sets none of its cookies.
    pub async fn create_session(
        &self,
        user_id: &Id,
        remember_me: bool,
    ) -> Result<SessionView, AuthError> {
        self.create_session_with(user_id, remember_me, NewSession::default())
            .await
    }

    /// [`create_session`](Self::create_session) for a user that a session or an earlier read
    /// authorised, such as a passkey registered from a session: when proof of the email
    /// claimed the user since `user` was read, the session is deleted again before anyone
    /// sees its token and the call answers 401. Runs no sign-in gate.
    pub async fn create_session_unless_claimed(
        &self,
        user: &UserView,
        remember_me: bool,
    ) -> Result<SessionView, AuthError> {
        self.insert_session(
            &user.id,
            Some(user.security_stamp()),
            remember_me,
            NewSession::default(),
        )
        .await
    }

    /// [`create_session`](Self::create_session) with an expiry or plugin columns of its own,
    /// stored in the one insert, so the session hooks and every later request see them.
    pub async fn create_session_with(
        &self,
        user_id: &Id,
        remember_me: bool,
        options: NewSession,
    ) -> Result<SessionView, AuthError> {
        self.insert_session(user_id, None, remember_me, options)
            .await
    }

    /// [`create_session_with`](Self::create_session_with), refused with 401 when proof of the
    /// email claimed the user since `stamp` was read: the session is deleted again before
    /// anyone sees its token.
    async fn insert_session(
        &self,
        user_id: &Id,
        stamp: Option<i64>,
        remember_me: bool,
        options: NewSession,
    ) -> Result<SessionView, AuthError> {
        let now = self.ctx.now();
        let token = random_token();
        let lifetime = match remember_me {
            true => self.ctx.config().session.expires_in,
            false => self
                .ctx
                .config()
                .session
                .expires_in
                .min(DONT_REMEMBER_LIFETIME),
        };
        let session = Session {
            id: self.ctx.new_id()?,
            token_hash: Hash::sha256(&token),
            user_id: user_id.clone(),
            expires_at: options.expires_at.unwrap_or(now + lifetime),
            ip_address: self.ctx.ip().map(str::to_owned),
            user_agent: self
                .ctx
                .user_agent()
                .map(|ua| ua.chars().take(512).collect()),
            created_at: now,
            updated_at: now,
        };
        let mut values = session.encode();
        values.extend(options.values);
        let row = self.ctx.db().insert_row::<Session>(values).await?;
        let session = Session::decode(&row).map_err(AuthError::internal)?;
        if let Some(stamp) = stamp
            && !self.stamp_holds(user_id, stamp).await?
        {
            self.ctx
                .db()
                .delete::<Session>(Session::ID.eq(&session.id))
                .await?;
            return Err(claimed_meanwhile());
        }
        let user = self
            .find_user_by_id(user_id)
            .await?
            .ok_or_else(|| AuthError::internal("session for a missing user"))?;
        let view = SessionView {
            session,
            row,
            user,
            token: Some(token.clone()),
            ephemeral: false,
            from_cache: false,
        };
        let config = self.ctx.config();
        let before = self.ctx.effects.lock().unwrap().cookies.clone();
        set_session_cookies(
            config,
            self.ctx.keys(),
            &self.ctx.effects,
            &token,
            remember_me,
        );
        for hook in &self.ctx.shared.session_hooks {
            if let Err(err) = hook(self.ctx.retype(), view.clone()).await {
                self.ctx.effects.lock().unwrap().cookies = before;
                self.ctx
                    .db()
                    .delete::<Session>(Session::ID.eq(&view.session.id))
                    .await?;
                return Err(err);
            }
        }
        self.ctx.set_cookie(crate::cookies::SetCookie::delete(
            config.cookie_name(SESSION_DATA),
        ));
        self.ctx.emit(SessionCreated {
            session_id: view.session.id.clone(),
            user_id: user_id.clone(),
        });
        Ok(view)
    }

    /// The unexpired session `token` belongs to, with its user, without refreshing it.
    /// For plugins that hold session tokens of their own, such as one per signed-in account.
    pub async fn find_session_by_token(
        &self,
        token: &str,
    ) -> Result<Option<SessionView>, AuthError> {
        crate::session::by_token(&self.ctx.shared, self.ctx.adapter(), token).await
    }

    /// The request-only session a resolver's [`Resolved::User`](crate::endpoint::Resolved)
    /// gets for this user, after the session gates. `None` when the user doesn't exist; the
    /// gate's error when one refuses the user (a banned user, with the admin plugin). For
    /// plugins that act for a user without a session, such as an API key's owner.
    pub async fn ephemeral_session(&self, user_id: &Id) -> Result<Option<SessionView>, AuthError> {
        crate::session::for_user(
            &self.ctx.shared,
            self.ctx.within.as_ref(),
            &self.ctx.request,
            &self.ctx.effects,
            user_id,
        )
        .await
    }

    /// Makes `token` the request's session: sets the session cookie (for the configured
    /// lifetime, or for the browser session when `remember_me` is false) and drops the
    /// cookie cache, which belonged to the previous session.
    pub fn set_session_cookies(&self, token: &str, remember_me: bool) {
        let config = self.ctx.config();
        set_session_cookies(
            config,
            self.ctx.keys(),
            &self.ctx.effects,
            token,
            remember_me,
        );
        self.ctx.set_cookie(crate::cookies::SetCookie::delete(
            config.cookie_name(SESSION_DATA),
        ));
    }

    /// Runs every sign-in gate in registration order, then creates the session. The first
    /// gate that denies or challenges ends the sign-in without a session.
    ///
    /// Read `user` before checking the credential it signs in with: when proof of the email
    /// claims the user after `user` was read, the sign-in answers 401 instead of a session
    /// (the security stamp changed), so a password check in flight during a claim can't keep
    /// the previous holder signed in.
    pub async fn sign_in(
        &self,
        user: UserView,
        method: impl Into<Cow<'static, str>>,
        remember_me: bool,
    ) -> Result<SignInResult, AuthError> {
        self.run_gates(user, method.into(), remember_me, None).await
    }

    /// Finishes a sign-in that a gate of plugin `challenger` answered with
    /// [`Gate::Challenge`], once the user has met the challenge (e.g. a correct TOTP code).
    /// Pass the plugin's own id (`TwoFactor::ID`, or `"app"` for a gate the app registered)
    /// and the method the sign-in started with.
    ///
    /// Runs every gate except `challenger`'s, in registration order, whether they come before
    /// or after it, then creates the session. A remaining gate can still deny, which returns
    /// its error with no session. It can also challenge, which returns
    /// [`SignInResult::Challenge`] with no session; answer with its body. That gate's plugin
    /// finishes the sign-in with its own `complete_sign_in`, which runs `challenger`'s gates
    /// again, so two gates that both challenge the same user keep challenging each other.
    ///
    /// A 500 when no gate belongs to `challenger`: a wrong id would run the challenger's
    /// own gate again and challenge forever.
    pub async fn complete_sign_in(
        &self,
        challenger: &str,
        user: UserView,
        method: impl Into<Cow<'static, str>>,
        remember_me: bool,
    ) -> Result<SignInResult, AuthError> {
        if !self
            .ctx
            .shared
            .gates
            .iter()
            .any(|gate| gate.owner == challenger)
        {
            return Err(AuthError::internal(format!(
                "complete_sign_in: no sign-in gate belongs to `{challenger}`"
            )));
        }
        self.run_gates(user, method.into(), remember_me, Some(challenger))
            .await
    }

    async fn run_gates(
        &self,
        user: UserView,
        method: Cow<'static, str>,
        remember_me: bool,
        skip: Option<&str>,
    ) -> Result<SignInResult, AuthError> {
        let attempt = SignInAttempt {
            user: user.clone(),
            method,
            remember_me,
        };
        for owned in &self.ctx.shared.gates {
            if skip == Some(owned.owner) {
                continue;
            }
            match (owned.gate)(self.ctx.retype(), attempt.clone()).await? {
                Gate::Allow => {}
                Gate::Deny(err) => return Err(err),
                Gate::Challenge(body) => return Ok(SignInResult::Challenge(body)),
            }
        }
        Ok(SignInResult::SignedIn(Box::new(
            self.insert_session(
                &user.id,
                Some(user.security_stamp()),
                remember_me,
                NewSession::default(),
            )
            .await?,
        )))
    }

    /// Makes whoever just proved control of `user`'s email its only owner. Every path that
    /// proves an email calls this: a magic link, an email code, a password-reset link, a
    /// verified social profile, and a verification link that came without the password (see
    /// [`prove_email`](Self::prove_email)).
    ///
    /// For a user whose email isn't verified, one transaction changes the security stamp,
    /// marks the email verified, deletes every account (password and OAuth links), session and
    /// core token (verification and reset links) the user collected before the proof, runs
    /// every plugin's [`on_claim`](crate::plugin::PluginBuilder::on_claim) cleanup (passkeys,
    /// API keys, two-factor), and links `link`, the account the proof came with, if any.
    /// A failing cleanup rolls the whole claim back and fails the call. Sign-ins and links
    /// that started before the claim can't finish after it, because the stamp changed.
    /// [`UserClaimed`] and [`EmailVerified`] are emitted after the commit, for
    /// notifications only.
    ///
    /// A verified user comes back unchanged, with `link` linked: whoever proved the email
    /// before already owns it.
    pub async fn claim_user(
        &self,
        user: UserView,
        link: Option<NewAccount>,
    ) -> Result<UserView, AuthError> {
        let linked_provider = link.as_ref().map(|account| account.provider_id.clone());
        let link = link
            .map(|account| self.account_values(&user.id, account))
            .transpose()?;
        if !user.email_verified {
            let tx = self.ctx.adapter().begin().await?;
            match self.claim_in(&tx, &user.id, link.clone()).await {
                Ok(Some(revoked)) => {
                    tx.commit().await?;
                    if revoked > 0 {
                        self.ctx.emit(SessionRevoked {
                            user_id: user.id.clone(),
                            session_id: None,
                        });
                    }
                    self.ctx.emit(EmailVerified {
                        user_id: user.id.clone(),
                    });
                    self.ctx.emit(UserClaimed {
                        user_id: user.id.clone(),
                    });
                    if let Some(provider_id) = linked_provider {
                        self.ctx.emit(AccountLinked {
                            user_id: user.id.clone(),
                            provider_id,
                        });
                    }
                    return self
                        .find_user_by_id(&user.id)
                        .await?
                        .ok_or_else(|| AuthError::internal("user deleted while claiming it"));
                }
                // Verified meanwhile, by a proof that claimed it first.
                Ok(None) => tx.rollback().await?,
                Err(err) => {
                    let _ = tx.rollback().await;
                    return Err(err);
                }
            }
        }
        if let Some(values) = link {
            self.ctx
                .db()
                .insert_row::<Account>(values)
                .await
                .map_err(account_linked)?;
            if let Some(provider_id) = linked_provider {
                self.ctx.emit(AccountLinked {
                    user_id: user.id.clone(),
                    provider_id,
                });
            }
        }
        self.find_user_by_id(&user.id)
            .await?
            .ok_or_else(|| AuthError::internal("user deleted while claiming it"))
    }

    /// [`claim_user`](Self::claim_user) without an account to link, the 0.5 name.
    #[deprecated(since = "0.6.0", note = "use `claim_user(user, None)`")]
    pub async fn claim_unverified_user(&self, user: UserView) -> Result<UserView, AuthError> {
        self.claim_user(user, None).await
    }

    /// The claim's statements, in `tx`. The user row is written first, so a concurrent
    /// [`stamp_holds`](Self::stamp_holds) waits for the claim. `None` when the user was
    /// verified meanwhile; otherwise how many sessions were revoked.
    async fn claim_in(
        &self,
        tx: &D::Tx,
        user_id: &Id,
        link: Option<Vec<(&'static str, Value)>>,
    ) -> Result<Option<u64>, AuthError> {
        let db = self.ctx.db_on(tx);
        let claimed = db
            .update::<User>(User::ID.eq(user_id).and(User::EMAIL_VERIFIED.eq(false)))
            .set(User::SECURITY_STAMP, new_security_stamp())
            .set(User::EMAIL_VERIFIED, true)
            .exec()
            .await?;
        if claimed == 0 {
            return Ok(None);
        }
        db.delete::<Account>(Account::USER_ID.eq(user_id)).await?;
        let revoked = db.delete::<Session>(Session::USER_ID.eq(user_id)).await?;
        db.delete::<Verification>(
            Verification::IDENTIFIER.in_(user_verification_identifiers(user_id)),
        )
        .await?;
        for cleanup in &self.ctx.shared.claim_hooks {
            cleanup(Claim {
                user_id,
                tx,
                schema: self.ctx.schema(),
                _adapter: PhantomData,
            })
            .await?;
        }
        if let Some(values) = link {
            db.insert_row::<Account>(values)
                .await
                .map_err(account_linked)?;
        }
        Ok(Some(revoked))
    }

    /// The request proved control of `user`'s email with a verification link or code. When
    /// it also proves it holds the user's password (it carries the user's session, or the
    /// signed cookie that sign-up or a refused unverified sign-in left in the browser that
    /// knew the password), the email is marked verified and nothing else changes. Otherwise
    /// whoever set the password may not own the mailbox, so the user is claimed
    /// ([`claim_user`](Self::claim_user)): the password and everything else from before the
    /// proof is gone, and the owner signs in by link or sets a password with a reset.
    pub async fn prove_email(&self, user: UserView) -> Result<UserView, AuthError> {
        if user.email_verified {
            return Ok(user);
        }
        if !self.holds_credentials_of(&user).await? {
            return self.claim_user(user, None).await;
        }
        self.ctx
            .db()
            .update::<User>(User::ID.eq(&user.id))
            .set(User::EMAIL_VERIFIED, true)
            .exec()
            .await?;
        self.ctx.emit(EmailVerified {
            user_id: user.id.clone(),
        });
        self.find_user_by_id(&user.id)
            .await?
            .ok_or_else(|| AuthError::internal("user deleted while verifying it"))
    }

    /// Whether this request comes from the browser that holds `user`'s credentials: it
    /// carries a live session of the user, or the signed [`PENDING_VERIFICATION`] cookie
    /// for the user's current security stamp.
    async fn holds_credentials_of(&self, user: &UserView) -> Result<bool, AuthError> {
        let binding = self.ctx.signed_cookie(PENDING_VERIFICATION);
        if binding.is_some() {
            self.ctx.delete_cookie(PENDING_VERIFICATION);
        }
        if binding.as_deref() == Some(user_binding(user).as_str()) {
            return Ok(true);
        }
        let Some(token) = self.ctx.signed_token_cookie(crate::session::SESSION_TOKEN) else {
            return Ok(false);
        };
        Ok(self
            .find_session_by_token(&token)
            .await?
            .is_some_and(|session| !session.ephemeral && session.user.id == user.id))
    }

    /// Leaves the signed cookie [`prove_email`](Self::prove_email) accepts as proof that this
    /// browser knows `user`'s password, for as long as a verification link lives. Sign-up and
    /// a sign-in refused for an unverified email call this.
    pub fn remember_password_holder(&self, user: &UserView) {
        self.ctx.set_signed_cookie(
            PENDING_VERIFICATION,
            &user_binding(user),
            Some(self.ctx.config().email_verification.ttl),
        );
    }

    /// Stores a single-use token for `user` under `{purpose}:{user_id}`, bound to the user's
    /// security stamp and email: [`consume_user_verification`](Self::consume_user_verification)
    /// refuses it once a claim or a change of email happened since. For links mailed to the
    /// user, such as email verification and password reset.
    pub async fn create_user_verification(
        &self,
        purpose: &str,
        user: &UserView,
        ttl: Duration,
    ) -> Result<String, AuthError> {
        self.create_verification(
            &format!("{purpose}:{}", user.id),
            ttl,
            Some(user_binding(user)),
        )
        .await
    }

    /// Consumes a token from [`create_user_verification`](Self::create_user_verification) for
    /// `purpose` and answers its user. `None` when the token is unknown, expired, for another
    /// purpose, or minted before the user was claimed or changed email.
    pub async fn consume_user_verification(
        &self,
        purpose: &str,
        token: &str,
    ) -> Result<Option<UserView>, AuthError> {
        let Some(verification) = self.consume_verification(token).await? else {
            return Ok(None);
        };
        let Some(user_id) = verification
            .identifier
            .strip_prefix(purpose)
            .and_then(|rest| rest.strip_prefix(':'))
        else {
            return Ok(None);
        };
        let Some(user) = self.find_user_by_id(&Id::from(user_id)).await? else {
            return Ok(None);
        };
        let bound = verification.data.as_deref() == Some(user_binding(&user).as_str());
        Ok(bound.then_some(user))
    }

    pub async fn revoke_session(&self, user_id: &Id, session_id: &Id) -> Result<bool, AuthError> {
        let deleted = self
            .ctx
            .db()
            .delete::<Session>(Session::ID.eq(session_id).and(Session::USER_ID.eq(user_id)))
            .await?;
        if deleted > 0 {
            self.ctx.emit(SessionRevoked {
                user_id: user_id.clone(),
                session_id: Some(session_id.clone()),
            });
        }
        Ok(deleted > 0)
    }

    /// Deletes every session of a user, except `keep` when given.
    pub async fn revoke_user_sessions(
        &self,
        user_id: &Id,
        keep: Option<&Id>,
    ) -> Result<u64, AuthError> {
        let mut filter = Session::USER_ID.eq(user_id);
        if let Some(keep) = keep {
            filter = filter.and(Session::ID.ne(keep));
        }
        let deleted = self.ctx.db().delete::<Session>(filter).await?;
        if deleted > 0 {
            self.ctx.emit(SessionRevoked {
                user_id: user_id.clone(),
                session_id: None,
            });
        }
        Ok(deleted)
    }

    pub fn clear_session_cookies(&self) {
        clear_session_cookies(self.ctx.config(), &self.ctx.effects);
    }

    /// Deletes every expired verification, as Better Auth does on lookup. Runs before each
    /// new one is stored, so rows anyone can mint (OAuth states, passkey challenges, magic
    /// links) don't pile up.
    async fn purge_expired_verifications(&self) -> Result<(), AuthError> {
        self.ctx
            .db()
            .delete::<Verification>(Verification::EXPIRES_AT.lt(self.ctx.now()))
            .await?;
        Ok(())
    }

    /// Stores a single-use value and returns it. Only its hash is kept.
    pub async fn create_verification(
        &self,
        identifier: &str,
        ttl: Duration,
        data: Option<String>,
    ) -> Result<String, AuthError> {
        self.purge_expired_verifications().await?;
        let token = random_token();
        let now = self.ctx.now();
        let verification = Verification {
            id: self.ctx.new_id()?,
            identifier: identifier.to_owned(),
            value_hash: Hash::sha256(&token),
            data,
            expires_at: now + ttl,
            created_at: now,
            updated_at: now,
        };
        self.ctx.db().insert(&verification).await?;
        Ok(token)
    }

    /// Stores a caller-chosen value (e.g. a 6-digit OTP) under `identifier`, replacing older ones.
    pub async fn store_verification_value(
        &self,
        identifier: &str,
        value: &str,
        ttl: Duration,
        data: Option<String>,
    ) -> Result<(), AuthError> {
        self.purge_expired_verifications().await?;
        self.ctx
            .db()
            .delete::<Verification>(Verification::IDENTIFIER.eq(identifier))
            .await?;
        let now = self.ctx.now();
        let verification = Verification {
            id: self.ctx.new_id()?,
            identifier: identifier.to_owned(),
            value_hash: Hash::sha256(format!("{identifier}:{value}")),
            data,
            expires_at: now + ttl,
            created_at: now,
            updated_at: now,
        };
        self.ctx.db().insert(&verification).await?;
        Ok(())
    }

    /// Consumes a value stored with `store_verification_value`.
    pub async fn consume_verification_value(
        &self,
        identifier: &str,
        value: &str,
    ) -> Result<Option<Verification>, AuthError> {
        self.consume_hash(Hash::sha256(format!("{identifier}:{value}")))
            .await
    }

    /// The unexpired verification for `token`, without consuming it.
    pub async fn find_verification(&self, token: &str) -> Result<Option<Verification>, AuthError> {
        let found = self
            .ctx
            .db()
            .find::<Verification>(Verification::VALUE_HASH.eq(Hash::sha256(token)))
            .one()
            .await?;
        Ok(found.filter(|v| v.expires_at > self.ctx.now()))
    }

    /// Finds and deletes the verification for `token`. `None` if unknown or expired.
    pub async fn consume_verification(
        &self,
        token: &str,
    ) -> Result<Option<Verification>, AuthError> {
        self.consume_hash(Hash::sha256(token)).await
    }

    async fn consume_hash(&self, hash: Hash) -> Result<Option<Verification>, AuthError> {
        let Some(found) = self
            .ctx
            .db()
            .find::<Verification>(Verification::VALUE_HASH.eq(hash))
            .one()
            .await?
        else {
            return Ok(None);
        };
        let deleted = self
            .ctx
            .db()
            .delete::<Verification>(Verification::ID.eq(&found.id))
            .await?;
        Ok((deleted == 1 && found.expires_at > self.ctx.now()).then_some(found))
    }

    /// Whether a mailer is configured, so `send_email` can succeed.
    pub fn can_send_email(&self) -> bool {
        self.ctx.mailer().is_some()
    }

    pub async fn send_email(&self, email: AuthEmail) -> Result<(), AuthError> {
        let Some(mailer) = self.ctx.mailer() else {
            return Err(AuthError::internal(
                "an email needs sending but no mailer is configured",
            ));
        };
        mailer.send(email).await.map_err(AuthError::internal)
    }

    /// Sends `email` without waiting for the mailer, so the route answers in the same time
    /// whether or not it sent anything. Use it where sending depends on whether an account
    /// exists. A failed send is logged (`tracing::error!`), not returned.
    pub async fn send_email_in_background(&self, email: AuthEmail) -> Result<(), AuthError> {
        let Some(mailer) = self.ctx.mailer() else {
            return Err(AuthError::internal(
                "an email needs sending but no mailer is configured",
            ));
        };
        crate::mail::send_in_background(mailer.clone(), email).await;
        Ok(())
    }

    /// The database work of creating and looking up a verification token, for the branch
    /// of a route that sends nothing, so both branches take about as long.
    pub async fn simulate_verification(&self) -> Result<(), AuthError> {
        let token = random_token();
        self.find_verification(&token).await?;
        Ok(())
    }

    /// Creates a verification token and emails the link in the background (see
    /// `send_email_in_background`).
    pub async fn send_verification_email(
        &self,
        user: &UserView,
        callback_url: Option<&str>,
    ) -> Result<(), AuthError> {
        let ttl = self.ctx.config().email_verification.ttl;
        let token = self
            .create_user_verification("email-verification", user, ttl)
            .await?;
        let mut url = format!(
            "{}/verify-email?token={token}",
            self.ctx.config().auth_url()
        );
        if let Some(callback) = callback_url {
            url.push_str(&format!("&callbackURL={}", url_encode(callback)));
        }
        self.send_email_in_background(AuthEmail::VerifyEmail(VerifyEmail {
            to: user.email.clone(),
            name: user.name.clone(),
            url,
            token,
        }))
        .await
    }
}
