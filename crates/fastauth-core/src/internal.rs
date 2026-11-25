//! Core operations shared by core endpoints and plugins: users, accounts, sessions,
//! sign-in with gates, verification values, email.

use http::StatusCode;
use time::{Duration, OffsetDateTime};

use crate::adapter::{Adapter, DbError, Transaction};
use crate::crypto::{Hash, random_token};
use crate::endpoint::{Ctx, Gate, SignInAttempt};
use crate::error::{AuthError, codes};
use crate::events::{AccountLinked, SessionCreated, SessionRevoked, UserCreated};
use crate::mail::{AuthEmail, VerifyEmail};
use crate::model::Model;
use crate::models::{Account, Session, User, Verification};
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

pub(crate) fn url_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
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

    fn account_values(&self, user_id: &Id, account: NewAccount) -> Vec<(&'static str, Value)> {
        let keys = self.ctx.keys();
        let seal = |t: Option<String>| t.map(|t| keys.encrypt(t.as_bytes()));
        vec![
            ("id", self.ctx.new_id().into_value()),
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
        ]
    }

    /// Creates a user (and optionally its first account) in one transaction.
    /// Answers `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` (422) when the email is taken.
    pub async fn create_user(
        &self,
        user: NewUser,
        account: Option<NewAccount>,
    ) -> Result<UserView, AuthError> {
        let id = self.ctx.new_id();
        let mut values = vec![
            ("id", id.clone().into_value()),
            ("email", user.email.trim().to_lowercase().into_value()),
            ("email_verified", user.email_verified.into_value()),
            ("name", user.name.into_value()),
            ("image", user.image.into_value()),
        ];
        values.extend(user.extra);
        let tx = self.ctx.adapter().begin().await?;
        let db = self.ctx.db_on(&tx);
        let row = db.insert_row::<User>(values).await.map_err(user_exists)?;
        if let Some(account) = account {
            db.insert_row::<Account>(self.account_values(&id, account))
                .await?;
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
            .insert_row::<Account>(self.account_values(user_id, account))
            .await?;
        self.ctx.emit(AccountLinked {
            user_id: user_id.clone(),
            provider_id,
        });
        Account::decode(&row).map_err(AuthError::internal)
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

    /// Validates, hashes and stores a password, creating the credential account if needed.
    pub async fn set_password(&self, user_id: &Id, password: &str) -> Result<(), AuthError> {
        self.validate_new_password(password)?;
        let hash = self
            .ctx
            .passwords()
            .hash(password)
            .await
            .map_err(AuthError::internal)?;
        let updated = self
            .ctx
            .db()
            .update::<Account>(
                Account::USER_ID
                    .eq(user_id)
                    .and(Account::PROVIDER_ID.eq(Account::CREDENTIAL)),
            )
            .set(Account::PASSWORD_HASH, Some(hash.clone()))
            .exec()
            .await?;
        if updated == 0 {
            self.link_account(user_id, NewAccount::credential(hash))
                .await?;
        }
        Ok(())
    }

    /// Creates a session and sets its cookies. Skips sign-in gates; use `sign_in` for a
    /// sign-in, and this to finish one after a challenge.
    pub async fn create_session(
        &self,
        user_id: &Id,
        remember_me: bool,
    ) -> Result<SessionView, AuthError> {
        let now = self.ctx.now();
        let token = random_token();
        let session = Session {
            id: self.ctx.new_id(),
            token_hash: Hash::sha256(&token),
            user_id: user_id.clone(),
            expires_at: now + self.ctx.config().session.expires_in,
            ip_address: self.ctx.ip().map(str::to_owned),
            user_agent: self
                .ctx
                .user_agent()
                .map(|ua| ua.chars().take(512).collect()),
            created_at: now,
            updated_at: now,
        };
        let row = self
            .ctx
            .db()
            .insert_row::<Session>(session.encode())
            .await?;
        let user = self
            .find_user_by_id(user_id)
            .await?
            .ok_or_else(|| AuthError::internal("session for a missing user"))?;
        let config = self.ctx.config();
        set_session_cookies(
            config,
            self.ctx.keys(),
            &self.ctx.effects,
            &token,
            remember_me,
        );
        self.ctx.set_cookie(crate::cookies::SetCookie::delete(
            config.cookie_name(SESSION_DATA),
        ));
        self.ctx.emit(SessionCreated {
            session_id: session.id.clone(),
            user_id: user_id.clone(),
        });
        Ok(SessionView {
            session,
            row,
            user,
            token: Some(token),
            ephemeral: false,
        })
    }

    /// Runs every sign-in gate, then creates the session.
    pub async fn sign_in(
        &self,
        user: UserView,
        method: &'static str,
        remember_me: bool,
    ) -> Result<SignInResult, AuthError> {
        let attempt = SignInAttempt {
            user: user.clone(),
            method,
            remember_me,
        };
        for gate in &self.ctx.shared.gates {
            match gate(self.ctx.retype(), attempt.clone()).await? {
                Gate::Allow => {}
                Gate::Deny(err) => return Err(err),
                Gate::Challenge(body) => return Ok(SignInResult::Challenge(body)),
            }
        }
        Ok(SignInResult::SignedIn(Box::new(
            self.create_session(&user.id, remember_me).await?,
        )))
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

    /// Stores a single-use value and returns it. Only its hash is kept.
    pub async fn create_verification(
        &self,
        identifier: &str,
        ttl: Duration,
        data: Option<String>,
    ) -> Result<String, AuthError> {
        let token = random_token();
        let now = self.ctx.now();
        let verification = Verification {
            id: self.ctx.new_id(),
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
        self.ctx
            .db()
            .delete::<Verification>(Verification::IDENTIFIER.eq(identifier))
            .await?;
        let now = self.ctx.now();
        let verification = Verification {
            id: self.ctx.new_id(),
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

    pub async fn send_verification_email(
        &self,
        user: &UserView,
        callback_url: Option<&str>,
    ) -> Result<(), AuthError> {
        let ttl = self.ctx.config().email_verification.ttl;
        let token = self
            .create_verification(&format!("email-verification:{}", user.id), ttl, None)
            .await?;
        let mut url = format!(
            "{}/verify-email?token={token}",
            self.ctx.config().auth_url()
        );
        if let Some(callback) = callback_url {
            url.push_str(&format!("&callbackURL={}", url_encode(callback)));
        }
        self.send_email(AuthEmail::VerifyEmail(VerifyEmail {
            to: user.email.clone(),
            name: user.name.clone(),
            url,
            token,
        }))
        .await
    }
}
