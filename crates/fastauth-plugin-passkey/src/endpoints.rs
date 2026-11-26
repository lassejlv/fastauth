//! The `/passkey/*` endpoints.

use fastauth_core::crypto::base64url;
use fastauth_core::plugin_prelude::*;
use fastauth_core::routes::{Status, normalize_email};
use serde_json::{Map, Value as Json};
use webauthn_rs::prelude::{
    Credential, PublicKeyCredential, RegisterPublicKeyCredential, Uuid, WebauthnError,
};
use webauthn_rs_proto::{
    AllowCredentials, AuthenticatorAttachment, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions, ResidentKeyRequirement,
};

use crate::ceremony::{
    self, CHALLENGE_COOKIE, CHALLENGE_TTL, Challenge, IDENTIFIER, MULTI_DEVICE, SINGLE_DEVICE,
};
use crate::model::PasskeyRow;
use crate::{Passkey, PasskeyAdded, PasskeyDeleted, PasskeyError, PasskeySignUp, PasskeyUser};

/// A passkey as clients see it: Better Auth's row, camelCase, `credentialID` included.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyView {
    pub id: Id,
    pub name: Option<String>,
    pub public_key: String,
    pub user_id: Id,
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    pub counter: i64,
    pub device_type: String,
    pub backed_up: bool,
    pub transports: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub aaguid: Option<String>,
}

impl From<PasskeyRow> for PasskeyView {
    fn from(row: PasskeyRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            public_key: row.public_key,
            user_id: row.user_id,
            credential_id: row.credential_id,
            counter: row.counter,
            device_type: row.device_type,
            backed_up: row.backed_up,
            transports: row.transports,
            created_at: row.created_at,
            aaguid: row.aaguid,
        }
    }
}

/// Starts a ceremony: stores its state for `CHALLENGE_TTL` and names it in the signed cookie.
async fn store_challenge<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    challenge: &Challenge,
) -> Result<(), AuthError> {
    let data = serde_json::to_string(challenge).map_err(AuthError::internal)?;
    let token = ctx
        .internal()
        .create_verification(IDENTIFIER, CHALLENGE_TTL, Some(data))
        .await?;
    ctx.set_signed_cookie(CHALLENGE_COOKIE, &token, Some(CHALLENGE_TTL));
    Ok(())
}

/// Consumes the challenge the cookie names. Each one works once, whatever the outcome.
async fn take_challenge<D: Adapter, A>(ctx: &Ctx<D, A>) -> Result<Challenge, AuthError> {
    let token = ctx
        .signed_cookie(CHALLENGE_COOKIE)
        .ok_or(PasskeyError::ChallengeNotFound)?;
    ctx.delete_cookie(CHALLENGE_COOKIE);
    ctx.internal()
        .consume_verification(&token)
        .await?
        .filter(|v| v.identifier == IDENTIFIER)
        .and_then(|v| serde_json::from_str(v.data.as_deref()?).ok())
        .ok_or_else(|| PasskeyError::ChallengeNotFound.into())
}

async fn user_passkeys<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    user_id: &Id,
) -> Result<Vec<PasskeyRow>, AuthError> {
    Ok(ctx
        .db()
        .find::<PasskeyRow>(PasskeyRow::USER_ID.eq(user_id))
        .all()
        .await?)
}

/// The session registering a passkey: one younger than `fresh_age`, read again from the
/// database (`Ctx::sensitive_session`), so API-key and impersonation sessions can't register
/// passkeys. `None` when signed out, which only passkey-first sign-up accepts.
async fn registering_session<D: Adapter>(
    ctx: &Ctx<D, MaybeAuthenticated>,
) -> Result<Option<SessionView>, AuthError> {
    match ctx.session() {
        None => Ok(None),
        Some(session) if session.ephemeral || !ctx.config().is_fresh(&session.session) => {
            Err(AuthError::not_fresh())
        }
        Some(_) => ctx.sensitive_session().await.map(Some),
    }
}

/// Whom a registration adds the passkey to.
enum Registrant {
    /// The signed-in user.
    User(Id),
    /// A user passkey-first sign-up creates.
    SignUp(PasskeyUser),
}

/// Query of `/passkey/generate-register-options`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateRegisterOptionsInput {
    /// `platform` for this device's authenticator, `cross-platform` for a security key or
    /// phone.
    #[serde(default)]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    /// The account name the authenticator shows. Default: the user's email.
    #[serde(default)]
    pub name: Option<String>,
    /// Passkey-first sign-up's `context`, handed to the [`Passkey::sign_up`] resolver.
    /// Ignored for signed-in users.
    #[serde(default)]
    pub context: Option<String>,
}

/// `GET /passkey/generate-register-options`: the `PublicKeyCredentialCreationOptions` to
/// pass to `navigator.credentials.create()`. Needs a fresh session that may mint
/// credentials (see `registering_session`): `401` without one, `403 SESSION_NOT_FRESH`
/// with an old or ephemeral one. The user's passkeys are excluded, so an authenticator can't
/// register twice. Signed out, with [`Passkey::sign_up`] on, its resolver names the user
/// the passkey will create.
pub struct GenerateRegisterOptions(pub(crate) Arc<Passkey>);

impl<D: Adapter> Endpoint<D> for GenerateRegisterOptions {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/passkey/generate-register-options";
    type Access = MaybeAuthenticated;
    type Input = GenerateRegisterOptionsInput;
    type Output = PublicKeyCredentialCreationOptions;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: GenerateRegisterOptionsInput,
    ) -> Result<PublicKeyCredentialCreationOptions, AuthError> {
        let (account, exclude, pending) = match registering_session(&ctx).await? {
            Some(session) => {
                let user = session.user;
                let exclude = user_passkeys(&ctx, &user.id)
                    .await?
                    .iter()
                    .map(|row| {
                        Ok(PublicKeyCredentialDescriptor {
                            type_: "public-key".into(),
                            id: ceremony::credential_id(row)?,
                            transports: ceremony::transports(row.transports.as_deref()),
                        })
                    })
                    .collect::<Result<Vec<_>, AuthError>>()?;
                let account = if user.email.is_empty() {
                    user.id.to_string()
                } else {
                    user.email.clone()
                };
                (account, exclude, Registrant::User(user.id.clone()))
            }
            None => {
                let resolve = self.0.sign_up.as_ref().ok_or(AuthError::unauthorized())?;
                let user = resolve(PasskeySignUp {
                    context: input.context,
                    name: input.name.clone(),
                })
                .await?;
                let user = PasskeyUser {
                    email: normalize_email(&user.email)?,
                    ..user
                };
                (user.email.clone(), Vec::new(), Registrant::SignUp(user))
            }
        };
        let rp = self.0.relying_party(ctx.config())?;
        let user_name = input.name.as_deref().filter(|n| !n.is_empty());
        let (mut options, state) = rp
            .start_passkey_registration(
                Uuid::new_v4(),
                user_name.unwrap_or(&account),
                &account,
                Some(exclude.iter().map(|d| d.id.clone()).collect()),
            )
            .map_err(AuthError::internal)?;
        let options = &mut options.public_key;
        options.exclude_credentials = Some(exclude);
        if let Some(selection) = &mut options.authenticator_selection {
            selection.resident_key = Some(ResidentKeyRequirement::Preferred);
            selection.require_resident_key = false;
            selection.authenticator_attachment = input.authenticator_attachment;
        }
        let challenge = match pending {
            Registrant::SignUp(user) => Challenge::SignUp { user, state },
            Registrant::User(user_id) => Challenge::Registration {
                user_id: user_id.to_string(),
                state,
            },
        };
        store_challenge(&ctx, &challenge).await?;
        Ok(options.clone())
    }
}

/// Body of `/passkey/verify-registration`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRegistrationInput {
    /// The `navigator.credentials.create()` result as JSON (`RegistrationResponseJSON`).
    pub response: Json,
    /// A name for the passkey.
    #[serde(default)]
    pub name: Option<String>,
    /// Also start a new session, as Better Auth does.
    #[serde(default)]
    pub create_session: Option<bool>,
}

/// The new passkey; with `createSession`, also the new session and the user, or for a
/// passkey-first sign-up a sign-in gate's answer (`{"twoFactorRedirect": true}`) instead.
#[derive(Debug, Serialize)]
pub struct RegisterOutput {
    #[serde(flatten)]
    pub passkey: PasskeyView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<Map<String, Json>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<Map<String, Json>>,
    #[serde(flatten)]
    pub challenge: Option<Map<String, Json>>,
}

/// `POST /passkey/verify-registration`: verifies the authenticator's attestation against the
/// challenge from `generate-register-options` and stores the passkey. Needs the session
/// `generate-register-options` needed, the same user's. A passkey-first sign-up's
/// challenge only verifies signed out, and creates its user here.
pub struct VerifyRegistration(pub(crate) Arc<Passkey>);

impl<D: Adapter> Endpoint<D> for VerifyRegistration {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/passkey/verify-registration";
    type Access = MaybeAuthenticated;
    type Input = VerifyRegistrationInput;
    type Output = RegisterOutput;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: VerifyRegistrationInput,
    ) -> Result<RegisterOutput, AuthError> {
        let session = registering_session(&ctx).await?;
        if session.is_none() && self.0.sign_up.is_none() {
            return Err(AuthError::unauthorized());
        }
        let rp = self.0.relying_party(ctx.config())?;
        let (registrant, state) = match (take_challenge(&ctx).await?, session) {
            (Challenge::Registration { user_id, state }, Some(session)) => {
                let user_id = Id::from(user_id);
                if user_id != session.user.id {
                    return Err(PasskeyError::NotAllowed.into());
                }
                (Registrant::User(user_id), state)
            }
            (Challenge::SignUp { user, state }, None) => (Registrant::SignUp(user), state),
            (Challenge::Registration { .. }, None) => return Err(AuthError::unauthorized()),
            (Challenge::SignUp { .. }, Some(_)) => return Err(PasskeyError::NotAllowed.into()),
            (Challenge::Authentication { .. }, _) => {
                return Err(PasskeyError::ChallengeNotFound.into());
            }
        };
        let failed = PasskeyError::FailedToVerifyRegistration;
        let transports = input.response["response"]["transports"]
            .as_array()
            .map(|t| {
                t.iter()
                    .filter_map(Json::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        let response: RegisterPublicKeyCredential =
            serde_json::from_value(input.response).map_err(|_| failed)?;
        let passkey = rp
            .finish_passkey_registration(&response, &state)
            .map_err(|_| failed)?;
        let attested = ceremony::attested(&response.response.attestation_object).ok_or(failed)?;
        let credential = Credential::from(passkey);
        let credential_id = base64url(&credential.cred_id);
        if ctx
            .db()
            .find::<PasskeyRow>(PasskeyRow::CREDENTIAL_ID.eq(&credential_id))
            .one()
            .await?
            .is_some()
        {
            return Err(failed.into());
        }
        let (user_id, new_user) = match registrant {
            Registrant::User(user_id) => (user_id, None),
            Registrant::SignUp(user) => {
                let user = ctx
                    .internal()
                    .create_user(
                        NewUser {
                            email: user.email,
                            name: user.name,
                            email_verified: user.email_verified,
                            ..NewUser::default()
                        },
                        None,
                    )
                    .await?;
                (user.id.clone(), Some(user))
            }
        };
        let row = PasskeyRow {
            id: ctx.new_id()?,
            name: input
                .name
                .map(|n| n.trim().to_owned())
                .filter(|n| !n.is_empty()),
            public_key: attested.public_key,
            user_id: user_id.clone(),
            credential_id,
            counter: i64::from(credential.counter),
            device_type: if credential.backup_eligible {
                MULTI_DEVICE
            } else {
                SINGLE_DEVICE
            }
            .into(),
            backed_up: credential.backup_state,
            transports: Some(transports),
            created_at: ctx.now(),
            aaguid: Some(attested.aaguid),
        };
        if let Err(err) = ctx.db().insert(&row).await {
            if new_user.is_some() {
                ctx.db().delete::<User>(User::ID.eq(&user_id)).await?;
            }
            return Err(err.into());
        }
        ctx.emit(PasskeyAdded {
            user_id: user_id.clone(),
            passkey_id: row.id.clone(),
        });
        let (session, challenge) = match (input.create_session == Some(true), new_user) {
            (false, _) => (None, None),
            (true, None) => (
                Some(ctx.internal().create_session(&user_id, true).await?),
                None,
            ),
            (true, Some(user)) => match ctx.internal().sign_in(user, Passkey::ID, true).await? {
                SignInResult::SignedIn(session) => (Some(*session), None),
                SignInResult::Challenge(body) => (None, body.as_object().cloned()),
            },
        };
        Ok(RegisterOutput {
            passkey: row.into(),
            user: session.as_ref().map(|s| s.user.to_json()),
            session: session.map(|s| s.to_json()),
            challenge,
        })
    }
}

/// `GET /passkey/generate-authenticate-options`: the `PublicKeyCredentialRequestOptions` to
/// pass to `navigator.credentials.get()`. Signed out, any discoverable passkey for this site
/// may answer; signed in, the options list the user's passkeys.
pub struct GenerateAuthenticateOptions(pub(crate) Arc<Passkey>);

impl<D: Adapter> Endpoint<D> for GenerateAuthenticateOptions {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/passkey/generate-authenticate-options";
    type Access = MaybeAuthenticated;
    type Input = Empty;
    type Output = PublicKeyCredentialRequestOptions;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        _: Empty,
    ) -> Result<PublicKeyCredentialRequestOptions, AuthError> {
        let rp = self.0.relying_party(ctx.config())?;
        let (options, state) = rp
            .start_discoverable_authentication()
            .map_err(AuthError::internal)?;
        let mut options = options.public_key;
        if let Some(session) = ctx.session() {
            options.allow_credentials = user_passkeys(&ctx, &session.user.id)
                .await?
                .iter()
                .map(|row| {
                    Ok(AllowCredentials {
                        type_: "public-key".into(),
                        id: ceremony::credential_id(row)?,
                        transports: ceremony::transports(row.transports.as_deref()),
                    })
                })
                .collect::<Result<_, AuthError>>()?;
        }
        store_challenge(&ctx, &Challenge::Authentication { state }).await?;
        Ok(options)
    }
}

/// Body of `/passkey/verify-authentication`.
#[derive(Debug, Deserialize)]
pub struct VerifyAuthenticationInput {
    /// The `navigator.credentials.get()` result as JSON (`AuthenticationResponseJSON`).
    pub response: Json,
}

/// What a passkey sign-in answers.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum SignInOutput {
    /// Signed in: Better Auth's `{ session, user }`.
    SignedIn {
        session: Map<String, Json>,
        user: Map<String, Json>,
    },
    /// A sign-in gate's answer, e.g. `{"twoFactorRedirect": true}`. No session exists yet.
    Challenge(Json),
}

/// `POST /passkey/verify-authentication`: verifies the assertion against the challenge from
/// `generate-authenticate-options` and the stored public key, checks and advances the
/// signature counter, then signs the passkey's user in through the sign-in gates (method
/// `"passkey"`).
pub struct VerifyAuthentication(pub(crate) Arc<Passkey>);

impl<D: Adapter> Endpoint<D> for VerifyAuthentication {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/passkey/verify-authentication";
    type Access = Public;
    type Input = VerifyAuthenticationInput;
    type Output = SignInOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Public>,
        input: VerifyAuthenticationInput,
    ) -> Result<SignInOutput, AuthError> {
        let rp = self.0.relying_party(ctx.config())?;
        let Challenge::Authentication { state } = take_challenge(&ctx).await? else {
            return Err(PasskeyError::ChallengeNotFound.into());
        };
        let response: PublicKeyCredential =
            serde_json::from_value(input.response).map_err(|_| PasskeyError::InvalidAssertion)?;
        let row = ctx
            .db()
            .find::<PasskeyRow>(PasskeyRow::CREDENTIAL_ID.eq(base64url(&response.raw_id)))
            .one()
            .await?
            .ok_or(PasskeyError::UnknownCredential)?;
        let credential = ceremony::credential(&row)?;
        let result = rp
            .finish_discoverable_authentication_v2(&response, state, &credential)
            .map_err(|err| match err {
                WebauthnError::AuthenticationFailure => PasskeyError::AuthenticationFailed,
                _ => PasskeyError::InvalidAssertion,
            })?;
        // The user is read before the counter moves: a claim that deletes this passkey after
        // the read changes the user's security stamp, which the sign-in then refuses.
        let user = ctx
            .internal()
            .find_user_by_id(&row.user_id)
            .await?
            .ok_or_else(|| AuthError::internal("a passkey's user is gone"))?;
        let counter = i64::from(result.counter().max(credential.counter));
        let advanced = ctx
            .db()
            .update::<PasskeyRow>(
                PasskeyRow::ID
                    .eq(&row.id)
                    .and(PasskeyRow::COUNTER.eq(row.counter)),
            )
            .set(PasskeyRow::COUNTER, counter)
            .set(PasskeyRow::BACKED_UP, result.backup_state())
            .exec()
            .await?;
        if advanced == 0 {
            return Err(PasskeyError::InvalidAssertion.into());
        }
        Ok(
            match ctx.internal().sign_in(user, Passkey::ID, true).await? {
                SignInResult::SignedIn(session) => SignInOutput::SignedIn {
                    session: session.to_json(),
                    user: session.user.to_json(),
                },
                SignInResult::Challenge(body) => SignInOutput::Challenge(body),
            },
        )
    }
}

/// `GET /passkey/list-user-passkeys`: the signed-in user's passkeys.
pub struct ListUserPasskeys;

impl<D: Adapter> Endpoint<D> for ListUserPasskeys {
    const METHOD: Method = Method::GET;
    const PATH: &'static str = "/passkey/list-user-passkeys";
    type Access = Authenticated;
    type Input = Empty;
    type Output = Vec<PasskeyView>;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        _: Empty,
    ) -> Result<Vec<PasskeyView>, AuthError> {
        let rows = user_passkeys(&ctx, &ctx.session().user.id).await?;
        Ok(rows.into_iter().map(PasskeyView::from).collect())
    }
}

/// The caller's passkey `id`: 404 `PASSKEY_NOT_FOUND` when there's none, 401 `not_yours`
/// when it's someone else's, as Better Auth's ownership check answers.
async fn own_passkey<D: Adapter>(
    ctx: &Ctx<D, Authenticated>,
    id: &str,
    not_yours: AuthError,
) -> Result<PasskeyRow, AuthError> {
    let row = ctx
        .db()
        .find::<PasskeyRow>(PasskeyRow::ID.eq(Id::from(id)))
        .one()
        .await?
        .ok_or(PasskeyError::PasskeyNotFound)?;
    if row.user_id != ctx.session().user.id {
        return Err(not_yours);
    }
    Ok(row)
}

/// Body of `/passkey/delete-passkey`.
#[derive(Debug, Deserialize)]
pub struct DeletePasskeyInput {
    pub id: String,
}

/// `POST /passkey/delete-passkey`: deletes one of the signed-in user's passkeys.
pub struct DeletePasskey;

impl<D: Adapter> Endpoint<D> for DeletePasskey {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/passkey/delete-passkey";
    type Access = Authenticated;
    type Input = DeletePasskeyInput;
    type Output = Status;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: DeletePasskeyInput,
    ) -> Result<Status, AuthError> {
        let not_yours = AuthError::new(
            StatusCode::UNAUTHORIZED,
            codes::UNAUTHORIZED,
            "Unauthorized",
        );
        let row = own_passkey(&ctx, &input.id, not_yours).await?;
        ctx.db()
            .delete::<PasskeyRow>(PasskeyRow::ID.eq(&row.id))
            .await?;
        ctx.emit(PasskeyDeleted {
            user_id: row.user_id,
            passkey_id: row.id,
        });
        Ok(Status { status: true })
    }
}

/// Body of `/passkey/update-passkey`.
#[derive(Debug, Deserialize)]
pub struct UpdatePasskeyInput {
    pub id: String,
    /// The new name; trimmed, and not empty.
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct UpdatePasskeyOutput {
    pub passkey: PasskeyView,
}

/// `POST /passkey/update-passkey`: renames one of the signed-in user's passkeys.
pub struct UpdatePasskey;

impl<D: Adapter> Endpoint<D> for UpdatePasskey {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/passkey/update-passkey";
    type Access = Authenticated;
    type Input = UpdatePasskeyInput;
    type Output = UpdatePasskeyOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: UpdatePasskeyInput,
    ) -> Result<UpdatePasskeyOutput, AuthError> {
        let name = input.name.trim();
        if name.is_empty() {
            return Err(AuthError::bad_request(
                codes::INVALID_BODY,
                "name must not be empty",
            ));
        }
        let mut row = own_passkey(&ctx, &input.id, PasskeyError::NotAllowed.into()).await?;
        ctx.db()
            .update::<PasskeyRow>(PasskeyRow::ID.eq(&row.id))
            .set(PasskeyRow::NAME, Some(name.to_owned()))
            .exec()
            .await?;
        row.name = Some(name.to_owned());
        Ok(UpdatePasskeyOutput {
            passkey: row.into(),
        })
    }
}
