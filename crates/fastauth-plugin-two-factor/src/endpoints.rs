//! The `/two-factor/*` endpoints, the sign-in gate, and the signed cookies they share.

use fastauth_core::adapter::Transaction;
use fastauth_core::crypto::{Keys, base64url, ct_eq, random_bytes};
use fastauth_core::mail::{AuthEmail, PluginEmail};
use fastauth_core::plugin_prelude::*;
use fastauth_core::routes::Status;
use serde_json::{Map, json};

use crate::model::{TwoFactorRow, TwoFactorUser};
use crate::{TwoFactor, TwoFactorDisabled, TwoFactorEnabled, TwoFactorError, totp};

const PENDING_COOKIE: &str = "two_factor";
const TRUST_COOKIE: &str = "trust_device";
const SESSION_CACHE_COOKIE: &str = "session_data";
const OTP_TTL: Duration = Duration::minutes(15);
const OTP_ATTEMPTS: u32 = 5;
/// Codes a pending sign-in may try, across TOTP, email and backup codes.
const PENDING_ATTEMPTS: u32 = 5;
const PENDING_PREFIX: &str = "two-factor-pending:";
/// `verification.data`: the guesses so far, and for a pending sign-in what finishes it.
const DATA: Col<Verification, Option<String>> = Col::new("data");
const BACKUP_CODE_ALPHABET: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Body of the endpoints that only ask for the password again.
#[derive(Debug, Deserialize)]
pub struct PasswordInput {
    pub password: String,
}

/// Body of `/two-factor/enable`.
#[derive(Debug, Deserialize)]
pub struct EnableInput {
    pub password: String,
    /// Overrides the configured issuer in the TOTP URI.
    #[serde(default)]
    pub issuer: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableOutput {
    /// Always `"totp"`; Better Auth's client also knows `"otp"`.
    pub method: &'static str,
    #[serde(rename = "totpURI")]
    pub totp_uri: String,
    /// Shown once; only their hashes are stored.
    pub backup_codes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TotpUriOutput {
    #[serde(rename = "totpURI")]
    pub totp_uri: String,
}

/// Body of the `/two-factor/verify-*` endpoints.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyInput {
    pub code: String,
    /// Skip the challenge on this device for `trust_device_for`.
    pub trust_device: Option<bool>,
}

/// What a successful verification answers.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum VerifyOutput {
    /// The session token and the user.
    Verified {
        token: String,
        user: Map<String, serde_json::Value>,
    },
    /// The code finished a sign-in, and a sign-in gate of another plugin challenged it in
    /// turn: answer with its JSON. No session exists yet.
    Challenge(serde_json::Value),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupCodesOutput {
    pub status: bool,
    pub backup_codes: Vec<String>,
}

/// `POST /two-factor/enable`: a new TOTP secret and backup codes, replacing any old ones. The
/// replacement runs in a transaction that locks the user's row first, so two enables at once
/// leave one secret, the one the later answer shows.
/// Two-factor turns on after the first `verify-totp`, or at once with
/// `skip_verification_on_enable`. Needs a session read from the database
/// (`Ctx::sensitive_session`): API-key and impersonation sessions can't enable two-factor.
pub struct Enable(pub(crate) Arc<TwoFactor>);

impl<D: Adapter> Endpoint<D> for Enable {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/two-factor/enable";
    type Access = Authenticated;
    type Input = EnableInput;
    type Output = EnableOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: EnableInput,
    ) -> Result<EnableOutput, AuthError> {
        let session = ctx.sensitive_session().await?;
        let user = &session.user;
        check_password(&ctx, &user.id, &input.password).await?;
        let secret = random_bytes::<20>();
        let backup_codes = new_backup_codes(self.0.backup_codes);
        let row = TwoFactorRow {
            id: ctx.new_id()?,
            user_id: user.id.clone(),
            secret: ctx.keys().encrypt(&secret),
            backup_codes: seal_codes(ctx.keys(), &backup_codes),
            last_used_step: None,
        };
        let tx = ctx.adapter().begin().await?;
        let db = ctx.db_on(&tx);
        db.update::<User>(User::ID.eq(&user.id))
            .set(User::ID, user.id.clone())
            .exec()
            .await?;
        db.delete::<TwoFactorRow>(TwoFactorRow::USER_ID.eq(&user.id))
            .await?;
        db.insert(&row).await?;
        tx.commit().await?;
        if self.0.skip_verification_on_enable {
            set_enabled(&ctx, &user.id, true).await?;
        }
        let totp_uri = self.0.totp_uri(
            &ctx.config().app_name,
            input.issuer.as_deref(),
            &user.email,
            &secret,
        );
        Ok(EnableOutput {
            method: "totp",
            totp_uri,
            backup_codes,
        })
    }
}

/// `POST /two-factor/disable`: turns two-factor off and deletes the secret and backup codes.
/// Needs a session read from the database, like `enable`.
pub struct Disable;

impl<D: Adapter> Endpoint<D> for Disable {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/two-factor/disable";
    type Access = Authenticated;
    type Input = PasswordInput;
    type Output = Status;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: PasswordInput,
    ) -> Result<Status, AuthError> {
        let session = ctx.sensitive_session().await?;
        let user_id = &session.user.id;
        check_password(&ctx, user_id, &input.password).await?;
        ctx.db()
            .delete::<TwoFactorRow>(TwoFactorRow::USER_ID.eq(user_id))
            .await?;
        set_enabled(&ctx, user_id, false).await?;
        Ok(Status { status: true })
    }
}

/// `POST /two-factor/get-totp-uri`: the current secret's URI, for showing the QR code again.
pub struct GetTotpUri(pub(crate) Arc<TwoFactor>);

impl<D: Adapter> Endpoint<D> for GetTotpUri {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/two-factor/get-totp-uri";
    type Access = Authenticated;
    type Input = PasswordInput;
    type Output = TotpUriOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: PasswordInput,
    ) -> Result<TotpUriOutput, AuthError> {
        let user = &ctx.sensitive_session().await?.user;
        check_password(&ctx, &user.id, &input.password).await?;
        let row = find_row(&ctx, &user.id)
            .await?
            .ok_or(TwoFactorError::TotpNotEnabled)?;
        let secret = open_secret(ctx.keys(), &row)?;
        Ok(TotpUriOutput {
            totp_uri: self
                .0
                .totp_uri(&ctx.config().app_name, None, &user.email, &secret),
        })
    }
}

/// `POST /two-factor/verify-totp`: checks an authenticator code. Finishes a pending sign-in,
/// or, for a signed-in user, turns two-factor on the first time.
pub struct VerifyTotp(pub(crate) Arc<TwoFactor>);

impl<D: Adapter> Endpoint<D> for VerifyTotp {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/two-factor/verify-totp";
    type Access = MaybeAuthenticated;
    type Input = VerifyInput;
    type Output = VerifyOutput;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: VerifyInput,
    ) -> Result<VerifyOutput, AuthError> {
        let plugin = &self.0;
        let mut subject = subject(&ctx).await?;
        claim_attempt(&ctx, &subject).await?;
        let user_id = subject.user().id.clone();
        let row = find_row(&ctx, &user_id)
            .await?
            .ok_or(TwoFactorError::TotpNotEnabled)?;
        let secret = open_secret(ctx.keys(), &row)?;
        let now_step = ctx.now().unix_timestamp().max(0) as u64 / u64::from(plugin.period);
        let step = totp::matching_step(&secret, input.code.trim(), now_step, plugin.digits)
            .ok_or(TwoFactorError::InvalidCode)? as i64;
        let unused = TwoFactorRow::LAST_USED_STEP
            .is_null()
            .or(TwoFactorRow::LAST_USED_STEP.lt(step));
        let claimed = ctx
            .db()
            .update::<TwoFactorRow>(TwoFactorRow::ID.eq(&row.id).and(unused))
            .set(TwoFactorRow::LAST_USED_STEP, step)
            .exec()
            .await?;
        if claimed == 0 {
            return Err(TwoFactorError::InvalidCode.into());
        }
        if let Subject::Session(session) = &mut subject
            && !is_enabled(&session.user)?
        {
            set_enabled(&ctx, &user_id, true).await?;
            session.user = ctx
                .internal()
                .find_user_by_id(&user_id)
                .await?
                .ok_or_else(|| AuthError::internal("user deleted while enabling two-factor"))?;
        }
        finish(plugin, &ctx, subject, input.trust_device).await
    }
}

/// `POST /two-factor/send-otp`: emails a 6-digit code to the pending or signed-in user.
pub struct SendOtp;

impl<D: Adapter> Endpoint<D> for SendOtp {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/two-factor/send-otp";
    type Access = MaybeAuthenticated;
    type Input = Empty;
    type Output = Status;

    async fn call(&self, ctx: Ctx<D, MaybeAuthenticated>, _: Empty) -> Result<Status, AuthError> {
        let subject = subject(&ctx).await?;
        let user = subject.user();
        let code = random_string(6, b"0123456789");
        let internal = ctx.internal();
        internal
            .store_verification_value(&otp_identifier(&user.id), &code, OTP_TTL, Some("0".into()))
            .await?;
        let app_name = &ctx.config().app_name;
        internal
            .send_email(AuthEmail::Plugin(PluginEmail {
                kind: "two-factor-otp",
                to: user.email.clone(),
                subject: format!("Your {app_name} verification code"),
                text: format!(
                    "Your verification code is {code}. It expires in {} minutes.",
                    OTP_TTL.whole_minutes()
                ),
                url: None,
                code: Some(code),
            }))
            .await?;
        Ok(Status { status: true })
    }
}

/// `POST /two-factor/verify-otp`: checks an emailed code. Five wrong codes burn it.
///
/// Every guess claims an attempt with a compare-and-swap on the counter before the code is
/// compared, so concurrent guesses can't try more than five codes.
pub struct VerifyOtp(pub(crate) Arc<TwoFactor>);

impl<D: Adapter> Endpoint<D> for VerifyOtp {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/two-factor/verify-otp";
    type Access = MaybeAuthenticated;
    type Input = VerifyInput;
    type Output = VerifyOutput;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: VerifyInput,
    ) -> Result<VerifyOutput, AuthError> {
        let subject = subject(&ctx).await?;
        let identifier = otp_identifier(&subject.user().id);
        let mine = || Verification::IDENTIFIER.eq(&identifier);
        let (stored, guess) = match claim_guess(&ctx, mine, OTP_ATTEMPTS).await? {
            Claim::Claimed { row, guess } => (row, guess),
            Claim::Gone => return Err(TwoFactorError::InvalidCode.into()),
            Claim::Expired => return Err(TwoFactorError::OtpHasExpired.into()),
            Claim::Spent => return Err(TwoFactorError::TooManyAttempts.into()),
        };
        claim_attempt(&ctx, &subject).await?;
        let this = || Verification::ID.eq(&stored.id);
        let expected = Hash::sha256(format!("{identifier}:{}", input.code.trim()));
        if !ct_eq(stored.value_hash.as_bytes(), expected.as_bytes()) {
            if guess >= OTP_ATTEMPTS {
                ctx.db().delete::<Verification>(this()).await?;
                return Err(TwoFactorError::TooManyAttempts.into());
            }
            return Err(TwoFactorError::InvalidCode.into());
        }
        if ctx.db().delete::<Verification>(this()).await? == 0 {
            return Err(TwoFactorError::InvalidCode.into());
        }
        finish(&self.0, &ctx, subject, input.trust_device).await
    }
}

/// `POST /two-factor/generate-backup-codes`: replaces every backup code with new ones.
pub struct GenerateBackupCodes(pub(crate) Arc<TwoFactor>);

impl<D: Adapter> Endpoint<D> for GenerateBackupCodes {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/two-factor/generate-backup-codes";
    type Access = Authenticated;
    type Input = PasswordInput;
    type Output = BackupCodesOutput;

    async fn call(
        &self,
        ctx: Ctx<D, Authenticated>,
        input: PasswordInput,
    ) -> Result<BackupCodesOutput, AuthError> {
        let user = &ctx.sensitive_session().await?.user;
        check_password(&ctx, &user.id, &input.password).await?;
        let enabled = is_enabled(user)?;
        let row = find_row(&ctx, &user.id)
            .await?
            .filter(|_| enabled)
            .ok_or(TwoFactorError::TwoFactorNotEnabled)?;
        let backup_codes = new_backup_codes(self.0.backup_codes);
        ctx.db()
            .update::<TwoFactorRow>(TwoFactorRow::ID.eq(&row.id))
            .set(
                TwoFactorRow::BACKUP_CODES,
                seal_codes(ctx.keys(), &backup_codes),
            )
            .exec()
            .await?;
        Ok(BackupCodesOutput {
            status: true,
            backup_codes,
        })
    }
}

/// `POST /two-factor/verify-backup-code`: accepts each backup code once.
pub struct VerifyBackupCode(pub(crate) Arc<TwoFactor>);

impl<D: Adapter> Endpoint<D> for VerifyBackupCode {
    const METHOD: Method = Method::POST;
    const PATH: &'static str = "/two-factor/verify-backup-code";
    type Access = MaybeAuthenticated;
    type Input = VerifyInput;
    type Output = VerifyOutput;

    async fn call(
        &self,
        ctx: Ctx<D, MaybeAuthenticated>,
        input: VerifyInput,
    ) -> Result<VerifyOutput, AuthError> {
        let subject = subject(&ctx).await?;
        claim_attempt(&ctx, &subject).await?;
        let row = find_row(&ctx, &subject.user().id)
            .await?
            .ok_or(TwoFactorError::TwoFactorNotEnabled)?;
        let mut hashes = open_hashes(ctx.keys(), &row)?;
        let given = hash_code(input.code.trim());
        let Some(index) = hashes
            .iter()
            .position(|h| ct_eq(h.as_bytes(), given.as_bytes()))
        else {
            return Err(TwoFactorError::InvalidBackupCode.into());
        };
        hashes.remove(index);
        let sealed = seal_hashes(ctx.keys(), &hashes);
        let claimed = ctx
            .db()
            .update::<TwoFactorRow>(
                TwoFactorRow::ID
                    .eq(&row.id)
                    .and(TwoFactorRow::BACKUP_CODES.eq(row.backup_codes.clone())),
            )
            .set(TwoFactorRow::BACKUP_CODES, sealed)
            .exec()
            .await?;
        if claimed == 0 {
            return Err(TwoFactorError::InvalidBackupCode.into());
        }
        finish(&self.0, &ctx, subject, input.trust_device).await
    }
}

/// Challenges sign-ins of users with two-factor on, unless this device is trusted.
pub(crate) async fn gate<D: Adapter>(
    plugin: &TwoFactor,
    ctx: HookCtx<D>,
    attempt: SignInAttempt,
) -> Result<Gate, AuthError> {
    if !is_enabled(&attempt.user)? || is_trusted(&ctx, &attempt.user.id).await? {
        return Ok(Gate::Allow);
    }
    let remember_me = if attempt.remember_me { "1" } else { "0" };
    let max_age = plugin.two_factor_cookie_max_age;
    let token = ctx
        .internal()
        .create_verification(
            &format!("{PENDING_PREFIX}{}", attempt.user.id),
            max_age,
            Some(format!("0|{remember_me}|{}", attempt.method)),
        )
        .await?;
    ctx.set_signed_cookie(PENDING_COOKIE, &token, Some(max_age));
    let methods: &[&str] = if ctx.internal().can_send_email() {
        &["totp", "otp"]
    } else {
        &["totp"]
    };
    Ok(Gate::Challenge(json!({
        "twoFactorRedirect": true,
        "twoFactorMethods": methods,
    })))
}

/// Who a verify endpoint acts for.
enum Subject {
    /// Signing in: the pending cookie names a `verification` row (`challenge`) that holds the
    /// user, the sign-in method and the guesses so far, and verifying finishes the sign-in.
    Pending {
        user: UserView,
        remember_me: bool,
        method: String,
        challenge: Box<Verification>,
    },
    /// Already signed in, e.g. confirming the authenticator after `/two-factor/enable`.
    Session(Box<SessionView>),
}

impl Subject {
    fn user(&self) -> &UserView {
        match self {
            Subject::Pending { user, .. } => user,
            Subject::Session(session) => &session.user,
        }
    }
}

/// The pending sign-in when its cookie names a live one, else the session.
async fn subject<D: Adapter>(ctx: &Ctx<D, MaybeAuthenticated>) -> Result<Subject, AuthError> {
    if let Some(token) = ctx.signed_cookie(PENDING_COOKIE)
        && let Some(challenge) = ctx.internal().find_verification(&token).await?
        && let Some(user_id) = challenge.identifier.strip_prefix(PENDING_PREFIX)
        && let Some((_, remember_me, method)) = pending_data(&challenge)
        && let Some(user) = ctx.internal().find_user_by_id(&Id::from(user_id)).await?
    {
        return Ok(Subject::Pending {
            user,
            remember_me: remember_me == "1",
            method: method.to_owned(),
            challenge: Box::new(challenge),
        });
    }
    ctx.session()
        .map(|s| Subject::Session(Box::new(s.clone())))
        .ok_or_else(|| TwoFactorError::InvalidTwoFactorCookie.into())
}

/// `attempts|remember_me|method` of a pending sign-in's `verification.data`.
fn pending_data(challenge: &Verification) -> Option<(u32, &str, &str)> {
    let mut fields = challenge.data.as_deref()?.splitn(3, '|');
    let attempts = fields.next()?.parse().ok()?;
    Some((attempts, fields.next()?, fields.next()?))
}

/// Spends one of a pending sign-in's guesses before a code is compared. Once
/// `PENDING_ATTEMPTS` are spent the pending sign-in is deleted and the user signs in again.
/// A signed-in subject has no limit beyond the rate limit.
async fn claim_attempt<D: Adapter>(
    ctx: &Ctx<D, MaybeAuthenticated>,
    subject: &Subject,
) -> Result<(), AuthError> {
    let Subject::Pending { challenge, .. } = subject else {
        return Ok(());
    };
    let this = || Verification::ID.eq(&challenge.id);
    match claim_guess(ctx, this, PENDING_ATTEMPTS).await? {
        Claim::Claimed { .. } => Ok(()),
        Claim::Gone | Claim::Expired => {
            ctx.delete_cookie(PENDING_COOKIE);
            Err(TwoFactorError::InvalidTwoFactorCookie.into())
        }
        Claim::Spent => {
            ctx.delete_cookie(PENDING_COOKIE);
            Err(TwoFactorError::TooManyAttempts.into())
        }
    }
}

/// What [`claim_guess`] found.
enum Claim {
    /// The guess is counted; it is guess number `guess` (from 1).
    Claimed {
        row: Verification,
        guess: u32,
    },
    Gone,
    /// Expired, now deleted.
    Expired,
    /// Every guess was spent, now deleted.
    Spent,
}

/// Counts one guess on the `verification` row `find` selects, whose `data` starts with the
/// guesses so far (`2`, or `2|..` for a pending sign-in). The count goes up with a
/// compare-and-swap that is retried when a concurrent guess wins it, so every guess is
/// counted and no more than `limit` are ever compared.
async fn claim_guess<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    find: impl Fn() -> Where<Verification>,
    limit: u32,
) -> Result<Claim, AuthError> {
    loop {
        let Some(row) = ctx.db().find::<Verification>(find()).one().await? else {
            return Ok(Claim::Gone);
        };
        let this = || Verification::ID.eq(&row.id);
        if row.expires_at <= ctx.now() {
            ctx.db().delete::<Verification>(this()).await?;
            return Ok(Claim::Expired);
        }
        let data = row.data.as_deref().unwrap_or_default();
        let (count, rest) = data
            .split_once('|')
            .map_or((data, None), |(c, r)| (c, Some(r)));
        let count = count.parse::<u32>().unwrap_or(limit);
        if count >= limit {
            ctx.db().delete::<Verification>(this()).await?;
            return Ok(Claim::Spent);
        }
        let next = match rest {
            Some(rest) => format!("{}|{rest}", count + 1),
            None => (count + 1).to_string(),
        };
        let claimed = ctx
            .db()
            .update::<Verification>(this().and(DATA.eq(row.data.clone())))
            .set(DATA, Some(next))
            .exec()
            .await?;
        if claimed == 1 {
            return Ok(Claim::Claimed {
                row,
                guess: count + 1,
            });
        }
    }
}

/// Finishes a pending sign-in through the other plugins' gates, and trusts the device when
/// asked. The pending sign-in is deleted first, so it finishes once.
async fn finish<D: Adapter>(
    plugin: &TwoFactor,
    ctx: &Ctx<D, MaybeAuthenticated>,
    subject: Subject,
    trust_device: Option<bool>,
) -> Result<VerifyOutput, AuthError> {
    let session = match subject {
        Subject::Pending {
            user,
            remember_me,
            method,
            challenge,
        } => {
            ctx.delete_cookie(PENDING_COOKIE);
            let consumed = ctx
                .db()
                .delete::<Verification>(Verification::ID.eq(&challenge.id))
                .await?;
            if consumed == 0 {
                return Err(TwoFactorError::InvalidTwoFactorCookie.into());
            }
            match ctx
                .internal()
                .complete_sign_in(TwoFactor::ID, user, method, remember_me)
                .await?
            {
                SignInResult::SignedIn(session) => *session,
                SignInResult::Challenge(body) => return Ok(VerifyOutput::Challenge(body)),
            }
        }
        Subject::Session(session) => *session,
    };
    if trust_device == Some(true)
        && let Some(row) = find_row(ctx, &session.user.id).await?
    {
        write_payload(
            ctx,
            TRUST_COOKIE,
            "trust",
            [session.user.id.as_str(), row.id.as_str()],
            plugin.trust_device_for,
        );
    }
    let user = session.user.to_json();
    Ok(VerifyOutput::Verified {
        token: session.token.unwrap_or_default(),
        user,
    })
}

/// A trusted-device cookie names the user and their `two_factor` row, so re-enabling
/// two-factor (a new row) forgets every trusted device.
async fn is_trusted<D: Adapter, A>(ctx: &Ctx<D, A>, user_id: &Id) -> Result<bool, AuthError> {
    let Some([trusted_user, row_id]) = read_payload(ctx, TRUST_COOKIE, "trust") else {
        return Ok(false);
    };
    if trusted_user != user_id.as_str() {
        return Ok(false);
    }
    Ok(find_row(ctx, user_id)
        .await?
        .is_some_and(|row| row.id.as_str() == row_id))
}

/// Sets the signed cookie `{prefix}.{cookie}` to `kind|field|..|expires`.
fn write_payload<D: Adapter, A, const N: usize>(
    ctx: &Ctx<D, A>,
    cookie: &str,
    kind: &str,
    fields: [&str; N],
    max_age: Duration,
) {
    let expires = (ctx.now() + max_age).unix_timestamp();
    let value = format!("{kind}|{}|{expires}", fields.join("|"));
    ctx.set_signed_cookie(cookie, &value, Some(max_age));
}

/// Reads a cookie written by `write_payload`, when its signature, kind, field count and
/// expiry check out.
fn read_payload<D: Adapter, A, const N: usize>(
    ctx: &Ctx<D, A>,
    cookie: &str,
    kind: &str,
) -> Option<[String; N]> {
    let value = ctx.signed_cookie(cookie)?;
    let parts: Vec<&str> = value.split('|').collect();
    let [found, fields @ .., expires] = &parts[..] else {
        return None;
    };
    let expires: i64 = expires.parse().ok()?;
    if *found != kind || expires <= ctx.now().unix_timestamp() {
        return None;
    }
    fields
        .iter()
        .map(|field| (*field).to_owned())
        .collect::<Vec<_>>()
        .try_into()
        .ok()
}

async fn check_password<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    user_id: &Id,
    password: &str,
) -> Result<(), AuthError> {
    let Some(hash) = ctx
        .internal()
        .credential_account(user_id)
        .await?
        .and_then(|a| a.password_hash)
    else {
        return Err(AuthError::bad_request(
            codes::CREDENTIAL_ACCOUNT_NOT_FOUND,
            "this user has no password",
        ));
    };
    if !ctx
        .passwords()
        .verify(password, &hash)
        .await
        .map_err(AuthError::internal)?
    {
        return Err(AuthError::bad_request(
            codes::INVALID_PASSWORD,
            "invalid password",
        ));
    }
    Ok(())
}

fn is_enabled(user: &UserView) -> Result<bool, AuthError> {
    Ok(user
        .fields::<TwoFactorUser>()
        .map_err(AuthError::internal)?
        .two_factor_enabled)
}

/// Sets `user.two_factor_enabled` and drops the session cookie cache, which holds the old value.
async fn set_enabled<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    user_id: &Id,
    enabled: bool,
) -> Result<(), AuthError> {
    ctx.db()
        .update::<User>(User::ID.eq(user_id))
        .set(TwoFactorUser::TWO_FACTOR_ENABLED, enabled)
        .exec()
        .await?;
    ctx.delete_cookie(SESSION_CACHE_COOKIE);
    let user_id = user_id.clone();
    if enabled {
        ctx.emit(TwoFactorEnabled { user_id });
    } else {
        ctx.emit(TwoFactorDisabled { user_id });
    }
    Ok(())
}

async fn find_row<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    user_id: &Id,
) -> Result<Option<TwoFactorRow>, AuthError> {
    Ok(ctx
        .db()
        .find::<TwoFactorRow>(TwoFactorRow::USER_ID.eq(user_id))
        .one()
        .await?)
}

fn open_secret(keys: &Keys, row: &TwoFactorRow) -> Result<Vec<u8>, AuthError> {
    keys.decrypt(&row.secret)
        .ok_or_else(|| AuthError::internal("two-factor secret does not decrypt"))
}

fn otp_identifier(user_id: &Id) -> String {
    format!("two-factor-otp:{user_id}")
}

/// Ends a claimed user's two-factor, inside the claim: the enrollment (TOTP secret and backup
/// codes, so trusted-device cookies stop matching too), the `two_factor_enabled` flag, a
/// sign-in waiting at the two-factor step and an emailed code. Whoever registered the address
/// before the proof set all of these up.
pub(crate) async fn end_on_claim<D: Adapter>(
    claim: fastauth_core::internal::Claim<'_, D>,
) -> Result<(), AuthError> {
    let db = claim.db();
    let user_id = claim.user_id();
    db.delete::<TwoFactorRow>(TwoFactorRow::USER_ID.eq(user_id))
        .await?;
    db.update::<User>(User::ID.eq(user_id))
        .set(TwoFactorUser::TWO_FACTOR_ENABLED, false)
        .exec()
        .await?;
    db.delete::<Verification>(Verification::IDENTIFIER.in_([
        format!("{PENDING_PREFIX}{user_id}"),
        otp_identifier(user_id),
    ]))
    .await?;
    Ok(())
}

/// Codes in Better Auth's shape: ten letters and digits, split `xxxxx-xxxxx`.
fn new_backup_codes(count: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            let code = random_string(10, BACKUP_CODE_ALPHABET);
            format!("{}-{}", &code[..5], &code[5..])
        })
        .collect()
}

fn hash_code(code: &str) -> String {
    base64url(Hash::sha256(code).as_bytes())
}

/// Hashes each code, then encrypts the JSON list of hashes.
fn seal_codes(keys: &Keys, codes: &[String]) -> Vec<u8> {
    let hashes: Vec<String> = codes.iter().map(|c| hash_code(c)).collect();
    seal_hashes(keys, &hashes)
}

fn seal_hashes(keys: &Keys, hashes: &[String]) -> Vec<u8> {
    keys.encrypt(&serde_json::to_vec(hashes).expect("a list of strings serializes"))
}

fn open_hashes(keys: &Keys, row: &TwoFactorRow) -> Result<Vec<String>, AuthError> {
    keys.decrypt(&row.backup_codes)
        .and_then(|json| serde_json::from_slice(&json).ok())
        .ok_or_else(|| AuthError::internal("two-factor backup codes do not decrypt"))
}
