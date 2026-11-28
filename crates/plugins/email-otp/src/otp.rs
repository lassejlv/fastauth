//! Issuing and checking codes. A code lives in one `verification` row per purpose and email:
//! `identifier` is Better Auth's `{type}-otp-{email}`, `value_hash` an HMAC of the code under a
//! key derived for this plugin, and `data` the count of guesses so far.

use fastauth_core::crypto::ct_eq;
use fastauth_core::plugin_prelude::*;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::{EmailOtp, EmailOtpError, OtpType};

/// Guesses made so far, as text.
const ATTEMPTS: Col<Verification, Option<String>> = Col::new("data");

pub(crate) fn identifier(kind: OtpType, email: &str) -> String {
    format!("{}-otp-{email}", kind.as_str())
}

fn digest<D: Adapter, A>(ctx: &Ctx<D, A>, identifier: &str, code: &str) -> Hash {
    let key = ctx.keys().derive_key(EmailOtp::ID);
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_ref()).expect("HMAC takes any key length");
    mac.update(identifier.as_bytes());
    mac.update(b":");
    mac.update(code.as_bytes());
    Hash::from_slice(&mac.finalize().into_bytes()).expect("HMAC-SHA256 is 32 bytes")
}

/// Stores a new code under `identifier`, replacing any older one, and returns it.
pub(crate) async fn issue<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    plugin: &EmailOtp,
    identifier: &str,
) -> Result<String, AuthError> {
    let code = random_string(plugin.otp_length, b"0123456789");
    let now = ctx.now();
    ctx.db()
        .delete::<Verification>(Verification::IDENTIFIER.eq(identifier))
        .await?;
    ctx.db()
        .insert(&Verification {
            id: ctx.new_id()?,
            identifier: identifier.to_owned(),
            value_hash: digest(ctx, identifier, &code),
            data: Some("0".into()),
            expires_at: now + plugin.expires_in,
            created_at: now,
            updated_at: now,
        })
        .await?;
    Ok(code)
}

pub(crate) async fn discard<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    identifier: &str,
) -> Result<(), AuthError> {
    ctx.db()
        .delete::<Verification>(Verification::IDENTIFIER.eq(identifier))
        .await?;
    Ok(())
}

/// What happens to a code that matched.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnMatch {
    /// Delete it: it signed in, verified or reset.
    Consume,
    /// Keep it, with the guess given back, for the call that uses it next.
    Keep,
}

/// Checks `code` against the one stored under `identifier`.
///
/// Every guess first claims an attempt with a compare-and-swap on the counter and only then
/// compares, in constant time. Concurrent guesses that lose the swap answer `INVALID_OTP`
/// without being compared, so parallel requests can't try more than `allowed_attempts`
/// codes. Once the counter reaches the limit the code is deleted and the next guess answers
/// `TOO_MANY_ATTEMPTS`.
pub(crate) async fn verify<D: Adapter, A>(
    ctx: &Ctx<D, A>,
    plugin: &EmailOtp,
    identifier: &str,
    code: &str,
    on_match: OnMatch,
) -> Result<(), AuthError> {
    let Some(stored) = ctx
        .db()
        .find::<Verification>(Verification::IDENTIFIER.eq(identifier))
        .one()
        .await?
    else {
        return Err(EmailOtpError::InvalidOtp.into());
    };
    let this = || Verification::ID.eq(&stored.id);
    if stored.expires_at <= ctx.now() {
        ctx.db().delete::<Verification>(this()).await?;
        return Err(EmailOtpError::OtpExpired.into());
    }
    let attempts = stored
        .data
        .as_deref()
        .and_then(|d| d.parse::<u32>().ok())
        .unwrap_or(plugin.allowed_attempts);
    if attempts >= plugin.allowed_attempts {
        ctx.db().delete::<Verification>(this()).await?;
        return Err(EmailOtpError::TooManyAttempts.into());
    }
    let claimed = ctx
        .db()
        .update::<Verification>(this().and(ATTEMPTS.eq(stored.data.clone())))
        .set(ATTEMPTS, Some((attempts + 1).to_string()))
        .exec()
        .await?;
    if claimed == 0 {
        return Err(EmailOtpError::InvalidOtp.into());
    }
    let expected = digest(ctx, identifier, code.trim());
    if !ct_eq(stored.value_hash.as_bytes(), expected.as_bytes()) {
        return Err(EmailOtpError::InvalidOtp.into());
    }
    match on_match {
        OnMatch::Consume => {
            if ctx.db().delete::<Verification>(this()).await? == 0 {
                return Err(EmailOtpError::InvalidOtp.into());
            }
        }
        OnMatch::Keep => {
            ctx.db()
                .update::<Verification>(this().and(ATTEMPTS.eq(Some((attempts + 1).to_string()))))
                .set(ATTEMPTS, stored.data.clone())
                .exec()
                .await?;
        }
    }
    Ok(())
}
