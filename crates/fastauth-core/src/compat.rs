//! Better Auth database compatibility: run fastauth next to a Better Auth app on one
//! database during a migration. Everything here is opt-in; without it fastauth behaves as it
//! always has.
//!
//! - [`CookieSigning::BetterAuth`]: session cookies in Better Auth's format, so each app
//!   accepts the other's cookies.
//! - [`BetterAuthScrypt`]: Better Auth's password hashes, verified and written.
//! - [`SlidingRefresh::ExpiresAt`]: Better Auth's rule for extending a session.
//! - [`BetterAuthCompat`]: all of the above with Better Auth's numbers, set with
//!   `FastAuth::builder().better_auth_compat(..)`.
//!
//! Each relaxes a fastauth default on purpose, for the migration window only:
//! `docs/integrations/04-migrating-from-better-auth.md` lists the trade-offs.

use std::borrow::Cow;

use base64::Engine as _;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use sha2::Sha256;
use time::Duration;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::config::{CookieConfig, CookieSigning, EmailPassword, SessionConfig, SlidingRefresh};
use crate::crypto::{PasswordHasher, Secret, ct_eq, random_bytes};
use crate::error::BuildError;

/// What `encodeURIComponent` leaves alone: letters, digits and `-_.!~*'()`.
const URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

/// Standard base64 decoded like the browser's `atob`, which ignores bits past the last byte.
const ATOB: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

fn mac(secret: &[u8], value: &str) -> Hmac<Sha256> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(value.as_bytes());
    mac
}

/// better-call's `signCookieValue`: `encodeURIComponent(value + "." + base64(HMAC-SHA256))`,
/// the HMAC keyed with the secret's bytes as they are and the signature in padded standard
/// base64.
pub(crate) fn sign_cookie(secret: &[u8], value: &str) -> String {
    let tag = mac(secret, value).finalize().into_bytes();
    let signed = format!("{value}.{}", STANDARD.encode(tag));
    utf8_percent_encode(&signed, URI_COMPONENT).to_string()
}

/// better-call's `getSignedCookie` on a value [`decode_cookie`] already decoded: the value
/// before the last `.`, when it isn't empty, the signature after it is 44 characters ending in
/// `=`, and the HMAC matches (compared in constant time).
pub(crate) fn verify_cookie<'a>(secret: &[u8], signed: &'a str) -> Option<&'a str> {
    let (value, signature) = signed.rsplit_once('.')?;
    if value.is_empty() || signature.len() != 44 || !signature.ends_with('=') {
        return None;
    }
    let signature = ATOB.decode(signature).ok()?;
    mac(secret, value).verify_slice(&signature).ok()?;
    Some(value)
}

/// better-call's cookie parser decodes every value holding a `%` with
/// `decodeURIComponent`, and keeps it as it came when that fails (a `%` without two hex
/// digits after it, or bytes that aren't UTF-8). Values without a `%` are used as they are,
/// so an unencoded signed value verifies too.
///
/// Like better-call's parser, surrounding whitespace is trimmed and one pair of quotes removed
/// first.
pub(crate) fn decode_cookie(raw: &str) -> Cow<'_, str> {
    let raw = raw.trim();
    let raw = match raw.strip_prefix('"') {
        Some(rest) => {
            let mut chars = rest.chars();
            chars.next_back();
            chars.as_str()
        }
        None => raw,
    };
    if !raw.contains('%') {
        return Cow::Borrowed(raw);
    }
    let bytes = raw.as_bytes();
    let escapes_ok = bytes.iter().enumerate().all(|(i, byte)| {
        *byte != b'%'
            || bytes
                .get(i + 1..i + 3)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
    });
    if !escapes_ok {
        return Cow::Borrowed(raw);
    }
    match percent_encoding::percent_decode_str(raw).decode_utf8() {
        Ok(decoded) => Cow::Owned(decoded.into_owned()),
        Err(_) => Cow::Borrowed(raw),
    }
}

/// Better Auth's password hashes, as `@better-auth/utils/password` writes them:
/// `"<salt>:<key>"`, where the salt is 16 random bytes in lowercase hex and the key is
/// scrypt (N = 16384, r = 16, p = 1, 64 bytes) of the NFKC-normalized password, salted with
/// the salt's hex string as UTF-8 (not the 16 bytes it encodes), in lowercase hex.
///
/// New hashes are written in the same format and [`PasswordHasher::needs_rehash`] is always
/// false, so a Better Auth app on the same database keeps verifying every password, and
/// rolling back to it loses nobody.
///
/// Each hash takes [`BetterAuthScrypt::MEMORY_BYTES`] (32 MiB), against argon2id's 19 MiB,
/// so cap how many run at once with `EmailPassword::max_concurrent_hashes`;
/// [`BetterAuthCompat`] does. It's weaker than fastauth's default argon2id: use it only
/// while a Better Auth app shares the database.
#[derive(Clone, Copy, Debug, Default)]
pub struct BetterAuthScrypt;

impl BetterAuthScrypt {
    /// scrypt's working memory per hash: 128 · N · r bytes, 32 MiB.
    pub const MEMORY_BYTES: usize = 128 * 16384 * 16;

    fn key(password: &str, salt: &str) -> Zeroizing<[u8; 64]> {
        let password: Zeroizing<String> = Zeroizing::new(password.nfkc().collect());
        let params = scrypt::Params::new(14, 16, 1).expect("valid scrypt parameters");
        let mut key = Zeroizing::new([0u8; 64]);
        scrypt::scrypt(password.as_bytes(), salt.as_bytes(), &params, key.as_mut())
            .expect("64 bytes is a valid scrypt output length");
        key
    }

    /// The hash of `password` with this salt. Better Auth's salts are 32 lowercase hex
    /// characters; [`PasswordHasher::hash`] makes a random one.
    pub fn hash_with_salt(password: &str, salt: &str) -> String {
        format!("{salt}:{}", hex(Self::key(password, salt).as_ref()))
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| [DIGITS[usize::from(b >> 4)], DIGITS[usize::from(b & 15)]])
        .map(char::from)
        .collect()
}

impl PasswordHasher for BetterAuthScrypt {
    fn hash(&self, password: &str) -> Result<String, String> {
        Ok(Self::hash_with_salt(password, &hex(&random_bytes::<16>())))
    }

    /// Like Better Auth: the first two `:`-separated parts are the salt and the key, and the
    /// key must equal the lowercase hex of the derived key. A hash without both parts is an
    /// error, as it is in Better Auth.
    fn verify(&self, password: &str, hash: &str) -> Result<bool, String> {
        let mut parts = hash.split(':');
        let (Some(salt), Some(key)) = (
            parts.next().filter(|s| !s.is_empty()),
            parts.next().filter(|k| !k.is_empty()),
        ) else {
            return Err("not a Better Auth password hash (\"<salt>:<key>\")".into());
        };
        let derived = Zeroizing::new(hex(Self::key(password, salt).as_ref()));
        Ok(ct_eq(derived.as_bytes(), key.as_bytes()))
    }
}

/// Runs fastauth on a database a Better Auth app also uses, and lets the two share sign-ins:
/// `FastAuth::builder().better_auth_compat(BetterAuthCompat::new(secret).cookie_prefix("vt"))`.
///
/// Applied at `.build()`, where it overrides the matching settings:
///
/// - cookies are named `{prefix}.session_token` (`__Secure-` in front on https) and signed in
///   Better Auth's format with the raw secret ([`CookieSigning::BetterAuth`]);
/// - sessions last [`BetterAuthCompat::expires_in`] (14 days unless set) and are extended
///   once [`BetterAuthCompat::update_age`] (one day) has passed since their last extension,
///   by Better Auth's rule ([`SlidingRefresh::ExpiresAt`]);
/// - passwords use [`BetterAuthScrypt`], at most
///   [`BetterAuthCompat::max_concurrent_hashes`] at a time.
///
/// The cookie cache can't be used with it: `.build()` refuses `SessionConfig::cookie_cache`.
/// fastauth's own `.secret(..)` is still needed; it keys everything that isn't a cookie
/// (encrypted columns, plugin keys, rate-limit buckets).
#[derive(Clone, Debug)]
pub struct BetterAuthCompat {
    secret: Secret,
    cookie_prefix: String,
    expires_in: Duration,
    update_age: Duration,
    max_concurrent_hashes: usize,
}

impl BetterAuthCompat {
    /// The Better Auth app's secret (`BETTER_AUTH_SECRET`), as the app has it: its UTF-8 bytes
    /// key the cookie HMAC, with no decoding and no key derivation.
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: Secret::from_bytes(secret),
            cookie_prefix: "better-auth".into(),
            expires_in: Duration::days(14),
            update_age: Duration::days(1),
            max_concurrent_hashes: 8,
        }
    }

    /// [`BetterAuthCompat::new`] with the value of an environment variable, read as it is.
    /// Unlike `Secret::from_env`, a value that happens to be valid base64 isn't decoded.
    pub fn from_env(var: &str) -> Result<Self, BuildError> {
        let value = std::env::var(var)
            .map_err(|_| BuildError::new(format!("environment variable `{var}` is not set")))?;
        Ok(Self::new(value))
    }

    /// The Better Auth app's `advanced.cookiePrefix` (default `"better-auth"`).
    pub fn cookie_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.cookie_prefix = prefix.into();
        self
    }

    /// The Better Auth app's `session.expiresIn` (14 days unless set; Better Auth's own
    /// default is 7). Both apps should use the same value, since each extends a session to
    /// its own.
    pub fn expires_in(mut self, d: Duration) -> Self {
        self.expires_in = d;
        self
    }

    /// The Better Auth app's `session.updateAge` (one day, Better Auth's default).
    pub fn update_age(mut self, d: Duration) -> Self {
        self.update_age = d;
        self
    }

    /// How many scrypt hashes run at once at most (default 8, and never more than the
    /// number of CPUs): 32 MiB each, so 256 MiB at most by default.
    pub fn max_concurrent_hashes(mut self, n: usize) -> Self {
        self.max_concurrent_hashes = n.max(1);
        self
    }

    pub(crate) fn apply(
        self,
        cookies: &mut CookieConfig,
        session: &mut SessionConfig,
        email_password: Option<&mut EmailPassword>,
    ) {
        cookies.prefix = self.cookie_prefix;
        cookies.signing = CookieSigning::BetterAuth(self.secret);
        session.expires_in = self.expires_in;
        session.update_age = self.update_age;
        session.sliding = SlidingRefresh::ExpiresAt;
        if let Some(email_password) = email_password {
            let cpus = std::thread::available_parallelism().map_or(2, |n| n.get());
            email_password.hasher = std::sync::Arc::new(BetterAuthScrypt);
            email_password.max_concurrent_hashes = Some(self.max_concurrent_hashes.min(cpus));
        }
    }
}

#[cfg(test)]
mod vectors;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_like_better_call() {
        let signed = sign_cookie(b"secret", "a b");
        assert!(signed.starts_with("a%20b."), "{signed}");
        assert!(signed.ends_with("%3D"), "{signed}");
        let decoded = decode_cookie(&signed);
        assert_eq!(verify_cookie(b"secret", &decoded), Some("a b"));
        assert_eq!(verify_cookie(b"other", &decoded), None);
    }

    #[test]
    fn decodes_like_try_decode() {
        assert_eq!(decode_cookie("abc"), "abc");
        assert_eq!(decode_cookie("a%3Db"), "a=b");
        assert_eq!(decode_cookie("a%zz"), "a%zz");
        assert_eq!(decode_cookie("a%2"), "a%2");
        assert_eq!(decode_cookie("%FF"), "%FF");
        assert_eq!(decode_cookie("%C3%A6"), "æ");
    }

    #[test]
    fn rejects_malformed_signatures() {
        let signed = decode_cookie(&sign_cookie(b"k", "tok")).into_owned();
        let (value, sig) = signed.rsplit_once('.').unwrap();
        assert_eq!(verify_cookie(b"k", &format!(".{sig}")), None);
        assert_eq!(verify_cookie(b"k", value), None);
        let url_safe = sig.replace('+', "-").replace('/', "_");
        if url_safe != sig {
            assert_eq!(verify_cookie(b"k", &format!("{value}.{url_safe}")), None);
        }
        assert_eq!(
            verify_cookie(b"k", &format!("{value}.{}", sig.trim_end_matches('='))),
            None
        );
    }

    #[test]
    fn scrypt_round_trips_and_normalizes() {
        let hasher = BetterAuthScrypt;
        let hash = hasher.hash("\u{fb01}sh").unwrap();
        let (salt, key) = hash.split_once(':').unwrap();
        assert_eq!(salt.len(), 32);
        assert_eq!(key.len(), 128);
        assert!(hasher.verify("fish", &hash).unwrap());
        assert!(!hasher.verify("fis", &hash).unwrap());
        assert!(!hasher.needs_rehash(&hash));
        assert!(hasher.verify("x", "nocolon").is_err());
        assert!(hasher.verify("x", ":key").is_err());
    }
}
