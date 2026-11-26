use std::fmt;
use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use url::Url;

use crate::crypto::{Argon2id, PasswordHasher};
use crate::error::AuthError;
use crate::models::Session;
use crate::rate_limit::RateLimit;
use crate::schema::IdStorage;
use crate::value::Id;

type PasswordPolicy = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Email and password sign-in. Off unless `.email_password(..)` is called.
#[derive(Clone)]
pub struct EmailPassword {
    pub(crate) min_password_length: usize,
    pub(crate) max_password_length: usize,
    pub(crate) require_email_verification: bool,
    pub(crate) auto_sign_in: bool,
    pub(crate) revoke_sessions_on_password_reset: bool,
    pub(crate) reset_password_ttl: Duration,
    pub(crate) password_policy: Option<PasswordPolicy>,
    pub(crate) hasher: Arc<dyn PasswordHasher>,
}

impl fmt::Debug for EmailPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmailPassword")
            .field("min_password_length", &self.min_password_length)
            .field("max_password_length", &self.max_password_length)
            .field(
                "require_email_verification",
                &self.require_email_verification,
            )
            .field("auto_sign_in", &self.auto_sign_in)
            .finish_non_exhaustive()
    }
}

impl Default for EmailPassword {
    fn default() -> Self {
        Self {
            min_password_length: 8,
            max_password_length: 128,
            require_email_verification: false,
            auto_sign_in: true,
            revoke_sessions_on_password_reset: false,
            reset_password_ttl: Duration::hours(1),
            password_policy: None,
            hasher: Arc::new(Argon2id::owasp()),
        }
    }
}

impl EmailPassword {
    /// Whether a password reset signs the user out everywhere, for plugins that reset passwords.
    pub fn revokes_sessions_on_password_reset(&self) -> bool {
        self.revoke_sessions_on_password_reset
    }

    /// Whether sign-in needs a verified email, for plugins that sign in with a password.
    pub fn requires_email_verification(&self) -> bool {
        self.require_email_verification
    }

    /// The longest password accepted, for plugins that check passwords.
    pub fn max_password_len(&self) -> usize {
        self.max_password_length
    }

    pub fn min_password_length(mut self, n: usize) -> Self {
        self.min_password_length = n;
        self
    }

    pub fn max_password_length(mut self, n: usize) -> Self {
        self.max_password_length = n;
        self
    }

    /// Sign-in fails with `EMAIL_NOT_VERIFIED` until the user verifies. Needs a mailer.
    pub fn require_email_verification(mut self, on: bool) -> Self {
        self.require_email_verification = on;
        self
    }

    /// Sign-up returns a session (default true). Ignored when verification is required.
    pub fn auto_sign_in(mut self, on: bool) -> Self {
        self.auto_sign_in = on;
        self
    }

    pub fn revoke_sessions_on_password_reset(mut self, on: bool) -> Self {
        self.revoke_sessions_on_password_reset = on;
        self
    }

    pub fn reset_password_ttl(mut self, ttl: Duration) -> Self {
        self.reset_password_ttl = ttl;
        self
    }

    /// Extra check on new passwords; returning false answers `PASSWORD_TOO_WEAK`.
    pub fn password_policy(
        mut self,
        policy: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.password_policy = Some(Arc::new(policy));
        self
    }

    pub fn hasher(mut self, hasher: impl PasswordHasher) -> Self {
        self.hasher = Arc::new(hasher);
        self
    }
}

#[derive(Clone, Debug)]
pub struct EmailVerification {
    pub(crate) send_on_sign_up: bool,
    pub(crate) auto_sign_in_after_verification: bool,
    pub(crate) ttl: Duration,
}

impl Default for EmailVerification {
    fn default() -> Self {
        Self {
            send_on_sign_up: true,
            auto_sign_in_after_verification: false,
            ttl: Duration::hours(1),
        }
    }
}

impl EmailVerification {
    /// Whether verifying an email signs the user in, for plugins that verify emails.
    pub fn auto_signs_in_after_verification(&self) -> bool {
        self.auto_sign_in_after_verification
    }

    pub fn send_on_sign_up(mut self, on: bool) -> Self {
        self.send_on_sign_up = on;
        self
    }

    pub fn auto_sign_in_after_verification(mut self, on: bool) -> Self {
        self.auto_sign_in_after_verification = on;
        self
    }

    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }
}

#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub(crate) expires_in: Duration,
    pub(crate) update_age: Duration,
    pub(crate) fresh_age: Duration,
    pub(crate) cookie_cache: Option<Duration>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            expires_in: Duration::days(7),
            update_age: Duration::days(1),
            fresh_age: Duration::days(1),
            cookie_cache: None,
        }
    }
}

impl SessionConfig {
    /// How long a session lasts, and the session cookie's `Max-Age`, for plugins that set
    /// session cookies of their own.
    pub fn lifetime(&self) -> Duration {
        self.expires_in
    }

    pub fn expires_in(mut self, d: Duration) -> Self {
        self.expires_in = d;
        self
    }

    /// Extend the expiry at most this often (default one day).
    pub fn update_age(mut self, d: Duration) -> Self {
        self.update_age = d;
        self
    }

    /// `Fresh` endpoints need a session created within this window. Zero disables the check.
    pub fn fresh_age(mut self, d: Duration) -> Self {
        self.fresh_age = d;
        self
    }

    /// A signed cookie caching the session for `max_age`. Saves the DB lookup, at the cost
    /// of revocations taking up to `max_age` to reach other devices.
    pub fn cookie_cache(mut self, max_age: Duration) -> Self {
        self.cookie_cache = Some(max_age);
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Secure {
    /// Secure (and `__Secure-` prefixed) when `base_url` is https.
    Auto,
    Always,
    Never,
}

#[derive(Clone, Debug)]
pub struct CookieConfig {
    pub(crate) prefix: String,
    pub(crate) same_site: SameSite,
    pub(crate) domain: Option<String>,
    pub(crate) secure: Secure,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            prefix: "fastauth".into(),
            same_site: SameSite::Lax,
            domain: None,
            secure: Secure::Auto,
        }
    }
}

impl CookieConfig {
    /// `"better-auth"` makes cookie names match a Better Auth server.
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    pub fn secure(mut self, secure: Secure) -> Self {
        self.secure = secure;
        self
    }
}

/// Where the client IP comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientIp {
    /// The socket address the integration puts in request extensions (default).
    Socket,
    /// A header set by a proxy you trust, e.g. `fly-client-ip`. Take the first value.
    Header(String),
}

type IdGenerator = Arc<dyn Fn() -> String + Send + Sync>;

/// How fastauth generates the ids of the rows it creates: users, sessions, accounts,
/// verifications and every row a plugin creates through `ctx.new_id()`.
///
/// Set it with `FastAuth::builder().ids(..)`. The strategy also picks how id columns are
/// stored ([`IdStrategy::storage`]): the UUID strategies use Postgres' native `uuid` type,
/// the others `text`. Switching strategies on an existing database doesn't convert its
/// columns; the migrator warns about the mismatch instead.
///
/// ```
/// use fastauth_core::config::IdStrategy;
///
/// let id = IdStrategy::default().generate().unwrap();
/// assert_eq!(id.as_str().len(), 26);
///
/// let custom = IdStrategy::custom(|| {
///     format!("usr_{}", fastauth_core::crypto::random_string(12, b"0123456789abcdef"))
/// });
/// assert!(custom.generate().unwrap().as_str().starts_with("usr_"));
/// ```
#[derive(Clone, Default)]
pub enum IdStrategy {
    /// A [ULID](https://github.com/ulid/spec): 26 characters of Crockford base32, sortable
    /// by creation time. Stored as `text`. The default.
    #[default]
    Ulid,
    /// A UUIDv7 in hyphenated form, sortable by creation time. Stored as `uuid` on Postgres.
    UuidV7,
    /// A random UUIDv4 in hyphenated form. Stored as `uuid` on Postgres.
    UuidV4,
    /// Ids from your own function, stored as `text`. Every id is checked when it's
    /// generated: an empty one, or one longer than [`IdStrategy::MAX_LEN`] bytes, fails the
    /// request with a 500 and an error log line. Ids must be unique; fastauth doesn't retry.
    Custom(IdGenerator),
}

impl IdStrategy {
    /// The longest id, in bytes, a custom generator may return.
    pub const MAX_LEN: usize = 255;

    /// `IdStrategy::Custom` from a closure.
    pub fn custom(generate: impl Fn() -> String + Send + Sync + 'static) -> Self {
        IdStrategy::Custom(Arc::new(generate))
    }

    /// A new id. Only a custom generator can fail: with a 500 `INTERNAL_SERVER_ERROR`
    /// whose detail is logged, never sent to the client.
    pub fn generate(&self) -> Result<Id, AuthError> {
        let id = match self {
            IdStrategy::Ulid => ulid(OffsetDateTime::now_utc()),
            IdStrategy::UuidV7 => uuid::Uuid::now_v7().to_string(),
            IdStrategy::UuidV4 => uuid::Uuid::new_v4().to_string(),
            IdStrategy::Custom(generate) => {
                let id = generate();
                if id.is_empty() {
                    return Err(AuthError::internal(
                        "the custom id generator (IdStrategy::Custom) returned an empty id",
                    ));
                }
                if id.len() > Self::MAX_LEN {
                    return Err(AuthError::internal(format_args!(
                        "the custom id generator (IdStrategy::Custom) returned a {}-byte id; ids are at most {} bytes",
                        id.len(),
                        Self::MAX_LEN
                    )));
                }
                id
            }
        };
        Ok(Id::from(id))
    }

    /// How id columns are stored for this strategy.
    pub fn storage(&self) -> IdStorage {
        match self {
            IdStrategy::UuidV7 | IdStrategy::UuidV4 => IdStorage::Uuid,
            IdStrategy::Ulid | IdStrategy::Custom(_) => IdStorage::Text,
        }
    }
}

impl fmt::Debug for IdStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdStrategy::Ulid => f.write_str("Ulid"),
            IdStrategy::UuidV7 => f.write_str("UuidV7"),
            IdStrategy::UuidV4 => f.write_str("UuidV4"),
            IdStrategy::Custom(_) => f.write_str("Custom(..)"),
        }
    }
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A ULID for `at`: 48 bits of Unix milliseconds, then 80 random bits, as 26 base32 digits.
fn ulid(at: OffsetDateTime) -> String {
    let millis = (at.unix_timestamp_nanos() / 1_000_000) as u128 & ((1 << 48) - 1);
    let mut random = [0u8; 16];
    getrandom::fill(&mut random[6..]).expect("the OS random number generator is available");
    let value = millis << 80 | u128::from_be_bytes(random);
    (0..26)
        .rev()
        .map(|digit| CROCKFORD[(value >> (digit * 5)) as usize & 31] as char)
        .collect()
}

/// Everything the builder collected, frozen at `.build()`.
#[derive(Clone, Debug)]
pub struct CoreConfig {
    pub app_name: String,
    pub base_url: Url,
    pub base_path: String,
    pub trusted_origins: Vec<String>,
    pub session: SessionConfig,
    pub cookies: CookieConfig,
    pub email_password: Option<EmailPassword>,
    pub email_verification: EmailVerification,
    pub rate_limit: RateLimit,
    pub client_ip: ClientIp,
    pub ids: IdStrategy,
    pub(crate) secure_cookies: bool,
}

impl CoreConfig {
    /// `https://acme.dk/api/auth`
    pub fn auth_url(&self) -> String {
        format!(
            "{}{}",
            self.base_url.as_str().trim_end_matches('/'),
            self.base_path
        )
    }

    pub fn is_trusted_origin(&self, origin: &str) -> bool {
        let origin = origin.trim_end_matches('/');
        origin == self.base_url.origin().ascii_serialization()
            || self.trusted_origins.iter().any(|o| o == origin)
    }

    /// Accepts relative paths (`/dashboard`) and absolute URLs on a trusted origin. See
    /// [`CoreConfig::resolve_redirect`].
    pub fn is_safe_redirect(&self, target: &str) -> bool {
        self.resolve_redirect(target).is_some()
    }

    /// Where a browser lands when redirected to `target`, or `None` when that isn't safe.
    ///
    /// Control characters and backslashes are refused anywhere, because browsers drop or
    /// reinterpret them (`/\t/evil.example` opens `//evil.example`). A relative target must
    /// start with a single `/`, have no encoded `/` or `\` (`%2f`, `%5c`) in its path, and
    /// still be on `base_url`'s origin once resolved against it. An absolute target must be on
    /// a trusted origin.
    pub fn resolve_redirect(&self, target: &str) -> Option<Url> {
        if target.chars().any(char::is_control) || target.contains('\\') {
            return None;
        }
        if !target.starts_with('/') {
            return Url::parse(target)
                .ok()
                .filter(|u| self.is_trusted_origin(&u.origin().ascii_serialization()));
        }
        let path = target
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if target.starts_with("//") || path.contains("%2f") || path.contains("%5c") {
            return None;
        }
        self.base_url
            .join(target)
            .ok()
            .filter(|u| u.origin() == self.base_url.origin())
    }

    /// Whether `session` was created within `fresh_age`, the rule behind `Fresh` access.
    /// A zero `fresh_age` makes every session fresh.
    pub fn is_fresh(&self, session: &Session) -> bool {
        let fresh_age = self.session.fresh_age;
        fresh_age.is_zero() || OffsetDateTime::now_utc() - session.created_at <= fresh_age
    }

    pub fn cookie_name(&self, name: &str) -> String {
        let secure = if self.secure_cookies { "__Secure-" } else { "" };
        format!("{secure}{}.{name}", self.cookies.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_ulid_millis(id: &str) -> i128 {
        let value = id.bytes().fold(0u128, |acc, ch| {
            let digit = CROCKFORD
                .iter()
                .position(|&c| c == ch)
                .expect("crockford digit");
            acc << 5 | digit as u128
        });
        (value >> 80) as i128
    }

    #[test]
    fn ulid_is_26_crockford_characters_with_the_current_time() {
        let before = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
        let id = IdStrategy::Ulid.generate().unwrap();
        let after = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
        let id = id.as_str();
        assert_eq!(id.len(), 26, "{id}");
        assert!(id.bytes().all(|b| CROCKFORD.contains(&b)), "{id}");
        assert!(id.as_bytes()[0] <= b'7', "a ULID fits in 128 bits: {id}");
        assert!((before..=after).contains(&decode_ulid_millis(id)), "{id}");
        assert_ne!(id, IdStrategy::Ulid.generate().unwrap().as_str());
    }

    #[test]
    fn ulids_sort_by_time() {
        let base = OffsetDateTime::now_utc();
        let ids: Vec<String> = (0..50)
            .map(|ms| ulid(base + Duration::milliseconds(ms)))
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);

        let first = IdStrategy::Ulid.generate().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let second = IdStrategy::Ulid.generate().unwrap();
        assert!(first < second, "{first:?} < {second:?}");
    }

    #[test]
    fn uuid_strategies_have_their_version_nibble() {
        for (strategy, version) in [(IdStrategy::UuidV7, '7'), (IdStrategy::UuidV4, '4')] {
            let id = strategy.generate().unwrap();
            let id = id.as_str();
            assert_eq!(id.len(), 36, "{id}");
            assert_eq!(id.as_bytes()[14] as char, version, "{id}");
            assert!(
                matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b'),
                "{id}"
            );
            assert_eq!(strategy.storage(), IdStorage::Uuid);
        }
    }

    #[test]
    fn custom_ids_are_validated() {
        let ok = IdStrategy::custom(|| "x".repeat(IdStrategy::MAX_LEN));
        assert_eq!(ok.generate().unwrap().as_str().len(), 255);
        assert_eq!(ok.storage(), IdStorage::Text);

        for bad in [String::new(), "x".repeat(IdStrategy::MAX_LEN + 1)] {
            let strategy = IdStrategy::custom(move || bad.clone());
            let err = strategy.generate().unwrap_err();
            assert_eq!(err.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(err.code(), crate::error::codes::INTERNAL);
        }
        assert_eq!(format!("{ok:?}"), "Custom(..)");
    }
}
