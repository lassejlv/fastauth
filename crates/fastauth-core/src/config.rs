use std::fmt;
use std::sync::Arc;

use time::Duration;
use url::Url;

use crate::crypto::{Argon2id, PasswordHasher};
use crate::rate_limit::RateLimit;

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

    /// Accepts relative paths (`/dashboard`) and absolute URLs on a trusted origin.
    pub fn is_safe_redirect(&self, target: &str) -> bool {
        if target.starts_with('/') {
            return !target.starts_with("//") && !target.starts_with("/\\");
        }
        Url::parse(target).is_ok_and(|u| self.is_trusted_origin(&u.origin().ascii_serialization()))
    }

    pub fn cookie_name(&self, name: &str) -> String {
        let secure = if self.secure_cookies { "__Secure-" } else { "" };
        format!("{secure}{}.{name}", self.cookies.prefix)
    }
}
