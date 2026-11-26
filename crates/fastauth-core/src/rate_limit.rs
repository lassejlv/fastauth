//! GCRA rate limiting: one timestamp per key, in sharded in-memory maps.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration as StdDuration, Instant};

use time::Duration;

use crate::config::ClientIp;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit {
    pub period: Duration,
    pub max: u32,
}

impl Limit {
    /// `max` requests per `period`, allowing bursts of `max`.
    pub fn per(period: Duration, max: u32) -> Self {
        assert!(max > 0, "a rate limit allows at least one request");
        Self { period, max }
    }

    fn interval(&self) -> StdDuration {
        StdDuration::try_from(self.period).unwrap_or(StdDuration::ZERO) / self.max
    }

    fn burst(&self) -> StdDuration {
        StdDuration::try_from(self.period).unwrap_or(StdDuration::ZERO)
    }
}

/// A path pattern: exact (`/sign-in/email`) or prefix (`/sign-in/*`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub pattern: String,
    pub limit: Limit,
}

impl Rule {
    fn matches(&self, path: &str) -> bool {
        match self.pattern.strip_suffix('*') {
            Some(prefix) => path.starts_with(prefix),
            None => self.pattern == path,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RateLimit {
    pub(crate) enabled: bool,
    pub(crate) default: Limit,
    /// Checked in order; the first match wins. App rules come first, then plugin rules, then core.
    pub(crate) rules: Vec<Rule>,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            enabled: true,
            default: Limit::per(Duration::seconds(10), 100),
            rules: Vec::new(),
        }
    }
}

impl RateLimit {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }

    pub fn default_limit(mut self, limit: Limit) -> Self {
        self.default = limit;
        self
    }

    pub fn rule(mut self, pattern: impl Into<String>, limit: Limit) -> Self {
        self.rules.push(Rule {
            pattern: pattern.into(),
            limit,
        });
        self
    }

    pub(crate) fn core_rules() -> Vec<Rule> {
        let strict = Limit::per(Duration::seconds(10), 3);
        [
            "/sign-in/*",
            "/sign-up/*",
            "/request-password-reset",
            "/forget-password",
            "/send-verification-email",
            "/change-password",
        ]
        .into_iter()
        .map(|p| Rule {
            pattern: p.into(),
            limit: strict,
        })
        .collect()
    }

    fn limit_for(&self, path: &str) -> (&str, Limit) {
        self.rules
            .iter()
            .find(|r| r.matches(path))
            .map_or(("*", self.default), |r| (r.pattern.as_str(), r.limit))
    }
}

const SHARDS: usize = 16;

/// The key prefix for requests without a client IP. Not an IP, so it can't collide with one.
const NO_CLIENT_IP: &str = "no-client-ip";

/// The account a JSON body names, lowercased: its `email`, else its `username`.
fn account_in(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Named {
        email: Option<String>,
        username: Option<String>,
    }
    let named: Named = serde_json::from_slice(body).ok()?;
    let account = named.email.or(named.username)?;
    Some(account.trim().to_lowercase())
}

pub(crate) struct RateLimiter {
    config: RateLimit,
    shards: Vec<Mutex<HashMap<String, Instant>>>,
    hasher: RandomState,
    warned_no_ip: AtomicBool,
}

impl RateLimiter {
    pub(crate) fn new(config: RateLimit) -> Self {
        Self {
            config,
            shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
            hasher: RandomState::new(),
            warned_no_ip: AtomicBool::new(false),
        }
    }

    /// Whether the request may proceed. `path` is relative to the base path.
    pub(crate) fn check(&self, client: &str, path: &str) -> bool {
        self.check_at(client, path, Instant::now())
    }

    /// Whether a request without a client IP may proceed. A JSON body naming an account
    /// (`email` or `username`) is limited per account, so one client guessing passwords can't
    /// throttle sign-in for everybody; other requests share one bucket, as in Better Auth.
    /// The first such request is logged.
    pub(crate) fn check_without_ip(&self, source: &ClientIp, path: &str, body: &[u8]) -> bool {
        if !self.config.enabled {
            return true;
        }
        if !self.warned_no_ip.swap(true, Ordering::Relaxed) {
            match source {
                ClientIp::Socket => tracing::warn!(
                    "fastauth can't tell clients apart: requests carry no client socket address, \
                     so rate limits are per account or shared by everyone. In axum, serve with \
                     into_make_service_with_connect_info::<SocketAddr>(); behind a proxy, set \
                     .client_ip(ClientIp::Header(..)) or ClientIp::TrustedProxies"
                ),
                ClientIp::Header(header) | ClientIp::TrustedProxies { header, .. } => {
                    tracing::warn!(
                        header = header.as_str(),
                        "fastauth got a request without a valid client IP in its client IP \
                         header, so rate limits are per account or shared by everyone. Check \
                         that the proxy sets the header and that ClientIp matches the proxy chain"
                    )
                }
            }
        }
        match account_in(body) {
            Some(account) => self.check(&format!("{NO_CLIENT_IP}:{account}"), path),
            None => self.check(NO_CLIENT_IP, path),
        }
    }

    fn check_at(&self, client: &str, path: &str, now: Instant) -> bool {
        if !self.config.enabled {
            return true;
        }
        let (rule, limit) = self.config.limit_for(path);
        let key = format!(
            "{client}|{rule}|{}",
            if rule.ends_with('*') { "" } else { path }
        );
        let shard = &self.shards[self.hasher.hash_one(&key) as usize % SHARDS];
        let mut map = shard.lock().unwrap();
        if map.len() > 50_000 {
            map.retain(|_, tat| *tat > now);
        }
        let interval = limit.interval();
        let tat = map.get(&key).copied().unwrap_or(now).max(now);
        let next = tat + interval;
        if next > now + limit.burst() {
            return false;
        }
        map.insert(key, next);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_burst_then_limits() {
        let limiter = RateLimiter::new(
            RateLimit::default().rule("/sign-in/*", Limit::per(Duration::seconds(10), 3)),
        );
        let now = Instant::now();
        assert!((0..3).all(|_| limiter.check_at("1.2.3.4", "/sign-in/email", now)));
        assert!(!limiter.check_at("1.2.3.4", "/sign-in/email", now));
        assert!(
            limiter.check_at("5.6.7.8", "/sign-in/email", now),
            "other clients are unaffected"
        );
        assert!(limiter.check_at("1.2.3.4", "/sign-in/email", now + StdDuration::from_secs(4)));
    }

    #[test]
    fn without_a_client_ip_limits_apply_per_named_account() {
        let limiter = RateLimiter::new(
            RateLimit::default().rule("/sign-in/*", Limit::per(Duration::seconds(10), 3)),
        );
        let source = ClientIp::Socket;
        let attacker = br#"{"email":"someone@acme.dk","password":"x"}"#;
        assert!((0..3).all(|_| limiter.check_without_ip(&source, "/sign-in/email", attacker)));
        assert!(!limiter.check_without_ip(&source, "/sign-in/email", attacker));
        assert!(
            !limiter.check_without_ip(
                &source,
                "/sign-in/email",
                br#"{"email":" SOMEONE@acme.dk "}"#
            ),
            "the account key is normalized"
        );
        assert!(limiter.check_without_ip(
            &source,
            "/sign-in/email",
            br#"{"email":"victim@acme.dk"}"#
        ));
        assert!(limiter.check_without_ip(&source, "/sign-in/username", br#"{"username":"ada"}"#));
        assert!((0..3).all(|_| limiter.check_without_ip(&source, "/sign-in/x", b"{}")));
        assert!(
            !limiter.check_without_ip(&source, "/sign-in/x", b""),
            "the rest share a bucket"
        );
    }
}
