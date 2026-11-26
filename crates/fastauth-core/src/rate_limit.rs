//! GCRA rate limiting: one timestamp per key, in sharded in-memory maps.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::{IpAddr, Ipv6Addr};
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
    pub(crate) account: Option<Limit>,
    pub(crate) ipv6_prefix: u8,
    pub(crate) max_keys: usize,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            enabled: true,
            default: Limit::per(Duration::seconds(10), 100),
            rules: Vec::new(),
            account: Some(Limit::per(Duration::minutes(10), 30)),
            ipv6_prefix: 64,
            max_keys: 100_000,
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

    /// A second limit on routes with a rule of their own (sign-in, sign-up, password reset,
    /// plugin routes that send mail or check codes), kept per account the JSON body names
    /// (`email` or `username`) whatever the client IP. It stops guesses at one account
    /// spread over many addresses. Default: 30 requests per 10 minutes; `None` turns it off.
    pub fn account_limit(mut self, limit: Option<Limit>) -> Self {
        self.account = limit;
        self
    }

    /// IPv6 clients share one bucket per network prefix of this many bits (default 64, as in
    /// Better Auth), because one subscriber or cloud VM holds a whole /64. 128 keeps every
    /// address apart.
    pub fn ipv6_prefix(mut self, bits: u8) -> Self {
        assert!(bits <= 128, "an IPv6 prefix is at most 128 bits");
        self.ipv6_prefix = bits;
        self
    }

    /// The most keys the limiter keeps in memory (default 100,000). When it is full, expired
    /// keys go first, then the half closest to expiry.
    pub fn max_keys(mut self, max: usize) -> Self {
        assert!(max > 0, "the rate limiter keeps at least one key");
        self.max_keys = max;
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

/// Every so many inserts, a shard drops its expired keys.
const PRUNE_EVERY: u32 = 1024;

/// The accounts a JSON body names, lowercased: its `email` and its `username`.
fn accounts_in(body: &[u8]) -> Vec<String> {
    #[derive(serde::Deserialize)]
    struct Named {
        email: Option<String>,
        username: Option<String>,
    }
    let Ok(named) = serde_json::from_slice::<Named>(body) else {
        return Vec::new();
    };
    [named.email, named.username]
        .into_iter()
        .flatten()
        .map(|account| account.trim().to_lowercase())
        .collect()
}

#[derive(Default)]
struct Shard {
    keys: HashMap<String, Instant>,
    inserts: u32,
}

pub(crate) struct RateLimiter {
    config: RateLimit,
    shards: Vec<Mutex<Shard>>,
    hasher: RandomState,
    warned_no_ip: AtomicBool,
    production: bool,
}

impl RateLimiter {
    /// `production` logs a request without a client IP as an error rather than a warning.
    pub(crate) fn new(config: RateLimit, production: bool) -> Self {
        Self {
            config,
            shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
            hasher: RandomState::new(),
            warned_no_ip: AtomicBool::new(false),
            production,
        }
    }

    /// Whether a request from `ip` may proceed. `path` is relative to the base path.
    pub(crate) fn check(&self, ip: IpAddr, path: &str, body: &[u8]) -> bool {
        self.check_at(&self.client_key(ip), path, body, Instant::now())
    }

    /// The bucket of a client address: the address for IPv4, its network prefix for IPv6.
    fn client_key(&self, ip: IpAddr) -> String {
        match ip.to_canonical() {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => {
                let prefix = self.config.ipv6_prefix;
                let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
                format!("{}/{prefix}", Ipv6Addr::from(u128::from(v6) & mask))
            }
        }
    }

    /// A fixed-size key for an account, so a long `email` in a body costs no memory.
    fn account_key(&self, account: &str) -> String {
        format!("{:016x}", self.hasher.hash_one(account))
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
            let header = match source {
                ClientIp::Socket => None,
                ClientIp::Header(header) | ClientIp::TrustedProxies { header, .. } => {
                    Some(header.as_str())
                }
            };
            let message = match header {
                None => {
                    "fastauth can't tell clients apart: requests carry no client socket address, \
                     so rate limits are per account or shared by everyone. In axum, serve with \
                     into_make_service_with_connect_info::<SocketAddr>(); behind a proxy, set \
                     .client_ip(ClientIp::Header(..)) or ClientIp::TrustedProxies"
                }
                Some(_) => {
                    "fastauth got a request without a valid client IP in its client IP header, \
                     so rate limits are per account or shared by everyone. Check that the proxy \
                     sets the header and that ClientIp matches the proxy chain"
                }
            };
            if self.production {
                tracing::error!(header, "{message}");
            } else {
                tracing::warn!(header, "{message}");
            }
        }
        let now = Instant::now();
        let accounts = accounts_in(body);
        if accounts.is_empty() {
            return self.take_rule(NO_CLIENT_IP, path, now);
        }
        accounts.iter().all(|account| {
            let client = format!("{NO_CLIENT_IP}:{}", self.account_key(account));
            self.take_rule(&client, path, now)
        })
    }

    /// The client's bucket for the route, then, on routes with a rule of their own, the
    /// bucket of each account the body names.
    fn check_at(&self, client: &str, path: &str, body: &[u8], now: Instant) -> bool {
        if !self.config.enabled {
            return true;
        }
        if !self.take_rule(client, path, now) {
            return false;
        }
        let (rule, _) = self.config.limit_for(path);
        let Some(limit) = self.config.account.filter(|_| rule != "*") else {
            return true;
        };
        accounts_in(body).iter().all(|account| {
            let key = format!("account:{}|{rule}", self.account_key(account));
            self.take(key, limit, now)
        })
    }

    fn take_rule(&self, client: &str, path: &str, now: Instant) -> bool {
        let (rule, limit) = self.config.limit_for(path);
        let key = format!(
            "{client}|{rule}|{}",
            if rule.ends_with('*') { "" } else { path }
        );
        self.take(key, limit, now)
    }

    /// GCRA on one key. Each shard holds at most its share of `max_keys`.
    fn take(&self, key: String, limit: Limit, now: Instant) -> bool {
        let shard = &self.shards[self.hasher.hash_one(&key) as usize % SHARDS];
        let mut shard = shard.lock().unwrap();
        let cap = (self.config.max_keys / SHARDS).max(1);
        shard.inserts = shard.inserts.wrapping_add(1);
        if shard.inserts.is_multiple_of(PRUNE_EVERY)
            || (shard.keys.len() >= cap && !shard.keys.contains_key(&key))
        {
            shard.keys.retain(|_, tat| *tat > now);
        }
        if shard.keys.len() >= cap && !shard.keys.contains_key(&key) {
            let mut tats: Vec<Instant> = shard.keys.values().copied().collect();
            let middle = tats.len() / 2;
            let cutoff = *tats.select_nth_unstable(middle).1;
            shard.keys.retain(|_, tat| *tat > cutoff);
        }
        let tat = shard.keys.get(&key).copied().unwrap_or(now).max(now);
        let next = tat + limit.interval();
        if next > now + limit.burst() {
            return false;
        }
        shard.keys.insert(key, next);
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
            false,
        );
        let now = Instant::now();
        assert!((0..3).all(|_| limiter.check_at("1.2.3.4", "/sign-in/email", b"", now)));
        assert!(!limiter.check_at("1.2.3.4", "/sign-in/email", b"", now));
        assert!(
            limiter.check_at("5.6.7.8", "/sign-in/email", b"", now),
            "other clients are unaffected"
        );
        assert!(limiter.check_at(
            "1.2.3.4",
            "/sign-in/email",
            b"",
            now + StdDuration::from_secs(4)
        ));
    }

    #[test]
    fn without_a_client_ip_limits_apply_per_named_account() {
        let limiter = RateLimiter::new(
            RateLimit::default().rule("/sign-in/*", Limit::per(Duration::seconds(10), 3)),
            false,
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

    #[test]
    fn ipv6_clients_share_their_prefix() {
        let limiter = RateLimiter::new(RateLimit::default(), false);
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(limiter.client_key(a), "2001:db8:1:2::/64");
        assert_eq!(limiter.client_key(a), limiter.client_key(b));
        assert_ne!(limiter.client_key(a), limiter.client_key(other));
        let mapped: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
        assert_eq!(limiter.client_key(mapped), "203.0.113.9");
        let full = RateLimiter::new(RateLimit::default().ipv6_prefix(128), false);
        assert_ne!(full.client_key(a), full.client_key(b));
        let all = RateLimiter::new(RateLimit::default().ipv6_prefix(0), false);
        assert_eq!(all.client_key(a), "::/0");
    }

    #[test]
    fn keys_stay_under_max_keys() {
        let limiter = RateLimiter::new(RateLimit::default().max_keys(SHARDS * 10), false);
        let now = Instant::now();
        for n in 0..5_000 {
            assert!(limiter.check_at(&format!("10.0.{}.{}", n / 256, n % 256), "/x", b"", now));
        }
        let kept: usize = limiter
            .shards
            .iter()
            .map(|s| s.lock().unwrap().keys.len())
            .sum();
        assert!(kept <= SHARDS * 10, "{kept} keys kept");
    }

    #[test]
    fn account_limit_spans_clients_on_ruled_routes() {
        let limiter = RateLimiter::new(
            RateLimit::default()
                .rule("/sign-in/*", Limit::per(Duration::seconds(10), 3))
                .account_limit(Some(Limit::per(Duration::minutes(10), 5))),
            false,
        );
        let now = Instant::now();
        let body = br#"{"email":"ada@acme.dk"}"#;
        let allowed = (0..10)
            .filter(|n| limiter.check_at(&format!("10.0.0.{n}"), "/sign-in/email", body, now))
            .count();
        assert_eq!(allowed, 5);
        assert!(
            (0..10).all(|n| limiter.check_at(&format!("10.0.1.{n}"), "/other", body, now)),
            "routes on the default limit have no account limit"
        );
    }
}
