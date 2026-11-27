//! Rate limiting: GCRA in sharded in-memory maps, or fixed windows in secondary storage.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use time::Duration;
use zeroize::Zeroizing;

use crate::config::ClientIp;
use crate::storage::{DynStorage, StorageError};

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
    /// Keys account buckets, so they name no email and agree across instances that share
    /// the secret.
    account_key: Zeroizing<[u8; 32]>,
    /// Where counters live when the app configured secondary storage; in `shards` otherwise.
    storage: Option<Arc<dyn DynStorage>>,
    last_storage_error: Mutex<Option<Instant>>,
    warned_no_ip: AtomicBool,
    production: bool,
}

/// How often a failing secondary storage is logged.
const STORAGE_ERROR_LOG_EVERY: StdDuration = StdDuration::from_secs(60);

impl RateLimiter {
    /// `production` logs a request without a client IP as an error rather than a warning.
    /// With `storage`, counters live there and every instance sharing it shares the limits.
    pub(crate) fn new(
        config: RateLimit,
        production: bool,
        account_key: Zeroizing<[u8; 32]>,
        storage: Option<Arc<dyn DynStorage>>,
    ) -> Self {
        Self {
            config,
            shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
            hasher: RandomState::new(),
            account_key,
            storage,
            last_storage_error: Mutex::new(None),
            warned_no_ip: AtomicBool::new(false),
            production,
        }
    }

    /// Whether a request from `ip` may proceed. `path` is relative to the base path.
    pub(crate) async fn check(&self, ip: IpAddr, path: &str, body: &[u8]) -> bool {
        if !self.config.enabled {
            return true;
        }
        self.take_all(self.buckets(&self.client_key(ip), path, body))
            .await
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

    /// A fixed-size key for an account: a keyed hash, so a long `email` in a body costs no
    /// memory and secondary storage never sees the address.
    fn account_key(&self, account: &str) -> String {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.account_key.as_slice())
            .expect("HMAC takes any key length");
        mac.update(account.as_bytes());
        mac.finalize().into_bytes()[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Whether a request without a client IP may proceed. A JSON body naming an account
    /// (`email` or `username`) is limited per account, so one client guessing passwords can't
    /// throttle sign-in for everybody; other requests share one bucket, as in Better Auth.
    /// The first such request is logged.
    pub(crate) async fn check_without_ip(
        &self,
        source: &ClientIp,
        path: &str,
        body: &[u8],
    ) -> bool {
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
        let accounts = accounts_in(body);
        if accounts.is_empty() {
            return self
                .take_all(vec![self.rule_bucket(NO_CLIENT_IP, path)])
                .await;
        }
        let buckets = accounts
            .iter()
            .map(|account| {
                let client = format!("{NO_CLIENT_IP}:{}", self.account_key(account));
                self.rule_bucket(&client, path)
            })
            .collect();
        self.take_all(buckets).await
    }

    /// The buckets a request takes from, in order: the client's bucket for the route, then,
    /// on routes with a rule of their own, the bucket of each account the body names.
    fn buckets(&self, client: &str, path: &str, body: &[u8]) -> Vec<(String, Limit)> {
        let mut buckets = vec![self.rule_bucket(client, path)];
        let (rule, _) = self.config.limit_for(path);
        if let Some(limit) = self.config.account.filter(|_| rule != "*") {
            buckets.extend(accounts_in(body).iter().map(|account| {
                let key = format!("account:{}|{rule}", self.account_key(account));
                (key, limit)
            }));
        }
        buckets
    }

    fn rule_bucket(&self, client: &str, path: &str) -> (String, Limit) {
        let (rule, limit) = self.config.limit_for(path);
        let key = format!(
            "{client}|{rule}|{}",
            if rule.ends_with('*') { "" } else { path }
        );
        (key, limit)
    }

    /// Takes one request from each bucket in turn and stops at the first that is empty.
    async fn take_all(&self, buckets: Vec<(String, Limit)>) -> bool {
        let now = Instant::now();
        for (key, limit) in buckets {
            let allowed = match &self.storage {
                Some(storage) => self.take_shared(storage.as_ref(), key, limit, now).await,
                None => self.take(key, limit, now),
            };
            if !allowed {
                return false;
            }
        }
        true
    }

    /// A fixed window in secondary storage: the first request in a window sets the counter's
    /// TTL to the period, and the window allows `max` requests (Better Auth's
    /// secondary-storage limiter). When the storage fails, this instance's in-memory bucket
    /// decides, so limits still hold per instance.
    async fn take_shared(
        &self,
        storage: &dyn DynStorage,
        key: String,
        limit: Limit,
        now: Instant,
    ) -> bool {
        match storage
            .increment(&format!("fastauth:rate-limit:{key}"), limit.burst())
            .await
        {
            Ok(count) => count <= u64::from(limit.max),
            Err(err) => {
                self.log_storage_error(&err);
                self.take(key, limit, now)
            }
        }
    }

    fn log_storage_error(&self, err: &StorageError) {
        let mut last = self.last_storage_error.lock().unwrap();
        if last.is_some_and(|at| at.elapsed() < STORAGE_ERROR_LOG_EVERY) {
            return;
        }
        *last = Some(Instant::now());
        tracing::error!(
            error = %err,
            "fastauth: secondary storage failed, so rate limits fall back to this instance's \
             memory until it answers again"
        );
    }

    /// The in-memory check of a request at `now`, for tests.
    #[cfg(test)]
    fn check_at(&self, client: &str, path: &str, body: &[u8], now: Instant) -> bool {
        !self.config.enabled
            || self
                .buckets(client, path, body)
                .into_iter()
                .all(|(key, limit)| self.take(key, limit, now))
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
    use crate::storage::fake::FakeStorage;

    #[test]
    fn allows_burst_then_limits() {
        let limiter = in_memory(
            RateLimit::default().rule("/sign-in/*", Limit::per(Duration::seconds(10), 3)),
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

    #[tokio::test]
    async fn without_a_client_ip_limits_apply_per_named_account() {
        let limiter = in_memory(
            RateLimit::default().rule("/sign-in/*", Limit::per(Duration::seconds(10), 3)),
        );
        let source = ClientIp::Socket;
        let check =
            async |path: &str, body: &[u8]| limiter.check_without_ip(&source, path, body).await;
        let attacker = br#"{"email":"someone@acme.dk","password":"x"}"#;
        for _ in 0..3 {
            assert!(check("/sign-in/email", attacker).await);
        }
        assert!(!check("/sign-in/email", attacker).await);
        assert!(
            !check("/sign-in/email", br#"{"email":" SOMEONE@acme.dk "}"#).await,
            "the account key is normalized"
        );
        assert!(check("/sign-in/email", br#"{"email":"victim@acme.dk"}"#).await);
        assert!(check("/sign-in/username", br#"{"username":"ada"}"#).await);
        for _ in 0..3 {
            assert!(check("/sign-in/x", b"{}").await);
        }
        assert!(!check("/sign-in/x", b"").await, "the rest share a bucket");
    }

    #[test]
    fn ipv6_clients_share_their_prefix() {
        let limiter = in_memory(RateLimit::default());
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(limiter.client_key(a), "2001:db8:1:2::/64");
        assert_eq!(limiter.client_key(a), limiter.client_key(b));
        assert_ne!(limiter.client_key(a), limiter.client_key(other));
        let mapped: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
        assert_eq!(limiter.client_key(mapped), "203.0.113.9");
        let full = in_memory(RateLimit::default().ipv6_prefix(128));
        assert_ne!(full.client_key(a), full.client_key(b));
        let all = in_memory(RateLimit::default().ipv6_prefix(0));
        assert_eq!(all.client_key(a), "::/0");
    }

    #[test]
    fn keys_stay_under_max_keys() {
        let limiter = in_memory(RateLimit::default().max_keys(SHARDS * 10));
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
        let limiter = in_memory(
            RateLimit::default()
                .rule("/sign-in/*", Limit::per(Duration::seconds(10), 3))
                .account_limit(Some(Limit::per(Duration::minutes(10), 5))),
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

    fn in_memory(config: RateLimit) -> RateLimiter {
        RateLimiter::new(config, false, Zeroizing::new([7; 32]), None)
    }

    fn shared(config: RateLimit, storage: &FakeStorage) -> RateLimiter {
        RateLimiter::new(
            config,
            false,
            Zeroizing::new([7; 32]),
            Some(Arc::new(storage.clone())),
        )
    }

    fn sign_in_rule() -> RateLimit {
        RateLimit::default().rule("/sign-in/*", Limit::per(Duration::seconds(10), 3))
    }

    #[tokio::test]
    async fn instances_sharing_storage_share_limits() {
        let storage = FakeStorage::default();
        let a = shared(sign_in_rule(), &storage);
        let b = shared(sign_in_rule(), &storage);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(a.check(ip, "/sign-in/email", b"").await);
        assert!(b.check(ip, "/sign-in/email", b"").await);
        assert!(a.check(ip, "/sign-in/email", b"").await);
        assert!(
            !b.check(ip, "/sign-in/email", b"").await,
            "the fourth request is refused, whichever instance gets it"
        );
        assert!(!a.check(ip, "/sign-in/email", b"").await);
        assert!(
            a.check("203.0.113.8".parse().unwrap(), "/sign-in/email", b"")
                .await,
            "other clients are unaffected"
        );

        let alone = [in_memory(sign_in_rule()), in_memory(sign_in_rule())];
        let mut allowed = 0;
        for n in 0..8 {
            allowed += usize::from(alone[n % 2].check(ip, "/sign-in/email", b"").await);
        }
        assert_eq!(
            allowed, 6,
            "without shared storage, each instance allows the limit"
        );
    }

    #[tokio::test]
    async fn shared_windows_reset_after_the_period() {
        let storage = FakeStorage::default();
        let config =
            RateLimit::default().rule("/sign-in/*", Limit::per(Duration::milliseconds(300), 2));
        let limiter = shared(config, &storage);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(limiter.check(ip, "/sign-in/email", b"").await);
        assert!(limiter.check(ip, "/sign-in/email", b"").await);
        assert!(!limiter.check(ip, "/sign-in/email", b"").await);
        tokio::time::sleep(StdDuration::from_millis(400)).await;
        assert!(limiter.check(ip, "/sign-in/email", b"").await);
    }

    #[tokio::test]
    async fn account_limits_are_shared_and_name_no_email() {
        let storage = FakeStorage::default();
        let config = sign_in_rule().account_limit(Some(Limit::per(Duration::minutes(10), 5)));
        let instances = [shared(config.clone(), &storage), shared(config, &storage)];
        let body = br#"{"email":"ada@acme.dk"}"#;
        let mut allowed = 0;
        for n in 0..10 {
            let ip: IpAddr = format!("10.0.0.{n}").parse().unwrap();
            allowed += usize::from(instances[n % 2].check(ip, "/sign-in/email", body).await);
        }
        assert_eq!(allowed, 5, "the account limit spans clients and instances");
        assert!(
            storage
                .keys()
                .iter()
                .all(|key| key.starts_with("fastauth:rate-limit:")
                    && !key.contains("ada")
                    && !key.contains("acme")),
            "{:?}",
            storage.keys()
        );

        let other_secret =
            RateLimiter::new(RateLimit::default(), false, Zeroizing::new([8; 32]), None);
        assert_eq!(
            instances[0].account_key("ada@acme.dk"),
            instances[1].account_key("ada@acme.dk")
        );
        assert_ne!(
            instances[0].account_key("ada@acme.dk"),
            other_secret.account_key("ada@acme.dk")
        );
    }

    #[tokio::test]
    async fn a_failing_storage_falls_back_to_memory() {
        let storage = FakeStorage::default();
        let limiter = shared(sign_in_rule(), &storage);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(limiter.check(ip, "/sign-in/email", b"").await);
        storage.set_down(true);
        for _ in 0..3 {
            assert!(limiter.check(ip, "/sign-in/email", b"").await);
        }
        assert!(
            !limiter.check(ip, "/sign-in/email", b"").await,
            "the in-memory limit still applies"
        );
        storage.set_down(false);
        assert!(
            limiter.check(ip, "/sign-in/email", b"").await,
            "the shared counter decides again once the storage answers"
        );
    }

    #[tokio::test]
    async fn a_disabled_limiter_never_calls_the_storage() {
        let storage = FakeStorage::default();
        let limiter = shared(RateLimit::disabled(), &storage);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        for _ in 0..200 {
            assert!(limiter.check(ip, "/sign-in/email", b"").await);
        }
        assert!(storage.keys().is_empty());
    }
}
