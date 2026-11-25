//! GCRA rate limiting: one timestamp per key, in sharded in-memory maps.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::sync::Mutex;
use std::time::{Duration as StdDuration, Instant};

use time::Duration;

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

pub(crate) struct RateLimiter {
    config: RateLimit,
    shards: Vec<Mutex<HashMap<String, Instant>>>,
    hasher: RandomState,
}

impl RateLimiter {
    pub(crate) fn new(config: RateLimit) -> Self {
        Self {
            config,
            shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
            hasher: RandomState::new(),
        }
    }

    /// Whether the request may proceed. `path` is relative to the base path.
    pub(crate) fn check(&self, client: &str, path: &str) -> bool {
        self.check_at(client, path, Instant::now())
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
}
