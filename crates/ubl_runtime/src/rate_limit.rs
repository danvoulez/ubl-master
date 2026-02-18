//! Rate limiting for the UBL pipeline.
//!
//! Three independent limiters per ARCHITECTURE.md §14.2:
//! - Per-DID: 100 requests/min (authenticated identity)
//! - Per-tenant: 1000 requests/min (world scope)
//! - Per-IP: 10 requests/min (unauthenticated)
//!
//! Uses a simple sliding-window counter (no external deps).
//! Thread-safe via DashMap-style sharded locking (here: tokio RwLock + HashMap).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
pub use ubl_canon::CanonFingerprint;

/// Configuration for a single rate limit bucket.
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Maximum requests allowed in the window.
    pub max_requests: u32,
    /// Time window duration.
    pub window: Duration,
}

impl RateLimitConfig {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            max_requests,
            window,
        }
    }

    pub fn per_minute(max_requests: u32) -> Self {
        Self::new(max_requests, Duration::from_secs(60))
    }
}

/// Default rate limits per ARCHITECTURE.md §14.2.
pub fn default_did_limit() -> RateLimitConfig {
    RateLimitConfig::per_minute(100)
}

pub fn default_tenant_limit() -> RateLimitConfig {
    RateLimitConfig::per_minute(1000)
}

pub fn default_ip_limit() -> RateLimitConfig {
    RateLimitConfig::per_minute(10)
}

/// A sliding-window entry for one key.
#[derive(Debug)]
struct WindowEntry {
    /// Timestamps of requests within the current window.
    timestamps: Vec<Instant>,
}

impl WindowEntry {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
        }
    }

    /// Prune expired timestamps and check if a new request is allowed.
    fn check_and_record(&mut self, now: Instant, config: &RateLimitConfig) -> RateLimitResult {
        // Remove timestamps outside the window
        let cutoff = now - config.window;
        self.timestamps.retain(|t| *t > cutoff);

        let current = self.timestamps.len() as u32;
        if current >= config.max_requests {
            let oldest = self.timestamps[0];
            let retry_after = config.window - (now - oldest);
            RateLimitResult::Limited {
                limit: config.max_requests,
                remaining: 0,
                retry_after,
            }
        } else {
            self.timestamps.push(now);
            RateLimitResult::Allowed {
                limit: config.max_requests,
                remaining: config.max_requests - current - 1,
            }
        }
    }

    /// Check without recording (peek).
    fn remaining(&self, now: Instant, config: &RateLimitConfig) -> u32 {
        let cutoff = now - config.window;
        let active = self.timestamps.iter().filter(|t| **t > cutoff).count() as u32;
        config.max_requests.saturating_sub(active)
    }
}

/// Result of a rate limit check.
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    Allowed {
        limit: u32,
        remaining: u32,
    },
    Limited {
        limit: u32,
        remaining: u32,
        retry_after: Duration,
    },
}

impl RateLimitResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    pub fn is_limited(&self) -> bool {
        matches!(self, Self::Limited { .. })
    }

    pub fn remaining(&self) -> u32 {
        match self {
            Self::Allowed { remaining, .. } | Self::Limited { remaining, .. } => *remaining,
        }
    }

    pub fn limit(&self) -> u32 {
        match self {
            Self::Allowed { limit, .. } | Self::Limited { limit, .. } => *limit,
        }
    }

    pub fn retry_after_secs(&self) -> Option<u64> {
        match self {
            Self::Limited { retry_after, .. } => Some(retry_after.as_secs() + 1),
            _ => None,
        }
    }
}

/// A single rate limiter for one dimension (e.g., per-DID, per-tenant, per-IP).
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    entries: RwLock<HashMap<String, WindowEntry>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Check and record a request for the given key.
    pub async fn check(&self, key: &str) -> RateLimitResult {
        let now = Instant::now();
        let mut entries = self.entries.write().await;
        let entry = entries
            .entry(key.to_string())
            .or_insert_with(WindowEntry::new);
        entry.check_and_record(now, &self.config)
    }

    /// Peek at remaining quota without consuming.
    pub async fn remaining(&self, key: &str) -> u32 {
        let now = Instant::now();
        let entries = self.entries.read().await;
        entries
            .get(key)
            .map(|e| e.remaining(now, &self.config))
            .unwrap_or(self.config.max_requests)
    }

    /// Prune all expired entries (call periodically to prevent memory growth).
    pub async fn prune(&self) {
        let now = Instant::now();
        let cutoff = now - self.config.window;
        let mut entries = self.entries.write().await;
        entries.retain(|_, e| {
            e.timestamps.retain(|t| *t > cutoff);
            !e.timestamps.is_empty()
        });
    }
}

/// Combined rate limiter with all three dimensions.
#[derive(Clone)]
pub struct GateRateLimiter {
    pub did_limiter: Arc<RateLimiter>,
    pub tenant_limiter: Arc<RateLimiter>,
    pub ip_limiter: Arc<RateLimiter>,
}

impl GateRateLimiter {
    /// Create with default limits from ARCHITECTURE.md §14.2.
    pub fn new() -> Self {
        Self {
            did_limiter: Arc::new(RateLimiter::new(default_did_limit())),
            tenant_limiter: Arc::new(RateLimiter::new(default_tenant_limit())),
            ip_limiter: Arc::new(RateLimiter::new(default_ip_limit())),
        }
    }

    /// Create with custom limits.
    pub fn with_config(
        did_config: RateLimitConfig,
        tenant_config: RateLimitConfig,
        ip_config: RateLimitConfig,
    ) -> Self {
        Self {
            did_limiter: Arc::new(RateLimiter::new(did_config)),
            tenant_limiter: Arc::new(RateLimiter::new(tenant_config)),
            ip_limiter: Arc::new(RateLimiter::new(ip_config)),
        }
    }

    /// Check all three dimensions. Returns the first limit hit, or Allowed.
    /// Order: IP → tenant → DID (cheapest to most specific).
    pub async fn check(
        &self,
        ip: &str,
        tenant: Option<&str>,
        did: Option<&str>,
    ) -> GateRateLimitResult {
        // 1. IP limit (always checked)
        let ip_result = self.ip_limiter.check(ip).await;
        if ip_result.is_limited() {
            return GateRateLimitResult {
                allowed: false,
                limited_by: "ip".to_string(),
                result: ip_result,
            };
        }

        // 2. Tenant limit (if tenant known from @world)
        if let Some(t) = tenant {
            let tenant_result = self.tenant_limiter.check(t).await;
            if tenant_result.is_limited() {
                return GateRateLimitResult {
                    allowed: false,
                    limited_by: "tenant".to_string(),
                    result: tenant_result,
                };
            }
        }

        // 3. DID limit (if authenticated)
        if let Some(d) = did {
            let did_result = self.did_limiter.check(d).await;
            if did_result.is_limited() {
                return GateRateLimitResult {
                    allowed: false,
                    limited_by: "did".to_string(),
                    result: did_result,
                };
            }
        }

        GateRateLimitResult {
            allowed: true,
            limited_by: String::new(),
            result: ip_result,
        }
    }

    /// Prune all expired entries across all limiters.
    pub async fn prune_all(&self) {
        tokio::join!(
            self.did_limiter.prune(),
            self.tenant_limiter.prune(),
            self.ip_limiter.prune(),
        );
    }
}

impl Default for GateRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a combined gate rate limit check.
#[derive(Debug, Clone)]
pub struct GateRateLimitResult {
    pub allowed: bool,
    pub limited_by: String,
    pub result: RateLimitResult,
}

// ---------------------------------------------------------------------------
// Canon-aware rate limiting (P0.2)
// ---------------------------------------------------------------------------

/// Canon-aware rate limiter.
///
/// Limits by `canon_fingerprint` of the payload so that cosmetic JSON
/// variations (whitespace, key reordering) don't bypass the limit.
/// Default: 5 identical canonical payloads per minute.
#[derive(Clone)]
pub struct CanonRateLimiter {
    limiter: Arc<RateLimiter>,
}

impl CanonRateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            limiter: Arc::new(RateLimiter::new(config)),
        }
    }

    /// Default: 5 identical canonical payloads per minute.
    pub fn default_config() -> RateLimitConfig {
        RateLimitConfig::per_minute(5)
    }

    /// Check a chip body against the canon rate limit.
    /// Returns `None` if the body can't be canonicalized (non-JSON, etc.).
    pub async fn check_body(
        &self,
        body: &serde_json::Value,
    ) -> Option<(CanonFingerprint, RateLimitResult)> {
        let fp = CanonFingerprint::from_chip_body(body)?;
        let result = self.limiter.check(&fp.rate_key()).await;
        Some((fp, result))
    }

    /// Prune expired entries.
    pub async fn prune(&self) {
        self.limiter.prune().await;
    }
}

impl Default for CanonRateLimiter {
    fn default() -> Self {
        Self::new(Self::default_config())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn single_limiter_allows_under_limit() {
        let limiter = RateLimiter::new(RateLimitConfig::per_minute(5));
        for _ in 0..5 {
            assert!(limiter.check("key1").await.is_allowed());
        }
    }

    #[tokio::test]
    async fn single_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(RateLimitConfig::per_minute(3));
        assert!(limiter.check("key1").await.is_allowed());
        assert!(limiter.check("key1").await.is_allowed());
        assert!(limiter.check("key1").await.is_allowed());
        assert!(limiter.check("key1").await.is_limited());
    }

    #[tokio::test]
    async fn different_keys_independent() {
        let limiter = RateLimiter::new(RateLimitConfig::per_minute(2));
        assert!(limiter.check("a").await.is_allowed());
        assert!(limiter.check("a").await.is_allowed());
        assert!(limiter.check("a").await.is_limited());
        // Different key still has quota
        assert!(limiter.check("b").await.is_allowed());
    }

    #[tokio::test]
    async fn remaining_decrements() {
        let limiter = RateLimiter::new(RateLimitConfig::per_minute(5));
        assert_eq!(limiter.remaining("k").await, 5);
        limiter.check("k").await;
        assert_eq!(limiter.remaining("k").await, 4);
        limiter.check("k").await;
        assert_eq!(limiter.remaining("k").await, 3);
    }

    #[tokio::test]
    async fn retry_after_is_set_when_limited() {
        let limiter = RateLimiter::new(RateLimitConfig::per_minute(1));
        assert!(limiter.check("k").await.is_allowed());
        let result = limiter.check("k").await;
        assert!(result.is_limited());
        assert!(result.retry_after_secs().unwrap() > 0);
    }

    #[tokio::test]
    async fn window_expiry() {
        let limiter = RateLimiter::new(RateLimitConfig::new(2, Duration::from_millis(50)));
        assert!(limiter.check("k").await.is_allowed());
        assert!(limiter.check("k").await.is_allowed());
        assert!(limiter.check("k").await.is_limited());
        // Wait for window to expire
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(limiter.check("k").await.is_allowed());
    }

    #[tokio::test]
    async fn gate_limiter_checks_all_dimensions() {
        let gate = GateRateLimiter::with_config(
            RateLimitConfig::per_minute(100),
            RateLimitConfig::per_minute(1000),
            RateLimitConfig::per_minute(2), // tight IP limit for testing
        );
        let r1 = gate
            .check("1.2.3.4", Some("tenant1"), Some("did:key:z123"))
            .await;
        assert!(r1.allowed);
        let r2 = gate
            .check("1.2.3.4", Some("tenant1"), Some("did:key:z123"))
            .await;
        assert!(r2.allowed);
        let r3 = gate
            .check("1.2.3.4", Some("tenant1"), Some("did:key:z123"))
            .await;
        assert!(!r3.allowed);
        assert_eq!(r3.limited_by, "ip");
    }

    #[tokio::test]
    async fn gate_limiter_ip_blocks_first() {
        let gate = GateRateLimiter::with_config(
            RateLimitConfig::per_minute(1),
            RateLimitConfig::per_minute(1),
            RateLimitConfig::per_minute(1),
        );
        let r = gate.check("ip1", Some("t1"), Some("d1")).await;
        assert!(r.allowed);
        let r = gate.check("ip1", Some("t1"), Some("d1")).await;
        assert!(!r.allowed);
        assert_eq!(r.limited_by, "ip"); // IP checked first
    }

    #[tokio::test]
    async fn gate_limiter_tenant_blocks_second() {
        let gate = GateRateLimiter::with_config(
            RateLimitConfig::per_minute(100),
            RateLimitConfig::per_minute(1), // tight tenant
            RateLimitConfig::per_minute(100),
        );
        let r = gate.check("ip1", Some("t1"), Some("d1")).await;
        assert!(r.allowed);
        // Same tenant, different IP
        let r = gate.check("ip2", Some("t1"), Some("d1")).await;
        assert!(!r.allowed);
        assert_eq!(r.limited_by, "tenant");
    }

    #[tokio::test]
    async fn gate_limiter_did_blocks_third() {
        let gate = GateRateLimiter::with_config(
            RateLimitConfig::per_minute(1), // tight DID
            RateLimitConfig::per_minute(100),
            RateLimitConfig::per_minute(100),
        );
        let r = gate.check("ip1", Some("t1"), Some("d1")).await;
        assert!(r.allowed);
        // Same DID, different IP and tenant
        let r = gate.check("ip2", Some("t2"), Some("d1")).await;
        assert!(!r.allowed);
        assert_eq!(r.limited_by, "did");
    }

    #[tokio::test]
    async fn gate_limiter_no_tenant_no_did() {
        let gate = GateRateLimiter::new();
        let r = gate.check("1.2.3.4", None, None).await;
        assert!(r.allowed);
    }

    #[tokio::test]
    async fn prune_removes_expired() {
        let limiter = RateLimiter::new(RateLimitConfig::new(10, Duration::from_millis(20)));
        limiter.check("a").await;
        limiter.check("b").await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        limiter.prune().await;
        // After prune, entries should be gone
        assert_eq!(limiter.remaining("a").await, 10);
        assert_eq!(limiter.remaining("b").await, 10);
    }

    #[tokio::test]
    async fn default_limits_match_spec() {
        let did = default_did_limit();
        assert_eq!(did.max_requests, 100);
        assert_eq!(did.window, Duration::from_secs(60));

        let tenant = default_tenant_limit();
        assert_eq!(tenant.max_requests, 1000);

        let ip = default_ip_limit();
        assert_eq!(ip.max_requests, 10);
    }

    // ── Canon-aware rate limit tests ──

    #[test]
    fn canon_fingerprint_deterministic() {
        let body = serde_json::json!({
            "@type": "ubl/user",
            "@ver": "1.0",
            "@world": "a/acme/t/prod",
            "@id": "alice",
            "name": "Alice"
        });
        let fp1 = CanonFingerprint::from_chip_body(&body).unwrap();
        let fp2 = CanonFingerprint::from_chip_body(&body).unwrap();
        assert_eq!(fp1.hash, fp2.hash);
        assert_eq!(fp1.at_type, "ubl/user");
        assert_eq!(fp1.at_world, "a/acme/t/prod");
    }

    #[test]
    fn canon_fingerprint_ignores_key_order() {
        let body1 = serde_json::json!({
            "@type": "ubl/user",
            "@ver": "1.0",
            "@world": "a/x/t/y",
            "@id": "a",
            "name": "Alice"
        });
        // Same fields, different insertion order (serde_json::json! sorts, but
        // NRF-1 canonical encoding guarantees same output regardless)
        let body2 = serde_json::json!({
            "name": "Alice",
            "@id": "a",
            "@world": "a/x/t/y",
            "@ver": "1.0",
            "@type": "ubl/user"
        });
        let fp1 = CanonFingerprint::from_chip_body(&body1).unwrap();
        let fp2 = CanonFingerprint::from_chip_body(&body2).unwrap();
        assert_eq!(fp1.hash, fp2.hash, "key order must not affect fingerprint");
    }

    #[test]
    fn canon_fingerprint_different_content_different_hash() {
        let body1 = serde_json::json!({"@type": "ubl/user", "@ver": "1.0", "@world": "a/x/t/y", "@id": "a"});
        let body2 = serde_json::json!({"@type": "ubl/user", "@ver": "1.0", "@world": "a/x/t/y", "@id": "b"});
        let fp1 = CanonFingerprint::from_chip_body(&body1).unwrap();
        let fp2 = CanonFingerprint::from_chip_body(&body2).unwrap();
        assert_ne!(fp1.hash, fp2.hash);
    }

    #[test]
    fn canon_fingerprint_rate_key_format() {
        let body = serde_json::json!({"@type": "ubl/token", "@ver": "2.0", "@world": "a/acme/t/prod", "@id": "tok1"});
        let fp = CanonFingerprint::from_chip_body(&body).unwrap();
        let key = fp.rate_key();
        assert!(key.starts_with("ubl/token|2.0|a/acme/t/prod|"));
        assert_eq!(key.matches('|').count(), 3);
    }

    #[tokio::test]
    async fn canon_rate_limiter_blocks_identical_payloads() {
        let limiter = CanonRateLimiter::new(RateLimitConfig::per_minute(2));
        let body = serde_json::json!({
            "@type": "ubl/user", "@ver": "1.0", "@world": "a/x/t/y",
            "@id": "spam", "data": "same"
        });

        let (_, r1) = limiter.check_body(&body).await.unwrap();
        assert!(r1.is_allowed());
        let (_, r2) = limiter.check_body(&body).await.unwrap();
        assert!(r2.is_allowed());
        let (_, r3) = limiter.check_body(&body).await.unwrap();
        assert!(r3.is_limited(), "3rd identical payload must be blocked");
    }

    #[tokio::test]
    async fn canon_rate_limiter_allows_different_payloads() {
        let limiter = CanonRateLimiter::new(RateLimitConfig::per_minute(1));
        let body1 = serde_json::json!({"@type": "ubl/user", "@ver": "1.0", "@world": "a/x/t/y", "@id": "a"});
        let body2 = serde_json::json!({"@type": "ubl/user", "@ver": "1.0", "@world": "a/x/t/y", "@id": "b"});

        let (_, r1) = limiter.check_body(&body1).await.unwrap();
        assert!(r1.is_allowed());
        // Different payload — different bucket
        let (_, r2) = limiter.check_body(&body2).await.unwrap();
        assert!(r2.is_allowed());
    }

    #[tokio::test]
    async fn canon_rate_limiter_cosmetic_variations_same_bucket() {
        let limiter = CanonRateLimiter::new(RateLimitConfig::per_minute(1));

        let body1 = serde_json::json!({
            "@type": "ubl/user", "@ver": "1.0", "@world": "a/x/t/y",
            "@id": "alice", "name": "Alice"
        });
        let body2 = serde_json::json!({
            "name": "Alice", "@id": "alice", "@world": "a/x/t/y",
            "@ver": "1.0", "@type": "ubl/user"
        });

        let (fp1, r1) = limiter.check_body(&body1).await.unwrap();
        assert!(r1.is_allowed());
        let (fp2, r2) = limiter.check_body(&body2).await.unwrap();
        assert_eq!(
            fp1.hash, fp2.hash,
            "cosmetic variation must have same fingerprint"
        );
        assert!(r2.is_limited(), "cosmetic variation must hit same bucket");
    }
}
