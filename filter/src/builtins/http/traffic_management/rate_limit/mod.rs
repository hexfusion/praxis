// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Token bucket rate limiter.

mod config;
mod limiter;

pub use self::config::RateLimitMode;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "tests"
)]
mod tests;

use std::{
    hash::Hash,
    net::IpAddr,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::Instant,
};

use async_trait::async_trait;
use dashmap::DashMap;

use self::config::RateLimitConfig;
use super::token_bucket::TokenBucket;
use crate::{
    FilterAction, FilterError, Rejection,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Rate-Limiter Constants
// -----------------------------------------------------------------------------

/// Maximum number of per-IP entries before eviction is triggered.
const MAX_PER_IP_ENTRIES: usize = 100_000;

/// Hard cap on per-IP entries; new IPs are rejected with 429 above this.
///
/// Acts as a safety net above the soft eviction threshold. Prevents
/// unbounded memory growth when attackers rotate source addresses
/// faster than the eviction scan can reclaim entries.
const HARD_CAP_PER_IP_ENTRIES: usize = 200_000; // 2 * MAX_PER_IP_ENTRIES

/// Minimum interval between eviction passes.
///
/// [`DashMap::retain`] takes a write lock on every shard and visits
/// every entry, so an eviction pass is O(entries) and excludes all
/// concurrent access for its duration. Running it per request would
/// make the limiter collapse exactly when the map is largest. Passes
/// are therefore rate-limited to at most one per interval, which
/// bounds the amortised cost to O(entries) per second regardless of
/// request rate. [`HARD_CAP_PER_IP_ENTRIES`] bounds growth between
/// passes.
///
/// [`DashMap::retain`]: dashmap::DashMap::retain
const EVICTION_INTERVAL_NANOS: u64 = 1_000_000_000; // 1 s

/// Rate limit header: maximum bucket capacity.
const HEADER_RATELIMIT_LIMIT: &str = "X-RateLimit-Limit";

/// Rate limit header: remaining tokens.
const HEADER_RATELIMIT_REMAINING: &str = "X-RateLimit-Remaining";

/// Rate limit header: Unix timestamp when the bucket fully refills.
const HEADER_RATELIMIT_RESET: &str = "X-RateLimit-Reset";

// -----------------------------------------------------------------------------
// RateLimitState
// -----------------------------------------------------------------------------

/// Per-filter state: either a single global bucket or per-IP buckets.
enum RateLimitState {
    /// One shared bucket for all clients.
    Global(TokenBucket),

    /// Independent bucket per source IP address.
    PerIp(KeyedState<IpAddr>),

    /// Independent bucket per authenticated principal.
    PerIdentity(KeyedState<String>),

    /// Independent bucket per authenticated peer site.
    PerPeer(KeyedState<String>),
}

// -----------------------------------------------------------------------------
// KeyedState
// -----------------------------------------------------------------------------

/// Keyed buckets plus the bookkeeping that keeps eviction off the
/// per-request path.
///
/// Generic over the key so `per_ip` and `per_identity` share one
/// implementation: the eviction cursor, the approximate entry count and
/// the cap heuristics are properties of a keyed bucket map, not of what
/// the key happens to be.
struct KeyedState<K: Eq + Hash> {
    /// One token bucket per key.
    buckets: DashMap<K, TokenBucket>,

    /// Approximate live entry count.
    ///
    /// Maintained alongside `buckets` so that cap checks are a single
    /// atomic load. [`DashMap::len`] sums a read lock over every shard,
    /// which is too costly to run per request on the new-address path —
    /// precisely the path an address-rotation flood takes.
    ///
    /// Concurrent inserts racing an eviction pass can leave this off by
    /// a small amount. It gates soft-cap and hard-cap heuristics, both
    /// of which tolerate drift; it is never used as an exact size.
    ///
    /// [`DashMap::len`]: dashmap::DashMap::len
    entries: AtomicUsize,

    /// Filter-epoch nanos at which the last eviction pass was claimed.
    last_eviction_nanos: AtomicU64,
}

impl<K: Eq + Hash> KeyedState<K> {
    /// Create empty keyed state.
    fn new() -> Self {
        Self::from_buckets(DashMap::new())
    }

    /// Wrap an existing bucket map, seeding the entry count from it.
    fn from_buckets(buckets: DashMap<K, TokenBucket>) -> Self {
        let entries = AtomicUsize::new(buckets.len());
        Self {
            buckets,
            entries,
            last_eviction_nanos: AtomicU64::new(0),
        }
    }

    /// Approximate live entry count.
    fn entries(&self) -> usize {
        self.entries.load(Ordering::Relaxed)
    }

    /// Try to claim the right to run an eviction pass.
    ///
    /// Returns `true` for at most one caller per
    /// [`EVICTION_INTERVAL_NANOS`]. Losers of the race return `false`
    /// immediately rather than blocking, so a burst of concurrent
    /// requests produces one pass, not one per request.
    fn claim_eviction_pass(&self, now_nanos: u64) -> bool {
        let last = self.last_eviction_nanos.load(Ordering::Relaxed);
        if now_nanos.saturating_sub(last) < EVICTION_INTERVAL_NANOS {
            return false;
        }
        self.last_eviction_nanos
            .compare_exchange(last, now_nanos, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }
}

// -----------------------------------------------------------------------------
// Limit
// -----------------------------------------------------------------------------

/// The rate and capacity in force for one request.
///
/// Constant for `global` and `per_ip`. Resolved per request for
/// `per_identity`, so one filter instance can hold different limits for
/// different principals. [`TokenBucket`] takes both per call and stores
/// neither, so a changed limit applies from the next refill with no
/// re-provisioning.
#[derive(Clone, Copy, Debug)]
struct Limit {
    /// Tokens replenished per second.
    rate: f64,

    /// Maximum bucket capacity.
    burst: f64,
}

// -----------------------------------------------------------------------------
// RateLimitFilter
// -----------------------------------------------------------------------------

/// Token bucket rate limiter that rejects excess traffic with 429.
///
/// Supports `global` (one shared bucket), `per_ip` (one bucket per
/// source IP), and `per_identity` (one bucket per authenticated
/// principal) modes. Rate limit headers (`X-RateLimit-Limit`,
/// `X-RateLimit-Remaining`, `X-RateLimit-Reset`) are injected into
/// both 429 rejections and successful responses.
///
/// `per_identity` keys on the [`AuthenticatedIdentity`] a trusted
/// authentication filter published, so a caller cannot select its own
/// bucket and the limit survives NAT and replica changes. A request
/// carrying no authenticated identity is rejected rather than given a
/// fresh bucket. Its rate and capacity can come from issuer-signed
/// claims, so one filter instance holds different limits for different
/// principals without a table of them.
///
/// State is all managed locally.
///
/// [`AuthenticatedIdentity`]: crate::AuthenticatedIdentity
///
/// # YAML configuration
///
/// ```yaml
/// filter: rate_limit
/// mode: per_ip        # "global", "per_ip", or "per_identity"
/// rate: 100           # tokens per second
/// burst: 200          # max bucket capacity
/// ```
///
/// Keyed on the authenticated principal, with issuer-signed limits:
///
/// ```yaml
/// filter: rate_limit
/// mode: per_identity
/// key_claim: grid_site      # optional; defaults to the subject id
/// rate_claim: grid_rate     # optional; falls back to `rate`
/// burst_claim: grid_burst   # optional; falls back to `burst`
/// rate: 10
/// burst: 20
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::RateLimitFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// mode: global
/// rate: 50
/// burst: 100
/// "#,
/// )
/// .unwrap();
/// let filter = RateLimitFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "rate_limit");
/// ```
///
/// [`DashMap`]: dashmap::DashMap
pub struct RateLimitFilter {
    /// Bucket state (global or per-IP).
    pub(self) state: RateLimitState,

    /// Tokens replenished per second.
    pub(self) rate: f64,

    /// Maximum bucket capacity.
    pub(self) burst: f64,

    /// Custom claim naming the bucket, `per_identity` only.
    pub(self) key_claim: Option<String>,

    /// Custom claim holding the principal's rate, `per_identity` only.
    pub(self) rate_claim: Option<String>,

    /// Custom claim holding the principal's burst, `per_identity` only.
    pub(self) burst_claim: Option<String>,

    /// Pre-built `X-RateLimit-*` header names, so the response path inserts
    /// them without re-validating the constant names on every response.
    pub(self) header_limit: http::header::HeaderName,
    /// Pre-built `X-RateLimit-Remaining` header name.
    pub(self) header_remaining: http::header::HeaderName,
    /// Pre-built `X-RateLimit-Reset` header name.
    pub(self) header_reset: http::header::HeaderName,

    /// Monotonic clock reference; all timestamps are offsets from this.
    pub(self) epoch: Instant,
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "limiter logic is split into a dedicated module"
)]
impl RateLimitFilter {
    /// Reject claim settings on a mode that cannot use them.
    ///
    /// # Errors
    ///
    /// Returns an error if any claim field is set outside
    /// `per_identity`, so a misplaced key fails at startup rather than
    /// silently limiting the wrong thing.
    fn validate_claims(cfg: &RateLimitConfig) -> Result<(), FilterError> {
        if matches!(cfg.mode, RateLimitMode::PerIdentity) {
            return Ok(());
        }
        if cfg.key_claim.is_some() || cfg.rate_claim.is_some() || cfg.burst_claim.is_some() {
            return Err("rate_limit: key_claim, rate_claim and burst_claim require mode per_identity".into());
        }
        Ok(())
    }

    /// Create a rate limit filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns an error if any field is missing, `rate` is not
    /// positive, `burst` is zero, or `burst < rate`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use praxis_filter::RateLimitFilter;
    ///
    /// let yaml: serde_yaml::Value = serde_yaml::from_str(
    ///     r#"
    /// mode: per_ip
    /// rate: 100
    /// burst: 200
    /// "#,
    /// )
    /// .unwrap();
    /// let filter = RateLimitFilter::from_config(&yaml).unwrap();
    /// assert_eq!(filter.name(), "rate_limit");
    ///
    /// // Invalid: rate is zero.
    /// let bad: serde_yaml::Value = serde_yaml::from_str("mode: global\nrate: 0\nburst: 10").unwrap();
    /// assert!(RateLimitFilter::from_config(&bad).is_err());
    /// ```
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: RateLimitConfig = parse_filter_config("rate_limit", config)?;

        if !cfg.rate.is_finite() || cfg.rate <= 0.0 {
            return Err("rate_limit: rate must be a finite number greater than 0".into());
        }
        if cfg.burst == 0 {
            return Err("rate_limit: burst must be at least 1".into());
        }
        if f64::from(cfg.burst) < cfg.rate {
            return Err("rate_limit: burst must be >= rate".into());
        }

        Self::validate_claims(&cfg)?;

        let burst = f64::from(cfg.burst);
        let state = match cfg.mode {
            RateLimitMode::Global => RateLimitState::Global(TokenBucket::new(burst)),
            RateLimitMode::PerIp => RateLimitState::PerIp(KeyedState::new()),
            RateLimitMode::PerIdentity => RateLimitState::PerIdentity(KeyedState::new()),
            RateLimitMode::PerPeer => RateLimitState::PerPeer(KeyedState::new()),
        };

        Ok(Box::new(Self {
            state,
            rate: cfg.rate,
            burst,
            key_claim: cfg.key_claim,
            rate_claim: cfg.rate_claim,
            burst_claim: cfg.burst_claim,
            // Lowercase literals: HeaderName::from_static panics on uppercase,
            // and HeaderMap stores names lowercased anyway, matching the wire
            // output of the previous from_bytes(HEADER_RATELIMIT_*) path.
            header_limit: http::header::HeaderName::from_static("x-ratelimit-limit"),
            header_remaining: http::header::HeaderName::from_static("x-ratelimit-remaining"),
            header_reset: http::header::HeaderName::from_static("x-ratelimit-reset"),
            epoch: Instant::now(),
        }))
    }
}

#[async_trait]
impl HttpFilter for RateLimitFilter {
    fn name(&self) -> &'static str {
        "rate_limit"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let principal = self.principal(ctx);
        let limit = self.resolve_limit(ctx);
        match self.try_acquire_for(ctx.client_addr, principal.as_deref(), limit) {
            Ok(_remaining) => Ok(FilterAction::Continue),
            Err(remaining) => {
                tracing::info!(
                    client = ?ctx.client_addr,
                    "rate_limit: rejecting request (429)"
                );
                let (headers, retry_secs) = Self::rate_limit_headers(remaining, limit, ctx.time_source);

                let mut rejection = Rejection::status(429).with_header("Retry-After", format!("{retry_secs}"));
                for (name, value) in headers {
                    rejection = rejection.with_header(name, value);
                }
                Ok(FilterAction::Reject(rejection))
            },
        }
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let principal = self.principal(ctx);
        let limit = self.resolve_limit(ctx);
        let remaining = self.current_remaining(ctx.client_addr, principal.as_deref(), limit);
        let (remaining_str, reset_str, _retry_secs) = Self::rate_limit_values(remaining, limit, ctx.time_source);

        // Formatted per response rather than precomputed: under
        // `per_identity` the capacity varies by principal, so a cached
        // string would describe the wrong caller.
        #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "burst fits u64")]
        let limit_str = (limit.burst as u64).to_string();
        if let Some(ref mut resp) = ctx.response_header {
            for (name, value) in [
                (&self.header_limit, limit_str.as_str()),
                (&self.header_remaining, remaining_str.as_str()),
                (&self.header_reset, reset_str.as_str()),
            ] {
                if let Ok(hv) = value.parse() {
                    resp.headers.insert(name, hv);
                    ctx.response_headers_modified = true;
                }
            }
        }

        Ok(FilterAction::Continue)
    }
}
