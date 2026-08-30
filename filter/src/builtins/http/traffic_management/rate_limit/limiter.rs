// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Rate limiting logic: token acquisition, eviction, and header generation.

use std::{hash::Hash, net::IpAddr, sync::atomic::Ordering};

use dashmap::mapref::entry::Entry;
use praxis_core::connectivity::normalize_mapped_ipv4;

use super::{
    HARD_CAP_PER_IP_ENTRIES, HEADER_RATELIMIT_LIMIT, HEADER_RATELIMIT_REMAINING, HEADER_RATELIMIT_RESET, KeyedState,
    Limit, MAX_PER_IP_ENTRIES, RateLimitFilter, RateLimitState,
};
use crate::{
    AuthenticatedIdentity, builtins::http::traffic_management::token_bucket::TokenBucket, filter::HttpFilterContext,
};

// -----------------------------------------------------------------------------
// Token Acquisition
// -----------------------------------------------------------------------------

impl RateLimitFilter {
    /// Nanoseconds elapsed since this filter's epoch.
    pub(super) fn now_nanos(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    /// Compute the `X-RateLimit-Remaining`/`-Reset` header values and the
    /// `Retry-After` seconds (floored at 1 when the client is rate-limited).
    ///
    /// Shared by the response path (which inserts headers directly) and the
    /// 429 rejection path (which builds an owned header list).
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "token count truncation"
    )]
    pub(super) fn rate_limit_values(
        remaining: f64,
        limit: Limit,
        time_source: &dyn praxis_core::time::TimeSource,
    ) -> (String, String, u64) {
        let retry_secs = if remaining < 1.0 {
            ((1.0 - remaining) / limit.rate).ceil().max(1.0) as u64
        } else {
            0
        };
        let now_unix = time_source.now().as_secs();
        let reset_unix = now_unix.saturating_add(retry_secs);
        let remaining_int = remaining.max(0.0) as u64;
        (format!("{remaining_int}"), format!("{reset_unix}"), retry_secs)
    }

    /// Build rate limit headers and compute the retry-after value.
    ///
    /// Returns the header list and the `Retry-After` seconds. Used by the
    /// cold 429 rejection path; the response path inserts pre-built header
    /// names directly instead.
    #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "burst fits u64")]
    pub(super) fn rate_limit_headers(
        remaining: f64,
        limit: Limit,
        time_source: &dyn praxis_core::time::TimeSource,
    ) -> (Vec<(&'static str, String)>, u64) {
        let (remaining_str, reset_str, retry_secs) = Self::rate_limit_values(remaining, limit, time_source);
        let headers = vec![
            (HEADER_RATELIMIT_LIMIT, (limit.burst as u64).to_string()),
            (HEADER_RATELIMIT_REMAINING, remaining_str),
            (HEADER_RATELIMIT_RESET, reset_str),
        ];
        (headers, retry_secs)
    }

    /// Evict stale entries from a per-IP map when it exceeds [`MAX_PER_IP_ENTRIES`].
    ///
    /// Removes buckets whose `last_refill` is older than
    /// `2 * burst / rate` seconds, meaning the bucket would be fully
    /// refilled and idle.
    ///
    /// Passes are claimed through [`PerIpState::claim_eviction_pass`],
    /// so at most one caller per [`EVICTION_INTERVAL_NANOS`] performs
    /// the scan and everyone else returns without touching the map.
    /// This ordering matters: the interval is checked *before* the
    /// entry count, because reading the count from the map itself
    /// would already cost a read lock on every shard.
    ///
    /// A pass evicts every eligible entry rather than stopping after a
    /// fixed number. [`DashMap::retain`] visits all entries regardless
    /// of what the callback returns, so a partial scan reclaims less
    /// for exactly the same cost.
    ///
    /// [`DashMap::retain`]: dashmap::DashMap::retain
    /// [`EVICTION_INTERVAL_NANOS`]: super::EVICTION_INTERVAL_NANOS
    pub(super) fn maybe_evict<K: Eq + Hash>(&self, state: &KeyedState<K>, now_nanos: u64) {
        if !state.claim_eviction_pass(now_nanos) {
            return;
        }
        if state.entries() <= MAX_PER_IP_ENTRIES {
            return;
        }

        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "rate/burst nanos"
        )]
        let idle_threshold_nanos = (2.0 * self.burst / self.rate * 1_000_000_000.0) as u64;

        let mut evicted = 0_usize;
        state.buckets.retain(|_key, bucket| {
            let last = bucket.last_refill_nanos();
            if now_nanos.saturating_sub(last) > idle_threshold_nanos {
                evicted += 1;
                return false;
            }
            true
        });

        if evicted > 0 {
            let remaining = state.entries.fetch_sub(evicted, Ordering::Relaxed) - evicted;
            tracing::debug!(evicted, remaining, "rate_limit: evicted stale entries");
        }
    }

    /// Resolve the bucket key for this request from the authenticated
    /// principal.
    ///
    /// Returns `None` for every mode except `per_identity`, and for a
    /// request that carries no [`AuthenticatedIdentity`]. That extension
    /// is published only by a trusted authentication filter and its
    /// fields are read-only outside the crate, so a caller cannot select
    /// its own bucket.
    ///
    /// [`AuthenticatedIdentity`]: crate::AuthenticatedIdentity
    pub(super) fn principal(&self, ctx: &HttpFilterContext<'_>) -> Option<String> {
        match self.state {
            RateLimitState::PerIdentity(_) => {
                let identity = ctx.extensions.get::<AuthenticatedIdentity>()?;
                match self.key_claim.as_ref() {
                    Some(claim) => identity.custom_claims().get(claim).cloned(),
                    None => Some(identity.subject_id().to_owned()),
                }
            },
            // The name the handshake proved, not one the caller sent. A
            // certificate presenting several URI SANs names nobody, so it
            // has no bucket and is refused.
            RateLimitState::PerPeer(_) => ctx.peer_identity.as_ref()?.spiffe_id().map(str::to_owned),
            RateLimitState::Global(_) | RateLimitState::PerIp(_) => None,
        }
    }

    /// The limit as configured, before any per-principal override.
    pub(super) fn static_limit(&self) -> Limit {
        Limit {
            rate: self.rate,
            burst: self.burst,
        }
    }

    /// Resolve the rate and capacity in force for this request.
    ///
    /// Under `per_identity` the values can come from claims on the
    /// validated credential. The identity provider signs them, so the
    /// limit is asserted by the issuer rather than by the caller, and
    /// the filter enforces a per-principal limit without holding a
    /// table of principals.
    ///
    /// An absent or unusable claim falls back to the configured limit,
    /// so a provider that publishes nothing keeps the static behaviour
    /// rather than no limit at all.
    pub(super) fn resolve_limit(&self, ctx: &HttpFilterContext<'_>) -> Limit {
        if !matches!(self.state, RateLimitState::PerIdentity(_)) {
            return self.static_limit();
        }
        let Some(identity) = ctx.extensions.get::<AuthenticatedIdentity>() else {
            return self.static_limit();
        };

        let read = |claim: Option<&String>| -> Option<f64> {
            let raw = identity.custom_claims().get(claim?)?;
            let parsed = raw.parse::<f64>().ok()?;
            parsed.is_finite().then_some(parsed)
        };

        let rate = read(self.rate_claim.as_ref()).unwrap_or(self.rate);
        let burst = read(self.burst_claim.as_ref()).unwrap_or(self.burst);

        // The same invariants from_config enforces on the static values.
        // A credential carrying nonsense must not disable the limiter.
        if rate <= 0.0 || burst < 1.0 || burst < rate {
            tracing::warn!(
                rate,
                burst,
                "rate_limit: claimed limit is not usable, using configured limit"
            );
            return self.static_limit();
        }
        Limit { rate, burst }
    }

    /// Try to acquire a token for the given request context.
    ///
    /// IPv4-mapped IPv6 addresses are normalized to plain IPv4 before
    /// keying the per-IP map (defense in depth; the Pingora boundary
    /// normalizes too).
    pub(super) fn try_acquire_for(
        &self,
        client_addr: Option<IpAddr>,
        principal: Option<&str>,
        limit: Limit,
    ) -> Result<f64, f64> {
        let now = self.now_nanos();
        match &self.state {
            RateLimitState::Global(bucket) => Self::acquire_from_bucket(bucket, limit, now),
            RateLimitState::PerIp(state) => {
                let ip = client_addr.map(normalize_mapped_ipv4);
                if ip.is_none() {
                    tracing::info!("rate_limit: rejecting request with no client address");
                }
                self.acquire_keyed(state, ip, now, limit)
            },
            RateLimitState::PerIdentity(state) => {
                if principal.is_none() {
                    tracing::info!("rate_limit: rejecting request with no authenticated identity");
                }
                self.acquire_keyed(state, principal.map(str::to_owned), now, limit)
            },
            RateLimitState::PerPeer(state) => {
                if principal.is_none() {
                    tracing::info!("rate_limit: rejecting request with no named peer");
                }
                self.acquire_keyed(state, principal.map(str::to_owned), now, limit)
            },
        }
    }

    /// Keyed token acquisition with hard cap enforcement.
    ///
    /// A request with no key is rejected rather than given a fresh
    /// bucket. Granting one would hand every unidentified caller an
    /// unlimited supply of full buckets, which inverts the point of a
    /// rate limit.
    ///
    /// Unknown keys are rejected once the map exceeds
    /// [`HARD_CAP_PER_IP_ENTRIES`], preventing unbounded memory growth
    /// through address or principal rotation.
    fn acquire_keyed<K: Eq + Hash>(
        &self,
        state: &KeyedState<K>,
        key: Option<K>,
        now: u64,
        limit: Limit,
    ) -> Result<f64, f64> {
        let Some(key) = key else {
            return Err(0.0);
        };
        self.maybe_evict(state, now);

        if let Some(bucket) = state.buckets.get(&key) {
            return Self::acquire_from_bucket(&bucket, limit, now);
        }

        if state.entries() >= HARD_CAP_PER_IP_ENTRIES {
            tracing::warn!(
                entries = state.entries(),
                hard_cap = HARD_CAP_PER_IP_ENTRIES,
                "rate_limit: tracked-entry hard cap reached, rejecting new key"
            );
            return Err(0.0);
        }

        // Insert through the entry API so a genuinely new key can be
        // distinguished from one another thread inserted concurrently;
        // only the former advances the entry count.
        match state.buckets.entry(key) {
            Entry::Occupied(occupied) => Self::acquire_from_bucket(occupied.get(), limit, now),
            Entry::Vacant(vacant) => {
                let bucket = vacant.insert(TokenBucket::new(limit.burst));
                state.entries.fetch_add(1, Ordering::Relaxed);
                Self::acquire_from_bucket(&bucket, limit, now)
            },
        }
    }

    /// Try to acquire one token from a single bucket.
    fn acquire_from_bucket(bucket: &TokenBucket, limit: Limit, now: u64) -> Result<f64, f64> {
        match bucket.try_acquire(limit.rate, limit.burst, now) {
            Some(remaining) => Ok(remaining),
            None => Err(bucket.current_tokens(limit.rate, limit.burst, now)),
        }
    }

    /// Debit a metered cost from the caller's bucket after the response.
    ///
    /// The mirror of [`try_acquire_for`] for `meter: tokens`: rather than
    /// consuming one unit at admission, it subtracts `amount` (the tokens
    /// the response used) once the cost is known. A request with no key is
    /// not debited, matching how [`acquire_keyed`] refuses one admission.
    ///
    /// [`try_acquire_for`]: Self::try_acquire_for
    /// [`acquire_keyed`]: Self::acquire_keyed
    pub(super) fn debit_for(&self, client_addr: Option<IpAddr>, principal: Option<&str>, limit: Limit, amount: f64) {
        match &self.state {
            RateLimitState::Global(bucket) => {
                bucket.debit(limit.rate, limit.burst, self.now_nanos(), amount);
            },
            RateLimitState::PerIp(state) => {
                self.debit_keyed(state, client_addr.map(normalize_mapped_ipv4), limit, amount);
            },
            RateLimitState::PerIdentity(state) | RateLimitState::PerPeer(state) => {
                self.debit_keyed(state, principal.map(str::to_owned), limit, amount);
            },
        }
    }

    /// Keyed debit, get-or-creating the bucket like [`acquire_keyed`].
    ///
    /// [`acquire_keyed`]: Self::acquire_keyed
    fn debit_keyed<K: Eq + Hash>(&self, state: &KeyedState<K>, key: Option<K>, limit: Limit, amount: f64) {
        let Some(key) = key else {
            return;
        };
        let now = self.now_nanos();
        self.maybe_evict(state, now);

        if let Some(bucket) = state.buckets.get(&key) {
            bucket.debit(limit.rate, limit.burst, now, amount);
            return;
        }

        if state.entries() >= HARD_CAP_PER_IP_ENTRIES {
            return;
        }

        match state.buckets.entry(key) {
            Entry::Occupied(occupied) => {
                occupied.get().debit(limit.rate, limit.burst, now, amount);
            },
            Entry::Vacant(vacant) => {
                let bucket = vacant.insert(TokenBucket::new(limit.burst));
                state.entries.fetch_add(1, Ordering::Relaxed);
                bucket.debit(limit.rate, limit.burst, now, amount);
            },
        }
    }

    /// Read current tokens for response header injection.
    ///
    /// Normalizes IPv4-mapped IPv6 addresses before lookup (defense in
    /// depth).
    pub(super) fn current_remaining(&self, client_addr: Option<IpAddr>, principal: Option<&str>, limit: Limit) -> f64 {
        let now = self.now_nanos();
        match &self.state {
            RateLimitState::Global(bucket) => bucket.current_tokens(limit.rate, limit.burst, now),
            RateLimitState::PerIp(state) => {
                let Some(ip) = client_addr.map(normalize_mapped_ipv4) else {
                    return 0.0;
                };
                state
                    .buckets
                    .get(&ip)
                    .map_or(limit.burst, |b| b.current_tokens(limit.rate, limit.burst, now))
            },
            RateLimitState::PerIdentity(state) | RateLimitState::PerPeer(state) => {
                let Some(principal) = principal else {
                    return 0.0;
                };
                state
                    .buckets
                    .get(principal)
                    .map_or(limit.burst, |b| b.current_tokens(limit.rate, limit.burst, now))
            },
        }
    }
}
