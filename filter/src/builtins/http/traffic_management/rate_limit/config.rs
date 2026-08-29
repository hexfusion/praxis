// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Deserialized YAML configuration types for the rate limit filter.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// RateLimitMode
// -----------------------------------------------------------------------------

/// How the rate limiter partitions its token buckets.
///
/// ```
/// use praxis_filter::RateLimitMode;
///
/// let mode: RateLimitMode = serde_yaml::from_str("global").unwrap();
/// assert!(matches!(mode, RateLimitMode::Global));
///
/// let mode: RateLimitMode = serde_yaml::from_str("per_ip").unwrap();
/// assert!(matches!(mode, RateLimitMode::PerIp));
///
/// let mode: RateLimitMode = serde_yaml::from_str("per_identity").unwrap();
/// assert!(matches!(mode, RateLimitMode::PerIdentity));
///
/// let mode: RateLimitMode = serde_yaml::from_str("per_peer").unwrap();
/// assert!(matches!(mode, RateLimitMode::PerPeer));
/// ```
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitMode {
    /// One shared bucket for all clients.
    Global,

    /// Independent bucket per source IP address.
    PerIp,

    /// Independent bucket per authenticated principal.
    ///
    /// Keys on the [`AuthenticatedIdentity`] a trusted authentication
    /// filter published, so the limit follows a verified identity rather
    /// than a network address, which survives NAT and multiple replicas.
    ///
    /// [`AuthenticatedIdentity`]: crate::AuthenticatedIdentity
    PerIdentity,

    /// Independent bucket per authenticated peer site.
    ///
    /// Keys on the SPIFFE ID in the peer's client certificate, so the
    /// limit follows an identity the handshake proved rather than
    /// anything the caller sent. This is the wholesale case: a provider
    /// bounding how much a peer consumes, without modelling that peer's
    /// own tenants.
    ///
    /// The certificate carries no rate, so `rate` and `burst` are the
    /// configured values. The claim fields belong to `per_identity`.
    PerPeer,
}

// -----------------------------------------------------------------------------
// RateLimitConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the rate limit filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RateLimitConfig {
    /// How to partition buckets: one shared, per source IP, or per
    /// authenticated principal.
    pub mode: RateLimitMode,

    /// Tokens replenished per second.
    pub rate: f64,

    /// Maximum bucket capacity.
    pub burst: u32,

    /// Custom claim naming the bucket, instead of the subject id.
    ///
    /// Lets several principals share one bucket (a tenant, a site) when
    /// the identity carries a coarser grouping than its subject.
    /// `per_identity` only.
    #[serde(default)]
    pub key_claim: Option<String>,

    /// Custom claim holding this principal's tokens per second.
    ///
    /// The claim is signed by the identity provider, so the limit is
    /// asserted by the issuer rather than by the caller. Falls back to
    /// `rate` when absent or unusable. `per_identity` only.
    #[serde(default)]
    pub rate_claim: Option<String>,

    /// Custom claim holding this principal's bucket capacity.
    ///
    /// Falls back to `burst` when absent or unusable. `per_identity` only.
    #[serde(default)]
    pub burst_claim: Option<String>,
}
