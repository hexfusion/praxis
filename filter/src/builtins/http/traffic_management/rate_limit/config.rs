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

    /// Independent bucket per resolved grid principal, of either kind.
    ///
    /// Keys on whichever identity the chain resolved: the peer SPIFFE ID
    /// if [`peer_identity_trust`] named a peer, otherwise the
    /// [`AuthenticatedIdentity`] subject a trusted auth filter published.
    /// This is the unified case a single grid gateway wants: one limiter
    /// that meters a peer site and a local user alike, keyed on the
    /// identity actually on the wire, with no side-channel tag to say
    /// which. A request that resolved neither has no key and is refused,
    /// so the mode is default-deny.
    ///
    /// When the principal is a user, the claim fields (`rate_claim`,
    /// `burst_claim`) apply exactly as under `per_identity`; a peer
    /// carries no claims, so it uses the configured `rate` and `burst`.
    ///
    /// [`peer_identity_trust`]: crate::builtins
    /// [`AuthenticatedIdentity`]: crate::AuthenticatedIdentity
    PerPrincipal,
}

// -----------------------------------------------------------------------------
// RateLimitMeter
// -----------------------------------------------------------------------------

/// What each request costs its bucket.
///
/// Orthogonal to [`RateLimitMode`], which decides *whose* bucket: so
/// `mode: per_peer` with `meter: tokens` is a per-peer token budget,
/// and `mode: per_identity` with `meter: tokens` is a per-tenant one.
///
/// ```
/// use praxis_filter::RateLimitMeter;
///
/// let meter: RateLimitMeter = serde_yaml::from_str("requests").unwrap();
/// assert!(matches!(meter, RateLimitMeter::Requests));
///
/// let meter: RateLimitMeter = serde_yaml::from_str("tokens").unwrap();
/// assert!(matches!(meter, RateLimitMeter::Tokens));
/// ```
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitMeter {
    /// One unit per request: a request-rate limit. Debited when the
    /// request is admitted. This is the default and the historical
    /// behaviour.
    #[default]
    Requests,

    /// The response's token usage: a token-consumption budget. The cost
    /// is only known once the response has been read, so it is debited
    /// after the response body finishes, from a metadata key another
    /// filter (`token_usage`) publishes. `rate` becomes tokens replenished
    /// per second and `burst` the token budget.
    Tokens,
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

    /// What each request costs the bucket: one unit (`requests`, the
    /// default) or the response's token usage (`tokens`).
    #[serde(default)]
    pub meter: RateLimitMeter,

    /// Metadata key holding the per-request cost when `meter: tokens`.
    ///
    /// Defaults to `token.total`, the key the `token_usage` filter
    /// publishes. A request whose cost key is absent or unparsable is
    /// treated as costing nothing, so a missing usage report degrades to
    /// no debit rather than to a wrong one.
    #[serde(default)]
    pub cost_metadata_key: Option<String>,

    /// Reserve the estimated cost at admission instead of admitting on any
    /// remaining budget. `meter: tokens` only.
    ///
    /// When set, the estimate is charged up front and a request that cannot
    /// afford it is refused with 429, then the reserve is reconciled to the
    /// actual cost after the response. When unset (the default), the limiter
    /// admits while any budget remains and debits the actual after, which lets
    /// one response overspend the budget into debt.
    #[serde(default)]
    pub reserve: bool,

    /// Metadata key holding the per-request estimate to reserve at admission.
    ///
    /// Defaults to `token.estimate_total`, symmetric with `cost_metadata_key`.
    /// Effective only when `reserve` is set. An absent or unparsable estimate
    /// falls back to admit-on-remaining, so a missing estimate degrades to the
    /// non-reserve behaviour rather than refusing.
    #[serde(default)]
    pub reserve_metadata_key: Option<String>,
}
