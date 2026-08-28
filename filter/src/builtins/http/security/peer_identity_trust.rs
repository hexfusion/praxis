// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Peer identity trust filter: validates downstream mTLS peer identity
//! against a configured set of trusted gateway peers.

use async_trait::async_trait;
use praxis_tls::TlsPeerIdentity;
use serde::Deserialize;

use crate::{
    FilterAction, FilterError, Rejection,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

/// Maximum length for string match fields.
const MAX_FIELD_LEN: usize = 256;

/// Maximum number of trusted peer entries.
const MAX_TRUSTED_PEERS: usize = 256;

/// Lowercase SHA-256 certificate digest length in hexadecimal characters.
const SHA256_HEX_DIGEST_LEN: usize = 64;

/// Required scheme for a SPIFFE ID.
const SPIFFE_SCHEME: &str = "spiffe://";

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the peer identity trust filter.
///
/// ```yaml
/// filter: peer_identity_trust
/// trusted_peers:
///   - cert_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
///   - cert_digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
///     organization: example-org
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerIdentityTrustConfig {
    /// Trusted peer entries.
    trusted_peers: Vec<TrustedPeerConfig>,
}

/// A trusted peer entry. All configured fields must match.
/// Omitted fields are not checked.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedPeerConfig {
    /// Lowercase hex-encoded SHA-256 certificate digest.
    cert_digest: Option<String>,

    /// X.509 subject organization (`O=` field).
    ///
    /// Weaker than certificate digest — useful for bootstrap and
    /// controlled test configurations where cert digests are not
    /// known ahead of time.
    organization: Option<String>,

    /// Certificate serial number.
    serial_number: Option<String>,

    /// SPIFFE ID carried in the certificate's URI SAN.
    ///
    /// The strongest match field: it names the peer, and unlike
    /// `cert_digest` it survives reissue.
    spiffe_id: Option<String>,
}

// -----------------------------------------------------------------------------
// PeerIdentityTrustFilter
// -----------------------------------------------------------------------------

/// Validates that the downstream mTLS peer identity matches a
/// configured trusted peer before allowing the request to continue.
///
/// Requests without a verified peer identity are rejected with 403.
/// Requests with a peer identity that does not match any trusted
/// peer entry are also rejected with 403.
///
/// Each trusted peer entry specifies one or more match fields.
/// All configured fields on an entry must match the peer identity
/// for that entry to accept the request.
///
/// `spiffe_id` names the peer and is the field to prefer: one
/// certificate authority signs every peer, so `organization` is
/// identical across them, while `cert_digest` and `serial_number`
/// change on every reissue and so are pinning rather than identity.
/// `organization` and `serial_number` remain useful for bootstrap
/// and controlled test configurations.
///
/// A `spiffe_id` is compared in full, including the trust domain,
/// and only against a certificate presenting exactly one URI SAN.
/// There is no prefix or wildcard form: an authorized name is a
/// prefix of longer ones.
///
/// # YAML configuration
///
/// ```yaml
/// filter: peer_identity_trust
/// trusted_peers:
///   - cert_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
///   - cert_digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
///     organization: example-org
/// ```
pub struct PeerIdentityTrustFilter {
    /// Validated trusted peer entries.
    trusted_peers: Vec<TrustedPeer>,
}

/// Validated trusted peer entry for runtime matching.
struct TrustedPeer {
    /// Lowercase hex SHA-256 certificate digest.
    cert_digest: Option<String>,

    /// X.509 subject organization.
    organization: Option<String>,

    /// Certificate serial number.
    serial_number: Option<String>,

    /// SPIFFE ID from the certificate's URI SAN.
    spiffe_id: Option<String>,
}

impl PeerIdentityTrustFilter {
    /// Create a peer identity trust filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the trusted peer list is empty,
    /// exceeds the maximum, or a peer entry has no match fields.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: PeerIdentityTrustConfig = parse_filter_config("peer_identity_trust", config)?;

        if cfg.trusted_peers.is_empty() {
            return Err("peer_identity_trust: trusted_peers must not be empty".into());
        }
        if cfg.trusted_peers.len() > MAX_TRUSTED_PEERS {
            return Err(format!("peer_identity_trust: trusted_peers exceeds maximum of {MAX_TRUSTED_PEERS}").into());
        }

        let peers = validate_peers(cfg.trusted_peers)?;
        Ok(Box::new(Self { trusted_peers: peers }))
    }
}

#[async_trait]
impl HttpFilter for PeerIdentityTrustFilter {
    fn name(&self) -> &'static str {
        "peer_identity_trust"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(identity) = &ctx.peer_identity else {
            tracing::warn!("peer identity trust: no peer identity; rejecting");
            return Ok(FilterAction::Reject(Rejection::status(403)));
        };

        if is_trusted(identity, &self.trusted_peers) {
            tracing::debug!(
                peer_digest = %identity.hex_digest(),
                peer_org = identity.organization.as_deref().unwrap_or(""),
                "peer identity trust: peer accepted"
            );
            Ok(FilterAction::Continue)
        } else {
            tracing::warn!(
                peer_digest = %identity.hex_digest(),
                "peer identity trust: peer not trusted; rejecting"
            );
            Ok(FilterAction::Reject(Rejection::status(403)))
        }
    }
}

// -----------------------------------------------------------------------------
// Private Helpers
// -----------------------------------------------------------------------------

/// Validate and build the trusted peer list from config.
fn validate_peers(raw: Vec<TrustedPeerConfig>) -> Result<Vec<TrustedPeer>, FilterError> {
    let mut peers = Vec::with_capacity(raw.len());
    for (i, p) in raw.into_iter().enumerate() {
        validate_cert_digest_field(&format!("trusted_peers[{i}].cert_digest"), p.cert_digest.as_ref())?;
        validate_optional_field(&format!("trusted_peers[{i}].organization"), p.organization.as_ref())?;
        validate_optional_field(&format!("trusted_peers[{i}].serial_number"), p.serial_number.as_ref())?;
        validate_spiffe_id_field(&format!("trusted_peers[{i}].spiffe_id"), p.spiffe_id.as_ref())?;

        if p.cert_digest.is_none() && p.organization.is_none() && p.serial_number.is_none() && p.spiffe_id.is_none() {
            return Err(
                format!("peer_identity_trust: trusted_peers[{i}] must specify at least one match field").into(),
            );
        }

        peers.push(TrustedPeer {
            cert_digest: p.cert_digest,
            organization: p.organization,
            serial_number: p.serial_number,
            spiffe_id: p.spiffe_id,
        });
    }
    Ok(peers)
}

/// Reject missing, malformed, or mixed-case SHA-256 digest strings.
fn validate_cert_digest_field(name: &str, value: Option<&String>) -> Result<(), FilterError> {
    let Some(v) = value else {
        return Ok(());
    };

    if v.len() != SHA256_HEX_DIGEST_LEN || !v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(format!("peer_identity_trust: {name} must be exactly 64 lowercase hex characters").into());
    }

    Ok(())
}

/// Reject empty or oversized optional string fields.
fn validate_optional_field(name: &str, value: Option<&String>) -> Result<(), FilterError> {
    if let Some(v) = value
        && (v.trim().is_empty() || v.len() > MAX_FIELD_LEN)
    {
        return Err(format!("peer_identity_trust: {name} must be 1-{MAX_FIELD_LEN} non-blank characters").into());
    }
    Ok(())
}

/// Reject SPIFFE IDs that are malformed or carry a wildcard.
fn validate_spiffe_id_field(name: &str, value: Option<&String>) -> Result<(), FilterError> {
    let Some(v) = value else {
        return Ok(());
    };

    validate_optional_field(name, Some(v))?;

    if !v.starts_with(SPIFFE_SCHEME) || v.len() == SPIFFE_SCHEME.len() {
        return Err(format!("peer_identity_trust: {name} must be a spiffe:// URI naming a peer").into());
    }

    // Matching is exact, so a wildcard would silently never match.
    if v.contains('*') {
        return Err(format!("peer_identity_trust: {name} must not contain a wildcard; names compare in full").into());
    }

    Ok(())
}

/// Check whether the peer identity matches any trusted peer entry.
fn is_trusted(identity: &TlsPeerIdentity, peers: &[TrustedPeer]) -> bool {
    peers.iter().any(|peer| matches_peer(identity, peer))
}

/// Check whether a single peer entry matches the identity.
/// All configured fields must match.
fn matches_peer(identity: &TlsPeerIdentity, peer: &TrustedPeer) -> bool {
    if let Some(digest) = &peer.cert_digest
        && identity.hex_digest() != *digest
    {
        return false;
    }
    if let Some(id) = &peer.spiffe_id
        && identity.spiffe_id() != Some(id.as_str())
    {
        return false;
    }
    if let Some(org) = &peer.organization
        && identity.organization.as_deref() != Some(org.as_str())
    {
        return false;
    }
    if let Some(serial) = &peer.serial_number
        && identity.serial_number.as_deref() != Some(serial.as_str())
    {
        return false;
    }
    true
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use http::Method;

    use super::*;

    // ---- Config validation ----

    #[test]
    fn empty_trusted_peers_rejected() {
        let err = parse("trusted_peers: []").err().expect("should fail");
        assert!(err.to_string().contains("must not be empty"), "{err}");
    }

    #[test]
    fn peer_with_no_fields_rejected() {
        let err = parse("trusted_peers:\n  - {}").err().expect("should fail");
        assert!(err.to_string().contains("at least one match field"), "{err}");
    }

    #[test]
    fn empty_organization_rejected() {
        let err = parse("trusted_peers:\n  - organization: ''")
            .err()
            .expect("should fail");
        assert!(err.to_string().contains("organization must be"), "{err}");
    }

    #[test]
    fn blank_organization_rejected() {
        let err = parse("trusted_peers:\n  - organization: '   '")
            .err()
            .expect("should fail");
        assert!(err.to_string().contains("organization must be"), "{err}");
    }

    #[test]
    fn empty_cert_digest_rejected() {
        let err = parse("trusted_peers:\n  - cert_digest: ''").err().expect("should fail");
        assert!(err.to_string().contains("cert_digest must be"), "{err}");
    }

    #[test]
    fn empty_serial_number_rejected() {
        let err = parse("trusted_peers:\n  - serial_number: ''")
            .err()
            .expect("should fail");
        assert!(err.to_string().contains("serial_number must be"), "{err}");
    }

    #[test]
    fn too_many_trusted_peers_rejected() {
        use std::fmt::Write as _;

        let mut yaml = String::from("trusted_peers:\n");
        for i in 0..=MAX_TRUSTED_PEERS {
            writeln!(yaml, "  - organization: org-{i}").expect("String write is infallible");
        }

        let err = parse(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("exceeds maximum"), "{err}");
    }

    #[test]
    fn oversized_organization_rejected() {
        let org = "a".repeat(MAX_FIELD_LEN + 1);
        let err = parse(&format!("trusted_peers:\n  - organization: {org}"))
            .err()
            .expect("should fail");
        assert!(err.to_string().contains("organization must be"), "{err}");
    }

    #[test]
    fn short_cert_digest_rejected() {
        let err = parse("trusted_peers:\n  - cert_digest: abcd")
            .err()
            .expect("should fail");
        assert!(err.to_string().contains("exactly 64 lowercase hex"), "{err}");
    }

    #[test]
    fn uppercase_cert_digest_rejected() {
        let err = parse(&format!("trusted_peers:\n  - cert_digest: {}", "AB".repeat(32)))
            .err()
            .expect("should fail");
        assert!(err.to_string().contains("exactly 64 lowercase hex"), "{err}");
    }

    #[test]
    fn non_hex_cert_digest_rejected() {
        let err = parse(&format!("trusted_peers:\n  - cert_digest: {}", "gg".repeat(32)))
            .err()
            .expect("should fail");
        assert!(err.to_string().contains("exactly 64 lowercase hex"), "{err}");
    }

    #[test]
    fn valid_digest_only_config() {
        parse(&format!("trusted_peers:\n  - cert_digest: {}", digest_hex(0xAB))).unwrap();
    }

    #[test]
    fn valid_org_only_config() {
        parse("trusted_peers:\n  - organization: test-org").unwrap();
    }

    #[test]
    fn valid_combined_config() {
        parse(&format!(
            "trusted_peers:\n  - cert_digest: {}\n    organization: test-org\n    serial_number: '42'",
            digest_hex(0xAB)
        ))
        .unwrap();
    }

    // ---- Trust decisions ----

    #[tokio::test]
    async fn no_peer_identity_rejects() {
        let f = make_org_filter("test-org");
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 403),
            "missing peer identity should reject with 403"
        );
    }

    #[tokio::test]
    async fn trusted_digest_accepts() {
        let f = make_digest_filter(&digest_hex(0xAB));
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.peer_identity = Some(make_identity(vec![0xAB; 32], "any-org", "1"));

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue), "trusted digest should accept");
    }

    #[tokio::test]
    async fn wrong_digest_rejects() {
        let f = make_digest_filter(&digest_hex(0xAB));
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.peer_identity = Some(make_identity(vec![0xCD; 32], "any-org", "1"));

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 403),
            "wrong digest should reject"
        );
    }

    #[tokio::test]
    async fn trusted_organization_accepts() {
        let f = make_org_filter("test-org");
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.peer_identity = Some(make_identity(vec![1], "test-org", "1"));

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue), "trusted org should accept");
    }

    #[tokio::test]
    async fn wrong_organization_rejects() {
        let f = make_org_filter("test-org");
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.peer_identity = Some(make_identity(vec![1], "wrong-org", "1"));

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 403),
            "wrong org should reject"
        );
    }

    #[tokio::test]
    async fn trusted_serial_accepts() {
        let f = parse("trusted_peers:\n  - serial_number: '42'").unwrap();
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.peer_identity = Some(make_identity(vec![1], "any", "42"));

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue), "trusted serial should accept");
    }

    #[tokio::test]
    async fn wrong_serial_rejects() {
        let f = parse("trusted_peers:\n  - serial_number: '42'").unwrap();
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.peer_identity = Some(make_identity(vec![1], "any", "99"));

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 403),
            "wrong serial should reject"
        );
    }

    #[tokio::test]
    async fn combined_fields_must_all_match() {
        let f = parse(&format!(
            "trusted_peers:\n  - cert_digest: '{}'\n    organization: good-org",
            digest_hex(0x01)
        ))
        .unwrap();
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.peer_identity = Some(make_identity(vec![0x01; 32], "wrong-org", "1"));

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 403),
            "digest match + org mismatch should still reject"
        );
    }

    #[tokio::test]
    async fn identity_without_organization_rejects_org_check() {
        let f = make_org_filter("test-org");
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.peer_identity = Some(std::sync::Arc::new(TlsPeerIdentity {
            cert_digest: vec![1],
            organization: None,
            serial_number: None,
            uri_sans: Vec::new(),
        }));

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 403),
            "identity missing org should reject when org is required"
        );
    }


    // ---- SPIFFE ID matching ----

    const POOL_A: &str = "spiffe://grid.internal/site/pool-a";

    #[tokio::test]
    async fn spiffe_id_exact_match_accepted() {
        assert!(spiffe_verdict(POOL_A, &[POOL_A]).await, "the named peer is admitted");
    }

    #[tokio::test]
    async fn spiffe_id_of_another_site_rejected() {
        assert!(
            !spiffe_verdict(POOL_A, &["spiffe://grid.internal/site/pool-b"]).await,
            "a validly issued certificate naming another site is refused"
        );
    }

    #[tokio::test]
    async fn spiffe_id_prefix_does_not_match() {
        assert!(
            !spiffe_verdict(POOL_A, &["spiffe://grid.internal/site/pool-a-evil"]).await,
            "an authorized name is a prefix of longer ones; matching is exact"
        );
    }

    #[tokio::test]
    async fn spiffe_id_from_another_trust_domain_rejected() {
        assert!(
            !spiffe_verdict(POOL_A, &["spiffe://attacker.example/site/pool-a"]).await,
            "the trust domain is part of the name"
        );
    }

    #[tokio::test]
    async fn certificate_with_two_uri_sans_names_nobody() {
        assert!(
            !spiffe_verdict(POOL_A, &[POOL_A, "spiffe://grid.internal/site/pool-b"]).await,
            "a certificate holding two names must not authenticate as either"
        );
    }

    #[tokio::test]
    async fn certificate_without_a_uri_san_rejected() {
        assert!(
            !spiffe_verdict(POOL_A, &[]).await,
            "membership in the grid is not a name"
        );
    }

    #[test]
    fn spiffe_id_wildcard_rejected() {
        let err = parse("trusted_peers:\n  - spiffe_id: 'spiffe://grid.internal/site/*'")
            .err()
            .expect("should fail");
        assert!(err.to_string().contains("wildcard"), "{err}");
    }

    #[test]
    fn spiffe_id_wrong_scheme_rejected() {
        let err = parse("trusted_peers:\n  - spiffe_id: 'https://grid.internal/site/pool-a'")
            .err()
            .expect("should fail");
        assert!(err.to_string().contains("spiffe:// URI"), "{err}");
    }

    // ---- Test Utilities ----

    fn parse(yaml: &str) -> Result<Box<dyn HttpFilter>, FilterError> {
        let val: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        PeerIdentityTrustFilter::from_config(&val)
    }

    fn make_org_filter(org: &str) -> Box<dyn HttpFilter> {
        parse(&format!("trusted_peers:\n  - organization: {org}")).unwrap()
    }

    fn make_digest_filter(hex: &str) -> Box<dyn HttpFilter> {
        parse(&format!("trusted_peers:\n  - cert_digest: {hex}")).unwrap()
    }

    fn digest_hex(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn make_identity(digest: Vec<u8>, org: &str, serial: &str) -> std::sync::Arc<TlsPeerIdentity> {
        std::sync::Arc::new(TlsPeerIdentity {
            cert_digest: digest,
            organization: Some(org.to_owned()),
            serial_number: Some(serial.to_owned()),
            uri_sans: Vec::new(),
        })
    }

    fn make_spiffe_identity(uri_sans: &[&str]) -> std::sync::Arc<TlsPeerIdentity> {
        std::sync::Arc::new(TlsPeerIdentity {
            cert_digest: vec![0x01; 32],
            organization: Some("grid".to_owned()),
            serial_number: Some("1".to_owned()),
            uri_sans: uri_sans.iter().map(|s| (*s).to_owned()).collect(),
        })
    }

    fn make_spiffe_filter(id: &str) -> Box<dyn HttpFilter> {
        parse(&format!("trusted_peers:\n  - spiffe_id: '{id}'")).unwrap()
    }

    async fn spiffe_verdict(configured: &str, presented: &[&str]) -> bool {
        let f = make_spiffe_filter(configured);
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.peer_identity = Some(make_spiffe_identity(presented));
        matches!(f.on_request(&mut ctx).await.unwrap(), FilterAction::Continue)
    }
}
