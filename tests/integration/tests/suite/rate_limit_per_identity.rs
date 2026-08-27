// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! End-to-end integration tests for `rate_limit` in `per_identity` mode.
//!
//! The unit tests construct an `AuthenticatedIdentity` directly. These
//! drive a real gateway over real HTTP and prove the whole chain: the
//! `policy` filter validates a JWT, publishes the identity, and
//! `rate_limit` buckets on it and honours the limits the issuer signed
//! into the token.
//!
//! Four cases:
//!
//! * **Isolation** — two principals hold independent buckets, so one exhausting its limit does not affect the other.
//! * **Per-principal limits** — one filter instance, one configured default, and two callers held to different
//!   issuer-signed limits.
//! * **Grouping** — two subjects sharing a `grid_site` claim draw from one bucket.
//! * **Unauthenticated** — a request with no token never reaches the limiter, because the policy filter rejects it
//!   first.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_send, parse_status, start_backend_with_shutdown, start_proxy};

// Mirrored from `tests/integration/fixtures/per-identity-rate-limit-policy.yaml`.
const FIXTURE_ISSUER: &str = "https://idp.example.com";
const FIXTURE_AUDIENCE: &str = "praxis-rate-limit-example";
const FIXTURE_SECRET: &str = "REPLACE-WITH-A-PROPERLY-RANDOM-SHARED-SECRET-DO-NOT-COMMIT";

/// Mint an HS256 JWT carrying a site and its issuer-granted limits.
///
/// `grid_rate` and `grid_burst` are signed by the issuer, so a caller
/// cannot raise its own limit by editing the token.
fn mint(subject: &str, site: &str, rate: &str, burst: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs();
    let claims = serde_json::json!({
        "iss": FIXTURE_ISSUER,
        "aud": FIXTURE_AUDIENCE,
        "sub": subject,
        "grid_site": site,
        "grid_rate": rate,
        "grid_burst": burst,
        "iat": now,
        "exp": now + 300,
    });
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(FIXTURE_SECRET.as_bytes()),
    )
    .expect("sign fixture JWT")
}

/// A gateway that authenticates with the policy filter, then rate limits
/// by the principal it established.
///
/// `key_claim` is left unset in most cases so the bucket keys on the
/// subject id; `bucket_by_site` switches it to the coarser `grid_site`
/// claim.
fn gateway_yaml(proxy_port: u16, backend_port: u16, rate: f64, burst: u32, bucket_by_site: bool) -> String {
    let policy_path = format!(
        "{}/fixtures/per-identity-rate-limit-policy.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    let key_claim = if bucket_by_site {
        "\n        key_claim: grid_site"
    } else {
        ""
    };
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: policy
        config_path: "{policy_path}"
      - filter: rate_limit
        mode: per_identity{key_claim}
        rate_claim: grid_rate
        burst_claim: grid_burst
        rate: {rate}
        burst: {burst}
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// Send one authenticated GET and return its status.
fn get_as(addr: &str, token: &str) -> u16 {
    let raw = http_send(
        addr,
        &format!("GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"),
    );
    parse_status(&raw)
}

#[test]
fn per_identity_isolates_principals_end_to_end() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    // A generous configured default, so any limiting observed comes from
    // the claims rather than from the static config.
    let yaml = gateway_yaml(proxy_port, backend.port(), 100.0, 100, false);
    let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());

    let site_a = mint("site-a", "site-a", "1", "1");
    assert_eq!(get_as(proxy.addr(), &site_a), 200, "site-a's first request should pass");
    assert_eq!(
        get_as(proxy.addr(), &site_a),
        429,
        "site-a's second should exhaust its claimed burst of 1"
    );

    let site_b = mint("site-b", "site-b", "1", "1");
    assert_eq!(
        get_as(proxy.addr(), &site_b),
        200,
        "site-b holds its own bucket and is unaffected by site-a"
    );
}

#[test]
fn per_identity_honours_different_limits_per_principal() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let yaml = gateway_yaml(proxy_port, backend.port(), 100.0, 100, false);
    let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());

    let small = mint("site-a", "site-a", "1", "1");
    assert_eq!(get_as(proxy.addr(), &small), 200, "site-a's first should pass");
    assert_eq!(get_as(proxy.addr(), &small), 429, "site-a is held to a burst of 1");

    // Same filter instance, a larger issuer-signed limit. Burst must
    // stay >= rate, the same invariant `from_config` enforces on the
    // static values; a token violating it falls back to the configured
    // limit instead.
    let large = mint("site-c", "site-c", "1", "5");
    for i in 0..5 {
        assert_eq!(
            get_as(proxy.addr(), &large),
            200,
            "site-c request {i} should pass under its own burst of 5"
        );
    }
    assert_eq!(
        get_as(proxy.addr(), &large),
        429,
        "site-c is held to its own burst of 5"
    );
}

#[test]
fn per_identity_groups_principals_by_claim_end_to_end() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let yaml = gateway_yaml(proxy_port, backend.port(), 100.0, 100, true);
    let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());

    // Two distinct subjects, one shared site.
    let first = mint("operator-one", "site-a", "1", "1");
    let second = mint("operator-two", "site-a", "1", "1");

    assert_eq!(get_as(proxy.addr(), &first), 200, "the first caller in site-a passes");
    assert_eq!(
        get_as(proxy.addr(), &second),
        429,
        "a different subject in the same site draws from the same bucket"
    );
}

#[test]
fn unauthenticated_requests_never_reach_the_limiter() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let yaml = gateway_yaml(proxy_port, backend.port(), 100.0, 100, false);
    let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        401,
        "with no token the policy filter rejects before the limiter is consulted"
    );
}
