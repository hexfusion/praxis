// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Client certificate verifier construction for listener mTLS.
//!
//! When the `hot-reload` feature is enabled and a listener uses
//! [`ReloadableClientVerifier`], CRL and CA files are monitored
//! for changes and the verifier is atomically rebuilt on disk
//! modifications.
//!
//! [`ReloadableClientVerifier`]: crate::reload::ReloadableClientVerifier

use std::sync::Arc;

use rustls::{
    DistinguishedName, RootCertStore, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime, pem::PemObject as _},
    server::{
        WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};

use crate::{ClientCertMode, TlsError};

// -----------------------------------------------------------------------------
// Verifier Builder
// -----------------------------------------------------------------------------

/// Build a [`ClientCertVerifier`] from a CA PEM file and verification mode.
///
/// When `crl_paths` is non-empty, the verifier checks presented client
/// certificates against the provided CRLs and rejects revoked certificates.
///
/// # Errors
///
/// Returns [`TlsError`] if the CA or CRL files cannot be read or parsed,
/// or if `mode` is [`ClientCertMode::None`].
///
/// ```ignore
/// use std::sync::Arc;
///
/// use crate::{ClientCertMode, client_auth::build_client_verifier};
///
/// let verifier = build_client_verifier(
///     "/etc/ssl/client-ca.pem",
///     ClientCertMode::Require,
///     &[],
/// )
/// .expect("valid CA file");
/// ```
///
/// [`ClientCertVerifier`]: rustls::server::danger::ClientCertVerifier
/// [`TlsError`]: crate::TlsError
/// [`ClientCertMode::None`]: crate::ClientCertMode::None
pub(crate) fn build_client_verifier(
    ca_path: &str,
    mode: ClientCertMode,
    crl_paths: &[String],
) -> Result<Arc<dyn ClientCertVerifier>, TlsError> {
    let root_store = load_ca_root_store(ca_path)?;
    let mut builder = WebPkiClientVerifier::builder(Arc::new(root_store));

    if !crl_paths.is_empty() {
        let crls = load_crls(crl_paths)?;
        builder = builder.with_crls(crls);
    }

    let verifier_err = |detail: String| TlsError::FileLoadError {
        path: ca_path.to_owned(),
        detail,
    };

    match mode {
        ClientCertMode::Request => builder
            .allow_unauthenticated()
            .build()
            .map_err(|e| verifier_err(format!("failed to build verifier: {e}"))),
        ClientCertMode::Require => builder
            .build()
            .map_err(|e| verifier_err(format!("failed to build verifier: {e}"))),
        ClientCertMode::RequireNamed => builder
            .build()
            .map(|inner| -> Arc<dyn ClientCertVerifier> { Arc::new(NamedPeerVerifier { inner }) })
            .map_err(|e| verifier_err(format!("failed to build verifier: {e}"))),
        ClientCertMode::None => Err(TlsError::ClientVerifierNotRequired),
    }
}


// -----------------------------------------------------------------------------
// NamedPeerVerifier
// -----------------------------------------------------------------------------

/// Requires the client certificate to name its bearer.
///
/// Chain validation is delegated first, so the name is only read from a
/// certificate that already verified against the configured authority.
/// A certificate must carry exactly one URI SAN: one holding several
/// would otherwise authenticate as any of them.
#[derive(Debug)]
struct NamedPeerVerifier {
    /// Verifier that validates the chain before the name is read.
    inner: Arc<dyn ClientCertVerifier>,
}

/// Return the single URI SAN in a DER-encoded certificate.
fn single_uri_san(cert: &CertificateDer<'_>) -> Option<String> {
    use x509_parser::{
        extensions::GeneralName,
        prelude::{FromDer as _, X509Certificate},
    };

    let (_, parsed) = X509Certificate::from_der(cert.as_ref()).ok()?;
    let san = parsed.subject_alternative_name().ok().flatten()?;

    let mut uris = san.value.general_names.iter().filter_map(|name| match name {
        GeneralName::URI(uri) => Some((*uri).to_owned()),
        GeneralName::OtherName(..)
        | GeneralName::RFC822Name(_)
        | GeneralName::DNSName(_)
        | GeneralName::X400Address(_)
        | GeneralName::DirectoryName(_)
        | GeneralName::EDIPartyName(_)
        | GeneralName::IPAddress(_)
        | GeneralName::RegisteredID(_) => None,
    });

    // Exactly one, so a certificate holding several names names nobody.
    let only = uris.next()?;
    if uris.next().is_some() {
        return None;
    }
    Some(only)
}

impl ClientCertVerifier for NamedPeerVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verified = self.inner.verify_client_cert(end_entity, intermediates, now)?;

        match single_uri_san(end_entity) {
            Some(id) if id.starts_with("spiffe://") && id.len() > "spiffe://".len() => Ok(verified),
            _ => Err(rustls::Error::General(
                "client certificate must carry exactly one spiffe:// URI SAN".to_owned(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }
}

// -----------------------------------------------------------------------------
// CRL Loading
// -----------------------------------------------------------------------------

/// Load CRL files from PEM-encoded paths.
fn load_crls(paths: &[String]) -> Result<Vec<CertificateRevocationListDer<'static>>, TlsError> {
    let mut crls = Vec::new();
    for path in paths {
        let pem = zeroize::Zeroizing::new(std::fs::read(path).map_err(|e| TlsError::FileLoadError {
            path: path.clone(),
            detail: e.to_string(),
        })?);

        let parsed: Vec<_> = CertificateRevocationListDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::FileLoadError {
                path: path.clone(),
                detail: format!("failed to parse CRL PEM: {e}"),
            })?;
        if parsed.is_empty() {
            return Err(TlsError::FileLoadError {
                path: path.clone(),
                detail: "no CRLs found in PEM file".to_owned(),
            });
        }
        crls.extend(parsed);
    }
    Ok(crls)
}

/// Load CA certificates from a PEM file into a [`RootCertStore`].
///
/// [`RootCertStore`]: rustls::RootCertStore
fn load_ca_root_store(ca_path: &str) -> Result<RootCertStore, TlsError> {
    let ca_pem = zeroize::Zeroizing::new(std::fs::read(ca_path).map_err(|e| TlsError::FileLoadError {
        path: ca_path.to_owned(),
        detail: e.to_string(),
    })?);

    let certs: Vec<_> = CertificateDer::pem_slice_iter(&ca_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::FileLoadError {
            path: ca_path.to_owned(),
            detail: format!("failed to parse PEM: {e}"),
        })?;

    if certs.is_empty() {
        return Err(TlsError::FileLoadError {
            path: ca_path.to_owned(),
            detail: "no certificates found in PEM file".to_owned(),
        });
    }

    let mut root_store = RootCertStore::empty();
    for cert in certs {
        root_store.add(cert).map_err(|e| TlsError::FileLoadError {
            path: ca_path.to_owned(),
            detail: format!("failed to add CA cert: {e}"),
        })?;
    }

    Ok(root_store)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use crate::test_utils::{ensure_crypto_provider, gen_ca_file};

    #[test]
    fn build_client_verifier_require_with_valid_ca() {
        ensure_crypto_provider();
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let verifier = build_client_verifier(ca_path, ClientCertMode::Require, &[])
            .expect("require mode with valid CA should succeed");
        assert!(
            verifier.client_auth_mandatory(),
            "require mode should mandate client auth"
        );
    }

    #[test]
    fn build_client_verifier_request_with_valid_ca() {
        ensure_crypto_provider();
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let verifier = build_client_verifier(ca_path, ClientCertMode::Request, &[])
            .expect("request mode with valid CA should succeed");
        assert!(
            !verifier.client_auth_mandatory(),
            "request mode should not mandate client auth"
        );
    }

    #[test]
    fn build_client_verifier_none_mode_returns_error() {
        ensure_crypto_provider();
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let err = build_client_verifier(ca_path, ClientCertMode::None, &[]).expect_err("mode=None should return error");
        assert!(
            matches!(err, TlsError::ClientVerifierNotRequired),
            "error should be ClientVerifierNotRequired, got: {err}"
        );
    }

    #[test]
    fn build_client_verifier_invalid_ca_path_returns_error() {
        let err = build_client_verifier("/nonexistent/ca.pem", ClientCertMode::Require, &[])
            .expect_err("nonexistent CA should fail");
        assert!(
            matches!(err, TlsError::FileLoadError { .. }),
            "error should be FileLoadError, got: {err}"
        );
    }

    #[test]
    fn load_ca_root_store_with_valid_ca() {
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let store = load_ca_root_store(ca_path).expect("valid CA file should load");
        assert!(!store.is_empty(), "root store should contain at least one certificate");
    }

    #[test]
    fn load_ca_root_store_empty_pem_returns_error() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir creation should succeed");
        let empty_path = temp_dir.path().join("empty.pem");
        std::fs::write(&empty_path, "").expect("write empty PEM should succeed");

        let err = load_ca_root_store(empty_path.to_str().expect("path should be valid UTF-8"))
            .expect_err("empty PEM should fail");
        assert!(
            matches!(&err, TlsError::FileLoadError { detail, .. } if detail.contains("no certificates")),
            "error should mention no certificates, got: {err}"
        );
    }

    #[test]
    fn load_ca_root_store_nonexistent_file_returns_error() {
        let err = load_ca_root_store("/nonexistent/ca.pem").expect_err("nonexistent file should fail");
        assert!(
            matches!(err, TlsError::FileLoadError { .. }),
            "error should be FileLoadError, got: {err}"
        );
    }

    #[test]
    fn load_crls_nonexistent_file_returns_error() {
        let err = load_crls(&["/nonexistent/crl.pem".to_owned()]).expect_err("nonexistent CRL file should fail");
        assert!(
            matches!(err, TlsError::FileLoadError { .. }),
            "error should be FileLoadError, got: {err}"
        );
        assert!(
            err.to_string().contains("load"),
            "error should mention file loading, got: {err}"
        );
    }

    #[test]
    fn load_crls_empty_pem_returns_error() {
        let temp = tempfile::NamedTempFile::new().expect("tempfile creation should succeed");
        std::fs::write(temp.path(), "").expect("write empty file should succeed");
        let path = temp.path().to_str().expect("path should be valid UTF-8").to_owned();

        let err = load_crls(&[path]).expect_err("empty PEM should fail");
        assert!(
            err.to_string().contains("no CRLs found"),
            "error should mention no CRLs found, got: {err}"
        );
    }

    /// Generate a CA PEM and an empty CRL PEM signed by that CA.
    fn gen_ca_and_crl(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let ca_key = rcgen::KeyPair::generate().expect("CA key generation");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "CRL Test CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-sign");
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);

        let crl = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2026, 1, 1),
            next_update: rcgen::date_time_ymd(2036, 1, 1),
            crl_number: rcgen::SerialNumber::from_slice(&[1]),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(&issuer)
        .expect("CRL signing");

        let ca_path = dir.join("ca.pem");
        let crl_path = dir.join("crl.pem");
        std::fs::write(&ca_path, ca_cert.pem()).expect("write CA PEM");
        std::fs::write(&crl_path, crl.pem().expect("CRL PEM encoding")).expect("write CRL PEM");
        (ca_path, crl_path)
    }

    #[test]
    fn build_client_verifier_with_valid_crl() {
        ensure_crypto_provider();
        let dir = tempfile::TempDir::new().expect("tempdir creation should succeed");
        let (ca_path, crl_path) = gen_ca_and_crl(dir.path());

        let verifier = build_client_verifier(
            ca_path.to_str().expect("ca path should be valid UTF-8"),
            ClientCertMode::Require,
            &[crl_path.to_str().expect("crl path should be valid UTF-8").to_owned()],
        )
        .expect("require mode with valid CA and CRL should succeed");
        assert!(
            verifier.client_auth_mandatory(),
            "require mode with CRLs should still mandate client auth"
        );
    }

    #[test]
    fn load_crls_parses_generated_crl() {
        let dir = tempfile::TempDir::new().expect("tempdir creation should succeed");
        let (_ca_path, crl_path) = gen_ca_and_crl(dir.path());

        let crls = load_crls(&[crl_path.to_str().expect("crl path should be valid UTF-8").to_owned()])
            .expect("valid CRL PEM should parse");
        assert_eq!(crls.len(), 1, "exactly one CRL should be parsed");
    }

    #[test]
    fn load_ca_root_store_rejects_garbage_certificate_der() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir creation should succeed");
        let bad_path = temp_dir.path().join("bad.pem");
        std::fs::write(
            &bad_path,
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        )
        .expect("write bad PEM should succeed");

        let err = load_ca_root_store(bad_path.to_str().expect("path should be valid UTF-8"))
            .expect_err("garbage certificate DER should fail");
        assert!(
            matches!(&err, TlsError::FileLoadError { detail, .. } if detail.contains("failed to add CA cert")),
            "error should mention the failing add, got: {err}"
        );
    }

    // ---- NamedPeerVerifier ----

    /// Build a leaf signed by a throwaway CA, carrying the given URI SANs.
    fn leaf_with_uri_sans(uris: &[&str]) -> Vec<u8> {
        use rcgen::{CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType};

        let ca_key = KeyPair::generate().expect("CA key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "Named Test CA");
        let issuer = Issuer::new(ca_params, &ca_key);

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        leaf_params.distinguished_name.push(DnType::CommonName, "peer");
        for uri in uris {
            leaf_params
                .subject_alt_names
                .push(SanType::URI((*uri).try_into().expect("URI SAN")));
        }
        leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf sign")
            .der()
            .to_vec()
    }

    #[test]
    fn single_uri_san_returns_the_only_name() {
        let der = leaf_with_uri_sans(&["spiffe://grid.internal/site/pool-a"]);
        let cert = CertificateDer::from(der);
        assert_eq!(
            single_uri_san(&cert).as_deref(),
            Some("spiffe://grid.internal/site/pool-a")
        );
    }

    #[test]
    fn single_uri_san_refuses_two_names() {
        let der = leaf_with_uri_sans(&[
            "spiffe://grid.internal/site/pool-a",
            "spiffe://grid.internal/site/pool-b",
        ]);
        let cert = CertificateDer::from(der);
        assert_eq!(
            single_uri_san(&cert),
            None,
            "a certificate holding two names must name nobody"
        );
    }

    #[test]
    fn single_uri_san_is_none_without_a_uri_san() {
        let der = leaf_with_uri_sans(&[]);
        let cert = CertificateDer::from(der);
        assert_eq!(single_uri_san(&cert), None);
    }

    #[test]
    fn require_named_mode_mandates_client_auth() {
        ensure_crypto_provider();
        let ca = gen_ca_file();
        let ca_path = ca.ca_path.to_str().expect("ca path should be valid UTF-8");

        let verifier = build_client_verifier(ca_path, ClientCertMode::RequireNamed, &[])
            .expect("require-named mode with valid CA should succeed");
        assert!(
            verifier.client_auth_mandatory(),
            "require-named mode should mandate client auth"
        );
    }
}
