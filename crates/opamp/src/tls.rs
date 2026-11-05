//! The TLS both sides of a connection share (ADR-0010). Behind either feature.
//!
//! This module turns material into what rustls takes, and opens no file. Which CA to trust and
//! which certificate to present is the application's policy, so the application reads the files
//! and hands the bytes here. Where a file is meant, the application wraps the error with its path.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::SupportedProtocolVersion;

/// The one protocol version either side speaks (specification Q-3).
pub const PROTOCOL_VERSIONS: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// The ring provider with the three TLS 1.3 suites and nothing else (ADR-0010). A provider without
/// a TLS 1.2 suite cannot negotiate TLS 1.2, whoever builds the configuration from it.
#[must_use]
pub fn provider() -> CryptoProvider {
    use rustls::crypto::ring::cipher_suite::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    };
    CryptoProvider {
        cipher_suites: vec![
            TLS13_AES_256_GCM_SHA384,
            TLS13_AES_128_GCM_SHA256,
            TLS13_CHACHA20_POLY1305_SHA256,
        ],
        ..rustls::crypto::ring::default_provider()
    }
}

/// Installs [`provider`] as the process-wide rustls provider — ring, never a system library
/// (ADR-0013) — once; later calls are no-ops. A binary calls it at startup, before anything builds
/// a TLS client. reqwest's `rustls-no-provider` feature refuses to build a client without a process
/// provider, which is the guarantee that keeps aws-lc-rs and its cmake out of the build; and since
/// reqwest builds its own configuration from this provider, it speaks TLS 1.3 alone too.
pub fn install_ring_provider() {
    if CryptoProvider::get_default().is_none() {
        // A concurrent second install can still lose the race; losing to the same provider is fine.
        let _ = provider().install_default();
    }
}

/// A server configuration builder pinned to [`provider`] and [`PROTOCOL_VERSIONS`].
#[must_use]
pub fn server_builder() -> rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier> {
    rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(PROTOCOL_VERSIONS)
        .expect("the ring provider supports TLS 1.3")
}

/// A client configuration builder pinned to [`provider`] and [`PROTOCOL_VERSIONS`].
#[must_use]
pub fn client_builder() -> rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier> {
    rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(PROTOCOL_VERSIONS)
        .expect("the ring provider supports TLS 1.3")
}

/// A certificate chain and its private key, as PEM — what one side presents to the other.
#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    /// The certificate, followed by any intermediates.
    pub cert_pem: Vec<u8>,
    /// The private key of the first certificate.
    pub key_pem: Vec<u8>,
}

impl std::fmt::Debug for Identity {
    /// The key is a secret, so a `Debug` of a connection's material never prints it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("cert_pem", &String::from_utf8_lossy(&self.cert_pem))
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

/// Every certificate of `pem` as the trust anchors of a root store.
///
/// # Errors
/// Returns an error when `pem` holds no certificate, or one that cannot be an anchor.
pub fn root_store(pem: &[u8]) -> Result<rustls::RootCertStore, String> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certificates(pem)? {
        roots
            .add(cert)
            .map_err(|e| format!("cannot trust a certificate: {e}"))?;
    }
    Ok(roots)
}

/// Every certificate in `pem`, in the order it appears — a chain, or a bundle of trust anchors.
///
/// An empty file is an error rather than an empty chain: a trust bundle that parsed to nothing
/// would configure a TLS stack that trusts nobody, and it would do it silently.
///
/// The PEM reader is `rustls-pki-types`' own (the crate `rustls::pki_types` re-exports), which
/// absorbed `rustls-pemfile` when that was retired (RUSTSEC-2025-0134) — so the parsing stays the
/// one rustls itself uses, without the unmaintained dependency.
///
/// # Errors
/// Returns an error when `pem` holds no certificate or a malformed one.
pub fn certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs: Result<Vec<_>, _> = CertificateDer::pem_slice_iter(pem).collect();
    let certs = certs.map_err(|e| format!("cannot parse a certificate: {e}"))?;
    if certs.is_empty() {
        return Err("no certificates".to_string());
    }
    Ok(certs)
}

/// The first private key in `pem`, in any of the encodings rustls accepts (PKCS#8, PKCS#1, SEC1).
///
/// A file with no key in it is an error, not an absence: the `NoItemsFound` case and a malformed
/// key both surface as `Err`, which the path-based callers wrap with what the file was meant to be.
///
/// # Errors
/// Returns an error when `pem` holds no key or a malformed one.
pub fn private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, String> {
    PrivateKeyDer::from_pem_slice(pem).map_err(|e| format!("cannot parse a private key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed certificate and its key, generated rather than pasted: a fixture with an
    /// expiry date is a test that starts failing on a date nobody chose.
    fn pair() -> (String, String) {
        let key = rcgen::KeyPair::generate().expect("generate a key");
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("parameters")
            .self_signed(&key)
            .expect("self-sign");
        (cert.pem(), key.serialize_pem())
    }

    /// Verifies: ADR-0010
    #[test]
    fn reads_a_certificate_and_a_key() {
        let (cert_pem, key_pem) = pair();
        assert_eq!(certificates(cert_pem.as_bytes()).expect("certs").len(), 1);
        private_key(key_pem.as_bytes()).expect("a key");
    }

    /// A bundle is several anchors in one file, and all of them have to arrive — a CA file read as
    /// its first certificate alone would silently stop trusting the rest of the fleet's issuers.
    #[test]
    fn reads_every_certificate_of_a_bundle_in_order() {
        let (first, _) = pair();
        let (second, _) = pair();
        let bundle = format!("{first}{second}");
        let certs = certificates(bundle.as_bytes()).expect("certs");
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0], certificates(first.as_bytes()).expect("first")[0]);
    }

    /// Fail closed: a file with no certificate in it is not an empty trust store.
    /// Verifies: ADR-0010
    #[test]
    fn a_file_holding_no_certificate_is_an_error() {
        assert!(certificates(b"").is_err());
        assert!(certificates(b"not pem at all").is_err());
        let (_, key_pem) = pair();
        assert!(
            certificates(key_pem.as_bytes()).is_err(),
            "a key is not a certificate"
        );
    }

    #[test]
    fn the_debug_form_of_an_identity_hides_its_key() {
        let (cert_pem, key_pem) = pair();
        let identity = Identity {
            cert_pem: cert_pem.into_bytes(),
            key_pem: key_pem.into_bytes(),
        };
        assert!(!format!("{identity:?}").contains("PRIVATE KEY"));
    }

    /// Verifies: ADR-0010, ADR-0013, ADR-0014, Q-3
    #[test]
    fn the_provider_offers_tls_1_3_suites_alone() {
        let provider = provider();
        assert_eq!(provider.cipher_suites.len(), 3);
        assert!(provider
            .cipher_suites
            .iter()
            .all(|suite| suite.version() == &rustls::version::TLS13));
    }

    #[test]
    fn a_file_holding_no_key_is_an_error() {
        assert!(private_key(b"").is_err());
        let (cert_pem, _) = pair();
        assert!(
            private_key(cert_pem.as_bytes()).is_err(),
            "a certificate is not a key"
        );
    }
}
