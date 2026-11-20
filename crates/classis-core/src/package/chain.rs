//! The adapter that verifies a [`PackageSignature`](super::PackageSignature) up to the Package
//! Roots (ADR-0066 clause 4): `rustls-webpki` for the path, the host's clock for the dates, and
//! the Roots compiled in — plus, in a debug build only, one named by
//! [`DEBUG_ROOT_ENV`](super::DEBUG_ROOT_ENV).

use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use webpki::{EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter};

use super::{parse_signature, Roots, SignatureError};

/// The Package Roots compiled into every binary (ADR-0066 clause 1), each a DER certificate. A
/// Root is added or dropped only by a reviewed change; the test below pins each by its SHA-256.
const COMPILED_ROOTS: &[&[u8]] = &[
    // CN=Signing Packages Root CA, Ed25519, 2026-11-16 to 2066-11-16; its key is the custodian's.
    include_bytes!("../package-roots/signing-packages-root-ca-2026.der"),
];

/// The SHA-256 of each compiled-in Root, in the order of [`COMPILED_ROOTS`].
#[cfg(test)]
const COMPILED_ROOT_FINGERPRINTS: &[&str] =
    &["16b7c670cbd11cbe9724dc4e2366bddea0352e7ac67fe9b23d18cb2c7e4a810f"];

/// The Package Roots compiled into this binary (ADR-0066 clause 1). A debug build adds the one
/// [`DEBUG_ROOT_ENV`](super::DEBUG_ROOT_ENV) names, if it is set; see [`debug_root`]. The Client
/// and the Server ask it once at startup, and refuse to start on an error.
///
/// # Errors
///
/// A compiled-in Root that is not a certificate, which a test of this module rules out; in a
/// debug build, a [`DEBUG_ROOT_ENV`](super::DEBUG_ROOT_ENV) that names no readable certificate,
/// naming the file.
pub fn compiled() -> Result<Roots, String> {
    let compiled = Roots::from_der(COMPILED_ROOTS.iter().copied())
        .map_err(|e| format!("the compiled-in Package Roots: {e}"))?;
    #[cfg(debug_assertions)]
    if let Some(path) = debug_root() {
        return Ok(compiled.with(debug_root_from(&path)?));
    }
    Ok(compiled)
}

/// The one Root a debug build reads from `path`, as [`compiled`] takes it.
#[cfg(debug_assertions)]
fn debug_root_from(path: &std::path::Path) -> Result<Roots, String> {
    let named =
        |e: &dyn std::fmt::Display| format!("{}={}: {e}", super::DEBUG_ROOT_ENV, path.display());
    let der = std::fs::read(path).map_err(|e| named(&e))?;
    Roots::from_der([der.as_slice()]).map_err(|e| named(&e))
}

/// The file a debug build takes one more Package Root from, so a program can say so at startup.
/// Always `None` in a release build.
#[must_use]
pub fn debug_root() -> Option<std::path::PathBuf> {
    #[cfg(debug_assertions)]
    {
        std::env::var_os(super::DEBUG_ROOT_ENV).map(std::path::PathBuf::from)
    }
    #[cfg(not(debug_assertions))]
    {
        None
    }
}

/// The Roots as `rustls-webpki` trust anchors.
fn anchors(roots: &Roots) -> Result<Vec<TrustAnchor<'_>>, SignatureError> {
    roots
        .certificates()
        .map(|der| {
            webpki::anchor_from_trusted_cert(&CertificateDer::from(der))
                .map(|anchor| anchor.to_owned())
                .map_err(|e| SignatureError::Chain(format!("a Package Root cannot be read: {e:?}")))
        })
        .collect()
}

/// A Package Signer carries no extendedKeyUsage (ADR-0066 clause 2): any one refuses it.
struct NoExtendedKeyUsage;

impl ExtendedKeyUsageValidator for NoExtendedKeyUsage {
    fn validate(&self, mut iter: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        match iter.next() {
            None => Ok(()),
            #[allow(deprecated)] // the variant without context carries no OID to misprint
            Some(_) => Err(webpki::Error::RequiredEkuNotFound),
        }
    }
}

/// Why the chain was refused, in words. Never prints an OID through `rustls-webpki`'s `Debug`,
/// which misprints it (ADR-0066 clause 4).
fn chain_error(error: &webpki::Error) -> String {
    #[allow(deprecated)]
    match error {
        webpki::Error::UnknownIssuer | webpki::Error::InvalidSignatureForPublicKey => {
            "it was not issued by a compiled-in Package Root".into()
        }
        webpki::Error::CertExpired { .. } => "its certificate has expired".into(),
        webpki::Error::CertNotValidYet { .. } => "its certificate is not valid yet".into(),
        webpki::Error::CaUsedAsEndEntity => "it is a CA certificate".into(),
        webpki::Error::RequiredEkuNotFound | webpki::Error::RequiredEkuNotFoundContext(_) => {
            "it carries an extendedKeyUsage".into()
        }
        webpki::Error::UnsupportedSignatureAlgorithm
        | webpki::Error::UnsupportedSignatureAlgorithmContext(_)
        | webpki::Error::UnsupportedSignatureAlgorithmForPublicKey
        | webpki::Error::UnsupportedSignatureAlgorithmForPublicKeyContext(_) => {
            "its chain is not Ed25519".into()
        }
        other => format!("{other:?}"),
    }
}

/// Verifies a `PackageSignature` over `statement` up to `roots`, at `now` (ADR-0066 clause 4):
/// the value, then the chain — Ed25519 only, no intermediate, no extendedKeyUsage, the
/// certificate's own dates — then the Package Signer's Ed25519 signature, the algorithm pinned.
///
/// # Errors
///
/// The first step that does not hold, as a [`SignatureError`].
pub fn verify(
    statement: &[u8],
    signature: &[u8],
    roots: &Roots,
    now: UnixTime,
) -> Result<(), SignatureError> {
    let parsed = parse_signature(signature)?;
    let anchors = anchors(roots)?;
    let der = CertificateDer::from(parsed.signer);
    let signer = EndEntityCert::try_from(&der)
        .map_err(|e| SignatureError::Chain(format!("its certificate cannot be read: {e:?}")))?;
    signer
        .verify_for_usage(
            &[webpki::ring::ED25519],
            &anchors,
            &[],
            now,
            NoExtendedKeyUsage,
            None,
            None,
        )
        .map_err(|e| SignatureError::Chain(chain_error(&e)))?;
    signer
        .verify_signature(webpki::ring::ED25519, statement, parsed.signature)
        .map_err(|e| {
            #[allow(deprecated)] // the variant without context is still what some paths return
            match e {
                webpki::Error::UnsupportedSignatureAlgorithmForPublicKey
                | webpki::Error::UnsupportedSignatureAlgorithmForPublicKeyContext(_) => {
                    SignatureError::Chain("its key is not Ed25519".into())
                }
                _ => SignatureError::Signature,
            }
        })
}

/// [`verify`] at the current time.
///
/// # Errors
///
/// As [`verify`].
pub fn verify_now(statement: &[u8], signature: &[u8], roots: &Roots) -> Result<(), SignatureError> {
    verify(statement, signature, roots, UnixTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::testing::{Deviation, TestRoot};
    use crate::package::{encode_signature, statement, MAX_SIGNATURE_LEN};

    fn stmt() -> Vec<u8> {
        statement("supervisor", "1.2.3", &[7; 32])
    }

    /// Verifies: ADR-0066
    #[test]
    fn a_package_signer_of_a_root_verifies() {
        let root = TestRoot::new();
        let signer = root.signer();
        assert_eq!(
            verify_now(&stmt(), &signer.sign(&stmt()), &root.roots()),
            Ok(())
        );
    }

    /// Verifies: ADR-0066
    #[test]
    fn a_signature_over_another_type_version_or_hash_is_refused() {
        let root = TestRoot::new();
        let sig = root.signer().sign(&stmt());
        for other in [
            statement("otelcol", "1.2.3", &[7; 32]),
            statement("supervisor", "1.2.4", &[7; 32]),
            statement("supervisor", "1.2.3", &[8; 32]),
        ] {
            assert_eq!(
                verify_now(&other, &sig, &root.roots()),
                Err(SignatureError::Signature)
            );
        }
    }

    /// Verifies: ADR-0066
    #[test]
    fn a_package_signer_of_another_root_is_refused() {
        let ours = TestRoot::new();
        let theirs = TestRoot::new();
        let sig = theirs.signer().sign(&stmt());
        assert_eq!(
            verify_now(&stmt(), &sig, &ours.roots()),
            Err(SignatureError::Chain(
                "it was not issued by a compiled-in Package Root".into()
            ))
        );
        let none = Roots::default();
        assert!(matches!(
            verify_now(&stmt(), &sig, &none),
            Err(SignatureError::Chain(_))
        ));
    }

    /// Verifies: ADR-0066
    #[test]
    fn a_package_signer_off_the_profile_is_refused() {
        let root = TestRoot::new();
        for (deviation, why) in [
            (Deviation::Expired, "its certificate has expired"),
            (Deviation::Ca, "it is a CA certificate"),
            (
                Deviation::ExtendedKeyUsage,
                "it carries an extendedKeyUsage",
            ),
        ] {
            let sig = root.signer_with(deviation).sign(&stmt());
            assert_eq!(
                verify_now(&stmt(), &sig, &root.roots()),
                Err(SignatureError::Chain(why.into())),
                "{deviation:?}"
            );
        }
        // An Ed25519 Root's certificate for a P-256 key: the chain holds, the pinned algorithm
        // refuses the key (ADR-0066 clause 4).
        let p256 = root.signer_with(Deviation::EcdsaKey);
        assert_eq!(
            verify_now(
                &stmt(),
                &encode_signature(&p256.der, &[7; 64]).expect("it fits"),
                &root.roots()
            ),
            Err(SignatureError::Chain("its key is not Ed25519".into()))
        );
        let ecdsa = TestRoot::ecdsa();
        let sig = ecdsa.signer().sign(&stmt());
        assert_eq!(
            verify_now(&stmt(), &sig, &ecdsa.roots()),
            Err(SignatureError::Chain("its chain is not Ed25519".into()))
        );
    }

    /// An intermediate between the Root and the Package Signer is refused: the value carries one
    /// certificate, and no intermediate is passed.
    ///
    /// Verifies: ADR-0066
    #[test]
    fn a_package_signer_under_an_intermediate_is_refused() {
        let root = TestRoot::new();
        let sig = root.intermediate().signer().sign(&stmt());
        assert_eq!(
            verify_now(&stmt(), &sig, &root.roots()),
            Err(SignatureError::Chain(
                "it was not issued by a compiled-in Package Root".into()
            ))
        );
    }

    /// Verifies: ADR-0066
    #[test]
    fn the_value_is_strict_der_and_bounded() {
        let root = TestRoot::new();
        let good = root.signer().sign(&stmt());
        let parsed = parse_signature(&good).unwrap();
        assert_eq!(
            encode_signature(parsed.signer, parsed.signature).as_ref(),
            Ok(&good)
        );

        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(
            parse_signature(&trailing),
            Err(SignatureError::Malformed("bytes follow it"))
        );

        let mut v2 = good.clone();
        let at = good
            .windows(3)
            .position(|w| w == [0x02, 0x01, 0x01])
            .unwrap();
        v2[at + 2] = 2;
        assert_eq!(
            parse_signature(&v2),
            Err(SignatureError::Malformed("its version is not 1"))
        );

        assert_eq!(
            parse_signature(&vec![0x30; MAX_SIGNATURE_LEN + 1]),
            Err(SignatureError::Malformed("it is longer than 2048 bytes"))
        );
        assert_eq!(
            parse_signature(&[0x30, 0x80, 0, 0]),
            Err(SignatureError::Malformed("an indefinite length is not DER"))
        );
        assert_eq!(
            parse_signature(&[0x30, 0x81, 0x05, 2, 1, 1, 0, 0]),
            Err(SignatureError::Malformed("a length is not minimal"))
        );
        assert!(parse_signature(&[0u8; 64]).is_err(), "a raw signature");
        assert!(parse_signature(&[]).is_err());
        let sig = [9u8; 64];
        let short = encode_signature(&[0x30, 0x00], &sig).expect("it fits");
        assert_eq!(parse_signature(&short).unwrap().signature, &sig);
        let mut long_sig = short.clone();
        long_sig[1] += 1;
        let pos = long_sig.len() - 65;
        long_sig[pos] = 65;
        long_sig.push(0);
        assert_eq!(
            parse_signature(&long_sig),
            Err(SignatureError::Malformed("its signature is not 64 bytes"))
        );
    }

    /// Verifies: ADR-0066
    #[test]
    fn the_compiled_in_roots_are_certificates() {
        let roots = compiled().expect("the compiled-in Roots");
        assert!(anchors(&roots).is_ok());
    }

    /// A debug build's extra Root that cannot be read, or is no certificate, is an error naming
    /// the variable and the file — the Client and the Server then refuse to start.
    /// Verifies: ADR-0066
    #[cfg(debug_assertions)]
    #[test]
    fn a_debug_root_that_cannot_be_read_is_an_error_naming_its_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir = dir.path();
        let missing = dir.join("missing.der");
        let error = debug_root_from(&missing).expect_err("no such file");
        assert!(error.starts_with(crate::package::DEBUG_ROOT_ENV), "{error}");
        assert!(error.contains("missing.der"), "{error}");
        let garbage = dir.join("garbage.der");
        std::fs::write(&garbage, b"not a certificate").expect("write");
        let error = debug_root_from(&garbage).expect_err("no certificate");
        assert!(error.contains("not a DER certificate"), "{error}");
        let root = TestRoot::new();
        let good = dir.join("root.der");
        std::fs::write(&good, &root.der).expect("write");
        assert_eq!(debug_root_from(&good), Ok(root.roots()));
    }

    /// The compiled-in Roots are the custodian's, byte for byte: a change to the list is a
    /// change to this test too (ADR-0066 clause 1).
    /// Verifies: ADR-0066
    #[test]
    fn the_compiled_in_roots_are_the_custodians() {
        use sha2::{Digest, Sha256};
        let found: Vec<String> = COMPILED_ROOTS
            .iter()
            .map(|der| hex::encode(Sha256::digest(der)))
            .collect();
        assert_eq!(found, COMPILED_ROOT_FINGERPRINTS);
    }
}
