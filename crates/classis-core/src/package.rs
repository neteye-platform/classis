//! What a package signature covers (ADR-0026), and how it is verified (ADR-0063).
//!
//! The signature covers not the artifact's bytes alone but which Agent type the artifact is for,
//! at which version, and its SHA-256 — so a signed artifact cannot be offered as another type's
//! program, or under another version.
//!
//! It is a [`PackageSignature`]: the certificate of the Package Signer that made it and its
//! Ed25519 signature over [`statement`]. It verifies only when a compiled-in Package Root issued
//! that certificate ([`Roots::compiled`]). The Client and the Server call the same [`verify`].

use std::fmt;

use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use webpki::{EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter};

/// The bytes a Package Signer signs and a Client verifies for one artifact:
/// `classis-package-v1`, the Agent type, the version and the artifact's SHA-256 in lowercase
/// hex, one per line, each line ended by a newline.
#[must_use]
pub fn statement(agent_type: &str, version: &str, content_hash: &[u8]) -> Vec<u8> {
    let mut hex = String::with_capacity(content_hash.len() * 2);
    for byte in content_hash {
        hex.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        hex.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    format!("classis-package-v1\n{agent_type}\n{version}\n{hex}\n").into_bytes()
}

/// The longest `PackageSignature` read, checked before anything inside it is parsed (ADR-0063
/// clause 3, Q-2). A Package Signer's certificate is about 340 bytes.
pub const MAX_SIGNATURE_LEN: usize = 2048;

/// The length of an Ed25519 signature.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// The Package Roots compiled into every binary (ADR-0063 clause 1), each a DER certificate. The
/// custodian's Root is added by a reviewed change; until then the list is empty and nothing
/// verifies.
const COMPILED_ROOTS: &[&[u8]] = &[];

/// The variable a **debug** build reads one more Package Root from, a DER file, so the
/// integration tests can sign with a Root of their own. A release build compiles no such read
/// (ADR-0063 clause 1).
pub const DEBUG_ROOT_ENV: &str = "CLASSIS_DEBUG_PACKAGE_ROOT";

/// `PackageSignature ::= SEQUENCE { version INTEGER (1), signer Certificate, signature OCTET
/// STRING (SIZE (64)) }`, borrowed from the bytes it was parsed from (ADR-0063 clause 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageSignature<'a> {
    /// The Package Signer's certificate, the whole DER `Certificate`.
    pub signer: &'a [u8],
    /// The Ed25519 signature over the statement.
    pub signature: &'a [u8; ED25519_SIGNATURE_LEN],
}

/// Why a package signature was refused, by the step that failed (ADR-0063 clause 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// The bytes are not a `PackageSignature`.
    Malformed(&'static str),
    /// The certificate does not lead to a compiled-in Package Root, or is not a Package Signer.
    Chain(String),
    /// The Package Signer's signature does not cover this statement.
    Signature,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "the signature is not a PackageSignature: {why}"),
            Self::Chain(why) => write!(f, "the signature's Package Signer is refused: {why}"),
            Self::Signature => f.write_str(
                "the signature does not cover this artifact — it must cover the Agent type, the \
                 version and the artifact's SHA-256",
            ),
        }
    }
}

impl std::error::Error for SignatureError {}

/// One DER element read off the front of the input: its value, the whole element, and what
/// follows it.
type Element<'a> = (&'a [u8], &'a [u8], &'a [u8]);

/// One DER tag-length-value (see [`Element`]). Definite, minimal lengths only, at most two length
/// octets (`MAX_SIGNATURE_LEN` fits).
fn tlv(input: &[u8], tag: u8) -> Result<Element<'_>, &'static str> {
    let (&got, rest) = input.split_first().ok_or("it ends early")?;
    if got != tag {
        return Err("an element has an unexpected tag");
    }
    let (&first, rest) = rest.split_first().ok_or("it ends early")?;
    let (len, rest) = match first {
        0..=0x7f => (usize::from(first), rest),
        0x81 => {
            let (&b, rest) = rest.split_first().ok_or("it ends early")?;
            if b < 0x80 {
                return Err("a length is not minimal");
            }
            (usize::from(b), rest)
        }
        0x82 => {
            let [hi, lo, rest @ ..] = rest else {
                return Err("it ends early");
            };
            let len = usize::from(*hi) << 8 | usize::from(*lo);
            if len < 0x100 {
                return Err("a length is not minimal");
            }
            (len, rest)
        }
        0x80 => return Err("an indefinite length is not DER"),
        _ => return Err("a length is too long"),
    };
    if rest.len() < len {
        return Err("it ends early");
    }
    let header = input.len() - rest.len();
    let (value, after) = rest.split_at(len);
    Ok((value, &input[..header + len], after))
}

/// Reads a `PackageSignature` (ADR-0063 clause 3). The length is checked before anything else.
///
/// # Errors
///
/// [`SignatureError::Malformed`] naming what is wrong.
pub fn parse_signature(bytes: &[u8]) -> Result<PackageSignature<'_>, SignatureError> {
    if bytes.len() > MAX_SIGNATURE_LEN {
        return Err(SignatureError::Malformed("it is longer than 2048 bytes"));
    }
    let malformed = SignatureError::Malformed;
    let (body, _, after) = tlv(bytes, 0x30).map_err(malformed)?;
    if !after.is_empty() {
        return Err(malformed("bytes follow it"));
    }
    let (version, _, body) = tlv(body, 0x02).map_err(malformed)?;
    if version != [1] {
        return Err(malformed("its version is not 1"));
    }
    let (_, signer, body) = tlv(body, 0x30).map_err(malformed)?;
    let (signature, _, body) = tlv(body, 0x04).map_err(malformed)?;
    if !body.is_empty() {
        return Err(malformed("bytes follow its signature"));
    }
    let signature = signature
        .try_into()
        .map_err(|_| malformed("its signature is not 64 bytes"))?;
    Ok(PackageSignature { signer, signature })
}

fn der_len(len: usize, out: &mut Vec<u8>) {
    match len {
        0..=0x7f => out.push(len as u8),
        0x80..=0xff => out.extend([0x81, len as u8]),
        _ => out.extend([0x82, (len >> 8) as u8, len as u8]),
    }
}

/// Writes a `PackageSignature` from a Package Signer's DER certificate and its signature — what
/// the release run's `sign` job writes in hex (ADR-0063 clause 13).
#[must_use]
pub fn encode_signature(signer: &[u8], signature: &[u8; ED25519_SIGNATURE_LEN]) -> Vec<u8> {
    let mut body = vec![0x02, 0x01, 0x01];
    body.extend_from_slice(signer);
    body.extend([0x04, ED25519_SIGNATURE_LEN as u8]);
    body.extend_from_slice(signature);
    let mut out = vec![0x30];
    der_len(body.len(), &mut out);
    out.extend(body);
    out
}

/// The Package Roots a signature is verified up to.
#[derive(Debug, Clone)]
pub struct Roots {
    anchors: Vec<TrustAnchor<'static>>,
}

impl Roots {
    /// Roots from DER certificates. Tests pass a test Root of their own here.
    ///
    /// # Errors
    ///
    /// A certificate `rustls-webpki` cannot take as a trust anchor.
    pub fn from_der<'a>(certs: impl IntoIterator<Item = &'a [u8]>) -> Result<Self, String> {
        let anchors = certs
            .into_iter()
            .map(|der| {
                webpki::anchor_from_trusted_cert(&CertificateDer::from(der))
                    .map(|anchor| anchor.to_owned())
                    .map_err(|e| format!("not a Package Root certificate: {e:?}"))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { anchors })
    }

    /// The Package Roots compiled into this binary (ADR-0063 clause 1). A debug build adds the
    /// one [`DEBUG_ROOT_ENV`] names, if it is set; see [`Roots::debug_root`].
    ///
    /// # Panics
    ///
    /// A compiled-in Root that is not a certificate, which a test of this module rules out.
    #[must_use]
    pub fn compiled() -> Self {
        let mut roots =
            Self::from_der(COMPILED_ROOTS.iter().copied()).expect("compiled-in Package Roots");
        #[cfg(debug_assertions)]
        if let Some(path) = Self::debug_root() {
            match std::fs::read(&path)
                .map_err(|e| e.to_string())
                .and_then(|der| Self::from_der([der.as_slice()]))
            {
                Ok(extra) => roots.anchors.extend(extra.anchors),
                Err(e) => panic!("{DEBUG_ROOT_ENV}={}: {e}", path.display()),
            }
        }
        roots
    }

    /// The file a debug build takes one more Package Root from, so a program can say so at
    /// startup. Always `None` in a release build.
    #[must_use]
    pub fn debug_root() -> Option<std::path::PathBuf> {
        #[cfg(debug_assertions)]
        {
            std::env::var_os(DEBUG_ROOT_ENV).map(std::path::PathBuf::from)
        }
        #[cfg(not(debug_assertions))]
        {
            None
        }
    }

    /// How many Roots there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether there is none, in which case nothing verifies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

/// A Package Signer carries no extendedKeyUsage (ADR-0063 clause 2): any one refuses it.
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
/// which misprints it (ADR-0063 clause 4).
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

/// Verifies a `PackageSignature` over `statement` up to `roots`, at `now` (ADR-0063 clause 4):
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
    let der = CertificateDer::from(parsed.signer);
    let signer = EndEntityCert::try_from(&der)
        .map_err(|e| SignatureError::Chain(format!("its certificate cannot be read: {e:?}")))?;
    signer
        .verify_for_usage(
            &[webpki::ring::ED25519],
            &roots.anchors,
            &[],
            now,
            NoExtendedKeyUsage,
            None,
            None,
        )
        .map_err(|e| SignatureError::Chain(chain_error(&e)))?;
    signer
        .verify_signature(webpki::ring::ED25519, statement, parsed.signature)
        .map_err(|_| SignatureError::Signature)
}

/// [`verify`] at the current time.
///
/// # Errors
///
/// As [`verify`].
pub fn verify_now(statement: &[u8], signature: &[u8], roots: &Roots) -> Result<(), SignatureError> {
    verify(statement, signature, roots, UnixTime::now())
}

/// A test Package Root and Package Signers, for the tests of every crate (ADR-0063). Compiled
/// only with the `test-support` feature; nothing here is trusted unless a test passes it in.
#[cfg(any(test, feature = "test-support"))]
pub mod testing {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_ED25519,
    };
    use time::{Duration, OffsetDateTime};

    /// A Package Root made for one test run.
    pub struct TestRoot {
        /// The Root's certificate, DER.
        pub der: Vec<u8>,
        issuer: Issuer<'static, KeyPair>,
    }

    /// A Package Signer: its certificate and the PKCS#8 key it signs with.
    pub struct TestSigner {
        /// The certificate, DER.
        pub der: Vec<u8>,
        /// The Ed25519 key, PKCS#8 v2 as `ring` writes it.
        pub pkcs8: Vec<u8>,
    }

    /// How a test Package Signer deviates from the profile (ADR-0063 clause 2).
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub enum Deviation {
        /// The profile.
        #[default]
        None,
        /// Valid until yesterday.
        Expired,
        /// `CA:true`.
        Ca,
        /// Carries `codeSigning`.
        ExtendedKeyUsage,
    }

    impl TestRoot {
        /// A fresh Ed25519 Root, valid from yesterday for 40 years.
        ///
        /// # Panics
        ///
        /// rcgen failing, which a test treats as a bug.
        #[must_use]
        pub fn new() -> Self {
            Self::with_key(KeyPair::generate_for(&PKCS_ED25519).expect("root key"))
        }

        /// A Root whose key is ECDSA P-256, which the verifier refuses.
        ///
        /// # Panics
        ///
        /// As [`TestRoot::new`].
        #[must_use]
        pub fn ecdsa() -> Self {
            Self::with_key(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root key"))
        }

        fn with_key(key: KeyPair) -> Self {
            let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
            p.distinguished_name
                .push(DnType::CommonName, "TEST ONLY Classis Package Root");
            p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            let now = OffsetDateTime::now_utc();
            p.not_before = now - Duration::days(1);
            p.not_after = now + Duration::days(365 * 40);
            let der = p.self_signed(&key).expect("root").der().to_vec();
            Self {
                der,
                issuer: Issuer::new(p, key),
            }
        }

        /// An intermediate CA this Root issued, itself able to issue Package Signers, which the
        /// verifier refuses to pass through.
        ///
        /// # Panics
        ///
        /// As [`TestRoot::new`].
        #[must_use]
        pub fn intermediate(&self) -> Self {
            let key = KeyPair::generate_for(&PKCS_ED25519).expect("intermediate key");
            let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
            p.distinguished_name
                .push(DnType::CommonName, "TEST ONLY Intermediate");
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            let now = OffsetDateTime::now_utc();
            p.not_before = now - Duration::days(1);
            p.not_after = now + Duration::days(365 * 10);
            let der = p
                .signed_by(&key, &self.issuer)
                .expect("intermediate")
                .der()
                .to_vec();
            Self {
                der,
                issuer: Issuer::new(p, key),
            }
        }

        /// A Package Signer of the profile.
        #[must_use]
        pub fn signer(&self) -> TestSigner {
            self.signer_with(Deviation::None)
        }

        /// A Package Signer that deviates as told.
        ///
        /// # Panics
        ///
        /// As [`TestRoot::new`].
        #[must_use]
        pub fn signer_with(&self, deviation: Deviation) -> TestSigner {
            let pkcs8 =
                ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                    .expect("signer key")
                    .as_ref()
                    .to_vec();
            let key = KeyPair::try_from(pkcs8.as_slice()).expect("signer key");
            let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
            p.distinguished_name
                .push(DnType::CommonName, "TEST ONLY Package Signer");
            p.is_ca = IsCa::ExplicitNoCa;
            p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            let now = OffsetDateTime::now_utc();
            p.not_before = now - Duration::days(2);
            p.not_after = now + Duration::days(365 * 10);
            match deviation {
                Deviation::None => {}
                Deviation::Expired => p.not_after = now - Duration::days(1),
                Deviation::Ca => p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained),
                Deviation::ExtendedKeyUsage => {
                    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
                }
            }
            let der = p
                .signed_by(&key, &self.issuer)
                .expect("signer")
                .der()
                .to_vec();
            TestSigner { der, pkcs8 }
        }

        /// These Roots, this one alone.
        ///
        /// # Panics
        ///
        /// Never for a Root this module made.
        #[must_use]
        pub fn roots(&self) -> super::Roots {
            super::Roots::from_der([self.der.as_slice()]).expect("test root")
        }
    }

    impl Default for TestRoot {
        fn default() -> Self {
            Self::new()
        }
    }

    impl TestSigner {
        /// The `PackageSignature` of `statement`, DER.
        ///
        /// # Panics
        ///
        /// A key this module did not make.
        #[must_use]
        pub fn sign(&self, statement: &[u8]) -> Vec<u8> {
            let key = ring::signature::Ed25519KeyPair::from_pkcs8(&self.pkcs8).expect("key");
            let sig: [u8; 64] = key.sign(statement).as_ref().try_into().expect("64 bytes");
            super::encode_signature(&self.der, &sig)
        }

        /// The `PackageSignature` of an artifact's statement, DER.
        #[must_use]
        pub fn sign_artifact(
            &self,
            agent_type: &str,
            version: &str,
            content_hash: &[u8],
        ) -> Vec<u8> {
            self.sign(&super::statement(agent_type, version, content_hash))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{Deviation, TestRoot};
    use super::*;

    /// Verifies: ADR-0026
    #[test]
    fn the_statement_names_type_version_and_hash() {
        assert_eq!(
            statement("otelcol-contrib", "0.110.0", &[0x0a, 0xff]),
            b"classis-package-v1\notelcol-contrib\n0.110.0\n0aff\n".to_vec()
        );
        assert_ne!(
            statement("a", "1", &[1]),
            statement("b", "1", &[1]),
            "the type is covered"
        );
        assert_ne!(
            statement("a", "1", &[1]),
            statement("a", "2", &[1]),
            "the version is covered"
        );
    }

    fn stmt() -> Vec<u8> {
        statement("supervisor", "1.2.3", &[7; 32])
    }

    /// Verifies: ADR-0063
    #[test]
    fn a_package_signer_of_a_root_verifies() {
        let root = TestRoot::new();
        let signer = root.signer();
        assert_eq!(
            verify_now(&stmt(), &signer.sign(&stmt()), &root.roots()),
            Ok(())
        );
    }

    /// Verifies: ADR-0063
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

    /// Verifies: ADR-0063
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
        let none = Roots::from_der([]).unwrap();
        assert!(matches!(
            verify_now(&stmt(), &sig, &none),
            Err(SignatureError::Chain(_))
        ));
    }

    /// Verifies: ADR-0063
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
    /// Verifies: ADR-0063
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

    /// Verifies: ADR-0063
    #[test]
    fn the_value_is_strict_der_and_bounded() {
        let root = TestRoot::new();
        let good = root.signer().sign(&stmt());
        let parsed = parse_signature(&good).unwrap();
        assert_eq!(encode_signature(parsed.signer, parsed.signature), good);

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
        let short = encode_signature(&[0x30, 0x00], &sig);
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

    /// Verifies: ADR-0063
    #[test]
    fn the_compiled_in_roots_are_certificates() {
        assert!(Roots::from_der(COMPILED_ROOTS.iter().copied()).is_ok());
    }
}
