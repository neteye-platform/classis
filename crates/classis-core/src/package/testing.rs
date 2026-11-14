//! A test Package Root and Package Signers, for the tests of every crate (ADR-0063). Compiled
//! only with the `test-support` feature; nothing here is trusted unless a test passes it in.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_ED25519,
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
    pub fn sign_artifact(&self, agent_type: &str, version: &str, content_hash: &[u8]) -> Vec<u8> {
        self.sign(&super::statement(agent_type, version, content_hash))
    }
}
