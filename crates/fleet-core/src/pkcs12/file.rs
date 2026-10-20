//! The bootstrap PKCS#12 file written and read with `p12-keystore` (ADR-0029 clauses 1 and 7).
//!
//! Reading is bounded: a file over [`MAX_FILE_BYTES`] is refused before it is parsed, and
//! `p12-keystore` itself refuses work factors above a million iterations. Before anything is
//! decrypted, the file's structure is held to clause 1's family: a MAC of HMAC with SHA-2, and every
//! encryption PBES2 with PBKDF2-HMAC-SHA-2 and AES-CBC — no PBES1, no scrypt, no AES-GCM, no key in
//! the clear. `p12-keystore` would read several of those.

use std::fmt;

use der::asn1::{Any, ObjectIdentifier, OctetString};
use der::{Decode as _, Encode as _};
use p12_keystore::{
    Certificate, EncryptionAlgorithm, KeyStore, KeyStoreEntry, MacAlgorithm, Pkcs12Archive,
    PrivateKey, PrivateKeyChain,
};
use pkcs5::pbes2::{EncryptionScheme, Kdf, Pbkdf2Prf};

use super::{ITERATIONS, MAX_FILE_BYTES};

/// The alias and local key id the key and its certificate share inside the file.
const ALIAS: &str = "bootstrap";

/// The file of a certificate and its key, both DER — the key PKCS#8 — under `password`.
///
/// # Errors
/// Returns an error when the certificate or the key cannot be read, or the file cannot be written.
pub fn seal(
    certificate_der: &[u8],
    private_key_der: &[u8],
    password: &str,
) -> Result<Vec<u8>, String> {
    let key = PrivateKey::from_der(private_key_der).map_err(|e| format!("the key: {e}"))?;
    let certificate =
        Certificate::from_der(certificate_der).map_err(|e| format!("the certificate: {e}"))?;
    let mut store = KeyStore::new();
    store.add_entry(
        ALIAS,
        KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(ALIAS, key, [certificate])),
    );
    store
        .writer(password)
        .encryption_algorithm(EncryptionAlgorithm::PbeWithHmacSha256AndAes256)
        .encryption_iterations(ITERATIONS)
        .mac_algorithm(MacAlgorithm::HmacSha256)
        .mac_iterations(ITERATIONS)
        .write()
        .map_err(|e| format!("cannot write the PKCS#12 file: {e}"))
}

/// What a file holds: the certificate and its key, DER, the key PKCS#8. Its `Debug` names neither.
#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    pub certificate_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity").finish_non_exhaustive()
    }
}

/// Why a file was not opened.
#[derive(Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The MAC does not verify under the password: the password is wrong, or the file was changed.
    WrongPassword,
    /// Anything else — too large, no MAC, an unsupported scheme, not one key with its certificate.
    Invalid(String),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::WrongPassword => f.write_str("the password does not open it"),
            OpenError::Invalid(why) => f.write_str(why),
        }
    }
}

/// The certificate and key in `bytes`, under `password` (ADR-0029 clause 7).
///
/// # Errors
/// [`OpenError::WrongPassword`] when the MAC fails, and [`OpenError::Invalid`] for a file over
/// [`MAX_FILE_BYTES`], one without a MAC, one in a scheme this build does not read, and one that
/// holds anything but exactly one private key with exactly the one certificate whose public key
/// is its own.
pub fn open(bytes: &[u8], password: &str) -> Result<Identity, OpenError> {
    let invalid = |why: String| OpenError::Invalid(why);
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(invalid(format!("larger than {MAX_FILE_BYTES} bytes")));
    }
    let pfx = ::pkcs12::pfx::Pfx::from_der(bytes)
        .map_err(|e| invalid(format!("not a PKCS#12 file: {e}")))?;
    clause_one(&pfx).map_err(invalid)?;
    let archive = Pkcs12Archive::from_pkcs12(bytes, password).map_err(|e| match e {
        p12_keystore::error::Error::MacError(_) => OpenError::WrongPassword,
        other => invalid(format!("cannot be read: {other}")),
    })?;
    let [key] = archive.keys.as_slice() else {
        return Err(invalid(format!(
            "holds {} private keys, not one",
            archive.keys.len()
        )));
    };
    let private_key_der = key.key.as_der().to_vec();
    let public = rcgen::KeyPair::try_from(private_key_der.as_slice())
        .map_err(|e| invalid(format!("its private key cannot be read: {e}")))?;
    let matching: Vec<&[u8]> = archive
        .certs
        .iter()
        .map(|bag| bag.cert.as_der())
        .filter(|der| public_key_of(der).is_some_and(|key| key == public.public_key_raw()))
        .collect();
    let ([certificate], 1) = (matching.as_slice(), archive.certs.len()) else {
        return Err(invalid(format!(
            "holds {} certificates, {} of them for its key — not exactly the one",
            archive.certs.len(),
            matching.len()
        )));
    };
    Ok(Identity {
        certificate_der: certificate.to_vec(),
        private_key_der,
    })
}

const SHA_2: [ObjectIdentifier; 3] = [
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2"),
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3"),
];
const PBES2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.13");
const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const ENCRYPTED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.6");

/// Whether the file is of clause 1's family, read from its structure before anything is
/// decrypted: a MAC — without one anyone could swap the certificate without the password — of
/// HMAC with SHA-2, and every encrypted part PBES2 with PBKDF2-HMAC-SHA-2 and AES-CBC. A key in the
/// clear, and any bag but an encrypted key and a certificate, is refused.
fn clause_one(pfx: &::pkcs12::pfx::Pfx) -> Result<(), String> {
    let der = |e: der::Error| format!("not a PKCS#12 file: {e}");
    let mac = pfx.mac_data.as_ref().ok_or("carries no MAC")?;
    if !SHA_2.contains(&mac.mac.algorithm.oid) {
        return Err(format!(
            "its MAC is not HMAC with SHA-2 ({})",
            mac.mac.algorithm.oid
        ));
    }
    if pfx.auth_safe.content_type != DATA {
        return Err("its content is not data".to_string());
    }
    let content = |any: &Any| -> Result<Vec<u8>, String> {
        Ok(OctetString::from_der(&any.to_der().map_err(der)?)
            .map_err(der)?
            .into_bytes()
            .into_vec())
    };
    let safes =
        ::pkcs12::AuthenticatedSafe::from_der(&content(&pfx.auth_safe.content)?).map_err(der)?;
    for safe in safes {
        if safe.content_type == ENCRYPTED_DATA {
            let encrypted = ::pkcs12::cms::encrypted_data::EncryptedData::from_der(
                &safe.content.to_der().map_err(der)?,
            )
            .map_err(der)?;
            let algorithm = &encrypted.enc_content_info.content_enc_alg;
            pbes2_of_clause_one(algorithm.oid, algorithm.parameters.as_ref())?;
        } else if safe.content_type == DATA {
            let bags = ::pkcs12::safe_bag::SafeContents::from_der(&content(&safe.content)?)
                .map_err(der)?;
            for bag in bags {
                if bag.bag_id == ::pkcs12::PKCS_12_PKCS8_KEY_BAG_OID {
                    let value = Any::from_der(&bag.bag_value).map_err(der)?;
                    let key =
                        ::pkcs12::pbe_params::EncryptedPrivateKeyInfo::from_der(value.value())
                            .map_err(der)?;
                    let algorithm = &key.encryption_algorithm;
                    pbes2_of_clause_one(algorithm.oid, algorithm.parameters.as_ref())?;
                } else if bag.bag_id != ::pkcs12::PKCS_12_CERT_BAG_OID {
                    return Err(format!(
                        "holds a bag that is neither an encrypted key nor a certificate ({})",
                        bag.bag_id
                    ));
                }
            }
        } else {
            return Err(format!("holds content of the type {}", safe.content_type));
        }
    }
    Ok(())
}

/// Whether an encryption is PBES2 with PBKDF2-HMAC-SHA-2 and AES-CBC.
fn pbes2_of_clause_one(oid: ObjectIdentifier, parameters: Option<&Any>) -> Result<(), String> {
    let refused = || {
        format!(
            "is encrypted with a scheme other than PBES2, PBKDF2-HMAC-SHA-2 and AES-CBC ({oid})"
        )
    };
    if oid != PBES2 {
        return Err(refused());
    }
    let parameters = parameters
        .ok_or_else(refused)?
        .to_der()
        .map_err(|_| refused())?;
    let parameters = pkcs5::pbes2::Parameters::from_der(&parameters).map_err(|_| refused())?;
    match (&parameters.kdf, &parameters.encryption) {
        (
            Kdf::Pbkdf2(pbkdf2),
            EncryptionScheme::Aes128Cbc { .. }
            | EncryptionScheme::Aes192Cbc { .. }
            | EncryptionScheme::Aes256Cbc { .. },
        ) if matches!(
            pbkdf2.prf,
            Pbkdf2Prf::HmacWithSha256 | Pbkdf2Prf::HmacWithSha384 | Pbkdf2Prf::HmacWithSha512
        ) =>
        {
            Ok(())
        }
        _ => Err(refused()),
    }
}

/// The public key a certificate certifies, as its bit string carries it.
fn public_key_of(certificate_der: &[u8]) -> Option<Vec<u8>> {
    let (_, certificate) = x509_parser::parse_x509_certificate(certificate_der).ok()?;
    Some(
        certificate
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(name: &str) -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().expect("key");
        let certificate = rcgen::CertificateParams::new(vec![name.to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("certificate");
        (certificate.der().to_vec(), key.serialize_der())
    }

    const PASSWORD: &str = "correct horse battery";

    /// Verifies: ADR-0029
    #[test]
    fn a_sealed_file_opens_under_its_password_to_exactly_the_certificate_and_its_key() {
        let (certificate, key) = pair("bootstrap");
        let file = seal(&certificate, &key, PASSWORD).expect("sealed");
        let opened = open(&file, PASSWORD).expect("opened");
        assert_eq!(opened.certificate_der, certificate);
        assert_eq!(opened.private_key_der, key);
        assert_eq!(
            open(&file, "a wrong password"),
            Err(OpenError::WrongPassword)
        );
        assert!(
            !format!("{opened:?}").contains(&format!("{:?}", &key[..8])),
            "Debug names no key"
        );
    }

    /// The file is the scheme ADR-0029 clause 1 names: PBES2 with AES-256 and a SHA-256 MAC, at
    /// 600 000 iterations.
    /// Verifies: ADR-0029
    #[test]
    fn a_sealed_file_is_pbes2_with_aes_256_and_a_sha_256_mac() {
        let (certificate, key) = pair("bootstrap");
        let file = seal(&certificate, &key, PASSWORD).expect("sealed");
        let pfx = ::pkcs12::pfx::Pfx::from_der(&file).expect("pfx");
        let mac = pfx.mac_data.expect("a MAC");
        assert_eq!(mac.iterations, ITERATIONS as i32);
        assert_eq!(
            mac.mac.algorithm.oid.to_string(),
            "2.16.840.1.101.3.4.2.1",
            "SHA-256"
        );
        let text = format!("{:02x?}", file);
        // The OIDs of PBES2 and of AES-256-CBC, DER-encoded, are in the file.
        let pbes2 = "2a, 86, 48, 86, f7, 0d, 01, 05, 0d";
        let aes256 = "60, 86, 48, 01, 65, 03, 04, 01, 2a";
        assert!(text.contains(pbes2), "PBES2");
        assert!(text.contains(aes256), "AES-256-CBC");
    }

    /// Verifies: ADR-0029
    #[test]
    fn a_file_is_refused_when_large_without_a_mac_or_not_one_key_with_its_certificate() {
        assert!(matches!(
            open(&vec![0u8; MAX_FILE_BYTES as usize + 1], PASSWORD),
            Err(OpenError::Invalid(why)) if why.contains("larger than")
        ));
        assert!(matches!(
            open(b"not der", PASSWORD),
            Err(OpenError::Invalid(_))
        ));

        let (certificate, key) = pair("bootstrap");
        let (other_certificate, _) = pair("other");
        let mut store = KeyStore::new();
        store.add_entry(
            ALIAS,
            KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(
                ALIAS,
                PrivateKey::from_der(&key).expect("key"),
                [Certificate::from_der(&other_certificate).expect("cert")],
            )),
        );
        let mismatched = store
            .writer(PASSWORD)
            .encryption_iterations(1_000)
            .mac_iterations(1_000)
            .write()
            .expect("written");
        assert!(
            matches!(open(&mismatched, PASSWORD), Err(OpenError::Invalid(why)) if why.contains("for its key")),
            "a certificate that is not the key's"
        );

        let mut store = KeyStore::new();
        store.add_entry(
            ALIAS,
            KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(
                ALIAS,
                PrivateKey::from_der(&key).expect("key"),
                [
                    Certificate::from_der(&certificate).expect("cert"),
                    Certificate::from_der(&other_certificate).expect("cert"),
                ],
            )),
        );
        let extra = store
            .writer(PASSWORD)
            .encryption_iterations(1_000)
            .mac_iterations(1_000)
            .write()
            .expect("written");
        assert!(
            matches!(open(&extra, PASSWORD), Err(OpenError::Invalid(_))),
            "a second certificate"
        );

        let mut sha1_mac = KeyStore::new();
        sha1_mac.add_entry(
            ALIAS,
            KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(
                ALIAS,
                PrivateKey::from_der(&key).expect("key"),
                [Certificate::from_der(&certificate).expect("cert")],
            )),
        );
        let sha1_mac = sha1_mac
            .writer(PASSWORD)
            .mac_algorithm(MacAlgorithm::HmacSha1)
            .encryption_iterations(1_000)
            .mac_iterations(1_000)
            .write()
            .expect("written");
        assert!(
            matches!(open(&sha1_mac, PASSWORD), Err(OpenError::Invalid(why)) if why.contains("SHA-2")),
            "a SHA-1 MAC"
        );

        let mut store = KeyStore::new();
        store.add_entry(
            "ca",
            KeyStoreEntry::Certificate(Certificate::from_der(&certificate).expect("cert")),
        );
        let keyless = store
            .writer(PASSWORD)
            .encryption_iterations(1_000)
            .mac_iterations(1_000)
            .write()
            .expect("written");
        assert!(
            matches!(open(&keyless, PASSWORD), Err(OpenError::Invalid(why)) if why.contains("private keys")),
            "no key"
        );
    }
}
