//! The Server as a local certificate authority (ADR-0021).
//!
//! The Baseline's CSR flow lets an Agent keep its private key and ask for a certificate over the
//! connection it already has: it sends a PEM certificate signing request, and the Server "creates a
//! client certificate … either by issuing a self-signed certificate (acting as a local CA) or
//! proxies the CSR to a CA". This is the first of those; proxying to an external CA is future work
//! and would sit behind the same `[client_ca]` seam.
//!
//! Nothing here decides *who* may enrol. A CSR from an Agent holding a certificate of the client
//! CA is a renewal and is signed at once; a CSR on an enrolment connection waits until an operator
//! approves it ([`crate::enrolment`], ADR-0021).

use rcgen::{
    CertificateSigningRequestParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType, SerialNumber,
};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::config::ClientCaConfig;
use crate::revocation::{CertId, Facts, Signed, SubjectValues};

/// The SAN URI prefix naming the host a certificate was issued to (ADR-0021 clause 7).
pub const HOST_URI_PREFIX: &str = "urn:opamp-fleet:host:";

/// The issuing authority, loaded once at startup. Holding it parsed is what makes `AppState`'s
/// capability honest: `AcceptsConnectionSettingsRequest` is declared only while this exists.
pub struct ClientCa {
    issuer: Issuer<'static, KeyPair>,
    /// The CA's own certificate, DER: what a renewal proof's certificate must be signed by.
    ca_der: Vec<u8>,
    /// The common name every certificate it signs carries, derived from the CA's (ADR-0028
    /// clause 28).
    leaf_name: String,
    validity_days: u32,
    /// A life shorter than a day, in place of `validity_days` — what a test of renewal waits out.
    validity: Option<time::Duration>,
}

impl ClientCa {
    /// Loads the CA from `[client_ca]`. Either file being unreadable, or a key that is not PKCS#8,
    /// fails startup rather than the first enrolment (ADR-0010), and so does a CA whose name
    /// gives its certificates a common name longer than 64 characters (ADR-0028 clause 28).
    /// Whether the key belongs to the certificate is not checked here.
    pub fn from_config(config: &ClientCaConfig) -> Result<Self, String> {
        let cert_pem = std::fs::read_to_string(&config.cert_file)
            .map_err(|e| format!("cannot read {}: {e}", config.cert_file.display()))?;
        let key_pem = std::fs::read_to_string(&config.key_file)
            .map_err(|e| format!("cannot read {}: {e}", config.key_file.display()))?;
        let key = KeyPair::from_pem(&key_pem)
            .map_err(|e| format!("cannot read {}: {e}", config.key_file.display()))?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key)
            .map_err(|e| format!("cannot use {} as a CA: {e}", config.cert_file.display()))?;
        let ca_der = opamp::tls::certificates(cert_pem.as_bytes())
            .map_err(|e| format!("cannot read {}: {e}", config.cert_file.display()))?
            .first()
            .map(|der| der.as_ref().to_vec())
            .ok_or_else(|| format!("{} holds no certificate", config.cert_file.display()))?;
        let leaf_name = leaf_name(&config.cert_file, &ca_der)?;
        Ok(ClientCa {
            issuer,
            ca_der,
            leaf_name,
            validity_days: config.validity_days,
            validity: None,
        })
    }

    /// Signs an Agent's CSR and returns the issued certificate as PEM.
    ///
    /// The subject is the Server's, not the request's: the six values `subject` names — copied by
    /// the caller from the bootstrap certificate an approval reads or the certificate a renewal
    /// renews (ADR-0036 clauses 3 and 4) — and the common name derived from the CA's (ADR-0021
    /// clause 7), so no self-asserted text reaches a signed certificate. The signed certificate
    /// must carry exactly those values, or nothing is handed out.
    /// Nor is it bound to anything the Agent reports. Binding a certificate to an `instance_uid`
    /// would mean it dies the moment the Server re-keys that Agent through `AgentIdentification` —
    /// an outage of the Server's own making (ADR-0021).
    ///
    /// What the request may *not* dictate either is the shape of the certificate. `rcgen` carries the
    /// CSR's `basicConstraints`, `keyUsage`, `extendedKeyUsage`, and SANs into the signed output,
    /// so a request asking for `CA:TRUE` would otherwise be handed a certificate that chains to the
    /// fleet CA and can mint more — a privilege this Server never means to grant. Enrolment issues
    /// one thing only: a client-authentication leaf. So the constraints are overwritten here rather
    /// than trusted from the request — forced to a non-CA cert with `clientAuth` and a plain
    /// signing key usage, and any requested SANs dropped, before it is signed.
    ///
    /// # Errors
    /// A request that cannot be parsed, or that this CA cannot sign, is an error the caller turns
    /// into the Baseline's `ServerErrorResponse` of type `BadRequest`.
    pub fn sign(
        &self,
        csr_pem: &str,
        host: &str,
        subject: &SubjectValues,
    ) -> Result<Signed, String> {
        let (_, mut request) = read(csr_pem)?;
        // The life starts now, less a few minutes for clocks that disagree: a start in the past
        // would put a fresh certificate into its renewal window at once (ADR-0021 clause 11), and
        // would lengthen what a stolen one is good for.
        // A life shorter than the skew allowance keeps a tenth of itself as its allowance, or it
        // would start out in its renewal window.
        let skew = match self.validity {
            Some(validity) => {
                let tenth: time::Duration = validity / 10_i32;
                tenth.min(CLOCK_SKEW)
            }
            None => CLOCK_SKEW,
        };
        request.params.not_before = time::OffsetDateTime::now_utc() - skew;
        request.params.not_after = match self.validity {
            Some(validity) => time::OffsetDateTime::now_utc() + validity,
            None => not_after(self.validity_days)?,
        };
        // Never trust the request for the certificate's name: the values carried over, and its
        // role as the CA names it.
        request.params.distinguished_name = distinguished_name(
            &crate::bootstrap::carried_attributes(subject, &self.leaf_name),
        )?;
        // Never trust the request for the certificate's powers: force a client-auth leaf.
        request.params.is_ca = IsCa::ExplicitNoCa;
        request.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        request.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        // None of the request's names — one could name another host. The one name this Server
        // puts in is the host the certificate is issued to (ADR-0021 clause 7), which a renewal
        // carries on.
        request.params.subject_alt_names.clear();
        request.params.subject_alt_names.push(SanType::URI(
            format!("{HOST_URI_PREFIX}{host}")
                .try_into()
                .map_err(|e| format!("cannot name the host {host:?}: {e}"))?,
        ));
        // A serial of its own for every certificate, so two certificates from one key are two
        // revocable things (ADR-0021 clause 32). rcgen would derive it from the key.
        request.params.serial_number = Some(random_serial()?);
        let certificate = request
            .signed_by(&self.issuer)
            .map_err(|e| format!("cannot sign the certificate signing request: {e}"))?;
        let facts = facts(certificate.der())?;
        // Exactly the values carried over, and no others (ADR-0036 clause 4).
        if facts.subject_values != *subject {
            return Err(
                "the signed certificate does not carry the subject values it was \
                        issued with"
                    .to_string(),
            );
        }
        Ok(Signed {
            facts,
            pem: certificate.pem(),
        })
    }

    /// Issues certificates that live `validity` instead of `validity_days` — seconds, for a test
    /// that watches renewal happen before expiry (ADR-0021 clause 9).
    #[must_use]
    pub fn with_validity(mut self, validity: time::Duration) -> Self {
        self.validity = Some(validity);
        self
    }

    /// The certificate a CSR proves it renews, when it carries a renewal proof (ADR-0021 clause
    /// 27): the proof's certificate must have been signed by this CA and be valid now, and its key
    /// must have signed the request's new key. `Ok(None)` for a request that carries no proof.
    ///
    /// # Errors
    /// Returns the `BadRequest` text for a proof that does not hold.
    pub fn renewal_proof(&self, csr_pem: &str) -> Result<Option<Facts>, String> {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        // The proof and the key it covers come from the one request this CSR is (ADR-0021
        // clause 27), and so does the key `sign` certifies.
        let (csr_der, request) = read(csr_pem)?;
        let Some(encoded) = request
            .params
            .subject_alt_names
            .iter()
            .find_map(|san| match san {
                SanType::URI(uri) => uri.as_str().strip_prefix(fleet_core::renewal::URI_PREFIX),
                _ => None,
            })
        else {
            return Ok(None);
        };
        // Neither proof stands beside the other (ADR-0039 clause 8).
        if request.params.subject_alt_names.iter().any(|san| {
            matches!(san, SanType::URI(uri)
                if uri.as_str().starts_with(fleet_core::bootstrap_proof::URI_PREFIX))
        }) {
            return Err(BOTH_PROOFS.to_string());
        }
        let refused = |why: &str| format!("the renewal proof does not hold: {why}");
        let content = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| refused("it is not base64url"))?;
        let (old_der, signature) =
            fleet_core::renewal::decode(&content).ok_or_else(|| refused("it does not parse"))?;
        let (_, old) = X509Certificate::from_der(old_der)
            .map_err(|_| refused("its certificate does not parse"))?;
        let (_, ca) = X509Certificate::from_der(&self.ca_der)
            .map_err(|_| refused("the CA does not parse"))?;
        old.verify_signature(Some(ca.public_key()))
            .map_err(|_| refused("its certificate was not issued by this CA"))?;
        if !old.validity().is_valid() {
            return Err(refused("its certificate is not valid now"));
        }
        let new_key = Sha256::digest(requested_key(&csr_der)?);
        let statement = fleet_core::renewal::statement(&new_key);
        verify_with(old.public_key(), &statement, signature)
            .map_err(|()| refused("its signature does not verify with the certificate's key"))?;
        facts(old_der).map(Some)
    }

    pub fn validity_days(&self) -> u32 {
        self.validity_days
    }
}

/// The bootstrap certificate (DER) a CSR proves it enrols with, when it carries a bootstrap proof
/// (ADR-0039 clauses 7, 8): the certificate must be valid now, and its key must have signed the
/// request's own key. Which CA issued it and whether it is revoked are the caller's to check, against
/// `[enrolment]` and the register. `Ok(None)` for a request that carries no proof.
///
/// # Errors
/// Returns the `BadRequest` text for a proof that does not hold, and for a request that carries a
/// renewal proof beside it.
pub fn bootstrap_proof(csr_pem: &str) -> Result<Option<Vec<u8>>, String> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let csr_der = fleet_core::csr::der(csr_pem.as_bytes())?;
    let Some(encoded) =
        fleet_core::csr::requested_uri(&csr_der, fleet_core::bootstrap_proof::URI_PREFIX)?
    else {
        return Ok(None);
    };
    if fleet_core::csr::requested_uri(&csr_der, fleet_core::renewal::URI_PREFIX)?.is_some() {
        return Err(BOTH_PROOFS.to_string());
    }
    let refused = |why: &str| format!("the bootstrap proof does not hold: {why}");
    let content = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| refused("it is not base64url"))?;
    let (der, signature) = fleet_core::bootstrap_proof::decode(&content)
        .ok_or_else(|| refused("it does not parse"))?;
    let (_, certificate) =
        X509Certificate::from_der(der).map_err(|_| refused("its certificate does not parse"))?;
    if !certificate.validity().is_valid() {
        return Err(refused("its certificate is not valid now"));
    }
    let new_key = Sha256::digest(requested_key(&csr_der)?);
    let statement = fleet_core::bootstrap_proof::statement(&new_key);
    verify_with(certificate.public_key(), &statement, signature)
        .map_err(|()| refused("its signature does not verify with the certificate's key"))?;
    Ok(Some(der.to_vec()))
}

/// The certificate (DER) a CSR's bootstrap proof embeds, read without checking the proof.
/// `Ok(None)` for a request without a proof.
///
/// # Errors
/// Returns the `BadRequest` text for a request that is not one PEM block, or a proof that does not
/// parse.
pub fn bootstrap_proof_certificate(csr_pem: &str) -> Result<Option<Vec<u8>>, String> {
    use base64::Engine as _;
    let csr_der = fleet_core::csr::der(csr_pem.as_bytes())?;
    let Some(encoded) =
        fleet_core::csr::requested_uri(&csr_der, fleet_core::bootstrap_proof::URI_PREFIX)?
    else {
        return Ok(None);
    };
    let unparsed = || "the bootstrap proof does not hold: it does not parse".to_string();
    let content = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| unparsed())?;
    let (der, _) = fleet_core::bootstrap_proof::decode(&content).ok_or_else(unparsed)?;
    X509Certificate::from_der(der).map_err(|_| unparsed())?;
    Ok(Some(der.to_vec()))
}

/// The issuer and serial of the certificate (DER) `der`, or `None` when it does not parse.
#[must_use]
pub fn cert_id(der: &[u8]) -> Option<CertId> {
    let (_, certificate) = X509Certificate::from_der(der).ok()?;
    Some(CertId::new(
        certificate.issuer().as_raw(),
        &hex::encode(certificate.raw_serial()),
    ))
}

/// What a CSR carrying both proofs is answered (ADR-0039 clause 8).
pub const BOTH_PROOFS: &str =
    "the certificate signing request carries both a renewal proof and a bootstrap proof";

/// 16 bytes from the system's secure random source, the top bit cleared so the serial is a
/// positive integer (RFC 5280 §4.1.2.2).
pub(crate) fn random_serial() -> Result<SerialNumber, String> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "no secure random source for a serial number".to_string())?;
    bytes[0] &= 0x7f;
    Ok(SerialNumber::from_slice(&bytes))
}

/// What a certificate (DER) says about itself: issuer and serial, subject, the SHA-256 of its
/// public key, and when it expires — for the register, and for a peer's certificate at admission.
///
/// # Errors
/// Returns an error when the certificate does not parse.
pub fn facts(der: &[u8]) -> Result<Facts, String> {
    use sha2::{Digest, Sha256};
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| format!("the certificate does not parse: {e}"))?;
    // RFC 5280 4.1.2.2: at most 20 octets, the length the register and every Gateway's list are
    // bounded on (Q-2). A certificate with a longer serial — only a foreign CA could issue one —
    // is not taken.
    if cert.raw_serial().len() > crate::revocation::MAX_SERIAL_HEX / 2 {
        return Err("the certificate's serial is longer than 20 octets".to_string());
    }
    let not_after = cert.validity().not_after.timestamp();
    let host = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .and_then(|san| {
            san.value.general_names.iter().find_map(|name| match name {
                x509_parser::extensions::GeneralName::URI(uri) => {
                    uri.strip_prefix(HOST_URI_PREFIX).map(str::to_string)
                }
                _ => None,
            })
        });
    Ok(Facts {
        id: CertId::new(cert.issuer().as_raw(), &hex::encode(cert.raw_serial())),
        issuer_name: name_text(cert.issuer()),
        subject: name_text(cert.subject()),
        // The key itself, not its SubjectPublicKeyInfo: the fingerprint an enrolment request is
        // listed by and the Client logs.
        key_fingerprint: hex::encode(Sha256::digest(&cert.public_key().subject_public_key.data)),
        not_after_ms: u64::try_from(not_after).unwrap_or(0).saturating_mul(1000),
        host,
        subject_values: subject_values(cert.subject()),
    })
}

/// A name as text, for the operator to read: `C=AT, O=…, organizationIdentifier=…, CN=…`. The
/// parser's own registry knows no `organizationIdentifier` and would print its OID.
pub(crate) fn name_text(name: &x509_parser::x509::X509Name<'_>) -> String {
    use x509_parser::oid_registry::{OidEntry, OidRegistry};
    static REGISTRY: std::sync::LazyLock<OidRegistry<'static>> = std::sync::LazyLock::new(|| {
        let mut registry = OidRegistry::default().with_all_crypto().with_x509();
        registry.insert(
            x509_parser::oid_registry::asn1_rs::oid!(2.5.4 .97),
            OidEntry::new("organizationIdentifier", "X.520 organizationIdentifier"),
        );
        registry
    });
    name.to_string_with_registry(&REGISTRY)
        .unwrap_or_else(|_| name.to_string())
}

/// The values of a subject a Host carries (ADR-0035 clause 1), each the first of its attribute.
/// A value that is not a string is left out.
pub(crate) fn subject_values(name: &x509_parser::x509::X509Name<'_>) -> SubjectValues {
    let first = |oid: &str| {
        name.iter_attributes()
            .filter(|attribute| attribute.attr_type().to_id_string() == oid)
            .find_map(|attribute| attribute.as_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    SubjectValues {
        country: first("2.5.4.6"),
        state: first("2.5.4.8"),
        locality: first("2.5.4.7"),
        organization: first("2.5.4.10"),
        organizational_unit: first("2.5.4.11"),
        organization_identifier: first("2.5.4.97"),
    }
}

/// The six values a bootstrap certificate's subject carries into a host certificate, read under
/// the rules they were issued by (ADR-0036 clauses 1 and 3): each attribute at most once, a
/// country of two upper-case letters as a `PrintableString`, every other value of 1 to 64
/// characters without a control character as a `UTF8String` or a `PrintableString`, and an
/// organization and an organizational unit present. Every other attribute, the common name
/// included, is passed over. The certificate may come from a foreign PKI, so nothing in it is
/// taken on trust.
///
/// # Errors
/// Returns why the subject cannot be carried, naming the attribute.
pub(crate) fn carried_subject(
    name: &x509_parser::x509::X509Name<'_>,
) -> Result<SubjectValues, String> {
    use crate::bootstrap::Attribute;
    use x509_parser::der_parser::asn1_rs::Tag;
    let mut values = SubjectValues::default();
    let mut seen = Vec::new();
    for entry in name.iter_attributes() {
        let oid = entry.attr_type().to_id_string();
        let Some(attribute) = Attribute::CARRIED
            .into_iter()
            .find(|attribute| attribute.oid() == oid)
        else {
            continue;
        };
        let key = attribute.key();
        if seen.contains(&attribute) {
            return Err(format!("{key} appears more than once"));
        }
        seen.push(attribute);
        // The country is a PrintableString. Every other value may be a UTF8String or the
        // PrintableString older PKIs write, a subset of it; it is carried as a UTF8String
        // (ADR-0036 clause 3).
        let tag = entry.attr_value().tag();
        let (fits, encoding) = if attribute.printable() {
            (tag == Tag::PrintableString, "PrintableString")
        } else {
            (
                tag == Tag::Utf8String || tag == Tag::PrintableString,
                "UTF8String or PrintableString",
            )
        };
        if !fits {
            return Err(format!("{key} is not encoded as a {encoding}"));
        }
        let value = entry
            .as_str()
            .map_err(|_| format!("{key} is not a {encoding}"))?;
        attribute.check(value)?;
        attribute.set(&mut values, value.to_string());
    }
    // Every Host names a customer and a site its Selectors can rely on (ADR-0036 clause 1).
    for attribute in [Attribute::Organization, Attribute::OrganizationalUnit] {
        if attribute.of(&values).is_empty() {
            return Err(format!("{} is missing", attribute.key()));
        }
    }
    Ok(values)
}

/// A subject of `attributes` in their order, each in the encoding ADR-0036 clause 1 gives it.
///
/// # Errors
/// Returns an error for a country that a `PrintableString` cannot hold.
fn distinguished_name(
    attributes: &[(crate::bootstrap::Attribute, String)],
) -> Result<rcgen::DistinguishedName, String> {
    use crate::bootstrap::Attribute;
    let mut name = rcgen::DistinguishedName::new();
    for (attribute, value) in attributes {
        let kind = match attribute {
            Attribute::Country => rcgen::DnType::CountryName,
            Attribute::State => rcgen::DnType::StateOrProvinceName,
            Attribute::Locality => rcgen::DnType::LocalityName,
            Attribute::Organization => rcgen::DnType::OrganizationName,
            Attribute::OrganizationalUnit => rcgen::DnType::OrganizationalUnitName,
            Attribute::OrganizationIdentifier => rcgen::DnType::CustomDnType(vec![2, 5, 4, 97]),
            Attribute::CommonName => rcgen::DnType::CommonName,
        };
        let value = if attribute.printable() {
            rcgen::DnValue::PrintableString(
                rcgen::string::PrintableString::try_from(value.as_str())
                    .map_err(|_| format!("{} {value:?} is no PrintableString", attribute.key()))?,
            )
        } else {
            rcgen::DnValue::Utf8String(value.clone())
        };
        name.push(kind, value);
    }
    Ok(name)
}

/// Checks a CSR's claims to an `instance_uid` against its sender's (ADR-0021): every canonical
/// UUID in the subject or in a requested SAN that carries text must be `sender`.
///
/// # Errors
/// Returns the `BadRequest` text for a request that does not parse or claims another identity.
pub fn check_claims(csr_pem: &str, sender: &[u8]) -> Result<(), String> {
    let (_, request) = read(csr_pem)?;
    let mut values: Vec<String> = request
        .params
        .distinguished_name
        .iter()
        .map(|(_, value)| dn_text(value))
        .collect();
    for san in &request.params.subject_alt_names {
        match san {
            SanType::DnsName(name) => values.push(name.as_str().to_string()),
            // A renewal proof is base64 this project wrote, never a claim (ADR-0021).
            SanType::URI(uri) if uri.as_str().starts_with(fleet_core::renewal::URI_PREFIX) => {}
            // So is a bootstrap proof (ADR-0039).
            SanType::URI(uri)
                if uri
                    .as_str()
                    .starts_with(fleet_core::bootstrap_proof::URI_PREFIX) => {}
            SanType::URI(uri) => values.push(uri.as_str().to_string()),
            SanType::Rfc822Name(mail) => values.push(mail.as_str().to_string()),
            _ => {}
        }
    }
    for value in &values {
        for claim in uuid_claims(value) {
            if claim.as_slice() != sender {
                return Err(format!(
                    "the certificate signing request claims the instance_uid {}, which is not \
                     the sender's",
                    opamp::uid::InstanceUid::from_wire(&claim)
                        .map_or_else(|| hex::encode(claim), |uid| uid.to_string())
                ));
            }
        }
    }
    Ok(())
}

/// Every canonical UUID text — 8-4-4-4-12 hex digits, either case — in `value`, standing alone or
/// inside a longer value, but not as part of a longer run of hex digits (ADR-0021 clause 28).
fn uuid_claims(value: &str) -> Vec<[u8; 16]> {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let bytes = value.as_bytes();
    let mut claims = Vec::new();
    let mut start = 0;
    while start + 36 <= bytes.len() {
        let bounded_before = start == 0 || !bytes[start - 1].is_ascii_hexdigit();
        let bounded_after = bytes.get(start + 36).is_none_or(|b| !b.is_ascii_hexdigit());
        let mut at = start;
        let mut shaped = bounded_before && bounded_after;
        for (index, len) in GROUPS.iter().enumerate() {
            if !shaped {
                break;
            }
            shaped = bytes[at..at + len].iter().all(u8::is_ascii_hexdigit);
            at += len;
            if index < 4 {
                shaped = shaped && bytes[at] == b'-';
                at += 1;
            }
        }
        if shaped {
            let hex: String = value[start..start + 36]
                .chars()
                .filter(|c| *c != '-')
                .collect();
            let mut uid = [0u8; 16];
            if hex::decode_to_slice(&hex, &mut uid).is_ok() {
                claims.push(uid);
            }
            start += 36;
        } else {
            start += 1;
        }
    }
    claims
}

/// A PEM certificate signing request, decoded once and strictly ([`fleet_core::csr::der`]): its
/// DER, and what rcgen reads from those bytes — the request's self-signature verified. Every proof,
/// claim, and signed key is read from one request this way, never through a second PEM reader.
///
/// # Errors
/// Returns the `BadRequest` text for a request that is not exactly one PEM block, does not parse,
/// or whose signature does not verify.
fn read(csr_pem: &str) -> Result<(Vec<u8>, CertificateSigningRequestParams), String> {
    let der = fleet_core::csr::der(csr_pem.as_bytes())?;
    let request = CertificateSigningRequestParams::from_der(&der.as_slice().into())
        .map_err(|e| format!("the certificate signing request does not parse: {e}"))?;
    Ok((der, request))
}

/// The SubjectPublicKeyInfo (DER) a certificate signing request (DER) asks to be certified.
fn requested_key(csr_der: &[u8]) -> Result<Vec<u8>, String> {
    let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(csr_der)
        .map_err(|_| "the certificate signing request does not parse".to_string())?;
    Ok(csr.certification_request_info.subject_pki.raw.to_vec())
}

/// Verifies `signature` over `message` with the key of `spki`: ECDSA P-256 or P-384 with the
/// matching SHA-2, Ed25519, or RSA PKCS#1 with SHA-256 — the keys a Client signs its renewals with.
fn verify_with(
    spki: &x509_parser::x509::SubjectPublicKeyInfo<'_>,
    message: &[u8],
    signature: &[u8],
) -> Result<(), ()> {
    use ring::signature as sig;
    let key_oid = spki.algorithm.algorithm.to_id_string();
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|oid| oid.to_id_string());
    let algorithm: &dyn sig::VerificationAlgorithm = match (key_oid.as_str(), curve.as_deref()) {
        ("1.2.840.10045.2.1", Some("1.2.840.10045.3.1.7")) => &sig::ECDSA_P256_SHA256_ASN1,
        ("1.2.840.10045.2.1", Some("1.3.132.0.34")) => &sig::ECDSA_P384_SHA384_ASN1,
        ("1.3.101.112", _) => &sig::ED25519,
        ("1.2.840.113549.1.1.1", _) => &sig::RSA_PKCS1_2048_8192_SHA256,
        _ => return Err(()),
    };
    sig::UnparsedPublicKey::new(algorithm, spki.subject_public_key.data.as_ref())
        .verify(message, signature)
        .map_err(|_| ())
}

/// How far an issued certificate's life starts before the moment it is signed, so an Agent whose
/// clock runs a little behind the Server's does not hold a certificate that is not yet valid.
const CLOCK_SKEW: time::Duration = time::Duration::minutes(5);

/// `now + validity_days`, in the time type rcgen speaks.
fn not_after(validity_days: u32) -> Result<time::OffsetDateTime, String> {
    let seconds = i64::from(validity_days) * 24 * 60 * 60;
    time::OffsetDateTime::now_utc()
        .checked_add(time::Duration::seconds(seconds))
        .ok_or_else(|| format!("validity_days = {validity_days} is out of range"))
}

/// What an enrolment request says about itself (ADR-0021 clause 22): its subject and the SHA-256
/// fingerprint of the public key it asks to be certified, by which the queue knows a re-sent
/// request.
///
/// # Errors
/// Returns an error when the request does not parse or its signature does not verify.
pub fn enrolment_request(
    csr_pem: &str,
    instance_uid: &[u8],
) -> Result<crate::enrolment::Request, String> {
    use rcgen::PublicKeyData as _;
    use sha2::{Digest, Sha256};
    let (_, request) = read(csr_pem)?;
    let subject = match request
        .params
        .distinguished_name
        .get(&rcgen::DnType::CommonName)
    {
        Some(value) => format!("CN={}", dn_text(value)),
        None => String::new(),
    };
    Ok(crate::enrolment::Request {
        csr_pem: csr_pem.to_string(),
        subject,
        key_fingerprint: hex::encode(Sha256::digest(request.public_key.der_bytes())),
        instance_uid: instance_uid.to_vec(),
    })
}

/// A distinguished-name value as text, whatever string type the request chose.
fn dn_text(value: &rcgen::DnValue) -> String {
    match value {
        rcgen::DnValue::Utf8String(s) => s.clone(),
        rcgen::DnValue::PrintableString(s) => s.as_str().to_string(),
        rcgen::DnValue::Ia5String(s) => s.as_str().to_string(),
        rcgen::DnValue::TeletexString(s) => s.as_str().to_string(),
        // Read as text, so a claim in either is found as in any other (ADR-0021 clause 29).
        rcgen::DnValue::BmpString(s) => String::from_utf16_lossy(
            &s.as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_be_bytes(*pair))
                .collect::<Vec<_>>(),
        ),
        rcgen::DnValue::UniversalString(s) => s
            .as_bytes()
            .as_chunks::<4>()
            .0
            .iter()
            .map(|quad| {
                char::from_u32(u32::from_be_bytes(*quad)).unwrap_or(char::REPLACEMENT_CHARACTER)
            })
            .collect(),
        other => format!("{other:?}"),
    }
}

impl crate::fleet::CertificateSigner for ClientCa {
    fn sign(&self, csr_pem: &str, host: &str, subject: &SubjectValues) -> Result<Signed, String> {
        ClientCa::sign(self, csr_pem, host, subject)
    }

    fn renewal_proof(&self, csr_pem: &str) -> Result<Option<Facts>, String> {
        ClientCa::renewal_proof(self, csr_pem)
    }

    fn bootstrap_proof_id(&self, csr_pem: &str) -> Result<Option<CertId>, String> {
        Ok(bootstrap_proof_certificate(csr_pem)?
            .as_deref()
            .and_then(cert_id))
    }

    fn check_claims(&self, csr_pem: &str, sender: &[u8]) -> Result<(), String> {
        check_claims(csr_pem, sender)
    }
}

/// The bootstrap CA with its key, which signs the bootstrap certificates an operator asks for
/// (ADR-0028). Loaded once at startup from `[enrolment]`.
pub struct BootstrapCa {
    issuer: Issuer<'static, KeyPair>,
    /// The common name every bootstrap certificate carries (ADR-0028 clause 28).
    leaf_name: String,
    not_after_ms: u64,
    key_fingerprint: String,
}

impl BootstrapCa {
    /// Loads the CA from `[enrolment]`, or `None` without `bootstrap_ca_key_file`.
    ///
    /// # Errors
    /// Refuses a file that cannot be read, a key that is not PKCS#8, a key that does not belong
    /// to `bootstrap_ca_file`, a key that is the client CA's (ADR-0021 clause 19), and a CA whose
    /// name gives its certificates a common name longer than 64 characters (ADR-0028 clause 28).
    pub fn from_config(
        enrolment: &crate::config::EnrolmentConfig,
        client_ca: Option<&ClientCaConfig>,
    ) -> Result<Option<Self>, String> {
        use rcgen::PublicKeyData as _;
        let Some(key_file) = &enrolment.bootstrap_ca_key_file else {
            return Ok(None);
        };
        let read = |path: &std::path::Path| {
            std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))
        };
        let cert_pem = read(&enrolment.bootstrap_ca_file)?;
        let key = KeyPair::from_pem(&read(key_file)?)
            .map_err(|e| format!("cannot read {}: {e}", key_file.display()))?;
        let der = first_certificate(&enrolment.bootstrap_ca_file, &cert_pem)?;
        let (_, cert) = X509Certificate::from_der(&der)
            .map_err(|e| format!("cannot read {}: {e}", enrolment.bootstrap_ca_file.display()))?;
        if cert.public_key().raw != key.subject_public_key_info().as_slice() {
            return Err(format!(
                "[enrolment] bootstrap_ca_key_file {} is not the key of bootstrap_ca_file {}",
                key_file.display(),
                enrolment.bootstrap_ca_file.display()
            ));
        }
        if let Some(client_ca) = client_ca {
            let client_key = KeyPair::from_pem(&read(&client_ca.key_file)?)
                .map_err(|e| format!("cannot read {}: {e}", client_ca.key_file.display()))?;
            if client_key.subject_public_key_info() == key.subject_public_key_info() {
                return Err(format!(
                    "[enrolment] bootstrap_ca_key_file {} is the client CA's key — the bootstrap \
                     CA must be a CA of its own",
                    key_file.display()
                ));
            }
        }
        let leaf_name = leaf_name(&enrolment.bootstrap_ca_file, &der)?;
        let key_fingerprint = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&cert.public_key().subject_public_key.data))
        };
        let not_after_ms = u64::try_from(cert.validity().not_after.timestamp())
            .unwrap_or(0)
            .saturating_mul(1000);
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key).map_err(|e| {
            format!(
                "cannot use {} as a CA: {e}",
                enrolment.bootstrap_ca_file.display()
            )
        })?;
        Ok(Some(BootstrapCa {
            issuer,
            leaf_name,
            not_after_ms,
            key_fingerprint,
        }))
    }
}

impl crate::bootstrap::BootstrapSigner for BootstrapCa {
    fn leaf_common_name(&self) -> String {
        self.leaf_name.clone()
    }

    fn ca_not_after_ms(&self) -> u64 {
        self.not_after_ms
    }

    fn ca_key_fingerprint(&self) -> String {
        self.key_fingerprint.clone()
    }

    fn sign(
        &self,
        subject: &[(crate::bootstrap::Attribute, String)],
        now_ms: u64,
        not_after_ms: u64,
        password: &str,
    ) -> Result<crate::bootstrap::Pair, String> {
        use crate::bootstrap::Pair;
        let key = KeyPair::generate().map_err(|e| format!("cannot make a key: {e}"))?;
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = distinguished_name(subject)?;
        // A client-authentication leaf and nothing more (ADR-0028 clause 21).
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.serial_number = Some(random_serial()?);
        params.not_before = at_ms(now_ms)? - CLOCK_SKEW;
        params.not_after = at_ms(not_after_ms)?;
        let certificate = params
            .signed_by(&key, &self.issuer)
            .map_err(|e| format!("cannot sign the bootstrap certificate: {e}"))?;
        let (_, parsed) = X509Certificate::from_der(certificate.der())
            .map_err(|e| format!("the bootstrap certificate does not parse: {e}"))?;
        let facts = facts(certificate.der())?;
        // The key leaves only sealed with its certificate (ADR-0036 clause 8).
        let pkcs12 =
            fleet_core::pkcs12::file::seal(certificate.der(), &key.serialize_der(), password)?;
        Ok(Pair {
            serial: facts.id.serial.clone(),
            id: facts.id,
            subject: facts.subject,
            key_fingerprint: facts.key_fingerprint,
            not_before_ms: u64::try_from(parsed.validity().not_before.timestamp())
                .unwrap_or(0)
                .saturating_mul(1000),
            not_after_ms: facts.not_after_ms,
            certificate_pem: certificate.pem(),
            pkcs12,
        })
    }
}

/// The common name a CA's certificates carry (ADR-0028 clause 28), from the CA's own common name,
/// or its whole subject when it has none.
///
/// # Errors
/// Refuses a CA that does not parse, and one whose derived name exceeds 64 characters.
fn leaf_name(path: &std::path::Path, ca_der: &[u8]) -> Result<String, String> {
    use fleet_core::naming;
    let (_, cert) = X509Certificate::from_der(ca_der)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let ca_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map_or_else(|| cert.subject().to_string(), str::to_string);
    let name = naming::leaf_common_name(&ca_name);
    if name.chars().count() > naming::MAX_COMMON_NAME {
        return Err(format!(
            "{}: the certificates of a CA named {ca_name:?} would be named {name:?}, longer than \
             {} characters",
            path.display(),
            naming::MAX_COMMON_NAME
        ));
    }
    Ok(name)
}

/// The first certificate of a PEM file, DER.
fn first_certificate(path: &std::path::Path, pem: &str) -> Result<Vec<u8>, String> {
    opamp::tls::certificates(pem.as_bytes())
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?
        .first()
        .map(|der| der.as_ref().to_vec())
        .ok_or_else(|| format!("{} holds no certificate", path.display()))
}

/// Milliseconds since the epoch, in the time type rcgen speaks.
fn at_ms(ms: u64) -> Result<time::OffsetDateTime, String> {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .map_err(|e| format!("{ms} ms is out of range: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CA and a Client, end to end: the Client's key never leaves it, and what comes back is a
    /// certificate the CA signed over the public half it was sent.
    fn ca() -> (String, String) {
        let key = KeyPair::generate().expect("ca key");
        let mut params =
            rcgen::CertificateParams::new(vec!["opamp-fleet-ca".to_string()]).expect("ca params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("self-signed ca");
        (cert.pem(), key.serialize_pem())
    }

    /// A certificate whose serial is longer than RFC 5280's 20 octets is not taken; one of 20 is.
    /// Verifies: Q-2
    #[test]
    fn a_certificate_with_a_serial_past_twenty_octets_is_not_taken() {
        let with_serial = |octets: usize| {
            let key = KeyPair::generate().expect("key");
            let mut params =
                rcgen::CertificateParams::new(vec!["edge".to_string()]).expect("params");
            let mut serial = vec![0x11; octets];
            serial[0] = 0x01;
            params.serial_number = Some(rcgen::SerialNumber::from(serial));
            params.self_signed(&key).expect("cert").der().to_vec()
        };
        assert!(facts(&with_serial(20)).is_ok());
        let refused = facts(&with_serial(21)).expect_err("21 octets");
        assert!(refused.contains("20 octets"), "{refused}");
    }

    fn csr(common_name: &str) -> String {
        let key = KeyPair::generate().expect("client key");
        let params =
            rcgen::CertificateParams::new(vec![common_name.to_string()]).expect("client params");
        params
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("csr pem")
    }

    fn client_ca(validity_days: u32) -> ClientCa {
        let (cert_pem, key_pem) = ca();
        let key = KeyPair::from_pem(&key_pem).expect("ca key");
        let ca_der = opamp::tls::certificates(cert_pem.as_bytes()).expect("ca")[0]
            .as_ref()
            .to_vec();
        ClientCa {
            issuer: Issuer::from_ca_cert_pem(&cert_pem, key).expect("issuer"),
            validity_days,
            validity: None,
            leaf_name: leaf_name(std::path::Path::new("client-ca.pem"), &ca_der).expect("name"),
            ca_der,
        }
    }

    /// The values a Host carries are read from a certificate's subject, each by its attribute,
    /// `organizationIdentifier` included; one the subject lacks stays empty.
    /// Verifies: ADR-0035
    #[test]
    fn a_certificates_subject_values_are_read_by_attribute() {
        let key = KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::default();
        let name = &mut params.distinguished_name;
        name.push(rcgen::DnType::CountryName, "AT");
        name.push(rcgen::DnType::StateOrProvinceName, "Wien");
        name.push(rcgen::DnType::OrganizationName, "Kunde GmbH");
        name.push(rcgen::DnType::OrganizationalUnitName, "Werk Nord");
        name.push(
            rcgen::DnType::CustomDnType(vec![2, 5, 4, 97]),
            "VATAT-U12345678",
        );
        name.push(rcgen::DnType::CommonName, "edge-01");
        let cert = params.self_signed(&key).expect("certificate");
        let values = facts(cert.der()).expect("facts").subject_values;
        assert_eq!(
            values,
            SubjectValues {
                country: "AT".into(),
                state: "Wien".into(),
                locality: String::new(),
                organization: "Kunde GmbH".into(),
                organizational_unit: "Werk Nord".into(),
                organization_identifier: "VATAT-U12345678".into(),
            }
        );
        assert_eq!(
            values.attributes().collect::<Vec<_>>(),
            [
                ("fleet.host.country", "AT"),
                ("fleet.host.state", "Wien"),
                ("fleet.host.organization", "Kunde GmbH"),
                ("fleet.host.site", "Werk Nord"),
                ("fleet.host.organization_id", "VATAT-U12345678"),
            ]
        );
    }

    /// A CA named `common_name`, as PEM certificate and key.
    fn named_ca(common_name: &str) -> (String, String) {
        let key = KeyPair::generate().expect("ca key");
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Acme AG");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let cert = params.self_signed(&key).expect("self-signed ca");
        (cert.pem(), key.serialize_pem())
    }

    fn client_ca_config(dir: &std::path::Path, cert_pem: &str, key_pem: &str) -> ClientCaConfig {
        std::fs::write(dir.join("client-ca.pem"), cert_pem).expect("write");
        std::fs::write(dir.join("client-ca-key.pem"), key_pem).expect("write");
        ClientCaConfig {
            cert_file: dir.join("client-ca.pem"),
            key_file: dir.join("client-ca-key.pem"),
            validity_days: 30,
        }
    }

    /// A host certificate's subject is the Server's: the common name derived from the client CA's
    /// and nothing of the request's (ADR-0021 clause 7 and ADR-0028 clause 28).
    /// Verifies: ADR-0028
    #[test]
    fn a_host_certificate_is_named_by_its_ca_not_by_its_request() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = named_ca("Acme Fleet Client CA");
        let ca = ClientCa::from_config(&client_ca_config(dir.path(), &cert_pem, &key_pem))
            .expect("loads");
        let issued = ca
            .sign(&hostile_csr(), "host-1", &SubjectValues::default())
            .expect("issued")
            .pem;
        let der = opamp::tls::certificates(issued.as_bytes()).expect("pem");
        let (_, cert) = X509Certificate::from_der(der[0].as_ref()).expect("parse");
        assert_eq!(
            cert.subject().to_string(),
            "CN=Acme Fleet Client Certificate"
        );
    }

    /// A CA whose certificates' name would exceed 64 characters stops the Server at startup
    /// (ADR-0028 clause 28).
    /// Verifies: ADR-0028
    #[test]
    fn a_ca_whose_certificates_name_is_too_long_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = named_ca(&format!("{} CA", "x".repeat(53)));
        let Err(err) = ClientCa::from_config(&client_ca_config(dir.path(), &cert_pem, &key_pem))
        else {
            panic!("a client CA whose certificates' name is 65 characters was accepted");
        };
        assert!(err.contains("longer than 64"), "{err}");
        let Err(err) =
            BootstrapCa::from_config(&enrolment_with(dir.path(), &cert_pem, &key_pem), None)
        else {
            panic!("a bootstrap CA whose certificates' name is 65 characters was accepted");
        };
        assert!(err.contains("longer than 64"), "{err}");
        let (cert_pem, key_pem) = named_ca(&format!("{} CA", "x".repeat(52)));
        assert!(ClientCa::from_config(&client_ca_config(dir.path(), &cert_pem, &key_pem)).is_ok());
    }

    /// The bootstrap CA names its certificates as the client CA does (ADR-0028 clause 28).
    /// Verifies: ADR-0028
    #[test]
    fn a_bootstrap_certificate_is_named_by_its_ca() {
        use crate::bootstrap::BootstrapSigner as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = named_ca("Acme Fleet Bootstrap CA");
        let signer =
            BootstrapCa::from_config(&enrolment_with(dir.path(), &cert_pem, &key_pem), None)
                .expect("loads")
                .expect("a key");
        assert_eq!(
            signer.leaf_common_name(),
            "Acme Fleet Bootstrap Certificate"
        );
    }

    /// A request that asks for the powers of a CA — `basicConstraints: CA`, a name of its own, and
    /// a wider extended key usage.
    fn hostile_csr() -> String {
        let key = KeyPair::generate().expect("client key");
        let mut params =
            rcgen::CertificateParams::new(vec!["edge-01".to_string()]).expect("client params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.subject_alt_names.push(rcgen::SanType::DnsName(
            "evil.example".try_into().expect("san"),
        ));
        params
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("csr pem")
    }

    /// Verifies: ADR-0021
    #[test]
    fn signs_a_request_into_a_certificate() {
        let issued = client_ca(90)
            .sign(&csr("edge-01"), "host-1", &SubjectValues::default())
            .expect("issued")
            .pem;
        assert!(issued.starts_with("-----BEGIN CERTIFICATE-----"));
        // What came back is a certificate, not the request echoed back.
        assert!(!issued.contains("CERTIFICATE REQUEST"));
    }

    /// A CSR asking for CA powers is signed into a plain client-auth leaf: the request does not get
    /// to choose the certificate's powers (a CA cert chaining to the fleet CA could mint more). The
    /// issued certificate must be non-CA, carry only `clientAuth`, and none of the CSR's SANs — only
    /// its host.
    /// Verifies: ADR-0021
    #[test]
    fn the_request_cannot_dictate_the_certificates_powers() {
        let issued = client_ca(90)
            .sign(&hostile_csr(), "host-1", &SubjectValues::default())
            .expect("issued")
            .pem;
        let der = cert_der(&issued);
        let (_, cert) = X509Certificate::from_der(&der).expect("der");

        // Absent basic constraints means non-CA, which is fine; present, it must say non-CA.
        if let Some(bc) = cert
            .basic_constraints()
            .expect("basic constraints readable")
        {
            assert!(!bc.value.ca, "the issued certificate must not be a CA");
        }
        let eku = cert
            .extended_key_usage()
            .expect("eku readable")
            .expect("eku present")
            .value;
        assert!(eku.client_auth, "the leaf authenticates a client");
        assert!(!eku.server_auth, "the CSR's serverAuth request was dropped");
        assert!(!eku.any, "no anyExtendedKeyUsage");
        let names: Vec<String> = cert
            .subject_alternative_name()
            .expect("san readable")
            .expect("the host")
            .value
            .general_names
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            names,
            vec![format!("URI({HOST_URI_PREFIX}host-1)")],
            "the CSR's SAN was dropped"
        );
    }

    /// An issued certificate's life is `validity_days` from now — not from a date long past, which
    /// would put it into its renewal window the moment it is issued and loop the Client into
    /// asking again and again.
    #[test]
    fn an_issued_certificate_lives_validity_days_from_now() {
        let issued = client_ca(90)
            .sign(&csr("edge-01"), "host-1", &SubjectValues::default())
            .expect("issued")
            .pem;
        let der = cert_der(&issued);
        let (_, cert) = X509Certificate::from_der(&der).expect("der");
        let now = time::OffsetDateTime::now_utc();
        let not_before = cert.validity().not_before.to_datetime();
        let not_after = cert.validity().not_after.to_datetime();
        assert!(
            now - not_before <= time::Duration::minutes(6),
            "{not_before}"
        );
        assert!(not_before <= now, "valid from the moment it is issued");
        let life = not_after - not_before;
        assert!(
            life >= time::Duration::days(90)
                && life <= time::Duration::days(90) + time::Duration::minutes(6)
        );
    }

    /// The Baseline makes this a MUST on the Server: a request it cannot act on is answered with a
    /// `BadRequest` error response, which is what the caller does with this `Err`.
    /// Verifies: ADR-0021
    #[test]
    fn refuses_a_request_that_does_not_parse() {
        let error = client_ca(90)
            .sign(
                "-----BEGIN CERTIFICATE REQUEST-----\nnot base64\n-----END CERTIFICATE REQUEST-----",
                "host-1",
                &SubjectValues::default(),
            )
            .expect_err("refused");
        assert!(error.contains("does not parse"), "{error}");
    }

    /// Verifies: ADR-0021
    #[test]
    fn two_certificates_from_one_key_have_two_serials() {
        let ca = client_ca(90);
        let request = csr("edge-01");
        let first = ca
            .sign(&request, "host-1", &SubjectValues::default())
            .expect("first");
        let second = ca
            .sign(&request, "host-1", &SubjectValues::default())
            .expect("second");
        assert_ne!(first.facts.id.serial, second.facts.id.serial);
        assert_eq!(first.facts.key_fingerprint, second.facts.key_fingerprint);
        assert_eq!(first.facts.id.issuer, second.facts.id.issuer);
        assert!(
            first.facts.issuer_name.starts_with("CN="),
            "{}",
            first.facts.issuer_name
        );
    }

    /// The register knows a certificate's key by the fingerprint its request was listed and
    /// approved by, which is also the one the Client logs: one key, one fingerprint.
    /// Verifies: ADR-0021
    #[test]
    fn a_certificate_carries_the_key_fingerprint_of_its_request() {
        let request = csr("edge-01");
        let signed = client_ca(90)
            .sign(&request, "host-1", &SubjectValues::default())
            .expect("signed");
        let enrolling = enrolment_request(&request, &[]).expect("request");
        assert_eq!(signed.facts.key_fingerprint, enrolling.key_fingerprint);
    }

    const UID: &str = "0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b";

    fn uid_bytes() -> Vec<u8> {
        hex::decode(UID.replace('-', "")).expect("hex")
    }

    /// Verifies: ADR-0021
    #[test]
    fn a_canonical_uuid_anywhere_in_a_value_is_a_claim() {
        let upper = UID.to_uppercase();
        for value in [
            UID.to_string(),
            format!("agent {UID}"),
            format!("urn:uuid:{upper}"),
        ] {
            assert_eq!(
                uuid_claims(&value),
                vec![<[u8; 16]>::try_from(uid_bytes()).expect("16")]
            );
        }
        assert!(
            uuid_claims(&format!("a{UID}")).is_empty(),
            "a longer run of hex digits is no claim"
        );
    }

    /// Verifies: ADR-0021
    #[test]
    fn hex_without_hyphens_is_no_claim() {
        assert!(uuid_claims(&UID.replace('-', "")).is_empty());
        assert!(uuid_claims("edge-01.example").is_empty());
    }

    fn csr_with(common_name: &str, sans: Vec<SanType>) -> String {
        let key = KeyPair::generate().expect("client key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        params.subject_alt_names = sans;
        params
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("csr pem")
    }

    /// Verifies: ADR-0021
    #[test]
    fn a_san_is_read_for_claims() {
        let other = "0192a3b4-c5d6-7e8f-9a0b-000000000000";
        let request = csr_with(
            "edge-01",
            vec![SanType::URI(
                format!("urn:uuid:{other}").try_into().expect("uri"),
            )],
        );
        let error = check_claims(&request, &uid_bytes()).expect_err("another identity");
        assert!(error.contains(other), "{error}");
        assert!(check_claims(&csr_with(UID, Vec::new()), &uid_bytes()).is_ok());
        assert!(check_claims(&csr_with("edge-01", Vec::new()), &uid_bytes()).is_ok());
    }

    /// A claim in a subject attribute of another string type is read as any other.
    /// Verifies: ADR-0021
    #[test]
    fn a_claim_in_a_bmp_or_universal_string_is_read() {
        let other = "0192a3b4-c5d6-7e8f-9a0b-000000000000";
        for value in [
            rcgen::DnValue::BmpString(other.try_into().expect("bmp")),
            rcgen::DnValue::UniversalString(other.try_into().expect("universal")),
        ] {
            let key = KeyPair::generate().expect("client key");
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, value);
            let request = params
                .serialize_request(&key)
                .expect("csr")
                .pem()
                .expect("pem");
            let error = check_claims(&request, &uid_bytes()).expect_err("a hidden claim");
            assert!(error.contains(other), "{error}");
        }
    }

    /// A CSR made with the key of a certificate this CA issued
    /// proves which certificate it renews.
    fn renewing(old_cert_pem: &str, old_key: &KeyPair) -> String {
        use base64::Engine as _;
        use rcgen::{PublicKeyData as _, SigningKey as _};
        use sha2::{Digest, Sha256};
        let new_key = KeyPair::generate().expect("new key");
        let old_der = cert_der(old_cert_pem);
        let signature = old_key
            .sign(&fleet_core::renewal::statement(&Sha256::digest(
                new_key.subject_public_key_info(),
            )))
            .expect("sign");
        let proof = format!(
            "{}{}",
            fleet_core::renewal::URI_PREFIX,
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(fleet_core::renewal::encode(&old_der, &signature))
        );
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .subject_alt_names
            .push(SanType::URI(proof.try_into().expect("uri")));
        params
            .serialize_request(&new_key)
            .expect("csr")
            .pem()
            .expect("pem")
    }

    /// A renewal proof names the certificate it renews and its host; a proof signed with another
    /// key, or over a certificate of another CA, does not hold, and the issued certificate names
    /// its host and nothing the request asked for.
    /// Verifies: ADR-0021
    #[test]
    fn a_renewal_proof_names_the_certificate_and_its_host() {
        let ca = client_ca(30);
        let old_key = KeyPair::generate().expect("old key");
        let params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        let old_csr = params
            .serialize_request(&old_key)
            .expect("csr")
            .pem()
            .expect("pem");
        let old = ca
            .sign(&old_csr, "host-7", &SubjectValues::default())
            .expect("sign");
        assert_eq!(old.facts.host.as_deref(), Some("host-7"));

        assert_eq!(ca.renewal_proof(&csr("edge-01")).expect("no proof"), None);
        let proven = ca
            .renewal_proof(&renewing(&old.pem, &old_key))
            .expect("holds")
            .expect("a proof");
        assert_eq!(proven.id, old.facts.id);
        assert_eq!(proven.host.as_deref(), Some("host-7"));
        let renewed = ca
            .sign(
                &renewing(&old.pem, &old_key),
                "host-7",
                &SubjectValues::default(),
            )
            .expect("sign");
        let renewed_der = cert_der(&renewed.pem);
        let (_, cert) = X509Certificate::from_der(&renewed_der).expect("parse");
        let names = cert
            .subject_alternative_name()
            .expect("san")
            .expect("san")
            .value
            .general_names
            .len();
        assert_eq!(names, 1, "the proof was copied into the certificate");
        let mut forged = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        forged.subject_alt_names.push(SanType::URI(
            format!("{HOST_URI_PREFIX}host-other")
                .try_into()
                .expect("uri"),
        ));
        let forged = forged
            .serialize_request(&KeyPair::generate().expect("key"))
            .expect("csr")
            .pem()
            .expect("pem");
        assert_eq!(
            ca.sign(&forged, "host-7", &SubjectValues::default())
                .expect("sign")
                .facts
                .host
                .as_deref(),
            Some("host-7"),
            "a request named its own host"
        );

        let stranger = KeyPair::generate().expect("stranger");
        assert!(ca.renewal_proof(&renewing(&old.pem, &stranger)).is_err());
        let other = client_ca(30);
        let foreign = other
            .sign(&old_csr, "host-7", &SubjectValues::default())
            .expect("sign");
        assert!(ca.renewal_proof(&renewing(&foreign.pem, &old_key)).is_err());
    }

    /// The DER of a PEM certificate.
    fn cert_der(pem: &str) -> Vec<u8> {
        opamp::tls::certificates(pem.as_bytes()).expect("pem")[0].to_vec()
    }

    /// `victim`'s proof, copied into a request of a key of the attacker's own.
    fn grafted(victim: &str) -> String {
        let victim = fleet_core::csr::der(victim.as_bytes()).expect("victim");
        let proof = CertificateSigningRequestParams::from_der(&victim.as_slice().into())
            .expect("victim")
            .params
            .subject_alt_names;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.subject_alt_names = proof;
        params
            .serialize_request(&KeyPair::generate().expect("attacker key"))
            .expect("csr")
            .pem()
            .expect("pem")
    }

    /// A request is read from exactly one PEM block. A proof copied from another host's renewal
    /// request into one of the attacker's, with that request after it — behind a prefix one PEM
    /// reader skips and another does not, or as a second block — is refused on every path, never
    /// read as the victim's proof over the attacker's key; and the copy alone does not hold.
    /// Verifies: ADR-0021
    /// Verifies: ADR-0039
    #[test]
    fn a_proof_and_the_key_it_signs_come_from_one_pem_block() {
        let ca = client_ca(30);
        let old_key = KeyPair::generate().expect("old key");
        let old = ca
            .sign(
                &rcgen::CertificateParams::new(Vec::<String>::new())
                    .expect("params")
                    .serialize_request(&old_key)
                    .expect("csr")
                    .pem()
                    .expect("pem"),
                "host-7",
                &SubjectValues::default(),
            )
            .expect("sign");
        let victim = renewing(&old.pem, &old_key);
        let attacker = grafted(&victim);
        let copy = ca.renewal_proof(&attacker).expect_err("a copied proof");
        assert!(copy.contains("does not verify"), "{copy}");

        for crafted in [
            format!("x{attacker}{victim}"),
            format!("{attacker}{victim}"),
        ] {
            let refusals = [
                ca.renewal_proof(&crafted).map(|_| ()),
                ca.sign(&crafted, "host-7", &SubjectValues::default())
                    .map(|_| ()),
                check_claims(&crafted, &[]),
                enrolment_request(&crafted, &[]).map(|_| ()),
                bootstrap_proof(&crafted).map(|_| ()),
                bootstrap_proof_certificate(&crafted).map(|_| ()),
            ];
            for refused in refusals {
                let why = refused.expect_err("read past its first block");
                assert!(why.contains("exactly one PEM block"), "{why}");
            }
        }
    }

    /// No code of the Server, of `fleet-core` or of the Gateway — its tests included — reads PEM
    /// with a reader of its own but `fleet_core::csr::der`: a request is decoded there alone, so
    /// two readers cannot read two requests from one. A certificate's PEM is read by
    /// `opamp::tls::certificates`, which no request reaches.
    /// Verifies: ADR-0021
    #[test]
    fn no_code_reads_a_request_through_another_pem_reader() {
        fn walk(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("src") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    walk(&path, found);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    found.push(path);
                }
            }
        }
        // Split, so that this test does not find itself.
        let readers = [
            concat!("CertificateSigningRequestParams", "::from_pem"),
            concat!("x509_parser", "::pem"),
            concat!("parse_x509", "_pem"),
            concat!("Pem", "::read"),
            concat!("pem", "::parse"),
            concat!("from_pem", "_slice"),
        ];
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates");
        let the_reader = crates.join("fleet-core/src/csr.rs");
        let mut files = Vec::new();
        for tree in [
            "fleet-server/src",
            "fleet-core/src",
            "fleet-agent/src/gateway",
        ] {
            walk(&crates.join(tree), &mut files);
        }
        assert!(files.contains(&the_reader), "{files:#?}");
        let mut broken = Vec::new();
        for file in files.iter().filter(|file| **file != the_reader) {
            let code = std::fs::read_to_string(file).expect("read");
            for reader in readers {
                if code.contains(reader) {
                    broken.push(format!("{}: {reader}", file.display()));
                }
            }
        }
        assert!(broken.is_empty(), "{broken:#?}");
    }

    /// Writes a CA's files and the `[enrolment]` naming them.
    fn enrolment_with(
        dir: &std::path::Path,
        cert_pem: &str,
        key_pem: &str,
    ) -> crate::config::EnrolmentConfig {
        std::fs::write(dir.join("bootstrap-ca.pem"), cert_pem).expect("write");
        std::fs::write(dir.join("bootstrap-ca-key.pem"), key_pem).expect("write");
        crate::config::EnrolmentConfig {
            bootstrap_ca_file: dir.join("bootstrap-ca.pem"),
            bootstrap_ca_key_file: Some(dir.join("bootstrap-ca-key.pem")),
            max_pending_per_bootstrap: crate::enrolment::DEFAULT_MAX_PENDING_PER_BOOTSTRAP,
        }
    }

    /// The Server refuses a bootstrap CA key that is not the certificate's, or that is the client
    /// CA's; without a key it issues nothing (ADR-0021 clause 19).
    /// Verifies: ADR-0028
    #[test]
    fn a_bootstrap_ca_key_must_be_its_own_and_its_certificates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = ca();
        let (_, other_key) = ca();
        let mismatched = enrolment_with(dir.path(), &cert_pem, &other_key);
        let Err(err) = BootstrapCa::from_config(&mismatched, None) else {
            panic!("a key of another certificate was accepted");
        };
        assert!(err.contains("is not the key of"), "{err}");

        let enrolment = enrolment_with(dir.path(), &cert_pem, &key_pem);
        let client_dir = tempfile::tempdir().expect("tempdir");
        let (client_cert, _) = ca();
        std::fs::write(client_dir.path().join("ca.pem"), client_cert).expect("write");
        std::fs::write(client_dir.path().join("ca-key.pem"), &key_pem).expect("write");
        let client_ca: ClientCaConfig = toml::from_str(&format!(
            "cert_file = {:?}\nkey_file = {:?}\n",
            client_dir.path().join("ca.pem").display().to_string(),
            client_dir.path().join("ca-key.pem").display().to_string(),
        ))
        .expect("client ca config");
        let Err(err) = BootstrapCa::from_config(&enrolment, Some(&client_ca)) else {
            panic!("the client CA's key was accepted as the bootstrap CA's");
        };
        assert!(err.contains("client CA's key"), "{err}");

        assert!(BootstrapCa::from_config(&enrolment, None)
            .expect("loads")
            .is_some());
        let without_key = crate::config::EnrolmentConfig {
            bootstrap_ca_key_file: None,
            ..enrolment
        };
        assert!(BootstrapCa::from_config(&without_key, None)
            .expect("loads")
            .is_none());
    }

    /// What the bootstrap CA signs is a client-authentication leaf of the subject asked for, with
    /// a key of its own (ADR-0028 clause 21).
    /// Verifies: ADR-0028
    #[test]
    fn a_bootstrap_certificate_is_a_client_leaf_of_the_named_subject() {
        use crate::bootstrap::{Attribute, BootstrapSigner as _};
        use rcgen::PublicKeyData as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = ca();
        let signer =
            BootstrapCa::from_config(&enrolment_with(dir.path(), &cert_pem, &key_pem), None)
                .expect("loads")
                .expect("a key");
        let now = 1_800_000_000_000;
        let pair = signer
            .sign(
                &[
                    (Attribute::Organization, "Kunde GmbH".to_string()),
                    (Attribute::CommonName, "fleet bootstrap".to_string()),
                ],
                now,
                now + 86_400_000,
                "twelve chars",
            )
            .expect("signed");
        let der = opamp::tls::certificates(pair.certificate_pem.as_bytes()).expect("pem");
        let (_, cert) = X509Certificate::from_der(der[0].as_ref()).expect("parse");
        assert_eq!(
            cert.subject().to_string(),
            "O=Kunde GmbH, CN=fleet bootstrap"
        );
        assert!(!cert.is_ca());
        let eku = cert
            .extended_key_usage()
            .expect("eku")
            .expect("present")
            .value;
        assert!(eku.client_auth && !eku.server_auth);
        assert_eq!(
            cert.validity().not_after.timestamp() * 1000,
            (now + 86_400_000) as i64
        );
        let opened = fleet_core::pkcs12::file::open(&pair.pkcs12, "twelve chars").expect("opens");
        let key = KeyPair::try_from(opened.private_key_der.as_slice()).expect("key");
        assert_eq!(
            cert.public_key().raw,
            key.subject_public_key_info().as_slice()
        );
    }

    /// The key is not handed back in PEM: it is in a PKCS#12 file with its certificate, which
    /// opens under the password to exactly the two (ADR-0036 clause 8).
    /// Verifies: ADR-0029, ADR-0036
    #[test]
    fn a_password_seals_the_key_with_its_certificate() {
        use crate::bootstrap::{Attribute, BootstrapSigner as _};
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = ca();
        let signer =
            BootstrapCa::from_config(&enrolment_with(dir.path(), &cert_pem, &key_pem), None)
                .expect("loads")
                .expect("a key");
        let now = 1_800_000_000_000;
        let pair = signer
            .sign(
                &[(Attribute::CommonName, "fleet bootstrap".to_string())],
                now,
                now + 86_400_000,
                "twelve chars",
            )
            .expect("signed");
        let opened = fleet_core::pkcs12::file::open(&pair.pkcs12, "twelve chars").expect("opens");
        let der = opamp::tls::certificates(pair.certificate_pem.as_bytes()).expect("pem");
        assert_eq!(
            opened.certificate_der,
            der[0].as_ref(),
            "the certificate signed"
        );
        assert!(fleet_core::pkcs12::file::open(
            &opened_file_again(&signer, now),
            "wrong password!"
        )
        .is_err());
    }

    fn opened_file_again(signer: &BootstrapCa, now: u64) -> Vec<u8> {
        use crate::bootstrap::{Attribute, BootstrapSigner as _};
        signer
            .sign(
                &[(Attribute::CommonName, "fleet bootstrap".to_string())],
                now,
                now + 86_400_000,
                "twelve chars",
            )
            .expect("signed")
            .pkcs12
    }

    fn six_values() -> SubjectValues {
        SubjectValues {
            country: "AT".to_string(),
            state: "Oberösterreich".to_string(),
            locality: "Linz".to_string(),
            organization: "Kunde GmbH".to_string(),
            organizational_unit: "Werk Nord".to_string(),
            organization_identifier: "6f1c0b9e-2a4d-4c55-9b1e-0d2f3a4b5c6d".to_string(),
        }
    }

    /// Each attribute of a subject with its OID and the tag of its string type, in order.
    fn attributes_of(pem: &str) -> Vec<(String, x509_parser::der_parser::asn1_rs::Tag, String)> {
        let der = opamp::tls::certificates(pem.as_bytes()).expect("pem");
        let (_, cert) = X509Certificate::from_der(der[0].as_ref()).expect("parse");
        cert.subject()
            .iter_attributes()
            .map(|attribute| {
                (
                    attribute.attr_type().to_id_string(),
                    attribute.attr_value().tag(),
                    attribute.as_str().expect("a string").to_string(),
                )
            })
            .collect()
    }

    /// Issued with all six attributes, a bootstrap certificate's subject holds them in the order
    /// C, ST, L, O, OU, organizationIdentifier, CN, the country as a `PrintableString` and every
    /// other value as a `UTF8String`.
    /// Verifies: ADR-0036
    #[test]
    fn a_bootstrap_certificate_holds_the_six_attributes_in_order_and_encoding() {
        use crate::bootstrap::{BootstrapSigner as _, Subject};
        use x509_parser::der_parser::asn1_rs::Tag;
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_pem, key_pem) = ca();
        let signer =
            BootstrapCa::from_config(&enrolment_with(dir.path(), &cert_pem, &key_pem), None)
                .expect("loads")
                .expect("a key");
        let values = six_values();
        let subject = Subject {
            country: Some(values.country.clone()),
            state: Some(values.state.clone()),
            locality: Some(values.locality.clone()),
            organization: Some(values.organization.clone()),
            organizational_unit: Some(values.organizational_unit.clone()),
            organization_identifier: Some(values.organization_identifier.clone()),
        };
        let now = 1_800_000_000_000;
        let pair = signer
            .sign(
                &subject.attributes("fleet bootstrap").expect("valid"),
                now,
                now + 86_400_000,
                "twelve chars",
            )
            .expect("signed");
        assert_eq!(
            pair.subject,
            "C=AT, ST=Oberösterreich, L=Linz, O=Kunde GmbH, OU=Werk Nord, \
             organizationIdentifier=6f1c0b9e-2a4d-4c55-9b1e-0d2f3a4b5c6d, CN=fleet bootstrap",
            "the subject as the record and the list show it"
        );
        let utf8 = Tag::Utf8String;
        assert_eq!(
            attributes_of(&pair.certificate_pem),
            vec![
                (
                    "2.5.4.6".to_string(),
                    Tag::PrintableString,
                    "AT".to_string()
                ),
                ("2.5.4.8".to_string(), utf8, values.state.clone()),
                ("2.5.4.7".to_string(), utf8, values.locality.clone()),
                ("2.5.4.10".to_string(), utf8, values.organization.clone()),
                (
                    "2.5.4.11".to_string(),
                    utf8,
                    values.organizational_unit.clone()
                ),
                (
                    "2.5.4.97".to_string(),
                    utf8,
                    values.organization_identifier.clone()
                ),
                ("2.5.4.3".to_string(), utf8, "fleet bootstrap".to_string()),
            ]
        );
    }

    /// The host certificate carries the values it is signed with — the bootstrap certificate's
    /// — in the same order and encoding, and nothing of the request's subject.
    /// Verifies: ADR-0036
    #[test]
    fn a_host_certificate_carries_the_values_and_ignores_the_requests_subject() {
        use x509_parser::der_parser::asn1_rs::Tag;
        let key = KeyPair::generate().expect("client key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        for (kind, value) in [
            (rcgen::DnType::CountryName, "DE"),
            (rcgen::DnType::OrganizationName, "Another Customer"),
            (rcgen::DnType::OrganizationalUnitName, "Elsewhere"),
            (rcgen::DnType::CommonName, "edge-01"),
        ] {
            params.distinguished_name.push(kind, value);
        }
        let csr = params
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("pem");
        let values = six_values();
        let signed = client_ca(90).sign(&csr, "host-1", &values).expect("signed");
        assert_eq!(signed.facts.subject_values, values);
        let attributes = attributes_of(&signed.pem);
        let oids: Vec<&str> = attributes.iter().map(|(oid, _, _)| oid.as_str()).collect();
        assert_eq!(
            oids,
            ["2.5.4.6", "2.5.4.8", "2.5.4.7", "2.5.4.10", "2.5.4.11", "2.5.4.97", "2.5.4.3"]
        );
        assert_eq!(attributes[0].1, Tag::PrintableString);
        assert!(
            attributes[6].2.ends_with(" Certificate"),
            "the common name is the CA's: {}",
            attributes[6].2
        );
        for (_, _, value) in &attributes {
            assert!(
                !["DE", "Another Customer", "Elsewhere", "edge-01"].contains(&value.as_str()),
                "the request's {value:?} was copied"
            );
        }
    }

    /// The subject a bootstrap certificate from any CA carries is read under the rules it is
    /// issued by: an attribute twice, a wrong string type, a malformed country, a value out of
    /// bounds and a missing organization or organizational unit are refused, naming the
    /// attribute; other attributes and the common name are passed over.
    /// Verifies: ADR-0036
    #[test]
    fn a_bootstrap_subject_is_carried_only_when_well_formed() {
        let read = |entries: Vec<(rcgen::DnType, rcgen::DnValue)>| {
            let key = KeyPair::generate().expect("key");
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
            for (kind, value) in entries {
                params.distinguished_name.push(kind, value);
            }
            let cert = params.self_signed(&key).expect("signed");
            let (_, parsed) = X509Certificate::from_der(cert.der()).expect("parse");
            carried_subject(parsed.subject())
        };
        let utf8 = |value: &str| rcgen::DnValue::Utf8String(value.to_string());
        let printable = |value: &str| {
            rcgen::DnValue::PrintableString(
                rcgen::string::PrintableString::try_from(value).expect("printable"),
            )
        };
        let carried = read(vec![
            (rcgen::DnType::CountryName, printable("AT")),
            (rcgen::DnType::OrganizationName, utf8("Kunde GmbH")),
            // An older PKI's PrintableString is taken for a value that is not the country.
            (rcgen::DnType::OrganizationalUnitName, printable("Wien")),
            (rcgen::DnType::CustomDnType(vec![2, 5, 4, 5]), utf8("SN-1")),
            (rcgen::DnType::CommonName, utf8("bootstrap of Kunde")),
        ])
        .expect("well-formed");
        assert_eq!(
            carried,
            SubjectValues {
                country: "AT".to_string(),
                organization: "Kunde GmbH".to_string(),
                organizational_unit: "Wien".to_string(),
                ..SubjectValues::default()
            },
            "serialNumber and the common name are not carried; a PrintableString OU is"
        );
        for (entries, named) in [
            (
                // rcgen keeps one value per type, so the second OU goes in under its OID.
                vec![
                    (rcgen::DnType::OrganizationalUnitName, utf8("Wien")),
                    (rcgen::DnType::CustomDnType(vec![2, 5, 4, 11]), utf8("Linz")),
                ],
                "organizational_unit",
            ),
            (vec![(rcgen::DnType::CountryName, utf8("AT"))], "country"),
            (
                vec![(rcgen::DnType::CountryName, printable("at"))],
                "country",
            ),
            (
                vec![(rcgen::DnType::CountryName, printable("AUT"))],
                "country",
            ),
            (
                vec![(
                    rcgen::DnType::OrganizationName,
                    rcgen::DnValue::BmpString(
                        rcgen::string::BmpString::try_from("Kunde GmbH").expect("bmp"),
                    ),
                )],
                "organization",
            ),
            (
                vec![(rcgen::DnType::LocalityName, utf8(&"x".repeat(65)))],
                "locality",
            ),
            (
                vec![(
                    rcgen::DnType::CustomDnType(vec![2, 5, 4, 97]),
                    utf8("a\u{1b}b"),
                )],
                "organization_identifier",
            ),
        ] {
            let refused = read(entries).expect_err("refused");
            assert!(refused.starts_with(named), "{refused} names {named}");
        }
        for (entries, refusal) in [
            (
                vec![(rcgen::DnType::OrganizationName, utf8("Kunde GmbH"))],
                "organizational_unit is missing",
            ),
            (
                vec![(rcgen::DnType::OrganizationalUnitName, utf8("Wien"))],
                "organization is missing",
            ),
            (
                vec![(rcgen::DnType::CommonName, utf8("bootstrap"))],
                "organization is missing",
            ),
        ] {
            assert_eq!(read(entries).expect_err("refused"), refusal);
        }
    }
}
