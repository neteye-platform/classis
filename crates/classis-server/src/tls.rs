//! What a certificate makes its holder (ADR-0021): the [`Issuers`] of the client and bootstrap CAs,
//! and the [`Peer`] they tell apart.
//!
//! The Server terminates no TLS (ADR-0064), so no listener is given material here any more and no
//! certificate reaches the Agent plane: what stays is the classification the enrolment code of
//! NEAG-34 starts from.

use std::path::Path;

use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo, X509Certificate};

use crate::revocation::{CertId, SubjectValues};

/// The CAs of both files. Without a bootstrap CA the handshake trusts the client CA alone, so
/// every certificate it accepted belongs to a member. With one, a member is only a certificate
/// issued directly by a CA of `client_ca_file` — named as its issuer and signed with its key; any
/// other — one from the bootstrap CA, or from an intermediate below either, whatever it is named —
/// may only enrol, so a chain cannot lift a bootstrap certificate into the fleet.
#[derive(Clone, Debug, Default)]
pub struct Issuers {
    /// The CAs of `client_ca_file`.
    members: Vec<Ca>,
    /// The CAs of `bootstrap_ca_file`.
    bootstrap: Vec<Ca>,
}

/// One certificate of a CA file, as far as it is read: its subject, raw, and its
/// public key (`SubjectPublicKeyInfo`, DER).
#[derive(Clone, Debug)]
struct Ca {
    subject: Vec<u8>,
    key: Vec<u8>,
}

/// What the certificate a connection carries makes it (ADR-0021).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Peer {
    /// A certificate from the client CA: a member of the fleet.
    Member,
    /// A bootstrap certificate: it may only enrol.
    Enrolling {
        subject: String,
        /// The values an approval carries into the host certificate, or why its subject breaks
        /// the rules they are issued by (ADR-0036 clause 3).
        carried: Box<Result<SubjectValues, String>>,
        /// SHA-256 of the certificate, hex.
        fingerprint: String,
        /// Its issuer and serial: the serial as the bootstrap record keys it (`ca::facts`), and the
        /// pair as the revocation list names it.
        id: CertId,
    },
}

impl Issuers {
    /// The CAs of the client CA file and of the bootstrap CA file, as PEM.
    ///
    /// # Errors
    /// Returns an error naming the file when one holds nothing usable.
    pub fn from_pem(
        client: (&Path, &[u8]),
        bootstrap: (&Path, &[u8]),
    ) -> Result<Self, String> {
        Ok(Issuers {
            members: cas(client.0, client.1)?,
            bootstrap: cas(bootstrap.0, bootstrap.1)?,
        })
    }

    /// What `certificate` (DER, already verified by the handshake) makes its connection.
    #[must_use]
    pub fn classify(&self, certificate: &[u8]) -> Peer {
        // The handshake verified it, so it parses; a certificate that does not is no member.
        let Ok((_, parsed)) = X509Certificate::from_der(certificate) else {
            return enrolling(certificate);
        };
        let issuer = parsed.issuer().as_raw();
        let member = self.bootstrap.is_empty()
            || self.members.iter().any(|ca| {
                ca.subject == issuer
                    && SubjectPublicKeyInfo::from_der(&ca.key)
                        .is_ok_and(|(_, key)| parsed.verify_signature(Some(&key)).is_ok())
            });
        if member {
            return Peer::Member;
        }
        enrolling(certificate)
    }

    /// What a bootstrap certificate (DER) an enrolment request proves says about itself
    /// (ADR-0039 clauses 8, 9), when a CA of `bootstrap_ca_file` issued it directly — named as its
    /// issuer and signed with its key — and it passes what the handshake checks of one: a leaf
    /// (no `CA:TRUE`) whose extended key usage, where it names one, includes `clientAuth`, valid
    /// now. The proof carries no chain, so a certificate below an intermediate cannot be told from
    /// one the CA never issued.
    ///
    /// # Errors
    /// Returns why the certificate is not one, for the `BadRequest` that refuses its proof.
    pub fn bootstrap_issued(&self, certificate: &[u8]) -> Result<Peer, String> {
        let (_, parsed) = X509Certificate::from_der(certificate)
            .map_err(|_| "its certificate does not parse".to_string())?;
        let issuer = parsed.issuer().as_raw();
        if !self.bootstrap.iter().any(|ca| {
            ca.subject == issuer
                && SubjectPublicKeyInfo::from_der(&ca.key)
                    .is_ok_and(|(_, key)| parsed.verify_signature(Some(&key)).is_ok())
        }) {
            return Err("its certificate was not issued by the bootstrap CA".to_string());
        }
        // As webpki checks an end-entity certificate for client authentication: no CA, and an
        // extended key usage that, where present, includes clientAuth.
        let leaf = parsed
            .basic_constraints()
            .is_ok_and(|constraints| !constraints.is_some_and(|c| c.value.ca));
        let client_auth = parsed
            .extended_key_usage()
            .is_ok_and(|usage| usage.is_none_or(|usage| usage.value.client_auth));
        if !(leaf && client_auth) {
            return Err("its certificate is no client-authentication leaf".to_string());
        }
        if !parsed.validity().is_valid() {
            return Err("its certificate is not valid now".to_string());
        }
        Ok(enrolling(certificate))
    }
}

/// What a bootstrap certificate (DER) makes the request it carries or proves: its subject, the
/// values an approval carries, its fingerprint and its issuer and serial.
#[must_use]
pub fn enrolling(certificate: &[u8]) -> Peer {
    use sha2::{Digest, Sha256};
    let fingerprint = hex::encode(Sha256::digest(certificate));
    match X509Certificate::from_der(certificate) {
        Ok((_, parsed)) => Peer::Enrolling {
            subject: crate::ca::name_text(parsed.subject()),
            carried: Box::new(crate::ca::carried_subject(parsed.subject())),
            fingerprint,
            id: CertId::new(parsed.issuer().as_raw(), &hex::encode(parsed.raw_serial())),
        },
        Err(_) => Peer::Enrolling {
            subject: String::new(),
            carried: Box::new(Err("the certificate does not parse".to_string())),
            fingerprint,
            id: CertId {
                issuer: String::new(),
                serial: String::new(),
            },
        },
    }
}

/// Every certificate in a CA file, read once.
fn cas(path: &Path, pem: &[u8]) -> Result<Vec<Ca>, String> {
    opamp::tls::certificates(pem)
        .map_err(|e| in_file(path, &e))?
        .iter()
        .map(|der| {
            X509Certificate::from_der(der.as_ref())
                .map(|(_, cert)| Ca {
                    subject: cert.subject().as_raw().to_vec(),
                    key: cert.public_key().raw.to_vec(),
                })
                .map_err(|e| format!("cannot parse {}: {e}", path.display()))
        })
        .collect()
}

/// What the file *means* is known here and nowhere else, so the wording names it.
fn in_file(path: &Path, error: &str) -> String {
    if error == "no certificates" {
        format!("{} contains no certificates", path.display())
    } else {
        format!("cannot parse {}: {error}", path.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

    /// A CA, with what [`Issuers`] keeps of it.
    fn ca(name: &str, issuer: Option<&Issuer<'_, KeyPair>>) -> (Vec<u8>, Ca, KeyPair) {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = match issuer {
            None => params.self_signed(&key),
            Some(issuer) => params.signed_by(&key, issuer),
        }
        .expect("ca");
        let parsed = X509Certificate::from_der(cert.der()).expect("parse").1;
        let kept = Ca {
            subject: parsed.subject().as_raw().to_vec(),
            key: parsed.public_key().raw.to_vec(),
        };
        (cert.der().to_vec(), kept, key)
    }

    /// The PEM form of a certificate.
    fn pem(der: &[u8]) -> String {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(der);
        let lines: Vec<&str> = encoded
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).expect("base64"))
            .collect();
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            lines.join("\n")
        )
    }

    /// The CAs an Agent plane would tell members from enrolling hosts by, when `client` is the
    /// client CA and `bootstrap` the bootstrap CA.
    fn issuers_from_files(client: &[u8], bootstrap: &[u8]) -> Issuers {
        Issuers::from_pem(
            (Path::new("client-ca.pem"), pem(client).as_bytes()),
            (Path::new("bootstrap-ca.pem"), pem(bootstrap).as_bytes()),
        )
        .expect("CAs")
    }

    fn leaf(issuer: &Issuer<'_, KeyPair>) -> Vec<u8> {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.distinguished_name.push(DnType::CommonName, "host");
        params.signed_by(&key, issuer).expect("leaf").der().to_vec()
    }

    /// A bootstrap certificate issued through an intermediate is still no member: with a bootstrap
    /// CA configured, membership is a certificate issued directly by the client CA, and nothing
    /// else (ADR-0021 clause 19).
    /// Verifies: ADR-0021
    #[test]
    fn a_certificate_not_issued_by_the_client_ca_only_enrols() {
        let (client_der, client_subject, client_key) = ca("client CA", None);
        let client = Issuer::from_ca_cert_der(&client_der.into(), client_key).expect("issuer");
        let (root_der, root_subject, root_key) = ca("bootstrap CA", None);
        let root = Issuer::from_ca_cert_der(&root_der.into(), root_key).expect("issuer");
        let (intermediate_der, _, intermediate_key) = ca("bootstrap intermediate", Some(&root));
        let intermediate =
            Issuer::from_ca_cert_der(&intermediate_der.into(), intermediate_key).expect("issuer");
        let issuers = Issuers {
            members: vec![client_subject],
            bootstrap: vec![root_subject],
        };
        assert_eq!(issuers.classify(&leaf(&client)), Peer::Member);
        assert!(matches!(
            issuers.classify(&leaf(&root)),
            Peer::Enrolling { .. }
        ));
        assert!(
            matches!(
                issuers.classify(&leaf(&intermediate)),
                Peer::Enrolling { .. }
            ),
            "an intermediate lifted a bootstrap certificate into the fleet"
        );
        assert_eq!(
            Issuers::default().classify(&leaf(&intermediate)),
            Peer::Member,
            "without a bootstrap CA the handshake trusts the client CA alone"
        );
    }

    /// An intermediate below the bootstrap CA that copies the client CA's name issues nothing a
    /// member holds: membership is what the client CA's key signed, not a name an issuer can
    /// take (ADR-0021 clause 19).
    /// Verifies: ADR-0021
    #[test]
    fn an_intermediate_named_like_the_client_ca_only_enrols() {
        let (client_der, _, client_key) = ca("client CA", None);
        let (root_der, _, root_key) = ca("bootstrap CA", None);
        let issuers = issuers_from_files(&client_der, &root_der);
        let client = Issuer::from_ca_cert_der(&client_der.into(), client_key).expect("issuer");
        let root = Issuer::from_ca_cert_der(&root_der.into(), root_key).expect("issuer");
        let (forged_der, _, forged_key) = ca("client CA", Some(&root));
        let forged = Issuer::from_ca_cert_der(&forged_der.into(), forged_key).expect("issuer");
        let forged_leaf = leaf(&forged);
        assert_eq!(
            X509Certificate::from_der(&forged_leaf)
                .expect("parse")
                .1
                .issuer(),
            X509Certificate::from_der(&leaf(&client))
                .expect("parse")
                .1
                .issuer(),
            "the intermediate copies the client CA's name"
        );
        assert_eq!(issuers.classify(&leaf(&client)), Peer::Member);
        assert!(
            matches!(issuers.classify(&forged_leaf), Peer::Enrolling { .. }),
            "an intermediate named like the client CA lifted its certificate into the fleet"
        );
    }

    /// Through a Gateway a proven bootstrap certificate is checked as the handshake checks one on
    /// an enrolment connection: issued directly by the bootstrap CA, no CA itself, an extended key
    /// usage that includes `clientAuth` where it names one, and valid now (ADR-0039 clause 8).
    /// Verifies: ADR-0039
    #[test]
    fn a_proven_bootstrap_certificate_is_checked_as_the_handshake_checks_it() {
        use rcgen::ExtendedKeyUsagePurpose as Eku;
        let (root_der, root_subject, root_key) = ca("bootstrap CA", None);
        let root = Issuer::from_ca_cert_der(&root_der.into(), root_key).expect("issuer");
        let (other_der, _, other_key) = ca("bootstrap CA", None);
        let other = Issuer::from_ca_cert_der(&other_der.into(), other_key).expect("issuer");
        let issuers = Issuers {
            members: Vec::new(),
            bootstrap: vec![root_subject],
        };
        let issue = |edit: &dyn Fn(&mut CertificateParams), by: &Issuer<'_, KeyPair>| {
            let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
            params
                .distinguished_name
                .push(DnType::CommonName, "bootstrap");
            params.extended_key_usages = vec![Eku::ClientAuth];
            edit(&mut params);
            params
                .signed_by(&KeyPair::generate().expect("key"), by)
                .expect("certificate")
                .der()
                .to_vec()
        };
        let keep = |_: &mut CertificateParams| {};
        assert!(issuers.bootstrap_issued(&issue(&keep, &root)).is_ok());
        let no_usage = |params: &mut CertificateParams| params.extended_key_usages.clear();
        assert!(
            issuers.bootstrap_issued(&issue(&no_usage, &root)).is_ok(),
            "the handshake takes a certificate that names no extended key usage"
        );
        type Edit<'a> = &'a dyn Fn(&mut CertificateParams);
        let refused: [(Edit<'_>, &str); 4] = [
            (
                &|params| params.extended_key_usages = vec![Eku::ServerAuth],
                "no client-authentication leaf",
            ),
            (
                &|params| params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained),
                "no client-authentication leaf",
            ),
            (
                &|params| {
                    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(2);
                    params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
                },
                "not valid now",
            ),
            (
                &|params| {
                    params.not_before = time::OffsetDateTime::now_utc() + time::Duration::days(1);
                    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(2);
                },
                "not valid now",
            ),
        ];
        for (edit, why) in refused {
            let error = issuers
                .bootstrap_issued(&issue(edit, &root))
                .expect_err(why);
            assert!(error.contains(why), "{error}");
        }
        let error = issuers
            .bootstrap_issued(&issue(&keep, &other))
            .expect_err("another key under the CA's name");
        assert!(error.contains("not issued by the bootstrap CA"), "{error}");
    }
}
