//! Which TLS material the Client uses (ADR-0013, ADR-0021), read from disk and handed to `opamp` as
//! [`ClientTls`] (ADR-0010).
//!
//! The decisions are the Client's: an optional CA file that *replaces* the built-in roots, and the
//! identity in force — the one the Server issued, else the one the operator configured. Building a
//! rustls configuration or an HTTP client from that material is `opamp`'s.

use std::path::Path;

use opamp::client::ClientTls;
use opamp::tls::Identity;

use crate::config::ClientConfig;

/// The Server-issued client certificate, in the state directory beside the connection settings —
/// it belongs to the Client's one upstream connection, not to any single Agent (ADR-0021).
pub const ISSUED_CERT_FILE: &str = "client-cert.pem";
/// The private key of [`ISSUED_CERT_FILE`]. Generated on this host and never sent anywhere: what
/// leaves is a CSR over its public half.
pub const ISSUED_KEY_FILE: &str = "client-key.pem";
/// The key a request in flight asks to be certified, kept apart from [`ISSUED_KEY_FILE`] so the
/// certificate in force keeps its own key until the new one is proved (ADR-0021 clause 11).
pub const PENDING_KEY_FILE: &str = "client-key.pending.pem";
/// An issued certificate staged beside [`PENDING_KEY_FILE`] while the two are put in force, so a
/// swap cut short is completed at the next start rather than leaving a mismatched pair.
pub const PENDING_CERT_FILE: &str = "client-cert.pending.pem";
/// The request in flight, re-sent unchanged until it is answered — the enrolment queue knows a
/// request by its public key (ADR-0021 clause 21).
pub const PENDING_CSR_FILE: &str = "client-csr.pending.pem";

/// The trust and the identity in force.
///
/// # Errors
/// Returns an error naming the file that cannot be read.
pub fn client_tls(config: &ClientConfig) -> Result<ClientTls, String> {
    client_tls_for(config, None)
}

/// The same, for a **candidate** identity: an offered certificate is proved by connecting with it
/// before it is stored (ADR-0014's MUST, applied to the certificate in ADR-0021), so the
/// certificate under test comes from the offer while its key is the pending one on disk.
///
/// # Errors
/// Returns an error naming the file that cannot be read, or the missing key of a candidate.
pub fn client_tls_for(
    config: &ClientConfig,
    candidate_cert: Option<&[u8]>,
) -> Result<ClientTls, String> {
    let ca_pem = config.ca_file().map(certificates_file).transpose()?;
    let identity = match candidate_cert {
        Some(cert) => {
            // An offered certificate belongs to the key this Client generated for its request;
            // without that key there is nothing to prove possession with.
            // The key of the request in flight, or — for a certificate offered over a key already in
            // force — that one.
            let pending = config.state_dir.join(PENDING_KEY_FILE);
            let key = if pending.exists() {
                pending
            } else {
                config.state_dir.join(ISSUED_KEY_FILE)
            };
            if !key.exists() {
                return Err(format!(
                    "an offered certificate has no key to go with it — {} is missing",
                    key.display()
                ));
            }
            Some(Identity {
                cert_pem: cert.to_vec(),
                key_pem: key_file(&key)?,
            })
        }
        // An identity opened from a `bootstrap.p12` stands in for the configured one until the
        // Server's certificate is stored (ADR-0029 clause 7); the issued one outranks both.
        None => match (&config.bootstrap_identity, config.is_enrolled()) {
            (Some(bootstrap), false) => Some(Identity {
                cert_pem: bootstrap.cert_pem.clone(),
                key_pem: bootstrap.key_pem.clone(),
            }),
            _ => match config.client_identity() {
                Some((cert, key)) => Some(Identity {
                    cert_pem: certificates_file(&cert)?,
                    key_pem: key_file(&key)?,
                }),
                None => None,
            },
        },
    };
    Ok(ClientTls { ca_pem, identity })
}

/// The trust anchors alone — what a download from a host that is not the Server needs. Reads no
/// identity, so a client certificate that cannot be read does not stop a download.
///
/// # Errors
/// Returns an error naming the CA file that cannot be read or holds no certificate.
pub fn trust(config: &ClientConfig) -> Result<ClientTls, String> {
    Ok(ClientTls {
        ca_pem: config.ca_file().map(certificates_file).transpose()?,
        identity: None,
    })
}

/// A PEM file of certificates, parsed here so that a bad one is named by its path.
pub(crate) fn certificates_file(path: &Path) -> Result<Vec<u8>, String> {
    let pem = read(path)?;
    opamp::tls::certificates(&pem).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(pem)
}

/// A PEM file holding a private key, parsed here so that a bad one is named by its path.
pub(crate) fn key_file(path: &Path) -> Result<Vec<u8>, String> {
    let pem = read(path)?;
    opamp::tls::private_key(&pem)
        .map_err(|_| format!("{} contains no private key", path.display()))?;
    Ok(pem)
}

/// The identity in the PKCS#12 file at `path`, under `password`, as PEM in memory (ADR-0029
/// clause 7). A file over [`fleet_core::pkcs12::MAX_FILE_BYTES`] is refused before it is read.
///
/// # Errors
/// [`OpenError::WrongPassword`](fleet_core::pkcs12::file::OpenError) when the password does not
/// open it, and `Invalid` naming the file for everything else.
pub fn pkcs12_identity(
    path: &Path,
    password: &str,
) -> Result<crate::config::BootstrapIdentity, fleet_core::pkcs12::file::OpenError> {
    use fleet_core::pkcs12::file::OpenError;
    use std::io::Read as _;
    let invalid = |why: String| OpenError::Invalid(format!("{}: {why}", path.display()));
    let limit = fleet_core::pkcs12::MAX_FILE_BYTES;
    // Before it is read, and only a regular file, so a pipe cannot hold the install.
    let meta = std::fs::metadata(path).map_err(|e| invalid(format!("cannot read it: {e}")))?;
    if !meta.is_file() {
        return Err(invalid("not a regular file".to_string()));
    }
    if meta.len() > limit {
        return Err(invalid(format!("larger than {limit} bytes")));
    }
    let file = std::fs::File::open(path).map_err(|e| invalid(format!("cannot read it: {e}")))?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| invalid(format!("cannot read it: {e}")))?;
    let opened = fleet_core::pkcs12::file::open(&bytes, password).map_err(|e| match e {
        OpenError::WrongPassword => OpenError::WrongPassword,
        OpenError::Invalid(why) => invalid(why),
    })?;
    Ok(crate::config::BootstrapIdentity {
        cert_pem: pem_block("CERTIFICATE", &opened.certificate_der).into_bytes(),
        key_pem: pem_block("PRIVATE KEY", &opened.private_key_der).into_bytes(),
    })
}

/// `der` as one PEM block.
fn pem_block(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `bootstrap.p12` opens to PEM in memory and stands in for the configured identity until
    /// the Server's certificate is stored; a file over the bound is refused unread (ADR-0029
    /// clause 7).
    /// Verifies: ADR-0029
    #[test]
    fn an_opened_bootstrap_p12_is_presented_until_the_client_is_enrolled() {
        use fleet_core::pkcs12::file::OpenError;
        let dir = tempfile::tempdir().expect("tempdir");
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["bootstrap".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        let p12 = dir.path().join("bootstrap.p12");
        std::fs::write(
            &p12,
            fleet_core::pkcs12::file::seal(cert.der(), &key.serialize_der(), "twelve chars")
                .expect("sealed"),
        )
        .expect("write");
        assert_eq!(
            pkcs12_identity(&p12, "not the password"),
            Err(OpenError::WrongPassword)
        );
        let identity = pkcs12_identity(&p12, "twelve chars").expect("opens");
        assert_eq!(
            opamp::tls::certificates(&identity.cert_pem).expect("pem")[0].as_ref(),
            cert.der().as_ref()
        );

        let config = ClientConfig {
            state_dir: dir.path().join("state"),
            bootstrap_identity: Some(identity.clone()),
            ..ClientConfig::default()
        };
        std::fs::create_dir_all(&config.state_dir).expect("state");
        assert_eq!(
            client_tls(&config).expect("tls").identity,
            Some(Identity {
                cert_pem: identity.cert_pem.clone(),
                key_pem: identity.key_pem.clone(),
            })
        );

        let issued = rcgen::KeyPair::generate().expect("key");
        let issued_cert = rcgen::CertificateParams::new(vec!["issued".to_string()])
            .expect("params")
            .self_signed(&issued)
            .expect("cert");
        std::fs::write(config.state_dir.join(ISSUED_CERT_FILE), issued_cert.pem()).expect("w");
        std::fs::write(
            config.state_dir.join(ISSUED_KEY_FILE),
            issued.serialize_pem(),
        )
        .expect("w");
        let presented = client_tls(&config).expect("tls").identity.expect("one");
        assert_eq!(
            presented.cert_pem,
            issued_cert.pem().into_bytes(),
            "the issued certificate outranks the bootstrap identity"
        );

        let large = dir.path().join("large.p12");
        let file = std::fs::File::create(&large).expect("create");
        file.set_len(fleet_core::pkcs12::MAX_FILE_BYTES + 1)
            .expect("size");
        assert!(matches!(
            pkcs12_identity(&large, "twelve chars"),
            Err(OpenError::Invalid(why)) if why.contains("larger than")
        ));
    }
}
