//! The listeners' TLS material (ADR-0013, ADR-0032), read from the files `[tls]` and `[rest.tls]`
//! name and handed to `opamp`'s listener (ADR-0010).
//!
//! What is the Server's here is which material and why. The Agent plane serves `[tls]`'s
//! certificate. The Operator plane serves `[rest.tls]`'s certificate, or without it the same one:
//! a browser reaches it with a password ([`crate::api`]). Neither asks for a client certificate.

use std::path::Path;

use opamp::server::listen::{ClientAuth, ServerTls};
use opamp::tls::Identity;

use crate::config::{RestTlsConfig, TlsConfig};

/// The material each plane serves with.
pub struct PlaneTls {
    pub agent: ServerTls,
    pub operator: ServerTls,
}

/// The material both planes serve with: `[tls]`'s on the Agent plane, and on the Operator plane
/// `operator`'s — `[rest.tls]` — or, without it, `[tls]`'s as well (ADR-0032).
///
/// # Errors
/// Returns an error naming the file that cannot be read or holds nothing usable, or a `[rest.tls]`
/// pair whose key does not match its certificate.
pub fn server_tls(tls: &TlsConfig, operator: Option<&RestTlsConfig>) -> Result<PlaneTls, String> {
    let identity = identity(&tls.cert_file, &tls.key_file)?;
    let operator = ServerTls {
        identity: match operator {
            Some(operator) => operator_identity(operator)?,
            None => identity.clone(),
        },
        client_auth: ClientAuth::None,
    };
    Ok(PlaneTls {
        agent: ServerTls {
            identity,
            client_auth: ClientAuth::None,
        },
        operator,
    })
}

/// The `[rest.tls]` pair, read and checked as `[tls]`'s is (ADR-0032 clause 3). The key is
/// matched against the certificate here rather than when the plane is built, so the refusal
/// names both files.
fn operator_identity(operator: &RestTlsConfig) -> Result<Identity, String> {
    let identity = identity(&operator.cert_file, &operator.key_file)?;
    ServerTls {
        identity: identity.clone(),
        client_auth: ClientAuth::None,
    }
    .rustls_config()
    .map_err(|e| {
        format!(
            "[rest.tls] key_file {} does not serve with cert_file {}: {e}",
            operator.key_file.display(),
            operator.cert_file.display()
        )
    })?;
    Ok(identity)
}

/// A certificate chain and its key, each file read and checked to hold what it is named for.
fn identity(cert_file: &Path, key_file: &Path) -> Result<Identity, String> {
    let cert_pem = read(cert_file)?;
    opamp::tls::certificates(&cert_pem).map_err(|e| in_file(cert_file, &e))?;
    // Read, and parsed, in buffers wiped when they are dropped; `opamp` takes the key as its own
    // buffer, so the copy is made here (ADR-0057 clause 3).
    let key_pem = zeroize::Zeroizing::new(read(key_file)?);
    opamp::tls::private_key(&key_pem)
        .map(zeroize::Zeroizing::new)
        .map_err(|_| format!("{} contains no private key", key_file.display()))?;
    Ok(Identity {
        cert_pem,
        key_pem: key_pem.to_vec(),
    })
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
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
    use rcgen::{CertificateParams, KeyPair};

    /// A `[rest.tls]` pair is checked at startup as `[tls]`'s is: a key that does not match its
    /// certificate, or a key file that cannot be read, refuses the start, and the message names
    /// the files (ADR-0032 clause 3). A matching pair is what the Operator plane serves, while the
    /// Agent plane keeps `[tls]`'s.
    /// Verifies: ADR-0032
    #[test]
    fn a_rest_tls_pair_is_checked_at_startup_and_served_on_the_operator_plane_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = |name: &str, content: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, content).expect("write");
            path
        };
        let self_signed = |key: &KeyPair| {
            CertificateParams::new(vec!["localhost".to_string()])
                .expect("params")
                .self_signed(key)
                .expect("certificate")
                .pem()
        };
        let server = KeyPair::generate().expect("key");
        let tls = TlsConfig {
            cert_file: path("server.pem", &self_signed(&server)),
            key_file: path("server-key.pem", &server.serialize_pem()),
        };
        let ui = KeyPair::generate().expect("key");
        let other = KeyPair::generate().expect("key");
        let ui_cert = self_signed(&ui);
        let operator = RestTlsConfig {
            cert_file: path("ui.pem", &ui_cert),
            key_file: path("ui-key.pem", &ui.serialize_pem()),
        };

        let planes = server_tls(&tls, Some(&operator)).expect("served");
        assert_eq!(planes.operator.identity.cert_pem, ui_cert.as_bytes());
        assert_eq!(
            planes.agent.identity.cert_pem,
            std::fs::read(&tls.cert_file).expect("read")
        );

        let mismatched = RestTlsConfig {
            cert_file: operator.cert_file.clone(),
            key_file: path("other-key.pem", &other.serialize_pem()),
        };
        let Err(refused) = server_tls(&tls, Some(&mismatched)) else {
            panic!("a key that does not match its certificate is served");
        };
        assert!(
            refused.contains("other-key.pem") && refused.contains("ui.pem"),
            "{refused}"
        );
        let missing = RestTlsConfig {
            cert_file: operator.cert_file.clone(),
            key_file: dir.path().join("absent-key.pem"),
        };
        let Err(refused) = server_tls(&tls, Some(&missing)) else {
            panic!("a key file that cannot be read is served");
        };
        assert!(refused.contains("absent-key.pem"), "{refused}");
    }
}
