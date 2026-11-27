//! Which TLS trust the Client uses, read from disk and handed to `opamp` as
//! [`ClientTls`].
//!
//! The decision is the Client's: an optional CA file that *replaces* the built-in roots. Building a
//! rustls configuration or an HTTP client from that material is `opamp`'s.

use std::path::Path;

use opamp::client::ClientTls;

use crate::config::ClientConfig;

/// The trust anchors the Client's connections use.
///
/// # Errors
/// Returns an error naming the CA file that cannot be read or holds no certificate.
pub fn trust(config: &ClientConfig) -> Result<ClientTls, String> {
    Ok(ClientTls {
        ca_pem: config.ca_file().map(certificates_file).transpose()?,
    })
}

/// A PEM file of certificates, parsed here so that a bad one is named by its path.
pub(crate) fn certificates_file(path: &Path) -> Result<Vec<u8>, String> {
    let pem = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    opamp::tls::certificates(&pem).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(pem)
}

#[cfg(test)]
mod tests {
    /// The Client's secrets are held in buffers wiped when they are dropped: the Supervisor
    /// Endpoint token, `[packages] archive_key`, and the client secret and the access token of
    /// `state.json`.
    /// Were any a plain buffer again, this would not compile.
    #[test]
    fn the_clients_secrets_are_held_in_zeroizing_buffers() {
        use zeroize::Zeroizing;
        fn archive_key(packages: crate::config::PackagesConfig) -> Option<Zeroizing<String>> {
            packages.archive_key
        }
        let makes_token: fn() -> Result<Zeroizing<String>, String> =
            crate::supervisor::endpoint::new_token;
        fn enrolment(
            credentials: crate::credentials::Credentials,
        ) -> (Zeroizing<String>, Zeroizing<String>) {
            (credentials.client_secret, credentials.access_token)
        }
        let _: fn(crate::credentials::Credentials) -> (Zeroizing<String>, Zeroizing<String>) =
            enrolment;

        assert_eq!(makes_token().expect("a token").len(), 64);
        let packages: crate::config::PackagesConfig =
            toml::from_str("archive_key = \"a-long-secret\"\n").expect("parses");
        assert_eq!(
            archive_key(packages).expect("a key").as_str(),
            "a-long-secret"
        );
    }
}
