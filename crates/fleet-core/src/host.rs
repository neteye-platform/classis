//! The host a client certificate that names none is taken for.
//!
//! A certificate the Server issues names its host (`urn:opamp-fleet:host:<id>`). One an operator
//! provisioned may name none; the Server gives it a host derived from its issuer and serial when it
//! first renews it (ADR-0036 clause 2), and a Gateway binds its Agents to that same host before the
//! renewal (ADR-0039 clause 6), so the renewal does not move them.

use sha2::{Digest as _, Sha256};

/// The host derived from a certificate's issuer — the SHA-256 of its DER-encoded name, lowercase
/// hex — and its serial, normalized to lowercase hex without leading zeros: the first 16 bytes of
/// the SHA-256 of `<issuer>\n<serial>`, in the canonical UUID text form.
#[must_use]
pub fn derived(issuer: &str, serial: &str) -> String {
    let digest = Sha256::digest(format!("{issuer}\n{serial}"));
    let hex = hex::encode(&digest[..16]);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same issuer and serial derive the same host, and either one changed derives another.
    /// Verifies: ADR-0039
    #[test]
    fn a_host_is_derived_from_issuer_and_serial_alone() {
        let host = derived("ab", "1f");
        assert_eq!(host, derived("ab", "1f"));
        assert_ne!(host, derived("ab", "20"));
        assert_ne!(host, derived("ac", "1f"));
        assert_eq!(host.len(), 36);
        assert_eq!(host.matches('-').count(), 4);
    }
}
