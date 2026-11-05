//! The proof an enrolment request carries (ADR-0039): the bootstrap certificate it enrols with,
//! and a signature made with that certificate's key over the new key. The Server reads which
//! bootstrap certificate a request rests on from the proof, so a request holds over any hop — a
//! Gateway in between included (ADR-0039).
//!
//! It has the renewal proof's shape (ADR-0021 clause 27): a requested SAN URI, [`URI_PREFIX`] and
//! the base64url (no padding) of [`encode`]'s bytes, with a statement of its own so that neither
//! proof can stand for the other.

pub use crate::renewal::{decode, encode};

/// The SAN URI prefix of a bootstrap proof.
pub const URI_PREFIX: &str = "urn:opamp-fleet:bootstrap:v1:";

/// What the bootstrap key signs: a fixed prefix and the SHA-256 of the new key's
/// SubjectPublicKeyInfo, in lowercase hex.
#[must_use]
pub fn statement(new_key_sha256: &[u8]) -> Vec<u8> {
    crate::renewal::statement_of("opamp-fleet-bootstrap-v1", new_key_sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: ADR-0039
    #[test]
    fn a_proof_round_trips_and_a_torn_one_does_not_parse() {
        let content = encode(b"cert", b"sig");
        assert_eq!(decode(&content), Some((&b"cert"[..], &b"sig"[..])));
        assert_eq!(decode(&content[..6]), None);
        assert_eq!(
            statement(&[0xab]),
            b"opamp-fleet-bootstrap-v1\nab\n".to_vec()
        );
    }

    /// The bootstrap proof's statement is not the renewal proof's, for the same key: a signature
    /// over one never verifies as the other.
    /// Verifies: ADR-0039
    #[test]
    fn its_statement_differs_from_the_renewal_proofs() {
        let key = [0x01, 0xfe];
        assert_ne!(statement(&key), crate::renewal::statement(&key));
        assert_ne!(URI_PREFIX, crate::renewal::URI_PREFIX);
        assert!(!URI_PREFIX.starts_with(crate::renewal::URI_PREFIX));
    }
}
