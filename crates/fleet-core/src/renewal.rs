//! The proof a certificate renewal carries (ADR-0021 clause 27): the certificate being renewed, and
//! a signature made with its key over the new key. The Server reads which host a renewal is for from
//! the proof, not from the connection it arrives on — behind a Gateway that connection presents the
//! Gateway's certificate.
//!
//! It travels in the CSR as a requested SAN URI — `URI_PREFIX` and the base64url (no padding) of
//! [`encode`]'s bytes — since the Server reads requested SANs and never copies them into what it
//! signs; an extension of its own would need an OID this project does not hold.

/// The SAN URI prefix of a renewal proof.
pub const URI_PREFIX: &str = "urn:opamp-fleet:renewal:v1:";

/// What the current key signs: a fixed prefix and the SHA-256 of the new key's
/// SubjectPublicKeyInfo, in lowercase hex.
#[must_use]
pub fn statement(new_key_sha256: &[u8]) -> Vec<u8> {
    statement_of("opamp-fleet-renewal-v1", new_key_sha256)
}

/// `label`, a newline, the SHA-256 of the new key in lowercase hex, and a newline: what a proof's
/// key signs. Each proof has a label of its own, so neither can stand for the other.
pub(crate) fn statement_of(label: &str, new_key_sha256: &[u8]) -> Vec<u8> {
    let mut text = format!("{label}\n");
    for byte in new_key_sha256 {
        text.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        text.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    text.push('\n');
    text.into_bytes()
}

/// The extension's content: the current certificate's DER, length-prefixed, then the signature.
#[must_use]
pub fn encode(certificate_der: &[u8], signature: &[u8]) -> Vec<u8> {
    let length = u32::try_from(certificate_der.len()).unwrap_or(u32::MAX);
    let mut content = Vec::with_capacity(4 + certificate_der.len() + signature.len());
    content.extend_from_slice(&length.to_be_bytes());
    content.extend_from_slice(certificate_der);
    content.extend_from_slice(signature);
    content
}

/// The certificate and the signature an extension's content holds; `None` for one that does not
/// parse.
#[must_use]
pub fn decode(content: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = usize::try_from(u32::from_be_bytes(content.get(..4)?.try_into().ok()?)).ok()?;
    let end = 4usize.checked_add(length)?;
    let certificate = content.get(4..end)?;
    let signature = content.get(end..)?;
    (!certificate.is_empty() && !signature.is_empty()).then_some((certificate, signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: ADR-0021
    #[test]
    fn a_proof_round_trips_and_a_torn_one_does_not_parse() {
        let content = encode(b"cert", b"sig");
        assert_eq!(decode(&content), Some((&b"cert"[..], &b"sig"[..])));
        assert_eq!(decode(&content[..6]), None);
        assert_eq!(decode(&encode(b"cert", b"")), None);
        assert_eq!(statement(&[0xab]), b"opamp-fleet-renewal-v1\nab\n".to_vec());
    }

    /// A length prefix past what the content holds — the largest one included — does not parse,
    /// on any pointer width.
    /// Verifies: ADR-0021
    #[test]
    fn a_length_past_the_content_does_not_parse() {
        let mut content = u32::MAX.to_be_bytes().to_vec();
        content.extend_from_slice(b"cert-and-sig");
        assert_eq!(decode(&content), None);
    }
}
