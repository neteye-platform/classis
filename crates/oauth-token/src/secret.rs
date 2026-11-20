//! The 256-bit random values this crate issues and the way the server keeps them: only as a
//! SHA-256 hash, which is enough for a value with that much entropy (RFC 6819 §5.1.4.1.3).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The length of a generated value: 256 bits in base64url without padding (RFC 4648 §5).
pub const GENERATED_LEN: usize = 43;

/// 256 random bits from the operating system's generator, as 43 characters of base64url without
/// padding. Every character is in the `b64token` set of RFC 6750 §2.1.
///
/// # Panics
///
/// When the operating system's generator fails: no credential may be issued from anything weaker.
pub fn generate() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    SystemRandom::new()
        .fill(bytes.as_mut())
        .expect("the operating system's random generator is unavailable");
    let mut encoded = Zeroizing::new(String::with_capacity(GENERATED_LEN));
    URL_SAFE_NO_PAD.encode_string(bytes.as_slice(), &mut encoded);
    encoded
}

/// `SHA-256(secret)`, which is what the server stores of a client secret or an access token.
pub fn hash(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

/// Whether two hashes are equal, in time that does not depend on where they differ.
pub fn hashes_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    constant_time_eq::constant_time_eq(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: ADR-0064
    /// RFC 4648 §5 and ADR-0064 clause 1: 256 random bits, base64url, no padding: 43 characters.
    #[test]
    fn a_generated_value_is_43_base64url_characters() {
        let value = generate();
        assert_eq!(value.len(), GENERATED_LEN);
        assert!(value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    }

    /// Verifies: ADR-0064
    #[test]
    fn generated_values_differ() {
        assert_ne!(*generate(), *generate());
    }

    /// Verifies: ADR-0064
    /// FIPS 180-4 test vector: SHA-256("abc").
    #[test]
    fn hash_is_sha256() {
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash("abc"), expected);
    }

    /// Verifies: ADR-0064
    #[test]
    fn hashes_compare_by_value() {
        assert!(hashes_equal(&hash("a"), &hash("a")));
        assert!(!hashes_equal(&hash("a"), &hash("b")));
    }
}
