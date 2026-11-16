//! What a package signature covers (ADR-0026), and how it is verified (ADR-0063).
//!
//! The signature covers not the artifact's bytes alone but which Agent type the artifact is for,
//! at which version, and its SHA-256 — so a signed artifact cannot be offered as another type's
//! program, or under another version.
//!
//! It is a [`PackageSignature`]: the certificate of the Package Signer that made it and its
//! Ed25519 signature over [`statement`]. It verifies only when a compiled-in Package Root issued
//! that certificate; [`chain`] is that check, which the Client and the Server call alike.

use std::fmt;

pub mod chain;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;

/// The bytes a Package Signer signs and a Client verifies for one artifact:
/// `classis-package-v1`, the Agent type, the version and the artifact's SHA-256 in lowercase
/// hex, one per line, each line ended by a newline.
#[must_use]
pub fn statement(agent_type: &str, version: &str, content_hash: &[u8]) -> Vec<u8> {
    let mut hex = String::with_capacity(content_hash.len() * 2);
    for byte in content_hash {
        hex.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        hex.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    format!("classis-package-v1\n{agent_type}\n{version}\n{hex}\n").into_bytes()
}

/// The longest `PackageSignature` read, checked before anything inside it is parsed (ADR-0063
/// clause 3, Q-2). A Package Signer's certificate is about 340 bytes.
pub const MAX_SIGNATURE_LEN: usize = 2048;

/// The length of an Ed25519 signature.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// The variable a **debug** build reads one more Package Root from, a DER file, so the
/// integration tests can sign with a Root of their own. A release build compiles no such read
/// (ADR-0063 clause 1).
pub const DEBUG_ROOT_ENV: &str = "CLASSIS_DEBUG_PACKAGE_ROOT";

/// `PackageSignature ::= SEQUENCE { version INTEGER (1), signer Certificate, signature OCTET
/// STRING (SIZE (64)) }`, borrowed from the bytes it was parsed from (ADR-0063 clause 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageSignature<'a> {
    /// The Package Signer's certificate, the whole DER `Certificate`.
    pub signer: &'a [u8],
    /// The Ed25519 signature over the statement.
    pub signature: &'a [u8; ED25519_SIGNATURE_LEN],
}

/// Why a package signature was refused, or could not be written, by the step that failed
/// (ADR-0063 clause 4).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureError {
    /// The bytes are not a `PackageSignature`.
    Malformed(&'static str),
    /// The certificate does not lead to a compiled-in Package Root, or is not a Package Signer.
    Chain(String),
    /// The Package Signer's signature does not cover this statement.
    Signature,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "the signature is not a PackageSignature: {why}"),
            Self::Chain(why) => write!(f, "the signature's Package Signer is refused: {why}"),
            Self::Signature => f.write_str(
                "the signature does not cover this artifact — it must cover the Agent type, the \
                 version and the artifact's SHA-256",
            ),
        }
    }
}

impl std::error::Error for SignatureError {}

/// The Package Roots a signature is verified up to (ADR-0063 clause 1): DER certificates, a
/// value. Where they come from — compiled in, or a test's own — and how a path to them is
/// checked is [`chain`]'s.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roots {
    der: Vec<Vec<u8>>,
}

impl Roots {
    /// Roots from DER certificates. Tests pass a test Root of their own here.
    ///
    /// # Errors
    ///
    /// A value that is not one DER `SEQUENCE` and nothing after it.
    pub fn from_der<'a>(certs: impl IntoIterator<Item = &'a [u8]>) -> Result<Self, String> {
        let der = certs
            .into_iter()
            .map(|cert| match tlv(cert, 0x30) {
                Ok(Element { after: [], .. }) => Ok(cert.to_vec()),
                _ => Err("a Package Root is not a DER certificate".to_string()),
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { der })
    }

    /// The certificates, DER.
    pub fn certificates(&self) -> impl Iterator<Item = &[u8]> {
        self.der.iter().map(Vec::as_slice)
    }

    /// How many Roots there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.der.len()
    }

    /// Whether there is none, in which case nothing verifies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.der.is_empty()
    }

    /// These Roots and `other`'s, in that order.
    #[must_use]
    pub fn with(mut self, other: Roots) -> Self {
        self.der.extend(other.der);
        self
    }
}

/// One DER element read off the front of an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Element<'a> {
    /// The element's contents.
    value: &'a [u8],
    /// The whole element: tag, length and contents.
    whole: &'a [u8],
    /// What follows it in the input.
    after: &'a [u8],
}

/// Reads one DER tag-length-value of `tag` off the front of `input`. Definite, minimal lengths
/// only, at most two length octets (`MAX_SIGNATURE_LEN` fits).
fn tlv(input: &[u8], tag: u8) -> Result<Element<'_>, &'static str> {
    let (&got, rest) = input.split_first().ok_or("it ends early")?;
    if got != tag {
        return Err("an element has an unexpected tag");
    }
    let (&first, rest) = rest.split_first().ok_or("it ends early")?;
    let (len, rest) = match first {
        0..=0x7f => (usize::from(first), rest),
        0x81 => {
            let (&b, rest) = rest.split_first().ok_or("it ends early")?;
            if b < 0x80 {
                return Err("a length is not minimal");
            }
            (usize::from(b), rest)
        }
        0x82 => {
            let [hi, lo, rest @ ..] = rest else {
                return Err("it ends early");
            };
            let len = usize::from(u16::from_be_bytes([*hi, *lo]));
            if len < 0x100 {
                return Err("a length is not minimal");
            }
            (len, rest)
        }
        0x80 => return Err("an indefinite length is not DER"),
        _ => return Err("a length is too long"),
    };
    if rest.len() < len {
        return Err("it ends early");
    }
    let header = input.len() - rest.len();
    let (value, after) = rest.split_at(len);
    Ok(Element {
        value,
        whole: &input[..header + len],
        after,
    })
}

/// Reads a `PackageSignature` (ADR-0063 clause 3). The length is checked before anything else.
///
/// # Errors
///
/// [`SignatureError::Malformed`] naming what is wrong.
pub fn parse_signature(bytes: &[u8]) -> Result<PackageSignature<'_>, SignatureError> {
    if bytes.len() > MAX_SIGNATURE_LEN {
        return Err(SignatureError::Malformed("it is longer than 2048 bytes"));
    }
    let malformed = SignatureError::Malformed;
    let outer = tlv(bytes, 0x30).map_err(malformed)?;
    if !outer.after.is_empty() {
        return Err(malformed("bytes follow it"));
    }
    let version = tlv(outer.value, 0x02).map_err(malformed)?;
    if version.value != [1] {
        return Err(malformed("its version is not 1"));
    }
    let signer = tlv(version.after, 0x30).map_err(malformed)?;
    let signature = tlv(signer.after, 0x04).map_err(malformed)?;
    if !signature.after.is_empty() {
        return Err(malformed("bytes follow its signature"));
    }
    let signature = signature
        .value
        .try_into()
        .map_err(|_| malformed("its signature is not 64 bytes"))?;
    Ok(PackageSignature {
        signer: signer.whole,
        signature,
    })
}

/// A DER length, in the shortest form, for a length this format can hold (below `0x10000`).
fn der_len(len: usize) -> Option<Vec<u8>> {
    if let Ok(short) = u8::try_from(len) {
        if short < 0x80 {
            return Some(vec![short]);
        }
        return Some(vec![0x81, short]);
    }
    let [hi, lo] = u16::try_from(len).ok()?.to_be_bytes();
    Some(vec![0x82, hi, lo])
}

/// Writes a `PackageSignature` from a Package Signer's DER certificate and its signature — what
/// the release run's `sign` job writes in hex (ADR-0062 clause 6).
///
/// ```
/// use classis_core::package::{encode_signature, parse_signature};
///
/// let certificate = [0x30, 0x00]; // an empty SEQUENCE stands in for a certificate here
/// let encoded = encode_signature(&certificate, &[7; 64]).expect("it fits");
/// let parsed = parse_signature(&encoded).expect("it reads back");
/// assert_eq!(parsed.signer, &certificate[..]);
/// ```
///
/// # Errors
///
/// [`SignatureError::Malformed`] when the result would be longer than [`MAX_SIGNATURE_LEN`],
/// which [`parse_signature`] would refuse. No Package Signer's certificate comes near it.
pub fn encode_signature(
    signer: &[u8],
    signature: &[u8; ED25519_SIGNATURE_LEN],
) -> Result<Vec<u8>, SignatureError> {
    const VERSION: [u8; 3] = [0x02, 0x01, 0x01];
    // `ED25519_SIGNATURE_LEN` is 64, a one-octet DER length.
    const SIGNATURE_HEADER: [u8; 2] = [0x04, 0x40];
    let too_long = SignatureError::Malformed("its certificate is too long for the format");
    let body_len = VERSION.len() + signer.len() + SIGNATURE_HEADER.len() + signature.len();
    let length = der_len(body_len).ok_or_else(|| too_long.clone())?;
    if 1 + length.len() + body_len > MAX_SIGNATURE_LEN {
        return Err(too_long);
    }
    let mut out = Vec::with_capacity(1 + length.len() + body_len);
    out.push(0x30);
    out.extend(length);
    out.extend(VERSION);
    out.extend_from_slice(signer);
    out.extend(SIGNATURE_HEADER);
    out.extend_from_slice(signature);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: ADR-0026
    #[test]
    fn the_statement_names_type_version_and_hash() {
        assert_eq!(
            statement("otelcol-contrib", "0.110.0", &[0x0a, 0xff]),
            b"classis-package-v1\notelcol-contrib\n0.110.0\n0aff\n".to_vec()
        );
        assert_ne!(
            statement("a", "1", &[1]),
            statement("b", "1", &[1]),
            "the type is covered"
        );
        assert_ne!(
            statement("a", "1", &[1]),
            statement("a", "2", &[1]),
            "the version is covered"
        );
    }

    /// Verifies: ADR-0063
    #[test]
    fn the_encoder_writes_the_shortest_lengths_and_refuses_what_the_parser_would() {
        assert_eq!(der_len(0x7f), Some(vec![0x7f]));
        assert_eq!(der_len(0x80), Some(vec![0x81, 0x80]));
        assert_eq!(der_len(0x100), Some(vec![0x82, 0x01, 0x00]));
        assert_eq!(der_len(0x1_0000), None);

        // A SEQUENCE of `contents` zero bytes stands in for a certificate of that size.
        let sequence = |contents: usize| {
            let mut der = vec![0x30];
            der.extend(der_len(contents).expect("a length the format holds"));
            der.resize(der.len() + contents, 0);
            der
        };
        let sig = [3u8; ED25519_SIGNATURE_LEN];
        // Short, one-octet and two-octet lengths, for the certificate and for the whole.
        for contents in [0, 60, 200, 400] {
            let certificate = sequence(contents);
            let encoded = encode_signature(&certificate, &sig).expect("it fits");
            let parsed = parse_signature(&encoded).expect("it reads back");
            assert_eq!(parsed.signer, certificate.as_slice(), "{contents}");
            assert_eq!(parsed.signature, &sig);
        }
        assert_eq!(
            encode_signature(&vec![0u8; MAX_SIGNATURE_LEN], &sig),
            Err(SignatureError::Malformed(
                "its certificate is too long for the format"
            ))
        );
    }
}
