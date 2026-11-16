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

/// Why a package signature was refused, by the step that failed (ADR-0063 clause 4).
#[derive(Debug, Clone, PartialEq, Eq)]
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
                Ok((_, _, [])) => Ok(cert.to_vec()),
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
}

/// One DER element read off the front of the input: its value, the whole element, and what
/// follows it.
type Element<'a> = (&'a [u8], &'a [u8], &'a [u8]);

/// One DER tag-length-value (see [`Element`]). Definite, minimal lengths only, at most two length
/// octets (`MAX_SIGNATURE_LEN` fits).
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
            let len = usize::from(*hi) << 8 | usize::from(*lo);
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
    Ok((value, &input[..header + len], after))
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
    let (body, _, after) = tlv(bytes, 0x30).map_err(malformed)?;
    if !after.is_empty() {
        return Err(malformed("bytes follow it"));
    }
    let (version, _, body) = tlv(body, 0x02).map_err(malformed)?;
    if version != [1] {
        return Err(malformed("its version is not 1"));
    }
    let (_, signer, body) = tlv(body, 0x30).map_err(malformed)?;
    let (signature, _, body) = tlv(body, 0x04).map_err(malformed)?;
    if !body.is_empty() {
        return Err(malformed("bytes follow its signature"));
    }
    let signature = signature
        .try_into()
        .map_err(|_| malformed("its signature is not 64 bytes"))?;
    Ok(PackageSignature { signer, signature })
}

fn der_len(len: usize, out: &mut Vec<u8>) {
    match len {
        0..=0x7f => out.push(len as u8),
        0x80..=0xff => out.extend([0x81, len as u8]),
        _ => out.extend([0x82, (len >> 8) as u8, len as u8]),
    }
}

/// Writes a `PackageSignature` from a Package Signer's DER certificate and its signature — what
/// the release run's `sign` job writes in hex (ADR-0063 clause 13).
///
/// # Panics
///
/// A certificate too long for the two length octets this format uses (past 65 000 bytes), which
/// no Package Signer's certificate comes near; [`parse_signature`] refuses anything past
/// [`MAX_SIGNATURE_LEN`] in any case.
#[must_use]
pub fn encode_signature(signer: &[u8], signature: &[u8; ED25519_SIGNATURE_LEN]) -> Vec<u8> {
    assert!(
        signer.len() <= 0xffff - 3 - 2 - ED25519_SIGNATURE_LEN,
        "a certificate too long for a PackageSignature"
    );
    let mut body = vec![0x02, 0x01, 0x01];
    body.extend_from_slice(signer);
    body.extend([0x04, ED25519_SIGNATURE_LEN as u8]);
    body.extend_from_slice(signature);
    let mut out = vec![0x30];
    der_len(body.len(), &mut out);
    out.extend(body);
    out
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
}
