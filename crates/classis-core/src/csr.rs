//! What a certificate signing request asks for, read with `x509-parser`: the adapter the proofs a
//! CSR carries (ADR-0021 clause 27, ADR-0039) are found through, on the Server and on a Gateway
//! alike.
//!
//! A request arrives as PEM and is decoded once, strictly, by [`der`]: every proof, every claim and
//! the key that is signed are then read from those same bytes. Two PEM readers can pick different
//! blocks out of one input, and a proof read through one would then cover a key the other hands
//! on to be signed.

/// The one PEM label a certificate signing request is taken under.
const LABEL: &str = "CERTIFICATE REQUEST";

/// The DER of a PEM certificate signing request: exactly one `CERTIFICATE REQUEST` block with
/// nothing but whitespace around it and nothing on its boundaries' lines, whose content parses as
/// a request with nothing after it.
///
/// # Errors
/// Returns the `BadRequest` text for anything else — text before or after the block or on a
/// boundary's line, a second block, another label, or content that does not parse.
pub fn der(csr_pem: &[u8]) -> Result<Vec<u8>, String> {
    use x509_parser::prelude::FromDer as _;
    let begin = format!("-----BEGIN {LABEL}-----");
    let end = format!("-----END {LABEL}-----");
    let not_one = || {
        format!(
            "the certificate signing request is not exactly one PEM block labelled {LABEL} with \
             nothing but whitespace around it"
        )
    };
    let text = csr_pem.trim_ascii();
    let body = text
        .strip_prefix(begin.as_bytes())
        .and_then(|rest| rest.strip_suffix(end.as_bytes()))
        .ok_or_else(not_one)?;
    // A line break straight after the BEGIN boundary and straight before the END boundary: no
    // text on either boundary's line.
    let line_break = |b: &u8| matches!(b, b'\n' | b'\r');
    if !body.first().is_some_and(line_break) || !body.last().is_some_and(line_break) {
        return Err(not_one());
    }
    // Base64 and line breaks only: no second boundary, no header, no other text.
    if !body.iter().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=') || b.is_ascii_whitespace()
    }) {
        return Err(not_one());
    }
    let unparsed = || "the certificate signing request does not parse".to_string();
    let (rest, block) = x509_parser::pem::parse_x509_pem(text).map_err(|_| unparsed())?;
    if block.label != LABEL || !rest.trim_ascii().is_empty() {
        return Err(not_one());
    }
    match x509_parser::certification_request::X509CertificationRequest::from_der(&block.contents) {
        Ok(([], _)) => Ok(block.contents),
        _ => Err(unparsed()),
    }
}

/// The text after `prefix` of the first SAN URI a certificate signing request (DER, from [`der`])
/// asks for that starts with it, or `None` when it asks for none. Nothing is verified: this reads
/// what a request carries.
///
/// # Errors
/// Returns an error when the request does not parse.
pub fn requested_uri(csr_der: &[u8], prefix: &str) -> Result<Option<String>, String> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::FromDer as _;
    let (_, request) =
        x509_parser::certification_request::X509CertificationRequest::from_der(csr_der)
            .map_err(|_| "the certificate signing request does not parse".to_string())?;
    Ok(request.requested_extensions().and_then(|mut extensions| {
        extensions.find_map(|extension| match extension {
            ParsedExtension::SubjectAlternativeName(san) => {
                san.general_names.iter().find_map(|name| match name {
                    GeneralName::URI(uri) => uri.strip_prefix(prefix).map(str::to_string),
                    _ => None,
                })
            }
            _ => None,
        })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap_proof::URI_PREFIX;

    fn csr(uri: &str) -> String {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::new(vec!["edge".to_string()]).expect("params");
        params
            .subject_alt_names
            .push(rcgen::SanType::URI(uri.try_into().expect("uri")));
        params
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("pem")
    }

    /// A request's SAN URI is found by its prefix, and a request without one has none.
    /// Verifies: ADR-0039
    #[test]
    fn a_requested_uri_is_found_by_its_prefix() {
        let csr = der(csr(&format!("{URI_PREFIX}abc")).as_bytes()).expect("one block");
        assert_eq!(requested_uri(&csr, URI_PREFIX), Ok(Some("abc".to_string())));
        assert_eq!(requested_uri(&csr, crate::renewal::URI_PREFIX), Ok(None));
        assert!(requested_uri(b"not der", URI_PREFIX).is_err());
    }

    /// One block with whitespace around it is read; text before or after it or on a boundary's
    /// line, a second block, another label, a header, and content that is no request are refused — what makes every
    /// reader of a request read the same one (ADR-0021 clause 27, ADR-0039).
    /// Verifies: ADR-0021
    /// Verifies: ADR-0039
    #[test]
    fn a_request_is_exactly_one_pem_block() {
        let one = csr("urn:example:one");
        let other = csr("urn:example:other");
        assert!(der(one.as_bytes()).is_ok());
        assert!(der(format!("\n  {one}\r\n\n").as_bytes()).is_ok());
        assert!(der(one.replace('\n', "\r\n").as_bytes()).is_ok());
        let begin = "-----BEGIN CERTIFICATE REQUEST-----";
        let end = "-----END CERTIFICATE REQUEST-----";
        let certificate = one.replace("CERTIFICATE REQUEST", "CERTIFICATE");
        let header = one.replacen("-----\n", "-----\nProc-Type: 4,ENCRYPTED\n\n", 1);
        for refused in [
            format!("x{one}"),
            format!("x{one}{other}"),
            format!("{one}{other}"),
            format!("{one}\n{other}"),
            format!("{one}trailing"),
            certificate,
            header,
            one.replacen(begin, &format!("{begin} junk"), 1),
            one.replacen(&format!("{begin}\n"), &format!("{begin}AAAA\n"), 1),
            one.replacen(&format!("\n{end}"), end, 1),
            one.replacen(&format!("\n{end}"), &format!("\n{end} junk"), 1),
            "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----"
                .to_string(),
            "not pem".to_string(),
        ] {
            assert!(der(refused.as_bytes()).is_err(), "{refused}");
        }
    }
}
