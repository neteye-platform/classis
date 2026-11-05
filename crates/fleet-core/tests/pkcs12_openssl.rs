//! The bootstrap PKCS#12 file against the tool operators already have (ADR-0029): a file OpenSSL 3
//! writes with its defaults opens, and one it writes with `-legacy` — RC2 and 3DES — is refused,
//! since the legacy schemes are not compiled in. Both were written by OpenSSL 3.0 under the
//! password below, the first with `openssl pkcs12 -export -iter 1000 -maciter -macalg sha256`, the
//! second with `openssl pkcs12 -export -legacy`.

use fleet_core::pkcs12::file::{open, OpenError};

const PASSWORD: &str = "fuzzing password";

/// Verifies: ADR-0029
#[test]
fn a_file_openssl_3_writes_by_default_opens_and_a_legacy_one_is_refused() {
    let current = include_bytes!("data/openssl-3-bootstrap.p12");
    let opened = open(current, PASSWORD).expect("OpenSSL 3's defaults open");
    let (_, certificate) =
        x509_parser::parse_x509_certificate(&opened.certificate_der).expect("a certificate");
    assert_eq!(
        certificate.subject().to_string(),
        "CN=fuzz bootstrap Certificate"
    );
    assert_eq!(
        open(current, "not the password"),
        Err(OpenError::WrongPassword)
    );

    let legacy = include_bytes!("data/openssl-3-legacy-bootstrap.p12");
    assert!(
        matches!(open(legacy, PASSWORD), Err(OpenError::Invalid(_))),
        "RC2 and 3DES are not read"
    );
}
