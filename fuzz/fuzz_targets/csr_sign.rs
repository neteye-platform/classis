//! A certificate signing request from an Agent, signed by the Server's CA. Whatever the request
//! asks for, what comes back is a leaf: never a CA. Verifies: Q-2
#![no_main]

use std::sync::OnceLock;

use fleet_server::ca::ClientCa;
use fleet_server::config::ClientCaConfig;
use libfuzzer_sys::fuzz_target;

fn ca() -> &'static ClientCa {
    static CA: OnceLock<(ClientCa, tempfile::TempDir)> = OnceLock::new();
    &CA.get_or_init(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::new(vec!["fuzz-ca".to_string()]).expect("ca");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("self-sign");
        let cert_file = dir.path().join("ca.pem");
        let key_file = dir.path().join("ca-key.pem");
        std::fs::write(&cert_file, cert.pem()).expect("write");
        std::fs::write(&key_file, key.serialize_pem()).expect("write");
        let ca = ClientCa::from_config(&ClientCaConfig {
            cert_file,
            key_file,
            validity_days: 30,
        })
        .expect("ca");
        (ca, dir)
    })
    .0
}

fuzz_target!(|data: &[u8]| {
    let Ok(csr) = std::str::from_utf8(data) else {
        return;
    };
    // The subject values an approval carries (ADR-0036), so the fuzzed request is signed with
    // a subject of the shape every host certificate has.
    let subject = fleet_server::revocation::SubjectValues {
        organization: "Fuzz Customer".to_string(),
        organizational_unit: "Fuzz Site".to_string(),
        ..fleet_server::revocation::SubjectValues::default()
    };
    if let Ok(issued) = ca().sign(csr, "fuzz-host", &subject) {
        let (_, pem) = x509_parser::pem::parse_x509_pem(issued.pem.as_bytes()).expect("issued PEM");
        let certificate = pem.parse_x509().expect("issued certificate");
        let is_ca = certificate
            .basic_constraints()
            .expect("at most one basicConstraints")
            .is_some_and(|constraints| constraints.value.ca);
        assert!(!is_ca, "a request was signed as a CA");
    }
});
