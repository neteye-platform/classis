//! A package signature, as a Client reads it from an offer and the Server from an upload
//! (ADR-0063 clause 3): a bounded, strict-DER `PackageSignature`, then the chain and the signature
//! up to a Root it was never issued by. Verifies: Q-2, ADR-0063
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = classis_core::package::parse_signature(data) {
        assert!(data.len() <= classis_core::package::MAX_SIGNATURE_LEN);
        assert_eq!(
            classis_core::package::encode_signature(parsed.signer, parsed.signature),
            data,
            "a value that parses is the one DER encoding of what it holds"
        );
    }
    let roots = classis_core::package::Roots::from_der([]).expect("no roots");
    assert!(
        classis_core::package::verify_now(b"statement", data, &roots).is_err(),
        "a signature verified up to no Root"
    );
});
