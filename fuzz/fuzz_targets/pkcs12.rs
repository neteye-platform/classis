//! A `bootstrap.p12` as the Client opens it (ADR-0029 clause 7): a file an operator downloaded
//! from the Server and carried to the host. Verifies: Q-2
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The seed is sealed under this password, so the fuzzer reaches past the MAC.
    if let Ok(identity) = fleet_core::pkcs12::file::open(data, "fuzzing password") {
        assert!(
            data.len() as u64 <= fleet_core::pkcs12::MAX_FILE_BYTES,
            "a file over the bound was opened"
        );
        assert!(!identity.certificate_der.is_empty() && !identity.private_key_der.is_empty());
    }
});
