//! The renewal proof a CSR carries (ADR-0021 clause 27), as the Server decodes it from a SAN a
//! peer chose. What decodes encodes back to the same bytes. Verifies: Q-2
#![no_main]

use fleet_core::renewal;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some((certificate, signature)) = renewal::decode(data) {
        assert!(!certificate.is_empty() && !signature.is_empty());
        assert_eq!(renewal::encode(certificate, signature), data);
    }
});
