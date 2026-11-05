//! A trust file, a certificate or a key, as the TLS material of either end reads it. Verifies: Q-2
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(roots) = opamp::tls::root_store(data) {
        assert!(!roots.is_empty(), "an empty trust store was accepted");
    }
    let _ = opamp::tls::private_key(data);
});
