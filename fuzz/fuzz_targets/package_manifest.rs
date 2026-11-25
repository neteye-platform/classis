//! A manifest of a Package Repository, as the Server reads it from a directory or a bucket that
//! another party writes: bounded before anything is held, then a strict document whose name must
//! match the identity it holds. Verifies: Q-2
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let read = classis_server::fs::read_manifest("otelcol@1.0.0.json", &mut &data[..]);
    if let Ok(package) = read {
        assert!(data.len() <= classis_server::fs::MAX_MANIFEST_BYTES);
        assert_eq!(
            package.id.to_string(),
            "otelcol@1.0.0",
            "a manifest that reads holds the identity its name states"
        );
        for entry in package.entries.values() {
            assert!(
                entry.offered_signature().is_none(),
                "a signature read from a manifest is offered only once it verifies"
            );
        }
    }
});
