//! The revoked certificates a Gateway fetches from its Server (ADR-0015, ADR-0021): a JSON body
//! the Gateway refuses its downstream peers by. Verifies: Q-2
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fleet_agent::gateway::revocations::parse_list(data);
});
