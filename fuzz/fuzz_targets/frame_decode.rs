//! A WebSocket frame from a peer: the varint header and the protobuf message behind it, in both
//! directions. Verifies: Q-2
#![no_main]

use libfuzzer_sys::fuzz_target;
use opamp::proto::{AgentToServer, ServerToAgent};

const LIMIT: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    let _ = opamp::frame::decode::<AgentToServer>(data, LIMIT);
    let _ = opamp::frame::decode::<ServerToAgent>(data, LIMIT);
});
