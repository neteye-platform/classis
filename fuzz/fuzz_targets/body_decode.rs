//! A plain-HTTP request body: gzip or identity, bounded after decompression, then decoded as the
//! report it claims to be. The size limit must hold whatever the bytes. Verifies: Q-2
#![no_main]

use libfuzzer_sys::fuzz_target;
use opamp::proto::AgentToServer;
use prost::Message;

const LIMIT: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let encoding = match selector % 3 {
        0 => "gzip",
        1 => "identity",
        _ => "",
    };
    if let Ok(decoded) = opamp::endpoint::decode_body(body, encoding, LIMIT) {
        assert!(decoded.len() <= LIMIT, "decode_body returned more than its limit");
        let _ = AgentToServer::decode(decoded.as_slice());
    }
});
