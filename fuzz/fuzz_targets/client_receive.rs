//! A reply from a server, decoded and handed to an Agent's protocol state machine — what the
//! client does with whatever a server sends. Verifies: Q-2
#![no_main]

use libfuzzer_sys::fuzz_target;
use opamp::client::protocol::AgentProtocol;
use opamp::proto::ServerToAgent;
use opamp::uid::InstanceUid;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    let Ok(reply) = ServerToAgent::decode(data) else {
        return;
    };
    let mut agent = AgentProtocol::new(InstanceUid([7; 16]), u64::MAX);
    let _ = agent.receive(&reply);
});
