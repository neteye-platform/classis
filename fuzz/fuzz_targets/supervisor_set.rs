//! A Supervisor set a Server delivers as a remote configuration (ADR-0017): entries of TOML read
//! for their `[[supervisor]]` blocks, then each block held to what a running configuration that
//! allows every name and argument still refuses. A NUL byte separates one entry from the next, so
//! blocks from several entries meet as they do in a composed config map. Verifies: Q-2
#![no_main]

use std::sync::LazyLock;

use fleet_agent::config::ClientConfig;
use libfuzzer_sys::fuzz_target;
use opamp::proto::{AgentConfigMap, AgentConfigObject, AgentRemoteConfig};

static RUNNING: LazyLock<ClientConfig> = LazyLock::new(|| {
    toml::from_str("[supervisors]\ndelivered_env = [\"*\"]\ndelivered_args = true\n")
        .expect("the running configuration")
});

fuzz_target!(|data: &[u8]| {
    let offer = AgentRemoteConfig {
        config: Some(AgentConfigMap {
            config_map: data
                .split(|byte| *byte == 0)
                .take(8)
                .enumerate()
                .map(|(index, body)| {
                    (
                        format!("entry-{index}"),
                        AgentConfigObject {
                            body: body.to_vec(),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        }),
        config_hash: Vec::new(),
    };
    let Ok((blocks, tables)) = fleet_agent::reconfigure::offered_blocks(&offer) else {
        return;
    };
    assert_eq!(
        blocks.len(),
        tables.len(),
        "every block keeps its verbatim table"
    );
    for block in &blocks {
        let _ = fleet_agent::supervisor::check_delivered_block(&RUNNING, block);
    }
});
