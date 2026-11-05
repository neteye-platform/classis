//! Support shared by the integration tests that start the Client binary.

use std::path::Path;

/// Writes a throwaway self-signed client certificate and key into `dir` and returns the `[tls]`
/// table that names them, to be appended at the end of a `supervisor.toml`.
///
/// The Client refuses to start without a client certificate (ADR-0021). The test Servers serve
/// plaintext with an open admission and do not check it, so the files only have to exist and
/// parse.
pub fn client_identity(dir: &Path) -> String {
    let key = rcgen::KeyPair::generate().expect("generate a key");
    let cert = rcgen::CertificateParams::new(vec!["test-agent".into()])
        .expect("certificate parameters")
        .self_signed(&key)
        .expect("self-sign the certificate");
    let cert_file = dir.join("test-client.pem");
    let key_file = dir.join("test-client-key.pem");
    std::fs::write(&cert_file, cert.pem()).expect("write the client certificate");
    std::fs::write(&key_file, key.serialize_pem()).expect("write the client key");
    format!(
        "\n[tls]\ncert_file = {:?}\nkey_file = {:?}\n",
        cert_file.display().to_string(),
        key_file.display().to_string(),
    )
}

/// The fleet state on `dir` with the Deployments armed, as the binary wires it: the Configuration
/// store under `fleet-configs`, and an empty package store under `packages`, which arms the
/// Deployments that release Configurations and Packages alike (ADR-0034).
#[allow(dead_code)] // each integration-test binary uses a different subset of this support
pub fn fleet_state(dir: &Path) -> fleet_server::fleet::AppState {
    let packages =
        fleet_server::packages::PackageStore::open(dir.join("packages")).expect("package store");
    fleet_server::fleet::AppState::new(dir.join("fleet-configs"))
        .expect("open the configuration store")
        .with_packages(Some(
            fleet_server::fleet::PackageOffering::new(&dir.join("packages"), packages)
                .expect("deployments"),
        ))
}

/// Saves a top-level Configuration for the Agent type `service_name` — content only, distributed
/// to nobody (ADR-0034).
#[allow(dead_code)] // each integration-test binary uses a different subset of this support
pub fn save(state: &fleet_server::fleet::AppState, name: &str, body: &str, service_name: &str) {
    state
        .save_configuration(
            name,
            fleet_server::configs::Revision {
                body: body.to_string(),
                role: String::new(),
                service_name: service_name.to_string(),
            },
        )
        .expect("save the configuration");
}

/// The label [`release_to_every_agent`] puts every Agent it finds into, and the Selector of the
/// Deployment it rolls out.
#[allow(dead_code)] // each integration-test binary uses a different subset of this support
pub const CHANNEL: (&str, &str) = ("channel", "e2e");

/// The Deployment [`release_to_every_agent`] rolls out.
#[allow(dead_code)] // each integration-test binary uses a different subset of this support
pub const FLEET_DEPLOYMENT: &str = "fleet";

/// Aims the Deployment `deployment` at `selector`, puts `configurations` into it beside what it
/// already holds, and rolls it out (ADR-0034) — answering how many Agents the press moved.
#[allow(dead_code)] // each integration-test binary uses a different subset of this support
pub fn release(
    state: &fleet_server::fleet::AppState,
    deployment: &str,
    selector: &[(&str, &str)],
    configurations: &[&str],
) -> usize {
    state
        .deployment_store()
        .expect("deployments are armed")
        .put(
            deployment,
            selector
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
        .expect("aim the deployment");
    for configuration in configurations {
        state
            .put_deployment_configuration(deployment, configuration)
            .expect("hold the configuration");
    }
    state
        .rollout_deployment(deployment)
        .expect("roll the deployment out")
}

/// Releases `configurations` to every Agent the Server knows now, the way an operator does since
/// ADR-0034: each Agent is labelled into the [`CHANNEL`] (beside the labels it has), and the
/// [`FLEET_DEPLOYMENT`] aimed at that channel holds the Configurations and is rolled out. An Agent
/// that appears later waits, as it would for any press.
#[allow(dead_code)] // each integration-test binary uses a different subset of this support
pub fn release_to_every_agent(
    state: &fleet_server::fleet::AppState,
    configurations: &[&str],
) -> usize {
    for agent in state.snapshot() {
        let uid = opamp::uid::InstanceUid::parse(&agent.instance_uid).expect("a uid");
        let mut labels = agent.labels.clone();
        labels.insert(CHANNEL.0.to_string(), CHANNEL.1.to_string());
        assert!(
            state.set_labels(&uid, labels).is_ok(),
            "label {} into the channel",
            agent.instance_uid
        );
    }
    release(state, FLEET_DEPLOYMENT, &[CHANNEL], configurations)
}
