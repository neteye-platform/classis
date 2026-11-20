//! Support shared by the integration tests that start the Client binary.

use std::path::Path;

/// The Space every host of these tests enrols in.
#[allow(dead_code)] // each integration-test binary uses a different subset of this support
pub const SPACE: &str = "lab";

/// The host of the `state.json` [`write_state_json`] writes, and the host [`app`] admits every
/// request as.
#[allow(dead_code)] // each integration-test binary uses a different subset of this support
pub const DEVICE_ID: &str = "0193a6f0-0000-7000-8000-000000000000";

/// What admits the hosts of a test to the Server under test (ADR-0064): a real
/// [`Enrolment`](classis_server::enrolment::Enrolment) over a Space of its own, behind the Agent
/// plane exactly as the binary builds it. A test serves its Agent plane through [`app`](Self::app),
/// and gives the Client a `state.json` with a token this Server issued through [`enrol`](Self::enrol)
/// — the real `enrol`, over the loopback in plaintext.
#[derive(Clone)]
#[allow(dead_code)] // each integration-test binary uses a different subset of this support
pub struct Admission {
    pub enrolment: std::sync::Arc<classis_server::enrolment::Enrolment>,
    /// The Space's enrolment key.
    pub key: String,
}

/// No service is registered for a test's state directory, whatever the machine has.
#[allow(dead_code)] // each integration-test binary uses a different subset of this support
pub struct NoService;

impl classis_agent::enrolment::ServiceHost for NoService {
    fn registered(&self, _: &Path) -> Result<Option<classis_agent::enrolment::Installed>, String> {
        Ok(None)
    }
}

#[allow(dead_code)] // each integration-test binary uses a different subset of this support
impl Admission {
    /// An Enrolment over a data directory made under `dir`, with the Space [`SPACE`] and tokens
    /// that never expire.
    pub fn new(dir: &Path) -> Admission {
        opamp::tls::install_ring_provider();
        let data = dir.join("admission");
        classis_server::fs::open_data_dir(&data, true).expect("the data directory");
        let records = classis_server::Records::Files(data);
        let clock = std::sync::Arc::new(classis_server::clock::SystemClock);
        // No back-off: a test of a refusal is not to be answered with a wait.
        let limits = classis_server::throttle::Limits {
            max_failures: u32::MAX,
            ..classis_server::throttle::Limits::default()
        };
        let enrolment = classis_server::enrolment::Enrolment::on(
            &records,
            oauth_token::server::Lifetime::Never,
            clock.clone(),
            std::sync::Arc::new(classis_server::throttle::Throttle::new(limits, clock)),
        )
        .expect("the enrolment");
        let key = enrolment
            .spaces()
            .create(SPACE)
            .expect("a space")
            .to_string();
        Admission {
            enrolment: std::sync::Arc::new(enrolment),
            key,
        }
    }

    /// The Agent plane over `state`, admitting by this Enrolment alone.
    pub fn app(&self, state: std::sync::Arc<classis_server::fleet::AppState>) -> axum::Router {
        classis_server::agent_app(state, self.enrolment.clone())
    }

    /// Enrols a host at the Agent plane on `addr`, through the real `enrol`: `state.json` is
    /// written in `state_dir`.
    pub async fn enrol(
        &self,
        addr: std::net::SocketAddr,
        state_dir: &Path,
    ) -> classis_agent::enrolment::Enrolled {
        classis_agent::enrolment::enrol(
            &format!("http://{addr}"),
            &self.key,
            state_dir,
            opamp::client::ClientTls::default(),
            &NoService,
        )
        .await
        .expect("enrol the host")
    }
}

/// The Agent plane over `state`, as these tests serve it to a Client whose admission is not what
/// they test: every request arrives as [`DEVICE_ID`], the host of the `state.json` that
/// [`client_identity`] writes, and no token is checked. A test about admission serves the plane
/// through [`Admission::app`] instead. The certificate cleanup moves these tests to it as well.
#[allow(dead_code)] // each integration-test binary uses a different subset of this support
pub fn app(state: std::sync::Arc<classis_server::fleet::AppState>) -> axum::Router {
    classis_server::agent_app_admitted_as_for_tests(state, Some(DEVICE_ID))
}

/// What a host needs to start against these tests' Servers, for a Client whose state directory is
/// `state_dir`: a `state.json` in `state_dir` from [`write_state_json`], which the Client starts
/// with, and the [`client_certificate`] in `dir`, whose `[tls]` table is returned to be appended
/// at the end of a `supervisor.toml` and which the Client ignores (ADR-0064).
#[allow(dead_code)] // each integration-test binary uses a different subset of this support
pub fn client_identity(dir: &Path, state_dir: &Path) -> String {
    let tls = client_certificate(dir);
    write_state_json(state_dir, "http://127.0.0.1:9");
    tls
}

/// Writes a `state.json` for a host whose Server is not one of these tests' Servers — a stub that
/// checks no token — with a token nobody issued.
#[allow(dead_code)] // each integration-test binary uses a different subset of this support
pub fn write_state_json(state_dir: &Path, base_url: &str) {
    std::fs::create_dir_all(state_dir).expect("the state directory");
    let state = serde_json::json!({
        "endpoint": base_url,
        "space": SPACE,
        "device_id": DEVICE_ID,
        "client_secret": "a-client-secret-nobody-issued",
        "access_token": "a-token-nobody-issued",
    });
    std::fs::write(
        state_dir.join("state.json"),
        serde_json::to_vec_pretty(&state).expect("json"),
    )
    .expect("write state.json");
}

/// Writes a throwaway self-signed client certificate and key into `dir` and returns the `[tls]`
/// table that names them, to be appended at the end of a `supervisor.toml`.
///
/// A file of the certificate era: the Client still parses `[tls] cert_file` and `key_file` and
/// ignores both (ADR-0064), and presents no certificate. Kept until the certificate cleanup.
#[allow(dead_code)] // each integration-test binary uses a different subset of this support
pub fn client_certificate(dir: &Path) -> String {
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
pub fn fleet_state(dir: &Path) -> classis_server::fleet::AppState {
    let packages =
        classis_server::packages::PackageStore::open(dir.join("packages")).expect("package store");
    classis_server::fleet::AppState::new(dir.join("fleet-configs"))
        .expect("open the configuration store")
        .with_packages(Some(
            classis_server::fleet::PackageOffering::new(&dir.join("packages"), packages)
                .expect("deployments"),
        ))
}

/// Saves a top-level Configuration for the Agent type `service_name` — content only, distributed
/// to nobody (ADR-0034).
#[allow(dead_code)] // each integration-test binary uses a different subset of this support
pub fn save(state: &classis_server::fleet::AppState, name: &str, body: &str, service_name: &str) {
    state
        .save_configuration(
            name,
            classis_server::configs::Revision {
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
    state: &classis_server::fleet::AppState,
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
    state: &classis_server::fleet::AppState,
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
