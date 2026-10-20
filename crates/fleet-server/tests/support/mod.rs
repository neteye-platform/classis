//! Shared scaffolding for the transport integration tests: the real router on an ephemeral port.

use std::net::SocketAddr;
use std::sync::Arc;

use fleet_server::fleet::AppState;
use opamp::proto::{
    any_value, AgentCapabilities, AgentDescription, AgentToServer, AnyValue, KeyValue,
};
use opamp::uid::InstanceUid;

#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub struct TestServer {
    /// The Agent plane (ADR-0013): `/v1/opamp` and the package download.
    pub addr: SocketAddr,
    /// The Operator plane (ADR-0013): the REST API, its docs, and the UI — a second listener, as
    /// in a real deployment, so a test that calls the wrong one finds out.
    pub rest_addr: SocketAddr,
    pub state: Arc<AppState>,
    // Held so the store directories outlive the test. Public so a test binary that wires its own
    // AppState (e.g. package delivery) can hand over the temp dir it kept alive.
    pub _dir: tempfile::TempDir,
}

#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub async fn spawn() -> TestServer {
    spawn_with(None).await
}

/// The same real router with a tightened message size limit, for the tests that drive the
/// Baseline's size rules without moving megabytes around.
#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub async fn spawn_with_limit(limit: usize) -> TestServer {
    spawn_full(None, limit, DEFAULT_STALE_AFTER).await
}

/// The same real router with a tightened staleness budget (ADR-0024), for the tests that need an
/// Agent to fall silent without waiting out the real one.
#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub async fn spawn_with_stale_after(stale_after: std::time::Duration) -> TestServer {
    spawn_full(None, opamp::frame::DEFAULT_MAX_MESSAGE_SIZE, stale_after).await
}

/// The Server's own default, restated here so a scaffolded Server behaves like a real one.
const DEFAULT_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(90);

/// The full shape: an optional connection-settings offer (ADR-0014).
#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub async fn spawn_with(offer: Option<fleet_server::fleet::ConnectionOffer>) -> TestServer {
    spawn_full(
        offer,
        opamp::frame::DEFAULT_MAX_MESSAGE_SIZE,
        DEFAULT_STALE_AFTER,
    )
    .await
}

/// The fleet state on `dir`, wired as the binary wires it: the Configuration store under
/// `fleet-configs`, and an empty package store under `packages`, which arms the Deployments that
/// release Configurations and Packages alike (ADR-0034).
#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub fn state_on(dir: &std::path::Path) -> AppState {
    let packages =
        fleet_server::packages::PackageStore::open(dir.join("packages")).expect("package store");
    AppState::new(dir.join("fleet-configs"))
        .expect("open the configuration store")
        .with_packages(Some(
            fleet_server::fleet::PackageOffering::new(&dir.join("packages"), packages)
                .expect("deployments"),
        ))
}

async fn spawn_full(
    offer: Option<fleet_server::fleet::ConnectionOffer>,
    limit: usize,
    stale_after: std::time::Duration,
) -> TestServer {
    // What main() does at startup: without a process provider, reqwest refuses to build a client.
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(
        state_on(dir.path())
            .with_connection_offer(offer)
            .with_max_message_size(limit)
            .with_stale_after(stale_after),
    );
    let (addr, rest_addr) = serve(state.clone(), fleet_server::transport::Admission::open()).await;
    TestServer {
        addr,
        rest_addr,
        state,
        _dir: dir,
    }
}

/// Serves the two planes on ephemeral ports, exactly as the binary serves them (ADR-0013), and
/// answers with the address of each. The Operator plane is open, as it is without `[rest.auth]`.
#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub async fn serve(
    state: Arc<AppState>,
    admission: fleet_server::transport::Admission,
) -> (SocketAddr, SocketAddr) {
    serve_guarded(state, admission, None).await
}

/// The same two planes, with the Operator plane's credential check active (ADR-0021).
#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub async fn serve_guarded(
    state: Arc<AppState>,
    admission: fleet_server::transport::Admission,
    operator_auth: Option<fleet_server::api::OperatorAuth>,
) -> (SocketAddr, SocketAddr) {
    let agents = fleet_server::agent_app(state.clone(), admission);
    let operators = fleet_server::operator_app(state, operator_auth);
    let agent_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the Agent plane");
    let operator_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("bind the Operator plane");
    let addr = agent_listener.local_addr().expect("local addr");
    let rest_addr = operator_listener.local_addr().expect("local addr");
    // Through `listen::plane`, as the binary serves them (ADR-0013), so the whole suite runs
    // against a Server whose connection setup is bounded the way a real one's is.
    let handle = opamp::server::listen::Handle::new();
    tokio::spawn(
        fleet_server::listen::plane(agent_listener, None, 1024, handle.clone()).serve(agents),
    );
    tokio::spawn(
        fleet_server::listen::plane(operator_listener, None, 1024, handle).serve(operators),
    );
    (addr, rest_addr)
}

/// The Agent type every scaffolded Agent reports as `service.name` (ADR-0016). It is a constant
/// because a type describes a *kind* of Agent: the test fleet is one kind of thing on many hosts,
/// which is also what makes one package able to reach several of them (ADR-0026).
#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub const AGENT_TYPE: &str = "io.opentelemetry.collector";

/// A full status report for one Agent, the way a fresh Client sends it. `name` is the operator's
/// name for it — `service.instance.name` — and is what tells two Agents apart; their *type* is the
/// shared [`AGENT_TYPE`].
#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub fn full_report(uid: &InstanceUid, name: &str, sequence_num: u64) -> AgentToServer {
    AgentToServer {
        instance_uid: uid.as_bytes().to_vec(),
        sequence_num,
        capabilities: AgentCapabilities::ReportsStatus as u64
            | AgentCapabilities::AcceptsRemoteConfig as u64
            | AgentCapabilities::ReportsEffectiveConfig as u64
            | AgentCapabilities::ReportsRemoteConfig as u64,
        agent_description: Some(AgentDescription {
            identifying_attributes: vec![KeyValue {
                key: "service.name".to_string(),
                value: Some(AnyValue {
                    value: Some(any_value::Value::StringValue(AGENT_TYPE.to_string())),
                }),
            }],
            non_identifying_attributes: vec![
                // The operator's name for this Agent (ADR-0016) — what distinguishes it from its
                // neighbours, since `service.name` says only what kind of thing it is.
                KeyValue {
                    key: "service.instance.name".to_string(),
                    value: Some(AnyValue {
                        value: Some(any_value::Value::StringValue(name.to_string())),
                    }),
                },
                KeyValue {
                    key: "os.type".to_string(),
                    value: Some(AnyValue {
                        value: Some(any_value::Value::StringValue("linux".to_string())),
                    }),
                },
                // The other half of the Platform a package is fitted against (ADR-0026). An Agent
                // reporting no `host.arch` fits no artifact at all, which is its own test.
                KeyValue {
                    key: "host.arch".to_string(),
                    value: Some(AnyValue {
                        value: Some(any_value::Value::StringValue("amd64".to_string())),
                    }),
                },
                KeyValue {
                    key: "os.description".to_string(),
                    value: Some(AnyValue {
                        value: Some(any_value::Value::StringValue("Testix 1.0 LTS".to_string())),
                    }),
                },
            ],
        }),
        ..Default::default()
    }
}

/// A compressed follow-up report: identity and sequence number only.
#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub fn compressed_report(uid: &InstanceUid, sequence_num: u64) -> AgentToServer {
    AgentToServer {
        instance_uid: uid.as_bytes().to_vec(),
        sequence_num,
        capabilities: AgentCapabilities::ReportsStatus as u64
            | AgentCapabilities::AcceptsRemoteConfig as u64,
        ..Default::default()
    }
}

/// The Deployment [`distribute`] releases through: it claims every scaffolded Agent, since they all
/// report [`AGENT_TYPE`].
#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub const FLEET_DEPLOYMENT: &str = "fleet";

/// Stores **and rolls out** a Configuration through the REST API v1, the way an operator (or
/// portal) does (ADR-0034): the Configuration is saved, held by the [`FLEET_DEPLOYMENT`] that
/// claims the whole scaffolded fleet, and that Deployment is rolled out — saving alone distributes
/// nothing (ADR-0025).
#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub async fn distribute(rest_addr: SocketAddr, name: &str, body: &str) {
    distribute_with_role(rest_addr, name, body, "").await;
}

/// [`distribute`] with the Baseline's `AgentConfigObject.role` set (ADR-0023); an empty role is the
/// ordinary top-level configuration and stays out of the request.
#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub async fn distribute_with_role(rest_addr: SocketAddr, name: &str, body: &str, role: &str) {
    save_configuration(rest_addr, name, body, role).await;
    deploy(
        rest_addr,
        FLEET_DEPLOYMENT,
        &[("service.name", AGENT_TYPE)],
        &[name],
    )
    .await;
}

/// Saves a Configuration for [`AGENT_TYPE`] through the REST API — content only, distributed to
/// nobody.
#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub async fn save_configuration(rest_addr: SocketAddr, name: &str, body: &str, role: &str) {
    let mut spec = serde_json::json!({ "body": body, "service_name": AGENT_TYPE });
    if !role.is_empty() {
        spec["role"] = role.into();
    }
    let response = reqwest::Client::new()
        .put(format!("http://{rest_addr}/api/v1/configurations/{name}"))
        .json(&spec)
        .send()
        .await
        .expect("put the configuration");
    assert_eq!(response.status(), 200, "the configuration is accepted");
}

/// Aims the Deployment `name` at `selector`, puts `configurations` into it beside what it already
/// holds, and rolls it out through the REST API (ADR-0034).
#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub async fn deploy(
    rest_addr: SocketAddr,
    name: &str,
    selector: &[(&str, &str)],
    configurations: &[&str],
) {
    let client = reqwest::Client::new();
    let selector: std::collections::BTreeMap<&str, &str> = selector.iter().copied().collect();
    let response = client
        .put(format!("http://{rest_addr}/api/v1/deployments/{name}"))
        .json(&serde_json::json!({ "selector": selector }))
        .send()
        .await
        .expect("put the deployment");
    assert_eq!(response.status(), 200, "the deployment is accepted");
    for configuration in configurations {
        let response = client
            .put(format!(
                "http://{rest_addr}/api/v1/deployments/{name}/configurations/{configuration}"
            ))
            .send()
            .await
            .expect("hold the configuration");
        assert_eq!(
            response.status(),
            200,
            "the deployment holds {configuration}"
        );
    }
    let response = client
        .post(format!(
            "http://{rest_addr}/api/v1/deployments/{name}/rollout"
        ))
        .send()
        .await
        .expect("roll out the deployment");
    assert_eq!(response.status(), 200, "the deployment is rolled out");
}

/// A clock a test moves by hand, so a rate limit refills when the test says (ADR-0013).
#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub struct ManualClock(pub std::sync::atomic::AtomicU64);

impl fleet_server::fleet::Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
impl ManualClock {
    pub fn new() -> Arc<Self> {
        Arc::new(ManualClock(std::sync::atomic::AtomicU64::new(1_000_000)))
    }

    pub fn advance(&self, by: std::time::Duration) {
        self.0.fetch_add(
            u64::try_from(by.as_millis()).expect("millis"),
            std::sync::atomic::Ordering::SeqCst,
        );
    }
}

/// The same real router with the Agent plane's rate limit armed (ADR-0013), its buckets on a clock
/// the test moves.
#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub async fn spawn_with_agent_rate(
    limits: fleet_server::agent_rate::Limits,
) -> (TestServer, Arc<ManualClock>) {
    opamp::tls::install_ring_provider();
    let clock = ManualClock::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(state_on(dir.path()).with_agent_rate(Some(Arc::new(
        fleet_server::agent_rate::AgentRate::new(limits, 100, clock.clone()),
    ))));
    let (addr, rest_addr) = serve(state.clone(), fleet_server::transport::Admission::open()).await;
    (
        TestServer {
            addr,
            rest_addr,
            state,
            _dir: dir,
        },
        clock,
    )
}

/// The same real router with own-telemetry destinations to offer (ADR-0016).
#[allow(dead_code)] // each integration-test binary uses a different subset of this scaffolding
pub async fn spawn_with_telemetry(offer: fleet_server::fleet::TelemetryOffer) -> TestServer {
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(state_on(dir.path()).with_telemetry_offer(offer));
    let (addr, rest_addr) = serve(state.clone(), fleet_server::transport::Admission::open()).await;
    TestServer {
        addr,
        rest_addr,
        state,
        _dir: dir,
    }
}
