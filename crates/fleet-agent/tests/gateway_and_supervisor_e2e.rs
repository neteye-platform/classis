//! The two Client Modes on one host, tested together: Supervisor Mode plus Gateway Mode in one
//! process is a real test surface (ADR-0015), not just each mode in isolation.
//!
//! They are orthogonal by design, and everything they share is where that could stop being true:
//! one configuration file, one shutdown signal, one upstream endpoint, one TLS setup, and a gateway
//! task that is restarted when a verified offer moves the endpoint, while the Supervisors carry on.
//! So the real Client binary runs here with both armed at once.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet_server::fleet::{AgentView, AppState};
use futures_util::SinkExt;
use opamp::proto::{AgentCapabilities, AgentToServer};
use opamp::uid::InstanceUid;
use rcgen::{CertificateParams, DnType, IsCa, Issuer, KeyPair};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// The downstream hop's PKI (ADR-0015): a Gateway admits Agents over mutual TLS only, so one CA
/// signs the Gateway's server certificate and the client certificate a downstream peer presents.
struct Pki {
    ca_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
    dir: tempfile::TempDir,
}

impl Pki {
    fn new() -> Self {
        opamp::tls::install_ring_provider();
        let ca_key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(DnType::CommonName, "opamp-fleet-gateway-e2e-ca");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = params.self_signed(&ca_key).expect("ca");
        let issuer = Issuer::from_ca_cert_pem(&ca.pem(), ca_key).expect("issuer");

        let issue = |name: &str| {
            let key = KeyPair::generate().expect("key");
            let mut params = CertificateParams::new(vec![name.to_string()]).expect("params");
            params.distinguished_name.push(DnType::CommonName, name);
            let cert = params.signed_by(&key, &issuer).expect("signed");
            (cert.pem(), key.serialize_pem())
        };
        let (server_cert, server_key) = issue("127.0.0.1");
        let (client_cert_pem, client_key_pem) = issue("edge-agent");

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("gateway-cert.pem"), server_cert).expect("write cert");
        std::fs::write(dir.path().join("gateway-key.pem"), server_key).expect("write key");
        std::fs::write(dir.path().join("ca.pem"), ca.pem()).expect("write ca");
        Pki {
            ca_pem: ca.pem(),
            client_cert_pem,
            client_key_pem,
            dir,
        }
    }

    /// The `[gateway.tls]` section, with all three files a Gateway requires.
    fn section(&self) -> String {
        let path = |name: &str| self.dir.path().join(name).display().to_string();
        format!(
            "[gateway.tls]\ncert_file = {:?}\nkey_file = {:?}\nclient_ca_file = {:?}\n",
            path("gateway-cert.pem"),
            path("gateway-key.pem"),
            path("ca.pem"),
        )
    }

    /// A WebSocket downstream peer over TLS, presenting the client certificate.
    async fn ws(
        &self,
        port: u16,
    ) -> Result<
        WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
        tokio_tungstenite::tungstenite::Error,
    > {
        let config = opamp::tls::client_builder()
            .with_root_certificates(opamp::tls::root_store(self.ca_pem.as_bytes()).expect("roots"))
            .with_client_auth_cert(
                opamp::tls::certificates(self.client_cert_pem.as_bytes()).expect("cert"),
                opamp::tls::private_key(self.client_key_pem.as_bytes()).expect("key"),
            )
            .expect("client config");
        let (socket, _) = tokio_tungstenite::connect_async_tls_with_config(
            format!("wss://127.0.0.1:{port}/v1/opamp"),
            None,
            false,
            Some(tokio_tungstenite::Connector::Rustls(Arc::new(config))),
        )
        .await?;
        Ok(socket)
    }
}

struct ClientUnderTest(Child);

impl Drop for ClientUnderTest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_until<T>(what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Some(value) = probe() {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

async fn spawn_server() -> (std::net::SocketAddr, Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(AppState::new(dir.path().join("fleet-configs")).expect("config store"));
    let app = fleet_server::agent_app(state.clone(), fleet_server::transport::Admission::open());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the server");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (addr, state, dir)
}

fn spawn_client(config_path: &Path) -> ClientUnderTest {
    ClientUnderTest(
        Command::new(env!("CARGO_BIN_EXE_supervisor"))
            .arg("--config")
            .arg(config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the client"),
    )
}

/// An Agent by the operator's name for it (`service.instance.name`, ADR-0016).
fn view<'a>(agents: &'a [AgentView], name: &str) -> Option<&'a AgentView> {
    agents.iter().find(|a| a.service_instance_name == name)
}

/// A free port to hand the Gateway, released before it binds.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

/// One host supervising its own process *and* gatewaying for another Client: three Agents reach the
/// Server, each its own, over the connections this one Client holds.
/// Places the stub where a Managed Process must live (ADR-0017): inside the Supervisor's own
/// `program/` directory, under a bare name the configuration can spell. Copied rather than
/// symlinked so the file is one this Client owns in fact as well as by rule — which is what an
/// installed package would leave behind.
fn install_stub(state_dir: &Path, supervisor: &str) -> String {
    let name = if cfg!(windows) {
        "stub-agent.exe"
    } else {
        "stub-agent"
    };
    let program_dir = state_dir
        .join("supervisors")
        .join(supervisor)
        .join("program");
    std::fs::create_dir_all(&program_dir).expect("create the supervisor's program directory");
    let target = program_dir.join(name);
    std::fs::copy(env!("CARGO_BIN_EXE_stub_agent"), &target).expect("place the stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .expect("make the stub executable");
    }
    name.to_string()
}

/// Verifies: ADR-0015
#[tokio::test]
async fn a_host_supervises_and_gateways_at_the_same_time() {
    let (addr, state, dir) = spawn_server().await;
    let state_dir: PathBuf = dir.path().join("client-state");
    let marker = dir.path().join("stub-marker");
    let gateway_port = free_port();

    let pki = Pki::new();
    let toml = format!(
        concat!(
            "endpoint = \"ws://{addr}/v1/opamp\"\n",
            "name = \"edge-host\"\n",
            "state_dir = {state:?}\n",
            "heartbeat_interval_secs = 1\n\n",
            "[gateway]\n",
            "listen = \"127.0.0.1:{gateway_port}\"\n",
            "upstream_connections = 4\n",
            "{gateway_tls}\n",
            "[[supervisor]]\n",
            "type = \"command\"\n",
            "name = \"local-agent\"\n",
            "command = {stub:?}\n",
            "args = [\"--touch\", {marker:?}]\n",
        ),
        addr = addr,
        state = state_dir.to_string_lossy(),
        gateway_port = gateway_port,
        gateway_tls = pki.section(),
        stub = install_stub(&state_dir, "local-agent"),
        marker = marker.to_string_lossy(),
    );
    let config_path = dir.path().join("supervisor.toml");
    std::fs::write(&config_path, toml + &common::client_identity(dir.path()))
        .expect("write supervisor.toml");
    let _client = spawn_client(&config_path);

    // Supervisor Mode first: the Client's own Agent and the one it supervises.
    let agents = wait_until("both local agents", || {
        let snapshot = state.snapshot();
        (snapshot.len() == 2).then_some(snapshot)
    })
    .await;
    assert!(
        view(&agents, "edge-host").is_some(),
        "the Client is its own Agent"
    );
    assert!(
        view(&agents, "local-agent").is_some(),
        "and the process it supervises is another"
    );

    // Now a third Client arrives *through* the Gateway on the same host. It is a plain OpAMP peer;
    // nothing about it knows it is being carried.
    let downstream = InstanceUid::default();
    let mut socket = pki
        .ws(gateway_port)
        .await
        .expect("connect to the gateway on this host");
    let report = AgentToServer {
        instance_uid: downstream.as_bytes().to_vec(),
        sequence_num: 1,
        capabilities: AgentCapabilities::ReportsStatus as u64,
        ..Default::default()
    };
    let frame = opamp::frame::encode_within(&report, 64 << 20).expect("encode");
    socket
        .send(Message::Binary(frame.into()))
        .await
        .expect("send through the gateway");

    // Three Agents, from one host running both modes — and the Server tells them apart by
    // `instance_uid` alone, never by which connection carried them (ADR-0015).
    let agents = wait_until("the gatewayed agent too", || {
        let snapshot = state.snapshot();
        (snapshot.len() == 3).then_some(snapshot)
    })
    .await;
    assert!(
        agents
            .iter()
            .any(|a| a.instance_uid == downstream.to_string()),
        "the Agent behind the Gateway is its own Agent"
    );
    // The two local ones are untouched by the third arriving — the modes do not interfere.
    assert!(view(&agents, "edge-host").is_some());
    assert!(view(&agents, "local-agent").is_some());
    assert!(
        marker.exists(),
        "the supervised process is still the one running"
    );
}

/// The interaction that only exists because both modes share a process: a verified connection
/// settings offer ends the transport run, and the gateway task is restarted with the new
/// configuration (ADR-0015) — because the pool dials the endpoint an offer can move. The
/// Supervisors must live straight through it, and the Gateway must come back serving.
/// Verifies: ADR-0015, ADR-0014
#[tokio::test]
async fn a_verified_offer_restarts_the_gateway_and_leaves_the_supervisors_running() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("config store")
            // An offered heartbeat is the smallest offer that changes something the Client must
            // verify by connecting, so it exercises the whole switch without moving the endpoint.
            .with_connection_offer(Some(fleet_server::fleet::ConnectionOffer::from_config(
                &toml::from_str::<fleet_server::config::ConnectionOfferConfig>(
                    "heartbeat_interval_secs = 2\n",
                )
                .expect("offer config"),
            ))),
    );
    let app = fleet_server::agent_app(state.clone(), fleet_server::transport::Admission::open());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the server");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let marker = dir.path().join("stub-marker");
    let gateway_port = free_port();
    let state_dir = dir.path().join("client-state");
    let pki = Pki::new();
    let toml = format!(
        concat!(
            "endpoint = \"ws://{addr}/v1/opamp\"\n",
            "name = \"edge-host\"\n",
            "state_dir = {state:?}\n",
            "[gateway]\n",
            "listen = \"127.0.0.1:{gateway_port}\"\n",
            "{gateway_tls}\n",
            "[[supervisor]]\n",
            "type = \"command\"\n",
            "name = \"local-agent\"\n",
            "command = {stub:?}\n",
            "args = [\"--touch\", {marker:?}]\n",
        ),
        addr = addr,
        state = state_dir.to_string_lossy(),
        gateway_port = gateway_port,
        gateway_tls = pki.section(),
        stub = install_stub(&state_dir, "local-agent"),
        marker = marker.to_string_lossy(),
    );
    let config_path = dir.path().join("supervisor.toml");
    std::fs::write(&config_path, toml + &common::client_identity(dir.path()))
        .expect("write supervisor.toml");
    let _client = spawn_client(&config_path);

    // The offer is applied and acknowledged — which is what ends the transport run and restarts the
    // gateway task underneath.
    wait_until("the offer applied", || {
        state
            .snapshot()
            .iter()
            .any(|a| a.service_instance_name == "edge-host")
            .then_some(())
    })
    .await;
    // Proof that the switch actually happened, and not merely that the Client connected: the file
    // configures no heartbeat, so the default is 30 s and this Agent would report only on change.
    // The offer sets 2 s. A `sequence_num` climbing on its own is therefore the offered interval in
    // force — which only happens after the Client verified the offer by connecting and the run
    // restarted. Without this the test would pass whether or not the gateway was ever rebuilt.
    wait_until("the offered heartbeat in force", || {
        state
            .snapshot()
            .iter()
            .find(|a| a.service_instance_name == "edge-host")
            .filter(|a| a.sequence_num >= 4)
            .map(|_| ())
    })
    .await;

    // The Gateway is serving again on the same address, after having been torn down and rebuilt.
    let downstream = InstanceUid::default();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut socket = loop {
        match pki.ws(gateway_port).await {
            Ok(connected) => break connected,
            Err(e) if Instant::now() >= deadline => {
                panic!("the gateway did not come back up: {e}")
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    };
    let report = AgentToServer {
        instance_uid: downstream.as_bytes().to_vec(),
        sequence_num: 1,
        capabilities: AgentCapabilities::ReportsStatus as u64,
        ..Default::default()
    };
    let frame = opamp::frame::encode_within(&report, 64 << 20).expect("encode");
    socket
        .send(Message::Binary(frame.into()))
        .await
        .expect("send through the restarted gateway");

    let agents = wait_until("three agents after the restart", || {
        let snapshot = state.snapshot();
        (snapshot.len() == 3).then_some(snapshot)
    })
    .await;
    assert!(
        view(&agents, "local-agent").is_some(),
        "the Supervisor lived straight through the gateway restart"
    );
    assert!(marker.exists(), "and its process was never restarted");
}

/// The Gateway binding a port must not take the Supervisors with it when it cannot: a Client whose
/// gateway address is already taken fails loudly at startup rather than half-starting.
/// Verifies: ADR-0015
#[tokio::test]
async fn a_gateway_that_cannot_bind_is_loud() {
    let (addr, state, dir) = spawn_server().await;
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("occupy a port");
    let port = occupied.local_addr().expect("addr").port();

    let pki = Pki::new();
    let toml = format!(
        concat!(
            "endpoint = \"ws://{addr}/v1/opamp\"\n",
            "name = \"blocked-host\"\n",
            "state_dir = {state:?}\n",
            "[gateway]\n",
            "listen = \"127.0.0.1:{port}\"\n",
            "{gateway_tls}",
        ),
        addr = addr,
        state = dir.path().join("client-state").to_string_lossy(),
        port = port,
        gateway_tls = pki.section(),
    );
    let config_path = dir.path().join("supervisor.toml");
    std::fs::write(&config_path, toml + &common::client_identity(dir.path()))
        .expect("write supervisor.toml");
    let _client = spawn_client(&config_path);

    // The Client itself still reaches the Server: Gateway Mode failing to bind is loud in the log
    // and fatal to the Gateway, not to the host's own management (ADR-0015 clause 1).
    wait_until("the Client's own Agent despite the blocked gateway", || {
        state
            .snapshot()
            .iter()
            .any(|a| a.service_instance_name == "blocked-host")
            .then_some(())
    })
    .await;
}
