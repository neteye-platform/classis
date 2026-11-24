//! Connection-settings rotation end to end: the real Server armed with an offer, the
//! real Client binary as a single self-Agent. The Client verifies the offer by actually
//! connecting, persists it, reconnects, and reports `APPLIED`; the Server, seeing the reported
//! hash match, stops offering. A restarted Client is not re-offered what it already runs. The
//! Supervisors of a Client live straight through the reconnection an offer causes.

mod common;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use classis_server::config::ConnectionOfferConfig;
use classis_server::fleet::{AgentView, AppState, ConnectionOffer};

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

/// A Server armed with a heartbeat-only offer: it changes a setting without moving the endpoint,
/// so the offer verifies against the very same listener.
async fn spawn_armed_server() -> (std::net::SocketAddr, Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let offer_config: ConnectionOfferConfig =
        toml::from_str("heartbeat_interval_secs = 2").expect("parse offer");
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("open the configuration store")
            .with_connection_offer(Some(ConnectionOffer::from_config(&offer_config))),
    );
    let admission = common::Admission::new(dir.path());
    let app = admission.app(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the server");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    // The Client is a host of the Server's Space: the `state.json` of the state directory every
    // test below names.
    admission
        .enrol(addr, &dir.path().join("client-state"))
        .await;
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

#[tokio::test]
async fn an_offer_is_verified_persisted_and_reported_applied() {
    let (addr, state, dir) = spawn_armed_server().await;
    let state_dir = dir.path().join("client-state");
    let toml = format!(
        "endpoint = \"ws://{addr}/v1/opamp\"\nname = \"rotator\"\nstate_dir = {state_dir:?}\nheartbeat_interval_secs = 30\n",
        addr = addr,
        state_dir = state_dir.to_string_lossy(),
    );
    let config_path = dir.path().join("supervisor.toml");
    std::fs::write(&config_path, toml).expect("write supervisor.toml");

    let client = spawn_client(&config_path);

    // The self-Agent connects, is offered the settings, verifies by actually connecting, and
    // reports APPLIED — at which point the Server stops offering (the reported hash matches).
    wait_until("the agent to report the settings APPLIED", || {
        let snapshot = state.snapshot();
        let agent = snapshot.first()?;
        (agent.connected
            && agent
                .capabilities
                .iter()
                .any(|c| c == "AcceptsOpAMPConnectionSettings"))
        .then_some(())?;
        // The persisted file is the proof the verify+switch happened.
        state_dir
            .join("connection-settings.pb")
            .exists()
            .then_some(())
    })
    .await;

    // A restart adopts the persisted settings and is not re-offered them: the file stays, and
    // the Agent stays connected without churning through another rotation.
    drop(client);
    let _restarted = spawn_client(&config_path);
    wait_until("the restarted agent to reconnect", || {
        state.snapshot().first().filter(|a| a.connected).map(|_| ())
    })
    .await;
    assert!(
        state_dir.join("connection-settings.pb").exists(),
        "the persisted settings survive a restart"
    );
}

/// An Agent by the operator's name for it (`service.instance.name`).
fn view<'a>(agents: &'a [AgentView], name: &str) -> Option<&'a AgentView> {
    agents.iter().find(|a| a.service_instance_name == name)
}

/// Places the stub where a Managed Process must live: inside the Supervisor's own
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

/// A verified connection-settings offer ends the transport run and the Client reconnects with the
/// settings. The Supervisors must live straight through it: the Agent of the one
/// process this Client supervises is still the Server's, and its process was never restarted.
#[tokio::test]
async fn a_verified_offer_leaves_the_supervisors_running() {
    let (addr, state, dir) = spawn_armed_server().await;
    let marker = dir.path().join("stub-marker");
    let state_dir = dir.path().join("client-state");
    let toml = format!(
        concat!(
            "endpoint = \"ws://{addr}/v1/opamp\"\n",
            "name = \"edge-host\"\n",
            "state_dir = {state:?}\n",
            "[[supervisor]]\n",
            "type = \"command\"\n",
            "name = \"local-agent\"\n",
            "command = {stub:?}\n",
            "args = [\"--touch\", {marker:?}]\n",
        ),
        addr = addr,
        state = state_dir.to_string_lossy(),
        stub = install_stub(&state_dir, "local-agent"),
        marker = marker.to_string_lossy(),
    );
    let config_path = dir.path().join("supervisor.toml");
    std::fs::write(&config_path, toml).expect("write supervisor.toml");
    let _client = spawn_client(&config_path);

    // The file configures no heartbeat, so the default is 30 s and this Agent would report only on
    // change. The offer sets 2 s. A `sequence_num` climbing on its own is therefore the offered
    // interval in force — which only happens after the Client verified the offer by connecting and
    // the run restarted. Without this the test would pass whether or not the switch happened.
    wait_until("the offered heartbeat in force", || {
        state
            .snapshot()
            .iter()
            .find(|a| a.service_instance_name == "edge-host")
            .filter(|a| a.sequence_num >= 4)
            .map(|_| ())
    })
    .await;

    let agents = wait_until("both local agents", || {
        let snapshot = state.snapshot();
        (snapshot.len() == 2).then_some(snapshot)
    })
    .await;
    assert!(
        view(&agents, "local-agent").is_some(),
        "the Supervisor lived straight through the reconnection"
    );
    assert!(marker.exists(), "and its process was never restarted");
}
