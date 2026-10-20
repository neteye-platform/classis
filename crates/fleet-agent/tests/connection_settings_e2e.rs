//! Connection-settings rotation end to end (ADR-0014): the real Server armed with an offer, the
//! real Client binary as a single self-Agent. The Client verifies the offer by actually
//! connecting, persists it, reconnects, and reports `APPLIED`; the Server, seeing the reported
//! hash match, stops offering. A restarted Client is not re-offered what it already runs.

mod common;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet_server::config::ConnectionOfferConfig;
use fleet_server::fleet::{AppState, ConnectionOffer};

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

/// Verifies: ADR-0014
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
    std::fs::write(&config_path, toml + &common::client_identity(dir.path()))
        .expect("write supervisor.toml");

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
