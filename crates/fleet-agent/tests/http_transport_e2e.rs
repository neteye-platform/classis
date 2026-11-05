//! End to end over **plain HTTP polling** (ADR-0013) — the same two things `e2e.rs` and
//! `packages_e2e.rs` prove over a WebSocket: a Configuration rollout is applied, and a signed
//! package is downloaded, verified, swapped and reported `Installed`.
//!
//! Both transports feed the same Agent state machine and differ only in how bytes travel, which
//! is exactly why this file has to exist: every other end-to-end test in this crate dials
//! `ws://`, so the polling loop in `opamp::client::http` — its own loop, its own follow-up order,
//! its own `ReportSink` that discards replies — was reachable by no test at all. A regression
//! there would have been invisible until an operator switched a scheme in `supervisor.toml`.
//!
//! The interval is the one real difference an operator feels, and it is not a defect: the
//! WebSocket Server pushes within seconds, while a poller learns at its next poll —
//! `poll_interval_secs`, 30 by default. These tests set it to 1 so they measure the mechanism
//! rather than the wait.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet_server::fleet::{AgentView, AppState, PackageOffering};
use fleet_server::packages::{PackageStore, Platform};
use ring::signature::{Ed25519KeyPair, KeyPair};

/// Puts a Package into a ring aimed at the Agent type it is built for, and hands back the ring's
/// name. Aim belongs to the Deployment now (ADR-0026): a Package reaches nobody by itself, so a
/// test that wants one delivered has to say which ring the host is in — which is the model.
/// The same, recording the artifact's signature on the ring — where a signature lives since
/// ADR-0026. A Client with `[packages] verification_key` set refuses an unsigned artifact, so the
/// ring is what has to carry it.
fn ring_holding_signed(
    state: &fleet_server::fleet::AppState,
    id: &fleet_server::packages::PackageId,
    signature: Option<(&fleet_server::packages::Platform, Vec<u8>)>,
) -> String {
    let deployments = state.deployment_store().expect("deployments are armed");
    let selector =
        std::collections::BTreeMap::from([("service.name".to_string(), id.agent_type.clone())]);
    deployments.put("stable", selector).expect("ring");
    // `replace`: a ring holds one Package per Agent type, so pointing it at another
    // version is a swap, which is exactly what a test walking through versions is doing.
    deployments
        .put_package("stable", id, true)
        .expect("package into the ring");
    // The signature is the entry's own (ADR-0033).
    if let Some((platform, bytes)) = signature {
        state
            .packages()
            .expect("package delivery")
            .put_signature(id, platform, bytes)
            .expect("signature onto the entry");
    }
    "stable".to_string()
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

fn view<'a>(agents: &'a [AgentView], name: &str) -> Option<&'a AgentView> {
    agents.iter().find(|a| a.service_instance_name == name)
}

fn this_host() -> Platform {
    Platform::new(std::env::consts::OS, std::env::consts::ARCH).expect("this host has a platform")
}

fn stub_program_name() -> String {
    Path::new(env!("CARGO_BIN_EXE_stub_agent"))
        .file_name()
        .expect("file name")
        .to_string_lossy()
        .into_owned()
}

fn stage_owned_program(state_dir: &Path, supervisor: &str, program: &str) {
    let program_dir = state_dir
        .join("supervisors")
        .join(supervisor)
        .join("program");
    std::fs::create_dir_all(&program_dir).expect("create");
    let dest = program_dir.join(program);
    std::fs::copy(env!("CARGO_BIN_EXE_stub_agent"), &dest).expect("stage");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
}

fn spawn_client(config_path: &Path) -> ClientUnderTest {
    ClientUnderTest(
        Command::new(env!("CARGO_BIN_EXE_supervisor"))
            .arg("--config")
            .arg(config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn"),
    )
}

/// A Configuration rollout reaches a poller and is applied — `APPLIED`, in sync, and the managed
/// process restarted on the written file. No Server push is involved: the offer rides the reply to
/// the Client's own next poll, which is the whole of how this transport learns anything.
/// Verifies: ADR-0013, G-1
#[tokio::test]
async fn a_configuration_rollout_reaches_a_polling_client() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(common::fleet_state(dir.path()));
    let app = fleet_server::agent_app(state.clone(), fleet_server::transport::Admission::open());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });

    let state_dir: PathBuf = dir.path().join("client-state");
    let marker = dir.path().join("otelcol-marker");
    let program = stub_program_name();
    let toml = format!(
        concat!(
            "endpoint = \"http://{addr}/v1/opamp\"\n",
            "state_dir = {state:?}\n",
            "poll_interval_secs = 1\n",
            "heartbeat_interval_secs = 1\n\n",
            "[[supervisor]]\n",
            "type = \"collector\"\n",
            "name = \"otelcol\"\n",
            "binary = {program:?}\n",
            "args = [\"--touch\", {marker:?}]\n",
        ),
        addr = addr,
        state = state_dir.to_string_lossy(),
        program = program,
        marker = marker.to_string_lossy(),
    );
    let config_path = dir.path().join("supervisor.toml");
    std::fs::write(&config_path, toml + &common::client_identity(dir.path())).expect("write");
    stage_owned_program(&state_dir, "otelcol", &program);

    let _client = spawn_client(&config_path);

    wait_until("the polling agent to appear", || {
        let s = state.snapshot();
        view(&s, "otelcol").filter(|a| a.connected).map(|_| ())
    })
    .await;

    let agent_type = view(&state.snapshot(), "otelcol")
        .expect("otelcol view")
        .service_name
        .clone();
    common::save(&state, "fleet", "receivers: {}\n", &agent_type);
    common::release_to_every_agent(&state, &["fleet"]);

    wait_until("the polling agent to apply the configuration", || {
        let s = state.snapshot();
        view(&s, "otelcol")
            .filter(|a| a.in_sync && a.remote_config_status == "APPLIED")
            .map(|_| ())
    })
    .await;
    assert!(marker.exists(), "the configuration reached the process");
}

/// A package rollout reaches a poller: offered on a poll, downloaded, verified against its content
/// hash and Ed25519 signature, swapped over the managed binary, and reported `Installed`. The
/// interim `Downloading` reports go out through this transport's `PollSink`, which POSTs each one
/// as an exchange of its own and discards the reply — so this also proves those discarded replies
/// cost the install nothing.
#[tokio::test]
async fn a_package_rollout_reaches_a_polling_client() {
    let artifact = std::fs::read(env!("CARGO_BIN_EXE_stub_agent")).expect("read stub");
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("keypair");
    let public_key_hex = hex::encode(keypair.public_key().as_ref());
    let signature = keypair
        .sign(&fleet_core::package::statement(
            "managed-agent",
            "2.0.0",
            &<sha2::Sha256 as sha2::Digest>::digest(&artifact),
        ))
        .as_ref()
        .to_vec();

    let store_dir = tempfile::tempdir().expect("store dir");
    let store = PackageStore::open(store_dir.path().to_path_buf()).expect("store");
    let set = fleet_server::packages::PackageId::new("managed-agent", "2.0.0").expect("package id");
    store.create(&set).expect("create package");
    store
        .put_entry(&set, &this_host(), artifact.clone())
        .expect("put entry");

    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("configs")
            .with_packages(Some(
                PackageOffering::new(store_dir.path(), store).expect("deployments"),
            )),
    );
    let app = fleet_server::agent_app(state.clone(), fleet_server::transport::Admission::open());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });

    let state_dir = dir.path().join("client-state");
    let program_dir = state_dir.join("supervisors/myagent/program");
    std::fs::create_dir_all(&program_dir).expect("create the program dir");
    let managed = program_dir.join("managed-agent");
    std::fs::copy(env!("CARGO_BIN_EXE_stub_agent"), &managed).expect("copy stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    let marker = dir.path().join("marker");
    let toml = format!(
        concat!(
            "endpoint = \"http://{addr}/v1/opamp\"\n",
            "state_dir = {state:?}\n",
            "poll_interval_secs = 1\n",
            "heartbeat_interval_secs = 1\n\n",
            "[packages]\n",
            "verification_key = \"{key}\"\n\n",
            "[[supervisor]]\n",
            "type = \"command\"\n",
            "name = \"myagent\"\n",
            "apply_grace_secs = 1\n",
            "command = \"managed-agent\"\n",
            "args = [\"--touch\", {marker:?}]\n",
        ),
        addr = addr,
        state = state_dir.to_string_lossy(),
        key = public_key_hex,
        marker = marker.to_string_lossy(),
    );
    let config_path = dir.path().join("supervisor.toml");
    std::fs::write(&config_path, toml + &common::client_identity(dir.path()))
        .expect("write supervisor.toml");

    let _client = spawn_client(&config_path);

    wait_until("the rollout act to reach the agent", || {
        state
            .rollout_deployment(&ring_holding_signed(
                &state,
                &set,
                Some((&this_host(), signature.clone())),
            ))
            .ok()
            .filter(|assigned| *assigned >= 1)
            .map(|_| ())
    })
    .await;
    wait_until("the package to be reported Installed", || {
        let snapshot = state.snapshot();
        let agent = view(&snapshot, "myagent")?;
        // The wire name is the Agent type (ADR-0026 clause 16), and this block states none — so it
        // is the program's file name, `managed-agent`, not the Supervisor's own name `myagent`.
        let package = agent.packages.iter().find(|p| p.name == "managed-agent")?;
        (package.status == "Installed" && package.version == "2.0.0").then_some(())
    })
    .await;
    assert!(marker.exists(), "the swapped binary ran");
}
