//! Package delivery end to end (ADR-0026): the real Server armed with a package store,
//! the real Client binary running a `command` Supervisor that consents to package updates — which
//! artifact it gets is the Server's choice, not this configuration's. The Client downloads the
//! offered artifact, verifies its content hash and Ed25519 signature, swaps it over the managed
//! binary, health-gates the restart, and reports `Installed` — visible in the fleet view.

mod common;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet_server::fleet::{AgentView, AppState, PackageOffering};
use fleet_server::packages::{PackageStore, Platform};
use ring::signature::{Ed25519KeyPair, KeyPair};

/// Puts a Package into a ring aimed at the Agent type it is built for, with the artifact's signature
/// on the ring — where a signature lives (ADR-0026) — and hands back the ring's name. A Package
/// reaches nobody by itself, so a test that wants one delivered has to say which ring the host is
/// in, and a Client installs nothing unsigned (ADR-0026).
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

/// The Platform this test's Client will report about itself (ADR-0026) — an artifact stored for
/// any other one would not fit it, and would rightly never be offered. `std::env::consts` is the
/// same source the Client reports from, and the store canonicalises both the same way.
fn this_host() -> Platform {
    Platform::new(std::env::consts::OS, std::env::consts::ARCH).expect("this host has a platform")
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

async fn spawn_server(
    store: PackageStore,
) -> (std::net::SocketAddr, Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("configs")
            .with_packages(Some(
                PackageOffering::new(dir.path(), store).expect("deployments"),
            )),
    );
    let app = fleet_server::agent_app(state.clone(), fleet_server::transport::Admission::open());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
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

/// Finds an Agent by the operator's name for it — `service.instance.name` (ADR-0016), which is the
/// `[[supervisor]]` block's `name`. The block below is deliberately named something other than its
/// program, so looking up by `service.name` would find nothing: that attribute is the Agent type,
/// and with no `service_name` set it falls back to the program's file name.
fn view<'a>(agents: &'a [AgentView], name: &str) -> Option<&'a AgentView> {
    agents.iter().find(|a| a.service_instance_name == name)
}

/// Verifies: ADR-0026, G-10
#[tokio::test]
async fn a_signed_package_is_downloaded_verified_swapped_and_reported_installed() {
    // The artifact is the stub binary itself — a real executable that stays up when swapped in.
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
    // The Set's identity states the Agent type it is built for (ADR-0026): the
    // Supervisor below names its program `managed-agent` and sets no `service_name`, so that file
    // name is the type it reports.
    let set = fleet_server::packages::PackageId::new("managed-agent", "2.0.0").expect("package id");
    store.create(&set).expect("create package");
    store
        .put_entry(&set, &this_host(), artifact.clone())
        .expect("put entry");

    let (addr, state, dir) = spawn_server(store).await;

    // The managed binary starts as a copy of the stub, in the Supervisor's own `program/`
    // directory — which is what a bare `command` names, and what consents to the update
    // (ADR-0017). The package swap replaces it there.
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
            "endpoint = \"ws://{addr}/v1/opamp\"\n",
            "state_dir = {state:?}\n",
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

    // A saved Set reaches nobody (ADR-0025): the rollout act releases it, retried until the
    // Agent has reported and can be assigned — which is the decision, not an accident of the
    // test.
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

    // The Agent connects, is offered the package, downloads and verifies it, swaps the binary,
    // and reports Installed at the offered version.
    wait_until("the package to be reported Installed", || {
        let snapshot = state.snapshot();
        let agent = view(&snapshot, "myagent")?;
        // The wire name is the Agent type (ADR-0026 clause 16) — the program's file name here, since
        // the block states no `service_name`, not the Supervisor's own name `myagent`.
        let package = agent.packages.iter().find(|p| p.name == "managed-agent")?;
        (package.status == "Installed" && package.version == "2.0.0").then_some(())
    })
    .await;

    // Name and type are the two things this block states separately, and they differ here: the
    // operator called the Supervisor `myagent`, its program is `managed-agent`, and with no
    // `service_name` set the program's file name is what the Agent reports as its type (ADR-0016).
    let agent = view(&state.snapshot(), "myagent")
        .expect("the agent is found by the operator's name for it")
        .service_name
        .clone();
    assert_eq!(agent, "managed-agent");

    // The managed process ran the swapped-in binary (the marker exists) and the persisted record
    // survives — a restart is not re-offered the same package.
    assert!(marker.exists(), "the swapped binary ran");
    assert!(state_dir
        .join("supervisors/myagent/installed-package.json")
        .exists());
}

/// ADR-0017 clause 57's preflight, reached through the `command` kind's own configuration: `version_args`
/// is the arguments an operator has declared safe to invoke the program with, so they are also
/// what proves a *staged* program runs before the running one is stopped.
///
/// The stub is asked to exit non-zero on them — what a binary this host's libc cannot satisfy
/// does, with the dynamic linker's message in place of the stub's silence. The package must be
/// refused with that message and nothing may be recorded as installed. Without the wiring the
/// swap itself would be the first thing to try the new binary, and this would report `Installed`.
#[tokio::test]
async fn a_package_that_fails_the_configured_version_check_is_refused() {
    let artifact = std::fs::read(env!("CARGO_BIN_EXE_stub_agent")).expect("read stub");
    // Signed, as everything a Client installs is (ADR-0026): the refusal under test is the version
    // check's, not the signature policy's.
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
        .put_entry(&set, &this_host(), artifact)
        .expect("put entry");

    let (addr, state, dir) = spawn_server(store).await;

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
    // `--exit-code 1` is both the version check and the refusal: the same arguments the probe
    // already runs after every swap, failing the way an unrunnable build fails. The supervised
    // process itself is started with `--touch` and is untouched by any of it.
    let toml = format!(
        concat!(
            "endpoint = \"ws://{addr}/v1/opamp\"\n",
            "state_dir = {state:?}\n",
            "heartbeat_interval_secs = 1\n\n",
            "[packages]\n",
            "verification_key = \"{key}\"\n\n",
            "[[supervisor]]\n",
            "type = \"command\"\n",
            "name = \"myagent\"\n",
            "apply_grace_secs = 1\n",
            "command = \"managed-agent\"\n",
            "args = [\"--touch\", {marker:?}]\n",
            "version_args = [\"--exit-code\", \"1\"]\n",
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

    let error = wait_until("the package to be reported InstallFailed", || {
        let snapshot = state.snapshot();
        let agent = view(&snapshot, "myagent")?;
        // The wire name is the Agent type (ADR-0026 clause 16) — the program's file name here, since
        // the block states no `service_name`, not the Supervisor's own name `myagent`.
        let package = agent.packages.iter().find(|p| p.name == "managed-agent")?;
        (package.status == "InstallFailed").then(|| package.error.clone())
    })
    .await;

    // The refusal carries what the program said rather than an exit status: a real one names the
    // library or the symbol version, which is the whole reason the check runs the program at all.
    assert!(
        error.contains("does not run on this host"),
        "the refusal names the preflight: {error:?}"
    );

    // Nothing was installed, and the process the operator configured ran throughout.
    assert!(
        !state_dir
            .join("supervisors/myagent/installed-package.json")
            .exists(),
        "a refused package records no installation"
    );
    assert!(marker.exists(), "the configured process kept running");
}
