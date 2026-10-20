//! The Client updating itself, end to end (ADR-0018, ADR-0019) — the one path in this project
//! whose failure takes a host out of the fleet's reach for good, and the only major feature that
//! had no test across the process boundary.
//!
//! Everything real except the service manager: the real Server armed with a package store, the
//! real Client binary running from a real ADR-0019 install layout, installing a real artifact over
//! itself. The restart the Client asks for by exiting is performed *here* — that is precisely the
//! step no CI can delegate to systemd, launchd, or the SCM, and standing in for it is what makes
//! the rest observable.
//!
//! The contract under test is the fleet's, not the mechanism's: whatever number of restarts it
//! takes, the Server must end up being told the new version is `Installed`. Asserting the step
//! count instead would freeze an implementation detail that ADR-0018 deliberately leaves open.
//!
//! Runs on all three platforms, because the pointer is the part of ADR-0019 that differs between
//! them — a symlink on Unix, a junction on Windows — and it is precisely what a self-update moves
//! while the Client is running through it. A test that only ever moved the symlink would leave the
//! platform whose mechanism is the unusual one entirely unasserted.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet_server::fleet::{AgentView, AppState, PackageOffering};
use fleet_server::packages::{PackageStore, Platform};

/// The Platform this test's Client will report about itself (ADR-0026) — the Server offers only
/// the artifact that fits the machine, so a self-update test has to store one for this one.
fn this_host() -> Platform {
    Platform::new(std::env::consts::OS, std::env::consts::ARCH).expect("this host has a platform")
}

// What the Client exits with to ask its service manager for a restart, and its file name inside a
// version directory. Imported rather than restated (ADR-0010 clause 21): a copied constant is a
// correctness risk that no comment can remove.
use fleet_agent::service::layout::BINARY_FILENAME as CLIENT_BINARY;
use fleet_agent::update::EXIT_RESTART_FOR_UPDATE;

/// The operator's signing key for these tests, and its public half in hex as `[packages]
/// verification_key` takes it. A Client updates itself only from a signed package (ADR-0018).
fn signing_key() -> &'static (ring::signature::Ed25519KeyPair, String) {
    static KEY: std::sync::OnceLock<(ring::signature::Ed25519KeyPair, String)> =
        std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        use ring::signature::KeyPair as _;
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
        let keypair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("keypair");
        let public = hex::encode(keypair.public_key().as_ref());
        (keypair, public)
    })
}

/// Puts a Package into a ring aimed at the Agent type it is built for, signed with
/// [`signing_key`], and hands back the ring's name. A Package reaches nobody by itself, so a test
/// that wants one delivered has to say which ring the host is in — which is the model.
fn ring_holding(
    state: &fleet_server::fleet::AppState,
    id: &fleet_server::packages::PackageId,
) -> String {
    let (sha256, _) = state
        .packages()
        .expect("packages are armed")
        .artifact(id, &this_host())
        .expect("the artifact is stored");
    let signature = signing_key()
        .0
        .sign(&fleet_core::package::statement(
            &id.agent_type,
            &id.version,
            &sha256,
        ))
        .as_ref()
        .to_vec();
    ring_holding_signed(state, id, Some((&this_host(), signature)))
}

/// The same with the signature given — where a signature lives (ADR-0026).
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

/// The version directory laid out before the update. Joined one component at a time, never as
/// `versions/<name>`: this test builds the Windows pointer with `mklink`, a `cmd` builtin that
/// reads an embedded `/` as the start of a switch.
const PREVIOUS_VERSION_DIR: &str = "supervisor-0.0.0-previous";

/// The tests of this file, one at a time. Two of them build a newer Client — a whole workspace,
/// minutes of every core — and the others wait on a running Client with a deadline; side by side
/// on a small runner the build starved them past it.
async fn one_at_a_time() -> tokio::sync::MutexGuard<'static, ()> {
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    SERIAL.lock().await
}

async fn wait_until<T>(what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if let Some(value) = probe() {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

async fn spawn_server(store: PackageStore) -> (std::net::SocketAddr, Arc<AppState>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("configs")
            .with_packages(Some(
                PackageOffering::new(dir.path(), store).expect("deployments"),
            )),
    );
    // The configuration directory only has to outlive the Server, which outlives the test.
    std::mem::forget(dir);
    let app = fleet_server::agent_app(state.clone(), fleet_server::transport::Admission::open());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (addr, state)
}

/// The version this Client binary reports for itself (ADR-0012, baked in at build time). The
/// package must be offered under exactly this version, because the staged binary is this same
/// binary and the self-check compares the two.
fn version_of(binary: &Path) -> String {
    let output = Command::new(binary)
        .arg("--version")
        .output()
        .expect("run --version");
    let text = String::from_utf8_lossy(&output.stdout);
    text.split_whitespace()
        .last()
        .expect("a version in the output")
        .to_string()
}

/// A `file://` URL for a local path, spelled the way git wants it on every platform.
///
/// `file://` rather than a plain path, for two reasons that only bite in CI: git ignores `--depth`
/// on a local path, and it refuses the local-clone optimisation against a *shallow* source — which
/// is what `actions/checkout` leaves behind at its default depth of one. Windows then needs the
/// spelling fixed twice over: canonicalisation there yields an extended-length path (`\\?\C:\…`)
/// and native separators, and neither belongs in a URL. Getting this wrong is what `exit code: 128`
/// on the Windows runner looked like, so the shape is pinned by a test that runs everywhere.
fn file_url(path: &Path) -> String {
    let text = path.display().to_string();
    let text = text
        .strip_prefix(r"\\?\")
        .unwrap_or(&text)
        .replace('\\', "/");
    // `file://` plus a path that already starts with `/` gives the three slashes a URL needs; a
    // Windows path starts with its drive letter and has to be given the third.
    if text.starts_with('/') {
        format!("file://{text}")
    } else {
        format!("file:///{text}")
    }
}

/// The three spellings this has to survive: a Unix path, and a Windows one with and without the
/// extended-length prefix `std::fs::canonicalize` puts in front of it.
#[test]
fn a_local_path_becomes_a_file_url_git_accepts() {
    assert_eq!(file_url(Path::new("/workspace")), "file:///workspace");
    assert_eq!(
        file_url(Path::new(r"\\?\C:\a\opamp-fleet")),
        "file:///C:/a/opamp-fleet"
    );
    assert_eq!(
        file_url(Path::new(r"C:\a\opamp-fleet")),
        "file:///C:/a/opamp-fleet"
    );
}

/// The version the artifact under offer is built as — greater than anything this repository has
/// released, so it is an upgrade for whatever the test runs.
const NEWER_VERSION: &str = "9.9.9";

/// A Client binary that is a *newer version* than the one this test runs, built once per test
/// binary with the override the build script documents (`OPAMP_PRODUCT_VERSION`, ADR-0012), and its
/// version as an operator would type it.
///
/// A second build, rather than offering the running binary back to itself, because the fleet
/// does not make that offer: a Set reaches an Agent only as an **upgrade** (ADR-0025), and a Client
/// reports the version it runs whether or not a package put it there — so a Set at the running
/// version reaches nobody, which is what `a_set_at_the_running_version_reaches_nobody` asserts.
/// What is left to test here is the update itself, and an update needs something newer to install.
///
/// It is built from a **tagless clone** of this repository rather than from the checkout itself,
/// and that is the whole reason a clone appears in a test: `build.rs` refuses a build whose
/// `OPAMP_PRODUCT_VERSION` disagrees with a `version/*` tag on HEAD (ADR-0012's drift rule), so this
/// helper broke on precisely the commits a release is cut from. The clone carries no tags, so the
/// override is the only version statement there is and the build is an ordinary `-dev` one.
///
/// What that costs: the artifact is built from the **committed** state. Uncommitted changes to the
/// Client are in the binary under test but not in the one it installs, which for what these tests
/// assert — a program that self-checks at the offered version, comes up, and reports `Installed` —
/// is a difference that does not show. Cheap after the first run: the clone is refreshed to HEAD
/// and both it and its target directory are kept under `CARGO_TARGET_TMPDIR`, without debug info.
fn newer_client() -> &'static (PathBuf, String) {
    static NEWER: std::sync::OnceLock<(PathBuf, String)> = std::sync::OnceLock::new();
    NEWER.get_or_init(|| {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("newer-client");
        let checkout = root.join("checkout");
        let target = root.join("target");
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("the workspace root resolves");
        let url = file_url(&workspace);

        let git = |args: &[&str], what: &str| {
            let out = Command::new("git")
                .args(args)
                .output()
                .unwrap_or_else(|e| panic!("cannot run git to {what}: {e}"));
            // stderr, not just the code: this runs on three platforms in CI, where `exit code:
            // 128` on its own says nothing about which of them git objected to.
            assert!(
                out.status.success(),
                "cannot {what}: {}\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        };
        // A clone that did not finish leaves a directory git will not clone into again ("already
        // exists and is not an empty directory") while `Cargo.toml` is still missing, so the two
        // branches below cannot be chosen by the presence of a file the reuse path needs. Ask
        // instead whether there is a repository to fetch into, and clear anything else out of the
        // way -- `target/` survives between CI runs, which is what makes a half-written clone here
        // outlive the run that abandoned it.
        let reusable = checkout.join(".git").exists() && checkout.join("Cargo.toml").exists();
        if !reusable && checkout.exists() {
            std::fs::remove_dir_all(&checkout).expect("clear an unusable checkout");
        }
        if reusable {
            // Kept between runs, so it has to follow HEAD rather than stay where it was cloned.
            let dir = checkout.to_string_lossy().to_string();
            git(
                &[
                    "-C",
                    &dir,
                    "fetch",
                    "--no-tags",
                    "--depth",
                    "1",
                    &url,
                    "HEAD",
                ],
                "fetch the sources to build the newer Client from",
            );
            git(
                &["-C", &dir, "reset", "--hard", "FETCH_HEAD"],
                "move the newer Client's sources to HEAD",
            );
        } else {
            std::fs::create_dir_all(&root).expect("create the build directory");
            git(
                &[
                    "clone",
                    "--no-tags",
                    "--depth",
                    "1",
                    &url,
                    &checkout.to_string_lossy(),
                ],
                "clone the sources to build the newer Client from",
            );
        }

        // `--no-tags` is the intent; this is the guarantee. The whole point of the clone is a HEAD
        // no `version/*` tag points at, and a tag that arrived anyway — by a git that copies refs
        // on a local optimisation, or by a source whose refs moved — would put the drift rule back
        // in the way with a message nobody would connect to this helper.
        let dir = checkout.to_string_lossy().to_string();
        let listed = Command::new("git")
            .args(["-C", &dir, "tag", "-l"])
            .output()
            .expect("list the clone's tags");
        for tag in String::from_utf8_lossy(&listed.stdout).lines() {
            let tag = tag.trim();
            if !tag.is_empty() {
                git(&["-C", &dir, "tag", "-d", tag], "drop a tag from the clone");
            }
        }

        let release = !cfg!(debug_assertions);
        let mut build = Command::new(env!("CARGO"));
        build
            .current_dir(&checkout)
            .args(["build", "-p", "fleet-agent", "--bin", "supervisor"])
            .env("OPAMP_PRODUCT_VERSION", NEWER_VERSION)
            .env("CARGO_TARGET_DIR", &target)
            // Nothing here is debugged; the binary only has to run and to say what it is.
            .env("CARGO_PROFILE_DEV_DEBUG", "0");
        if release {
            build.arg("--release");
        }
        let status = build.status().expect("run cargo");
        assert!(
            status.success(),
            "building the newer Client failed: {status}"
        );

        let binary = target
            .join(if release { "release" } else { "debug" })
            .join(CLIENT_BINARY);
        let full = version_of(&binary);
        let identity = fleet_core::version::identity(&full)
            .unwrap_or_else(|| panic!("{full:?} is not a version"))
            .to_string();
        assert!(
            identity.starts_with(NEWER_VERSION),
            "the override did not reach the build: {full:?}"
        );
        (binary, identity)
    })
}

/// Lays out `<root>/versions/<dir>/<client>` + `<root>/current` the way `service install` would,
/// and returns the path the "service" runs — through the pointer, which is how the service manager
/// is registered and therefore the only way this is worth starting.
///
/// The version directory is deliberately **not** named after the version this binary reports:
/// installing a package resolves its target directory from the offered version, and a Client
/// already running from that directory is told the version it was offered is the one it runs. A
/// host that installed by hand and one that arrived by package differ exactly here, and the
/// interesting case is the one where the two names differ.
fn install_layout(root: &Path, client: &Path) -> PathBuf {
    let version_dir = root.join("versions").join(PREVIOUS_VERSION_DIR);
    std::fs::create_dir_all(&version_dir).expect("create the version directory");
    let binary = version_dir.join(CLIENT_BINARY);
    std::fs::copy(client, &binary).expect("copy the client");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    point_current_at(root, &version_dir);
    root.join("current").join(CLIENT_BINARY)
}

/// Creates `<root>/current` pointing at `version_dir`, by the mechanism `service install` uses on
/// this platform (`layout::set_current`): a symbolic link on Unix, a directory junction on Windows.
///
/// Restated here rather than called, for the reason the exit code above is: `client` is a binary
/// crate. Restating it is also what makes the Windows run worth having — a junction is created by
/// `mklink /J` and needs no privilege, and if that stopped being true this test would say so.
fn point_current_at(root: &Path, version_dir: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(version_dir, root.join("current")).expect("point current");
    #[cfg(windows)]
    {
        let status = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(root.join("current"))
            .arg(version_dir)
            .status()
            .expect("run mklink");
        assert!(status.success(), "mklink /J failed with {status}");
    }
}

/// A Client under a stand-in service manager: it is restarted whenever it exits, exactly as
/// systemd would, and every exit code it produced is kept for the assertions.
struct Supervised {
    program: PathBuf,
    config: PathBuf,
    child: Child,
    exits: Vec<i32>,
}

impl Supervised {
    fn start(program: &Path, config: &Path) -> Self {
        Supervised {
            program: program.to_path_buf(),
            config: config.to_path_buf(),
            child: Self::spawn(program, config),
            exits: Vec::new(),
        }
    }

    fn spawn(program: &Path, config: &Path) -> Child {
        // The Client logs to stdout; keeping it beside the configuration makes a failing run
        // readable instead of silent.
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(config.with_extension("log"))
            .expect("open the client log");
        Command::new(program)
            .arg("--config")
            .arg(config)
            .stdout(Stdio::from(log))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the client")
    }

    /// Restarts the process if it has exited. Call it from the polling loop — this is the service
    /// manager's whole job in this test.
    fn tend(&mut self) {
        if let Some(status) = self.child.try_wait().expect("wait on the client") {
            self.exits.push(status.code().unwrap_or(-1));
            assert!(
                self.exits.len() <= 8,
                "the Client keeps restarting without settling: exits {:?}",
                self.exits
            );
            self.child = Self::spawn(&self.program, &self.config);
        }
    }
}

impl Drop for Supervised {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Finds an Agent by the operator's name for it — `service.instance.name` (ADR-0016). The Client's
/// configured `name` is its *instance* name; its `service.name` is the constant type `supervisor`
/// (ADR-0019), the same on every host in the fleet, which is what a Selector aiming the Client's own
/// package matches on.
fn view<'a>(agents: &'a [AgentView], name: &str) -> Option<&'a AgentView> {
    agents.iter().find(|a| a.service_instance_name == name)
}

fn config_toml(addr: std::net::SocketAddr, state_dir: &Path) -> String {
    format!(
        concat!(
            "endpoint = \"ws://{addr}/v1/opamp\"\n",
            "name = \"self-updating-client\"\n",
            "state_dir = {state:?}\n",
            "heartbeat_interval_secs = 1\n\n",
            "[packages]\n",
            "verification_key = \"{key}\"\n",
        ),
        addr = addr,
        state = state_dir.to_string_lossy(),
        key = signing_key().1,
    )
}

/// The whole loop: the Server offers the Client a version of itself, the Client stages it beside
/// the running one, proves it with `self-check`, moves `current`, and asks to be restarted — and
/// whatever comes up afterwards owes the Server a terminal status, which must be `Installed`.
/// Verifies: ADR-0018, ADR-0012, G-10, G-11
#[tokio::test]
async fn the_client_installs_a_version_of_itself_and_reports_it_installed() {
    let _serial = one_at_a_time().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let client = PathBuf::from(env!("CARGO_BIN_EXE_supervisor"));
    // The artifact is a Client built as a greater version — the only thing that will pass the
    // staged binary's own self-check, which requires it to *be* an OpAMP Fleet Client at the
    // offered version, and the only thing the fleet will offer a Client at all (ADR-0025).
    //
    // Offered the way an operator uploads a release: the number on the archive, without the commit
    // the build carries (ADR-0012). The staged binary reports the full string and must still be
    // recognised as this release — the failure that ADR exists for.
    let (newer, version) = newer_client();
    let artifact = std::fs::read(newer).expect("read the newer client binary");
    let store_dir = tempfile::tempdir().expect("store dir");
    let store = PackageStore::open(store_dir.path().to_path_buf()).expect("store");
    // The Client's own Agent reports the constant type `supervisor` (ADR-0016, ADR-0019), and a Set
    // reaches only Agents of its type — the type is part of its identity (ADR-0026). Its name is
    // the same string, which is what the consent below is narrowed to.
    let set = fleet_server::packages::PackageId::new("supervisor", version).expect("package id");
    store.create(&set).expect("create package");
    store
        .put_entry(&set, &this_host(), artifact)
        .expect("put entry");

    let (addr, state) = spawn_server(store).await;
    let root = dir.path().join("install");
    let program = install_layout(&root, &client);
    let state_dir = dir.path().join("client-state");
    let config = dir.path().join("supervisor.toml");
    std::fs::write(
        &config,
        config_toml(addr, &state_dir) + &common::client_identity(dir.path()),
    )
    .expect("write config");

    let mut service = Supervised::start(&program, &config);

    // A saved Package reaches nobody (ADR-0025): the rollout act releases it, and it needs the
    // Client's Agent to be known and fitted — so it is retried until the first report arrived.
    wait_until("the rollout act to reach the agent", || {
        service.tend();
        state
            .rollout_deployment(&ring_holding(&state, &set))
            .ok()
            .filter(|assigned| *assigned >= 1)
            .map(|_| ())
    })
    .await;

    // The contract: however many restarts it takes, the Server is told the new version is in.
    wait_until("the self-update to be reported Installed", || {
        service.tend();
        let snapshot = state.snapshot();
        let agent = view(&snapshot, "self-updating-client")?;
        let package = agent.packages.iter().find(|p| p.name == "supervisor")?;
        (package.status == "Installed" && package.version == *version).then_some(())
    })
    .await;

    // The configured `name` names this instance; the type is the constant `supervisor`, the same
    // for every Client in the fleet, so one Selector aims the Client's package at all of them
    // without naming a host (ADR-0016, ADR-0019).
    assert_eq!(
        view(&state.snapshot(), "self-updating-client")
            .expect("the client's own agent")
            .service_name,
        "supervisor"
    );

    assert!(
        service.exits.contains(&EXIT_RESTART_FOR_UPDATE),
        "the Client asked its service manager for the restart rather than restarting itself: \
         exits {:?}",
        service.exits
    );

    // `current` moved to a directory named after the offered version, and the previous one is
    // still there — a rollback needs somewhere to go back to.
    let current = std::fs::canonicalize(root.join("current")).expect("current resolves");
    assert_ne!(
        current,
        std::fs::canonicalize(root.join("versions").join(PREVIOUS_VERSION_DIR))
            .expect("the previous version"),
        "current still points at the version that was running before the update"
    );
    assert!(
        current.join(CLIENT_BINARY).is_file(),
        "the new version is staged"
    );
    assert!(
        root.join("versions")
            .join(PREVIOUS_VERSION_DIR)
            .join(CLIENT_BINARY)
            .is_file(),
        "the version it replaced is kept, so a rollback has a target"
    );
    assert!(
        !state_dir.join("self-update.json").exists(),
        "the in-flight marker is cleared once the new version has settled"
    );
}

/// ADR-0018: exiting for the self-update restart is a *graceful* shutdown — the Managed Processes
/// are stopped, not abandoned. Before the fix the restart path returned before that shutdown, so on
/// a service manager that does not reap the process group the Collector was orphaned and the next
/// Client spawned a duplicate. Here every managed process that ran before a restart is dead
/// afterwards. Linux-only: it reads `/proc/<pid>` to tell a process apart from its successor.
/// Verifies: ADR-0018, ADR-0012
#[cfg(target_os = "linux")]
#[tokio::test]
async fn managed_processes_stop_cleanly_on_the_self_update_restart() {
    let _serial = one_at_a_time().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let client = PathBuf::from(env!("CARGO_BIN_EXE_supervisor"));

    // Offer the Client a newer version of itself, exactly as the test above does.
    let (newer, version) = newer_client();
    let artifact = std::fs::read(newer).expect("read the newer client binary");
    let store_dir = tempfile::tempdir().expect("store dir");
    let store = PackageStore::open(store_dir.path().to_path_buf()).expect("store");
    let set = fleet_server::packages::PackageId::new("supervisor", version).expect("package id");
    store.create(&set).expect("create package");
    store
        .put_entry(&set, &this_host(), artifact)
        .expect("put entry");

    let (addr, state) = spawn_server(store).await;
    let root = dir.path().join("install");
    let program = install_layout(&root, &client);
    let state_dir = dir.path().join("client-state");
    let config = dir.path().join("supervisor.toml");

    // A supervised Managed Process that stays up and records its pid — rewritten with a fresh one
    // every time it is (re)started. Placed in the Supervisor's own `program/` directory and named
    // by a bare file name, the only shape a block may carry (ADR-0017): a Managed Process is always
    // one this Client installed.
    let stub = {
        let program_dir = state_dir.join("supervisors/managed/program");
        std::fs::create_dir_all(&program_dir).expect("create the supervisor's program directory");
        let target = program_dir.join("stub-agent");
        std::fs::copy(env!("CARGO_BIN_EXE_stub_agent"), &target).expect("place the stub");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .expect("make the stub executable");
        "stub-agent"
    };
    let marker = dir.path().join("managed.pid");
    std::fs::write(
        &config,
        format!(
            concat!(
                "endpoint = \"ws://{addr}/v1/opamp\"\n",
                "name = \"self-updating-client\"\n",
                "state_dir = {state:?}\n",
                "heartbeat_interval_secs = 1\n\n",
                "[packages]\n",
                "verification_key = \"{key}\"\n\n",
                "[[supervisor]]\n",
                "type = \"command\"\n",
                "name = \"managed\"\n",
                "command = {stub:?}\n",
                "args = [\"--touch\", {marker:?}]\n",
            ),
            addr = addr,
            state = state_dir.to_string_lossy(),
            key = signing_key().1,
            stub = stub,
            marker = marker.to_string_lossy(),
        ) + &common::client_identity(dir.path()),
    )
    .expect("write config");

    let mut service = Supervised::start(&program, &config);

    // A saved Set reaches nobody (ADR-0025): the rollout act releases it, and it needs the
    // Client's Agent to be known and fitted — so it is retried until the first report arrived.
    wait_until("the rollout act to reach the agent", || {
        service.tend();
        state
            .rollout_deployment(&ring_holding(&state, &set))
            .ok()
            .filter(|assigned| *assigned >= 1)
            .map(|_| ())
    })
    .await;

    let read_managed_pid = |path: &Path| -> Option<u32> {
        let text = std::fs::read_to_string(path).ok()?;
        text.lines()
            .find_map(|line| line.strip_prefix("pid="))
            .and_then(|n| n.trim().parse().ok())
    };
    // Every distinct managed pid seen while the update runs, in order — the last is the one running
    // once it has settled; all before it were superseded by a restart and must have been stopped.
    let mut seen: Vec<u32> = Vec::new();
    wait_until("the self-update to be reported Installed", || {
        service.tend();
        if let Some(pid) = read_managed_pid(&marker) {
            if seen.last() != Some(&pid) {
                seen.push(pid);
            }
        }
        let snapshot = state.snapshot();
        let agent = view(&snapshot, "self-updating-client")?;
        let package = agent.packages.iter().find(|p| p.name == "supervisor")?;
        (package.status == "Installed" && package.version == *version).then_some(())
    })
    .await;

    assert!(
        seen.len() >= 2,
        "the update restarted the Client, so the managed process was (re)started too: pids {seen:?}"
    );
    let alive = |pid: u32| Path::new(&format!("/proc/{pid}")).exists();
    for pid in &seen[..seen.len() - 1] {
        assert!(
            !alive(*pid),
            "a managed process from before a restart (pid {pid}) was orphaned, not stopped: {seen:?}"
        );
    }
}

/// The hazard this guards against: a Server holding the 0.4.0 package offering it to Clients
/// already running 0.4.0, and to one running 0.4.1-dev — a downgrade of the host that manages the
/// host.
///
/// ADR-0025 holds a Set against what the Agent reports installed, and a Client that arrived by
/// `.deb`, `.rpm`, MSI or by hand has installed no *package*, so it reports the version it runs —
/// which is what this asserts across the process boundary, together with what the Server then does
/// with it: an equal Set and an older one reach nobody, a greater one reaches this Client.
/// Verifies: ADR-0018
#[tokio::test]
async fn a_set_at_the_running_version_reaches_nobody() {
    let _serial = one_at_a_time().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let client = PathBuf::from(env!("CARGO_BIN_EXE_supervisor"));
    let full = version_of(&client);
    let running = fleet_core::version::identity(&full)
        .unwrap_or_else(|| panic!("{full:?} is not a version"))
        .to_string();

    // Three Sets differing only in their version. What is *in* them never matters here: no offer
    // is expected to reach the Client at all, and the one that may is asserted at the rollout act
    // rather than on the host.
    let store_dir = tempfile::tempdir().expect("store dir");
    let store = PackageStore::open(store_dir.path().to_path_buf()).expect("store");
    let set_of = |version: &str| {
        let id = fleet_server::packages::PackageId::new("supervisor", version).expect("package id");
        store.create(&id).expect("create package");
        store
            .put_entry(&id, &this_host(), b"not a client".to_vec())
            .expect("put entry");
        id
    };
    let same = set_of(&running);
    let older = set_of("0.0.1");
    let newer = set_of("9.9.9");

    let (addr, state) = spawn_server(store).await;
    let root = dir.path().join("install");
    let program = install_layout(&root, &client);
    let state_dir = dir.path().join("client-state");
    let config = dir.path().join("supervisor.toml");
    std::fs::write(
        &config,
        config_toml(addr, &state_dir) + &common::client_identity(dir.path()),
    )
    .expect("write config");

    // A Client installed the way a package manager installs one: a layout, a binary, and no record
    // of any package ever having been installed over it.
    assert!(
        !state_dir.join("installed-package.json").exists(),
        "this Client must start without an install record for the test to mean anything"
    );
    let mut service = Supervised::start(&program, &config);

    let (reported_version, reported_status) =
        wait_until("the Client to report what it runs", || {
            service.tend();
            let snapshot = state.snapshot();
            let agent = view(&snapshot, "self-updating-client")?;
            let package = agent.packages.iter().find(|p| p.name == "supervisor")?;
            (!package.version.is_empty()).then(|| (package.version.clone(), package.status.clone()))
        })
        .await;
    assert_eq!(
        reported_version, running,
        "a Client states the version it runs, whatever put it there"
    );
    assert_eq!(reported_status, "Installed");

    assert_eq!(
        state
            .rollout_deployment(&ring_holding(&state, &same))
            .expect("the act runs"),
        0,
        "a Set at the version this Client already runs must reach nobody (ADR-0025)"
    );
    assert_eq!(
        state
            .rollout_deployment(&ring_holding(&state, &older))
            .expect("the act runs"),
        0,
        "and an older one must never be installed over a newer Client"
    );
    // The control: what the gate refuses is the version, not this Client — a greater Set still
    // reaches it, which is the whole point of being able to update a fleet at all.
    assert_eq!(
        state
            .rollout_deployment(&ring_holding(&state, &newer))
            .expect("the act runs"),
        1,
        "a greater Set still reaches this Client"
    );

    assert!(
        service.exits.is_empty(),
        "nothing was installed and nothing restarted: exits {:?}",
        service.exits
    );
}

/// A self-update whose signature does not verify against `[packages] verification_key` fails with
/// `InstallFailed` naming the signature, nothing is staged, and the Client keeps running the
/// version it runs. The Server never offers an unsigned Package (ADR-0026), so a signature over
/// other bytes is the case that reaches the Client.
/// Verifies: ADR-0018
#[tokio::test]
async fn a_self_update_whose_signature_does_not_verify_is_refused_and_the_client_keeps_running() {
    let _serial = one_at_a_time().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let client = PathBuf::from(env!("CARGO_BIN_EXE_supervisor"));

    let artifact = std::fs::read(&client).expect("read the client binary");
    let store_dir = tempfile::tempdir().expect("store dir");
    let store = PackageStore::open(store_dir.path().to_path_buf()).expect("store");
    let set =
        fleet_server::packages::PackageId::new("supervisor", NEWER_VERSION).expect("package id");
    store.create(&set).expect("create package");
    store
        .put_entry(&set, &this_host(), artifact)
        .expect("put entry");

    let (addr, state) = spawn_server(store).await;
    let root = dir.path().join("install");
    let program = install_layout(&root, &client);
    let previous = std::fs::canonicalize(root.join("current")).expect("current resolves");
    let state_dir = dir.path().join("client-state");
    let config = dir.path().join("supervisor.toml");
    std::fs::write(
        &config,
        config_toml(addr, &state_dir) + &common::client_identity(dir.path()),
    )
    .expect("write config");

    let mut service = Supervised::start(&program, &config);

    // Signed with the operator's key, over bytes that are not the artifact.
    let signature = signing_key()
        .0
        .sign(&fleet_core::package::statement(
            &set.agent_type,
            &set.version,
            &<sha2::Sha256 as sha2::Digest>::digest(b"another artifact"),
        ))
        .as_ref()
        .to_vec();
    let ring = ring_holding_signed(&state, &set, Some((&this_host(), signature)));
    wait_until("the rollout act to reach the agent", || {
        service.tend();
        state
            .rollout_deployment(&ring)
            .ok()
            .filter(|assigned| *assigned >= 1)
            .map(|_| ())
    })
    .await;

    let error = wait_until("the self-update to be reported InstallFailed", || {
        service.tend();
        let snapshot = state.snapshot();
        let agent = view(&snapshot, "self-updating-client")?;
        let package = agent.packages.iter().find(|p| p.name == "supervisor")?;
        (package.status == "InstallFailed").then(|| package.error.clone())
    })
    .await;
    assert!(
        error.contains("signature"),
        "the failure names the signature: {error:?}"
    );
    assert!(
        service.exits.is_empty(),
        "a refused package is not a reason to restart: exits {:?}",
        service.exits
    );
    assert_eq!(
        std::fs::canonicalize(root.join("current")).expect("current resolves"),
        previous,
        "nothing was pointed anywhere else"
    );
    let staged: Vec<_> = std::fs::read_dir(root.join("versions"))
        .expect("versions")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(NEWER_VERSION))
        .collect();
    assert!(staged.is_empty(), "nothing was staged: {staged:?}");
}
