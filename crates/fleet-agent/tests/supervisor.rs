//! Integration: a `command` Supervisor brings a Foreign Agent (the stub) under management —
//! the process is spawned from the configured command line, and a Client shutdown stops it
//! first (ADR-0017).

mod common;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn wait_for(what: &str, timeout: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

fn spawn_client(config_path: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_supervisor"))
        .arg("--config")
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the client")
}

/// Places the stub where a Managed Process must live (ADR-0017): inside the Supervisor's own
/// `program/` directory, under a bare name the configuration can spell. `root` is whatever
/// `supervisor_dir` resolves to for the Client under test — `<state_dir>/supervisors` by default.
///
/// Copied rather than symlinked, and named with the platform's executable suffix: Windows spawns
/// `x.exe` when told `x` and would not find a file missing it.
fn install_stub(root: &Path, supervisor: &str) -> String {
    let name = format!("stub-agent{}", std::env::consts::EXE_SUFFIX);
    let program_dir = root.join(supervisor).join("program");
    std::fs::create_dir_all(&program_dir).expect("create the supervisor's program directory");
    let target = program_dir.join(&name);
    std::fs::copy(env!("CARGO_BIN_EXE_stub_agent"), &target).expect("place the stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .expect("make the stub executable");
    }
    name
}

fn write_config(dir: &Path, marker: &Path) -> std::path::PathBuf {
    // An unreachable endpoint: supervision must not depend on the Server being there.
    let config = format!
        (
        "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\n\n[[supervisor]]\ntype = \"command\"\nname = \"stub\"\ncommand = {command:?}\nargs = [\"--touch\", {marker:?}]\n",
        state = dir.join("state").to_string_lossy(),
        command = install_stub(&dir.join("state/supervisors"), "stub"),
        marker = marker.to_string_lossy(),
    );
    let path = dir.join("supervisor.toml");
    std::fs::write(&path, config + &common::client_identity(dir)).expect("write supervisor.toml");
    path
}

/// ADR-0017 end to end: what the Foreign Agent is actually invoked with. The stub writes every
/// argument it received into the marker, so this asserts on the expanded command line rather than
/// on the substitution function — the argument has to survive all the way into `argv`, which is
/// the only place the silent failure this prevents would show up.
#[test]
fn a_command_supervisors_arguments_are_expanded_to_its_own_directories() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("marker");
    // Relocated on purpose: an argument written against the default layout would be wrong here,
    // which is exactly the drift the placeholders exist to make impossible.
    let supervisor_dir = dir.path().join("elsewhere");
    let config = format!(
        "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\nsupervisor_dir = {supervisors:?}\n\n\
         [[supervisor]]\ntype = \"command\"\nname = \"stub\"\ncommand = {command:?}\n\
         args = [\"--touch\", {marker:?}, \"-c\", \"${{config_dir}}/agent-conf\", \"--keep\", \"${{FLB_LEVEL}}\"]\n",
        state = dir.path().join("state").to_string_lossy(),
        supervisors = supervisor_dir.to_string_lossy(),
        command = install_stub(&supervisor_dir, "stub"),
        marker = marker.to_string_lossy(),
    );
    let config_path = dir.path().join("supervisor.toml");
    std::fs::write(&config_path, config + &common::client_identity(dir.path()))
        .expect("write supervisor.toml");

    let mut client = spawn_client(&config_path);
    wait_for("the stub's marker file", Duration::from_secs(20), || {
        marker.exists()
    });
    let argv = std::fs::read_to_string(&marker).expect("read the marker");

    // Built the way the Client builds it — a path, so its separators are the platform's — with the
    // rest of the argument appended as the operator wrote it, which is what expansion leaves alone.
    let expected = format!(
        "{}/agent-conf",
        supervisor_dir.join("stub").join("config").display()
    );
    assert!(
        argv.contains(&expected),
        "the placeholder resolved to the relocated directory: {argv}"
    );
    assert!(
        !argv.contains("${config_dir}"),
        "nothing unexpanded reached the process: {argv}"
    );
    assert!(
        argv.contains("${FLB_LEVEL}"),
        "an unknown placeholder is the process's own business: {argv}"
    );

    client.kill().expect("kill the client");
    let _ = client.wait();
}

/// ADR-0026 end to end: a Supervisor configured for a package that is a whole tree runs the
/// program from inside it. The tree is put in place here rather than delivered, because what this
/// has to prove is the half the unit tests cannot — that the path the *configuration* resolves to
/// at startup is the path the process is actually spawned from, across the process boundary.
#[test]
fn a_command_supervisor_runs_its_program_from_inside_an_unpacked_tree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("marker");
    let supervisor_dir = dir.path().join("supervisors");

    // Where an installed package tree ends up: <supervisor_dir>/<name>/program/tree/<program_path>.
    // Named with the platform's executable suffix, because Windows spawns `x.exe` when told `x`
    // and would not find a file that is missing it.
    let file_name = format!("stub-agent{}", std::env::consts::EXE_SUFFIX);
    let inside = format!("bin/{file_name}");
    let program = supervisor_dir.join("stub/program/tree").join(&inside);
    std::fs::create_dir_all(program.parent().expect("a parent")).expect("create the tree");
    std::fs::copy(env!("CARGO_BIN_EXE_stub_agent"), &program).expect("place the program");

    let config = format!(
        "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\nsupervisor_dir = {supervisors:?}\n\n\
         [[supervisor]]\ntype = \"command\"\nname = \"stub\"\ncommand = {file_name:?}\n\
         program_path = {inside:?}\nargs = [\"--touch\", {marker:?}]\n",
        state = dir.path().join("state").to_string_lossy(),
        supervisors = supervisor_dir.to_string_lossy(),
        marker = marker.to_string_lossy(),
    );
    let config_path = dir.path().join("supervisor.toml");
    std::fs::write(&config_path, config + &common::client_identity(dir.path()))
        .expect("write supervisor.toml");

    let mut client = spawn_client(&config_path);
    wait_for("the stub's marker file", Duration::from_secs(20), || {
        marker.exists()
    });

    client.kill().expect("kill the client");
    let _ = client.wait();
}

#[test]
fn a_command_supervisor_spawns_the_configured_process() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("marker");
    let config = write_config(dir.path(), &marker);

    let mut client = spawn_client(&config);
    wait_for("the stub's marker file", Duration::from_secs(20), || {
        marker.exists()
    });
    let content = std::fs::read_to_string(&marker).expect("read the marker");
    assert!(
        content.contains("--touch"),
        "marker carries the argv: {content}"
    );

    client.kill().expect("kill the client");
    let _ = client.wait();
}

#[test]
fn a_collector_supervisor_passes_each_config_entry_as_a_config_flag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("marker");

    // A configuration that survived a previous run: the collector starts on it right away.
    let config_dir = dir.path().join("state/supervisors/otelcol/config");
    std::fs::create_dir_all(&config_dir).expect("config dir");
    std::fs::write(config_dir.join("collector.yaml"), "receivers: {}\n").expect("seed config");

    let toml = format!(
        "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\n\n[[supervisor]]\ntype = \"collector\"\nname = \"otelcol\"\nbinary = {binary:?}\nargs = [\"--touch\", {marker:?}]\n",
        state = dir.path().join("state").to_string_lossy(),
        binary = install_stub(&dir.path().join("state/supervisors"), "otelcol"),
        marker = marker.to_string_lossy(),
    );
    let config_path = dir.path().join("supervisor.toml");
    std::fs::write(&config_path, toml + &common::client_identity(dir.path()))
        .expect("write supervisor.toml");

    let mut client = spawn_client(&config_path);
    wait_for(
        "the stub collector's marker",
        Duration::from_secs(20),
        || marker.exists(),
    );
    let content = std::fs::read_to_string(&marker).expect("read the marker");
    assert!(
        content.contains("--config"),
        "argv carries --config: {content}"
    );
    assert!(
        content.contains("collector.yaml"),
        "argv names the entry file: {content}"
    );

    client.kill().expect("kill the client");
    let _ = client.wait();
}

/// ADR-0023: supplementary content is on disk next to the configuration — that is what makes a
/// `${file:...}` reference resolve — but it is never handed to the Collector as `--config`.
// Verifies: ADR-0023
#[test]
fn a_collector_supervisor_leaves_supplementary_entries_out_of_its_config_flags() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("marker");

    let config_dir = dir.path().join("state/supervisors/otelcol/config");
    std::fs::create_dir_all(&config_dir).expect("config dir");
    std::fs::write(config_dir.join("collector.yaml"), "receivers: {}\n").expect("seed config");
    std::fs::write(config_dir.join("ruleset"), "rules: []\n").expect("seed supplementary");
    std::fs::write(config_dir.join(".supplementary"), "ruleset\n").expect("seed bookkeeping");

    let toml = format!(
        "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\n\n[[supervisor]]\ntype = \"collector\"\nname = \"otelcol\"\nbinary = {binary:?}\nargs = [\"--touch\", {marker:?}]\n",
        state = dir.path().join("state").to_string_lossy(),
        binary = install_stub(&dir.path().join("state/supervisors"), "otelcol"),
        marker = marker.to_string_lossy(),
    );
    let config_path = dir.path().join("supervisor.toml");
    std::fs::write(&config_path, toml + &common::client_identity(dir.path()))
        .expect("write supervisor.toml");

    let mut client = spawn_client(&config_path);
    wait_for(
        "the stub collector's marker",
        Duration::from_secs(20),
        || marker.exists(),
    );
    let content = std::fs::read_to_string(&marker).expect("read the marker");
    assert!(
        content.contains("collector.yaml"),
        "the configuration is passed: {content}"
    );
    assert!(
        !content.contains("ruleset"),
        "supplementary content is not passed as configuration: {content}"
    );
    assert!(
        !content.contains(".supplementary"),
        "the bookkeeping is not passed either: {content}"
    );
    assert!(
        config_dir.join("ruleset").exists(),
        "supplementary content stays on disk to be read by path"
    );

    client.kill().expect("kill the client");
    let _ = client.wait();
}

/// ADR-0017 clause 53 end to end: a listed Collector runs on the files the operator placed in its
/// `config/` directory, and the Server's last configuration stored there before the switch is not
/// among what it is started with.
/// Verifies: ADR-0017
#[test]
fn a_listed_collector_runs_on_the_entries_the_operator_placed() {
    use fleet_agent::supervisor::ports::AgentStorage as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("marker");

    let supervisor_dir = dir.path().join("state/supervisors/otelcol");
    let storage =
        fleet_agent::storage::Storage::new(supervisor_dir.clone()).expect("the supervisor's dir");
    storage
        .store_remote_config(&opamp::proto::AgentRemoteConfig {
            config: Some(opamp::proto::AgentConfigMap {
                config_map: std::collections::HashMap::from([(
                    "fleet".to_string(),
                    opamp::proto::AgentConfigObject {
                        body: b"receivers: {}\n".to_vec(),
                        ..Default::default()
                    },
                )]),
            }),
            config_hash: b"stored".to_vec(),
        })
        .expect("a configuration the Server delivered before the switch");
    let config_dir = storage.config_dir();
    std::fs::write(config_dir.join("local.yaml"), "receivers: {}\n").expect("operator's file");

    let toml = format!(
        "endpoint = \"ws://127.0.0.1:1/v1/opamp\"\nstate_dir = {state:?}\n\n\
         [supervisors]\nremote_config_disabled = [\"otelcol\"]\n\n\
         [[supervisor]]\ntype = \"collector\"\nname = \"otelcol\"\nbinary = {binary:?}\n\
         args = [\"--touch\", {marker:?}]\n",
        state = dir.path().join("state").to_string_lossy(),
        binary = install_stub(&dir.path().join("state/supervisors"), "otelcol"),
        marker = marker.to_string_lossy(),
    );
    let config_path = dir.path().join("supervisor.toml");
    std::fs::write(&config_path, toml + &common::client_identity(dir.path()))
        .expect("write supervisor.toml");

    let mut client = spawn_client(&config_path);
    wait_for(
        "the stub collector's marker",
        Duration::from_secs(20),
        || marker.exists(),
    );
    let content = std::fs::read_to_string(&marker).expect("read the marker");
    assert!(
        content.contains("local.yaml"),
        "the operator's file is passed: {content}"
    );
    assert!(
        !content.contains(&config_dir.join("fleet").display().to_string()),
        "the Server's stored entry is not: {content}"
    );
    assert!(!config_dir.join("fleet").exists());
    assert!(!supervisor_dir.join("remote-config.pb").exists());

    client.kill().expect("kill the client");
    let _ = client.wait();
}

#[cfg(unix)]
#[test]
fn sigterm_stops_the_managed_process_and_the_client_cleanly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("marker");
    let config = write_config(dir.path(), &marker);

    let mut client = spawn_client(&config);
    wait_for("the stub's marker file", Duration::from_secs(20), || {
        marker.exists()
    });
    let stub_pid: u32 = std::fs::read_to_string(&marker)
        .expect("read the marker")
        .lines()
        .find_map(|l| l.strip_prefix("pid=").and_then(|p| p.parse().ok()))
        .expect("the marker names the stub's pid");

    let term = Command::new("kill")
        .args(["-TERM", &client.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(term.success());

    wait_for("the client to exit", Duration::from_secs(20), || {
        matches!(client.try_wait(), Ok(Some(_)))
    });
    let status = client.wait().expect("client exit status");
    assert!(status.success(), "clean shutdown, got {status}");

    // The Managed Process went down with it (kill -0 probes for existence).
    wait_for("the stub to be gone", Duration::from_secs(10), || {
        !Command::new("kill")
            .args(["-0", &stub_pid.to_string()])
            .status()
            .expect("probe the stub")
            .success()
    });
}
