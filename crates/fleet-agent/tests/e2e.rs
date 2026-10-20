//! End to end (ADR-0017): the real Server in-process, the real Client binary with two
//! Supervisors — a Collector-type on the stub and a command-type Foreign Agent — over one
//! WebSocket connection. A configuration change reaches both Agents, restarts their processes
//! on the written files, and comes back `APPLIED` and in sync. A Configuration typed for the
//! Client itself then changes its Supervisor set at runtime (ADR-0017): an added block starts
//! and appears as a new Agent, unchanged ones ride through untouched, a removed one stops,
//! says goodbye, and its directory is purged (ADR-0017) — and `supervisor.toml` is rewritten around
//! the operator's globals each time.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet_server::fleet::{AgentView, AppState};

/// Kills the client on drop so a failing assertion never leaks the process.
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
    let state = Arc::new(common::fleet_state(dir.path()));
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

fn stub_pid(marker: &Path) -> Option<u32> {
    std::fs::read_to_string(marker)
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("pid=").and_then(|p| p.parse().ok()))
}

/// Finds an Agent by the operator's name for it — `service.instance.name`, the `[[supervisor]]`
/// block's `name` (ADR-0016). Deliberately not `service.name`: that is the Agent *type*, and both
/// Supervisors below run the same stub program, so it does not tell them apart.
fn view<'a>(agents: &'a [AgentView], name: &str) -> Option<&'a AgentView> {
    agents.iter().find(|a| a.service_instance_name == name)
}

/// What this Client presents: its two Supervisors, plus itself (ADR-0018).
const AGENTS: usize = 3;

/// The stub binary's own file name — what a **bare** program name resolves to inside a Supervisor's
/// owned `program/` directory. Blocks below name their program bare (not by absolute path), because
/// a Server-delivered Supervisor set may run only a program this Client owns (ADR-0017), and the
/// operator-local blocks use the same shape so the delivered set can restate them verbatim.
fn stub_program_name() -> String {
    Path::new(env!("CARGO_BIN_EXE_stub_agent"))
        .file_name()
        .expect("the stub binary has a file name")
        .to_string_lossy()
        .into_owned()
}

/// Places the stub binary where a bare program name resolves — `<state_dir>/supervisors/<name>/
/// program/<program>` (ADR-0017) — standing in for the package install that would normally put it
/// there. A Supervisor whose owned program is present starts it; one whose program is absent waits
/// for a package, which is not what this test exercises.
fn stage_owned_program(state_dir: &Path, supervisor: &str, program: &str) {
    let program_dir = state_dir
        .join("supervisors")
        .join(supervisor)
        .join("program");
    std::fs::create_dir_all(&program_dir).expect("create the owned program directory");
    let dest = program_dir.join(program);
    std::fs::copy(env!("CARGO_BIN_EXE_stub_agent"), &dest).expect("stage the stub binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
            .expect("make the staged program executable");
    }
}

// Verifies: ADR-0017, ADR-0015, G-1, G-6, G-14
#[tokio::test]
async fn a_config_change_reaches_both_supervised_agents_over_one_connection() {
    let (addr, state, dir) = spawn_server().await;
    let state_dir: PathBuf = dir.path().join("client-state");
    let stub_marker = dir.path().join("stub-marker");
    let otelcol_marker = dir.path().join("otelcol-marker");

    let program = stub_program_name();
    let otelcol_block = format!(
        concat!(
            "[[supervisor]]\n",
            "type = \"collector\"\n",
            "name = \"otelcol\"\n",
            "binary = {program:?}\n",
            "args = [\"--touch\", {otelcol_marker:?}]\n",
        ),
        program = program,
        otelcol_marker = otelcol_marker.to_string_lossy(),
    );
    let stub_block = format!(
        concat!(
            "[[supervisor]]\n",
            "type = \"command\"\n",
            "name = \"stub\"\n",
            "command = {program:?}\n",
            "args = [\"--touch\", {stub_marker:?}]\n",
            "version_args = [\"--version\"]\n",
        ),
        program = program,
        stub_marker = stub_marker.to_string_lossy(),
    );
    let toml = format!(
        concat!(
            "endpoint = \"ws://{addr}/v1/opamp\"\n",
            "state_dir = {state:?}\n",
            "heartbeat_interval_secs = 1\n\n",
            "[attributes]\n",
            "env = \"prod\"\n\n",
            // The set the Server delivers below carries arguments; the operator consents to that
            // here, where the Server cannot (ADR-0017 clause 38).
            "[supervisors]\n",
            "delivered_args = true\n\n",
            "{otelcol_block}\n",
            "{stub_block}",
        ),
        addr = addr,
        state = state_dir.to_string_lossy(),
        otelcol_block = otelcol_block,
        stub_block = stub_block,
    );
    let config_path = dir.path().join("supervisor.toml");
    std::fs::write(&config_path, toml + &common::client_identity(dir.path()))
        .expect("write supervisor.toml");

    // Both owned Supervisors have their program staged before the Client starts, so they run at
    // once rather than waiting for a package (ADR-0017 makes the delivery path owned-only).
    stage_owned_program(&state_dir, "otelcol", &program);
    stage_owned_program(&state_dir, "stub", &program);

    let _client = spawn_client(&config_path);

    // Both Supervisors appear as their own connected Agents — over the one WebSocket connection
    // this Client maintains (ADR-0015: routed by instance_uid alone) — and so does the Client
    // itself, which is an Agent (ADR-0018) whether or not it supervises anything.
    let agents = wait_until("every agent connected", || {
        let snapshot = state.snapshot();
        (snapshot.len() == AGENTS && snapshot.iter().all(|a| a.connected)).then_some(snapshot)
    })
    .await;
    assert!(view(&agents, "otelcol").is_some());
    assert!(view(&agents, "stub").is_some());
    assert!(
        view(&agents, "Supervisor Agent").is_some(),
        "the Client is its own Agent (ADR-0018)"
    );
    // The two Supervisors run the *same* stub program, so they report the same Agent type — which
    // is what a type is for, and exactly why it cannot double as the name (ADR-0016). They stay
    // apart because the operator's name is its own attribute, out of reach of the fold.
    let otelcol_type = &view(&agents, "otelcol").expect("otelcol view").service_name;
    let stub_type = &view(&agents, "stub").expect("stub view").service_name;
    assert_eq!(
        otelcol_type, stub_type,
        "one program, one type — both blocks name the same stub binary"
    );
    assert!(
        !otelcol_type.is_empty(),
        "a type is reported even though neither block sets `service_name`: \
         the program's file name is the fallback"
    );
    let uids: std::collections::HashSet<_> = agents.iter().map(|a| &a.instance_uid).collect();
    assert_eq!(uids.len(), AGENTS, "each Agent has its own identity");

    // The Foreign Agent runs from the start; the Collector awaits its first configuration.
    let first_stub_pid = wait_until("the stub to run", || stub_pid(&stub_marker)).await;
    assert!(!otelcol_marker.exists(), "no config, no collector");
    let otelcol = view(&agents, "otelcol").expect("otelcol view");
    assert!(!otelcol.healthy);
    assert_eq!(otelcol.health_status, "awaiting configuration");

    // The operator distributes a Configuration for the supervised type, and a YAML one typed for
    // the Client itself — saved, put into a Deployment claiming all three, then rolled out,
    // because saving alone distributes nothing (ADR-0025, ADR-0034); the act assigns every Agent
    // the Deployment claims, fits each Configuration to its type, and the Server pushes the
    // release over the socket.
    common::save(&state, "fleet", "receivers: {}\n", otelcol_type);
    common::save(&state, "client-yaml", "receivers: {}\n", "supervisor");
    common::release_to_every_agent(&state, &["fleet", "client-yaml"]);

    // Both Supervisors acknowledge APPLIED and are in sync; the processes restarted on the
    // files. The Client's own Agent receives the one typed for it — its configuration is its
    // Supervisor set (ADR-0017), and a YAML body is not one: the Client refuses it loudly rather
    // than pretend it took effect.
    wait_until("the supervised agents in sync, the client refusing", || {
        let snapshot = state.snapshot();
        let supervised = ["otelcol", "stub"].iter().all(|name| {
            view(&snapshot, name).is_some_and(|a| a.in_sync && a.remote_config_status == "APPLIED")
        });
        let refused =
            view(&snapshot, "Supervisor Agent").is_some_and(|a| a.remote_config_status == "FAILED");
        (supervised && refused).then_some(())
    })
    .await;
    let collector_pid = wait_until("the collector to start on the new config", || {
        stub_pid(&otelcol_marker)
    })
    .await;
    assert!(collector_pid > 0);
    let restarted_stub_pid = wait_until("the stub to restart", || {
        stub_pid(&stub_marker).filter(|pid| *pid != first_stub_pid)
    })
    .await;
    assert_ne!(restarted_stub_pid, first_stub_pid);

    // The written entry files carry the Configuration's name (ADR-0023) and are what the
    // processes were pointed at.
    let collector_argv = std::fs::read_to_string(&otelcol_marker).expect("collector marker");
    assert!(collector_argv.contains("--config"));
    let stub_config = state_dir.join("supervisors/stub/config/fleet");
    assert_eq!(
        std::fs::read_to_string(stub_config).expect("the stub's written config"),
        "receivers: {}\n"
    );

    // Both Agents report healthy now.
    wait_until("both agents healthy", || {
        let snapshot = state.snapshot();
        snapshot.iter().all(|a| a.healthy).then_some(())
    })
    .await;

    // The probed process version arrived for both *supervised* Agents: the collector plugin
    // probes `--version` by itself, the command plugin because the block sets `version_args`. The
    // stub prints its SemVer inside free text ("stub_agent version 9.9.9 (test build)").
    wait_until("both supervised agents report the probed version", || {
        let snapshot = state.snapshot();
        ["otelcol", "stub"]
            .iter()
            .all(|name| view(&snapshot, name).is_some_and(|a| a.service_version == "9.9.9"))
            .then_some(())
    })
    .await;

    // The Client's own Agent reports the Client's version instead — never a Managed Process's,
    // because it has none (ADR-0018 makes it visible; ADR-0012 supplies the version).
    let snapshot = state.snapshot();
    let client_agent = view(&snapshot, "Supervisor Agent").expect("the client's own agent");
    assert_ne!(client_agent.service_version, "9.9.9");
    assert!(
        !client_agent.service_version.is_empty(),
        "the Client reports its own baked version"
    );

    // The Client-wide attributes arrived — they describe the *host*, so both Agents carry them
    // (ADR-0023).
    let agents = state.snapshot();
    let stub = view(&agents, "stub").expect("stub view");
    let otelcol = view(&agents, "otelcol").expect("otelcol view");
    for agent in [stub, otelcol] {
        assert_eq!(
            agent
                .non_identifying_attributes
                .get("env")
                .map(String::as_str),
            Some("prod"),
            "the host's own tag reaches every Agent on it"
        );
        assert!(
            !agent.non_identifying_attributes.contains_key("role"),
            "no block tags one Agent any more (ADR-0017)"
        );
    }

    // Tagging *one* Agent among several is the fleet's job now: one label, keyed by the Agent's
    // uid, matched by the same Selectors — and it takes effect without touching the host's file
    // (ADR-0024, ADR-0017).
    let uid = opamp::uid::InstanceUid::parse(&stub.instance_uid).expect("the uid the Server holds");
    assert!(state
        .set_labels(&uid, [("role".to_string(), "edge".to_string())].into())
        .is_ok());
    let agents = state.snapshot();
    assert_eq!(
        view(&agents, "stub")
            .expect("stub view")
            .labels
            .get("role")
            .map(String::as_str),
        Some("edge")
    );
    assert!(!view(&agents, "otelcol")
        .expect("otelcol view")
        .labels
        .contains_key("role"));

    // …and a Deployment aimed at it reaches that Agent and no other. The label replaced the
    // Agent's labels, so the stub has left the fleet-wide channel: an Agent belongs to one
    // Deployment, and this one holds both Configurations (ADR-0034).
    common::save(&state, "edge-extra", "processors: {}\n", otelcol_type);
    assert_eq!(
        common::release(
            &state,
            "edge",
            &[("role", "edge")],
            &["fleet", "edge-extra"]
        ),
        1,
        "the edge Deployment claims the stub alone"
    );
    wait_until("the stub to apply both entries", || {
        let snapshot = state.snapshot();
        let stub = view(&snapshot, "stub")?;
        (stub.in_sync
            && stub.matched_configurations == ["edge-extra", "fleet"]
            && stub.remote_config_status == "APPLIED")
            .then_some(())
    })
    .await;
    wait_until("the collector to stay on the fleet configuration", || {
        let snapshot = state.snapshot();
        let otelcol = view(&snapshot, "otelcol")?;
        (otelcol.in_sync && otelcol.matched_configurations == ["fleet"]).then_some(())
    })
    .await;
    let stub_extra = state_dir.join("supervisors/stub/config/edge-extra");
    assert_eq!(
        std::fs::read_to_string(stub_extra).expect("the stub's second entry file"),
        "processors: {}\n"
    );

    // Heartbeats (ReportsHeartbeat, 1 s in this test): with nothing left to change, every
    // Agent's sequence number keeps advancing and the description survives — routine reports,
    // not ReportFullState churn.
    let quiesced: Vec<(String, u64)> = state
        .snapshot()
        .iter()
        .map(|a| (a.instance_uid.clone(), a.sequence_num))
        .collect();
    assert!(state
        .snapshot()
        .iter()
        .all(|a| a.capabilities.iter().any(|c| c == "ReportsHeartbeat")));
    wait_until(
        "heartbeats to advance every agent's sequence number",
        || {
            let snapshot = state.snapshot();
            quiesced
                .iter()
                .all(|(uid, seq)| {
                    snapshot.iter().any(|a| {
                        &a.instance_uid == uid
                            && a.sequence_num > *seq
                            && !a.service_name.is_empty()
                    })
                })
                .then_some(())
        },
    )
    .await;

    // ——— The Server manages the Client's own Supervisor set (ADR-0017) ———

    // The YAML Configuration typed for the Client keeps poisoning its composed map. A pinned
    // Configuration cannot be deleted (ADR-0034), and taking it out of the Deployment withdraws
    // nothing already rolled out (ADR-0025) — the Client keeps its pinned assignment until the
    // next press. So the recovery is to take it out and press the Deployments again: the Client's
    // release drops it, while the Supervisors' revision — body and role unchanged — keeps its hash.
    assert!(
        state.delete_configuration("client-yaml").is_err(),
        "a pinned Configuration is not deleted"
    );
    state
        .remove_deployment_configuration(common::FLEET_DEPLOYMENT, "client-yaml")
        .expect("take it out of the Deployment");
    for deployment in [common::FLEET_DEPLOYMENT, "edge"] {
        state
            .rollout_deployment(deployment)
            .expect("roll out without it");
    }
    wait_until("the supervised agents to settle on the fleet map", || {
        let snapshot = state.snapshot();
        ["otelcol", "stub"]
            .iter()
            .all(|name| {
                view(&snapshot, name).is_some_and(|a| {
                    a.in_sync
                        && a.remote_config_status == "APPLIED"
                        && a.assigned_configurations.iter().any(|c| c == "fleet")
                })
            })
            .then_some(())
    })
    .await;

    // A Configuration typed for the Client itself carries `[[supervisor]]` blocks: the running
    // two, verbatim, plus a third. Unchanged blocks ride through — the stub must keep its pid.
    let added_marker = dir.path().join("added-marker");
    let added_block = format!(
        concat!(
            "[[supervisor]]\n",
            "type = \"command\"\n",
            "name = \"added\"\n",
            "command = {program:?}\n",
            "args = [\"--touch\", {added_marker:?}]\n",
        ),
        program = program,
        added_marker = added_marker.to_string_lossy(),
    );
    // The added Supervisor is owned too (ADR-0017): stage its program before the set is delivered,
    // so the block the Server pushes starts a process instead of waiting for a package.
    stage_owned_program(&state_dir, "added", &program);
    let stub_pid_before = stub_pid(&stub_marker).expect("the stub runs");
    common::save(
        &state,
        "client-supervisors",
        &format!("{otelcol_block}\n{stub_block}\n{added_block}"),
        "supervisor",
    );
    common::release(
        &state,
        common::FLEET_DEPLOYMENT,
        &[common::CHANNEL],
        &["client-supervisors"],
    );

    wait_until("the added supervisor to connect, the set applied", || {
        let snapshot = state.snapshot();
        let added = view(&snapshot, "added").is_some_and(|a| a.connected);
        let applied = view(&snapshot, "Supervisor Agent")
            .is_some_and(|a| a.in_sync && a.remote_config_status == "APPLIED");
        (added && applied).then_some(())
    })
    .await;
    let _ = wait_until("the added stub to run", || stub_pid(&added_marker)).await;
    let rewritten = std::fs::read_to_string(&config_path).expect("read back supervisor.toml");
    assert!(rewritten.contains("name = \"added\""), "{rewritten}");
    assert!(
        rewritten.contains("env = \"prod\"") && rewritten.contains("heartbeat_interval_secs = 1"),
        "the operator's globals survive the rewrite: {rewritten}"
    );
    assert_eq!(
        stub_pid(&stub_marker),
        Some(stub_pid_before),
        "an unchanged supervisor rides through the apply untouched"
    );

    // Removing the block stops its Supervisor and retires its Agent: the goodbye arrives, the
    // file no longer names it — and the unchanged neighbours still ride through.
    common::save(
        &state,
        "client-supervisors",
        &format!("{otelcol_block}\n{stub_block}"),
        "supervisor",
    );
    state
        .rollout_deployment(common::FLEET_DEPLOYMENT)
        .expect("roll out the shrunken set");

    wait_until("the added supervisor to say goodbye", || {
        let snapshot = state.snapshot();
        let gone = view(&snapshot, "added").is_some_and(|a| !a.connected);
        let applied = view(&snapshot, "Supervisor Agent")
            .is_some_and(|a| a.in_sync && a.remote_config_status == "APPLIED");
        (gone && applied).then_some(())
    })
    .await;
    let rewritten = std::fs::read_to_string(&config_path).expect("read back supervisor.toml");
    assert!(!rewritten.contains("\"added\""), "{rewritten}");
    assert_eq!(
        stub_pid(&stub_marker),
        Some(stub_pid_before),
        "the unchanged supervisors ride through the removal too"
    );

    // A removed Supervisor is purged (ADR-0017): its whole directory — identity, program, written
    // configuration — goes with it, while the supervisors that stay keep theirs.
    wait_until("the removed supervisor's directory to be purged", || {
        (!state_dir.join("supervisors/added").exists()).then_some(())
    })
    .await;
    assert!(
        state_dir.join("supervisors/stub/instance-uid").is_file(),
        "a supervisor that stays keeps its directory and identity"
    );
}

/// A delivered Supervisor set with one block the Client refuses is refused whole: the running
/// Supervisor keeps its process, `supervisor.toml` keeps every byte, and the Client's own Agent
/// reports the refusal.
/// Verifies: ADR-0017
#[tokio::test]
async fn a_refused_supervisor_set_leaves_the_running_supervisors_untouched() {
    let (addr, state, dir) = spawn_server().await;
    let state_dir: PathBuf = dir.path().join("client-state");
    let marker = dir.path().join("stub-marker");
    let program = stub_program_name();
    let toml = format!(
        concat!(
            "endpoint = \"ws://{addr}/v1/opamp\"\n",
            "state_dir = {state:?}\n",
            "heartbeat_interval_secs = 1\n\n",
            // Consent to delivered arguments, so the one refusal is the unknown kind.
            "[supervisors]\n",
            "delivered_args = true\n\n",
            "[[supervisor]]\n",
            "type = \"command\"\n",
            "name = \"stub\"\n",
            "command = {program:?}\n",
            "args = [\"--touch\", {marker:?}]\n",
        ),
        addr = addr,
        state = state_dir.to_string_lossy(),
        program = program,
        marker = marker.to_string_lossy(),
    );
    let config_path = dir.path().join("supervisor.toml");
    std::fs::write(&config_path, toml + &common::client_identity(dir.path())).expect("write");
    let written = std::fs::read(&config_path).expect("read");
    stage_owned_program(&state_dir, "stub", &program);
    let _client = spawn_client(&config_path);

    let pid = wait_until("the stub to run", || stub_pid(&marker)).await;
    wait_until("the Client's own Agent", || {
        view(&state.snapshot(), "Supervisor Agent").map(|_| ())
    })
    .await;

    // The stub with other arguments — applied, it would restart — beside a kind no Client has.
    let offered = format!(
        concat!(
            "[[supervisor]]\n",
            "type = \"command\"\n",
            "name = \"stub\"\n",
            "command = {program:?}\n",
            "args = [\"--touch\", {marker:?}, \"--changed\"]\n\n",
            "[[supervisor]]\n",
            "type = \"shell\"\n",
            "name = \"intruder\"\n",
            "command = \"sh\"\n",
        ),
        program = program,
        marker = marker.to_string_lossy(),
    );
    common::save(&state, "supervisor-set", &offered, "supervisor");
    common::release_to_every_agent(&state, &["supervisor-set"]);

    let refusal = wait_until("the Client to refuse the set", || {
        view(&state.snapshot(), "Supervisor Agent")
            .filter(|agent| agent.remote_config_status == "FAILED")
            .map(|agent| agent.remote_config_error.clone())
    })
    .await;
    assert!(
        refusal.contains("shell"),
        "the refusal names the kind: {refusal}"
    );

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        stub_pid(&marker),
        Some(pid),
        "the running Supervisor was restarted"
    );
    assert_eq!(
        std::fs::read(&config_path).expect("read"),
        written,
        "supervisor.toml changed"
    );
    assert!(
        view(&state.snapshot(), "intruder").is_none(),
        "the refused block started"
    );
}

/// ADR-0017 over one connection: a released Configuration reaches the unlisted Supervisor and not
/// the listed one, whose Agent declares neither remote-configuration capability. Switched back on,
/// the next start declares both, is offered what is released, and the stored offer replaces every
/// file in `config/`, the operator's included (clauses 3 and 8).
/// Verifies: ADR-0017
#[tokio::test]
async fn a_server_offers_no_configuration_to_a_listed_supervisor() {
    let (addr, state, dir) = spawn_server().await;
    let state_dir: PathBuf = dir.path().join("client-state");
    let program = stub_program_name();
    let block = |name: &str| {
        format!(
            "[[supervisor]]\ntype = \"command\"\nname = {name:?}\ncommand = {program:?}\n\
             args = [\"--touch\", {marker:?}]\n\n",
            marker = dir.path().join(format!("{name}-marker")).to_string_lossy(),
        )
    };
    let write_config = |listed: &str| {
        let toml = format!(
            "endpoint = \"ws://{addr}/v1/opamp\"\nstate_dir = {state:?}\n\
             heartbeat_interval_secs = 1\n\n[supervisors]\nremote_config_disabled = {listed}\n\n\
             {open}{closed}",
            state = state_dir.to_string_lossy(),
            open = block("open"),
            closed = block("closed"),
        );
        let path = dir.path().join("supervisor.toml");
        std::fs::write(&path, toml + &common::client_identity(dir.path()))
            .expect("write supervisor.toml");
        path
    };
    stage_owned_program(&state_dir, "open", &program);
    stage_owned_program(&state_dir, "closed", &program);
    let operators_file = state_dir.join("supervisors/closed/config/local.conf");
    std::fs::create_dir_all(operators_file.parent().expect("config/")).expect("config/");
    std::fs::write(&operators_file, "mine\n").expect("the operator's file");

    let client = spawn_client(&write_config("[\"closed\"]"));
    wait_until("every agent connected", || {
        let snapshot = state.snapshot();
        (snapshot.len() == AGENTS && snapshot.iter().all(|a| a.connected)).then_some(())
    })
    .await;
    let declares = |name: &str, capability: &str| {
        view(&state.snapshot(), name)
            .is_some_and(|a| a.capabilities.iter().any(|c| c == capability))
    };
    assert!(declares("open", "AcceptsRemoteConfig"));
    for capability in ["AcceptsRemoteConfig", "ReportsRemoteConfig"] {
        assert!(
            !declares("closed", capability),
            "closed declares {capability}"
        );
    }
    assert!(declares("closed", "ReportsEffectiveConfig"));

    // Both run the same program, so they report one Agent type, which the Configuration is for.
    let supervised_type = view(&state.snapshot(), "open")
        .expect("open view")
        .service_name
        .clone();
    common::save(&state, "fleet", "receivers: {}\n", &supervised_type);
    common::release_to_every_agent(&state, &["fleet"]);
    wait_until("the unlisted Supervisor in sync", || {
        view(&state.snapshot(), "open")
            .filter(|a| a.in_sync && a.remote_config_status == "APPLIED")
            .map(|_| ())
    })
    .await;
    // Over the same connection, a few exchanges later: still nothing for the listed one.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let snapshot = state.snapshot();
    let closed = view(&snapshot, "closed").expect("closed view");
    assert_eq!(
        closed.remote_config_status, "UNSET",
        "no status from the listed Supervisor"
    );
    assert!(!state_dir.join("supervisors/closed/config/fleet").exists());
    assert!(!state_dir
        .join("supervisors/closed/remote-config.pb")
        .exists());
    assert!(operators_file.is_file());

    // Switched back on: the next start declares both and takes what is released.
    drop(client);
    let _client = spawn_client(&write_config("[]"));
    wait_until(
        "the formerly listed Supervisor to apply the release",
        || {
            view(&state.snapshot(), "closed")
                .filter(|a| {
                    a.connected
                        && a.remote_config_status == "APPLIED"
                        && a.capabilities.iter().any(|c| c == "AcceptsRemoteConfig")
                })
                .map(|_| ())
        },
    )
    .await;
    assert_eq!(
        std::fs::read_to_string(state_dir.join("supervisors/closed/config/fleet"))
            .expect("the stored entry"),
        "receivers: {}\n"
    );
    assert!(
        !operators_file.exists(),
        "the first stored offer replaces every file in config/"
    );
}

/// ADR-0017 over one connection: a host that keeps its Supervisor set is offered none. A released
/// set that would add a block reaches neither `supervisor.toml` nor the running Supervisors, and
/// the Client's own Agent declares neither remote-configuration capability and reports no status.
/// Switched back on, the next start is offered the released set, and it replaces the
/// `[[supervisor]]` array, the operator's block included (clauses 22, 25 and 27).
/// Verifies: ADR-0017
#[tokio::test]
async fn a_server_offers_no_supervisor_set_to_a_host_that_keeps_it() {
    let (addr, state, dir) = spawn_server().await;
    let state_dir: PathBuf = dir.path().join("client-state");
    let marker = dir.path().join("stub-marker");
    let program = stub_program_name();
    let config_path = dir.path().join("supervisor.toml");
    let write_config = |server_manages_set: bool| {
        let toml = format!(
            concat!(
                "endpoint = \"ws://{addr}/v1/opamp\"\n",
                "state_dir = {state:?}\n",
                "heartbeat_interval_secs = 1\n\n",
                "[supervisors]\n",
                "server_manages_set = {manages}\n\n",
                "[[supervisor]]\n",
                "type = \"command\"\n",
                "name = \"stub\"\n",
                "command = {program:?}\n",
                "args = [\"--touch\", {marker:?}]\n",
            ),
            addr = addr,
            state = state_dir.to_string_lossy(),
            manages = server_manages_set,
            program = program,
            marker = marker.to_string_lossy(),
        );
        std::fs::write(&config_path, toml + &common::client_identity(dir.path()))
            .expect("write supervisor.toml");
        std::fs::read(&config_path).expect("read")
    };
    let written = write_config(false);
    stage_owned_program(&state_dir, "stub", &program);
    let client = spawn_client(&config_path);

    let pid = wait_until("the stub to run", || stub_pid(&marker)).await;
    let capabilities = wait_until("the Client's own Agent", || {
        view(&state.snapshot(), "Supervisor Agent")
            .filter(|a| a.connected)
            .map(|a| a.capabilities.clone())
    })
    .await;
    for capability in ["AcceptsRemoteConfig", "ReportsRemoteConfig"] {
        assert!(
            !capabilities.iter().any(|c| c == capability),
            "the Client's own Agent declares {capability}"
        );
    }
    assert!(capabilities.iter().any(|c| c == "ReportsEffectiveConfig"));

    common::save(
        &state,
        "supervisor-set",
        &format!("[[supervisor]]\ntype = \"command\"\nname = \"added\"\ncommand = {program:?}\n"),
        "supervisor",
    );
    common::release_to_every_agent(&state, &["supervisor-set"]);

    // A few exchanges later: nothing reached the host.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let snapshot = state.snapshot();
    let own = view(&snapshot, "Supervisor Agent").expect("own view");
    assert_eq!(own.remote_config_status, "UNSET", "a status from the host");
    assert!(
        view(&snapshot, "added").is_none(),
        "the released block started"
    );
    assert_eq!(
        std::fs::read(&config_path).expect("read"),
        written,
        "supervisor.toml changed"
    );
    assert_eq!(
        stub_pid(&marker),
        Some(pid),
        "the running Supervisor was restarted"
    );
    assert!(!state_dir.join("remote-config.pb").exists());

    // Switched back on: the next start takes the released set, which replaces the operator's.
    drop(client);
    write_config(true);
    let _client = spawn_client(&config_path);
    wait_until("the Client to apply the released set", || {
        view(&state.snapshot(), "Supervisor Agent")
            .filter(|a| {
                a.connected
                    && a.remote_config_status == "APPLIED"
                    && a.capabilities.iter().any(|c| c == "AcceptsRemoteConfig")
            })
            .map(|_| ())
    })
    .await;
    let rewritten = std::fs::read_to_string(&config_path).expect("read");
    assert!(rewritten.contains("name = \"added\""), "{rewritten}");
    assert!(!rewritten.contains("name = \"stub\""), "{rewritten}");
    assert!(
        rewritten.contains("server_manages_set = true"),
        "{rewritten}"
    );
}
