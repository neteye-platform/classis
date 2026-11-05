//! The supervision `Runner` (ADR-0017) across everything it does *to a host*: spawn and watchdog,
//! the health-gated apply, the binary swap and its rollback (ADR-0026), and the tree install
//! (ADR-0026).
//!
//! An integration test rather than a unit test, and that is the reason ADR-0010 exists: these cases
//! need the supervision core **and** a real program to spawn, and Cargo hands a test the path of a
//! helper binary "only … when building an integration test or benchmark". As unit tests inside a
//! binary crate they could reach no such program, so they ran `/bin/sh` scripts and were gated to
//! Unix — leaving the swap, the gate and the rollback asserted by nothing on the two platforms
//! where a failed install is hardest to inspect.
//!
//! The two stubs are the vocabulary: [`stub_agent`] stays up until it is killed, [`stub_crasher`]
//! exits at once. Which one's *bytes* an artifact carries is what decides whether an install
//! survives its grace, said in a form all three platforms can execute.

use std::path::{Path, PathBuf};
use std::time::Duration;

use fleet_agent::config::TREE_DIR;
use fleet_agent::shutdown::{shutdown_channel, Shutdown};
use fleet_agent::supervisor::ports::{EventSender, InstallTarget, ProcessCommand, ProcessEvent};
use fleet_agent::supervisor::process::{
    probe_version, Preflight, ProcessSpec, Runner, Spawner, VersionProbe,
};
use opamp::proto::{AgentRemoteConfig, ComponentHealth};
use tokio::sync::mpsc;

/// The program a Supervisor is configured with, named the way this platform needs it: Windows
/// appends `.exe` when told a path without an extension, and would not find a file that lacks it.
fn program_name(stem: &str) -> String {
    format!("{stem}{}", std::env::consts::EXE_SUFFIX)
}

/// A Managed Process that runs until it is stopped.
fn stub_agent() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_stub_agent"))
}

/// A Managed Process that exits non-zero at once.
fn stub_crasher() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_stub_crasher"))
}

fn bytes_of(program: &Path) -> Vec<u8> {
    std::fs::read(program).expect("read a stub binary")
}

/// A spec running the given program with no arguments — the behaviour is the program's own, which
/// is what lets an *installed artifact* decide it.
fn spec(program: &Path) -> ProcessSpec {
    ProcessSpec {
        program: program.to_path_buf(),
        args: Vec::new(),
        env: Vec::new(),
        working_dir: None,
        own_process_group: false,
        ensure_dirs: Vec::new(),
    }
}

/// Who starts the Managed Process under test (ADR-0059): the Client itself, or the second service
/// through its channel. The supervision is the same either way, so every case that runs a process
/// runs against both — [`both!`] makes the pair.
#[derive(Debug, Clone, Copy)]
enum Via {
    Local,
    #[cfg(unix)]
    Channel,
}

/// Runs the case `$name(via)` once per [`Via`], as `$name::local` and `$name::channel`. The channel
/// case runs the second service in this process on a socket in a temporary directory, under this
/// test's own uid, which is the uid it admits.
/// Verifies: ADR-0059
macro_rules! both {
    ($(#[$attr:meta])* $name:ident) => {
        $(#[$attr])*
        mod $name {
            #[tokio::test]
            async fn local() {
                super::$name(super::Via::Local).await;
            }
            #[cfg(unix)]
            #[tokio::test]
            async fn channel() {
                super::$name(super::Via::Channel).await;
            }
        }
    };
}

/// The second service a channel case runs against; stopped, with whatever it still runs, when the
/// case ends.
struct AgentsService {
    _dir: tempfile::TempDir,
    task: tokio::task::AbortHandle,
}

impl Drop for AgentsService {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The process this test runs as, named as the second service's: the in-process services run in
/// it (ADR-0059 clause 4).
#[cfg(unix)]
fn this_process() -> fleet_agent::supervisor::channel::ServiceProcess {
    fleet_agent::supervisor::channel::ServiceProcess::named(|| Ok(Some(std::process::id())))
}

/// Starts `runner` with the spawner `via` names, the second service first where it is one.
fn launch(
    via: Via,
    runner: Runner,
    shutdown: Shutdown,
) -> (tokio::task::JoinHandle<()>, Option<AgentsService>) {
    match via {
        Via::Local => (tokio::spawn(runner.run(shutdown)), None),
        #[cfg(unix)]
        Via::Channel => {
            use fleet_agent::supervisor::channel::{bind, serve, Channel};
            let dir = tempfile::tempdir().expect("tempdir");
            let socket = dir.path().join("agents.sock");
            let listener = bind(&socket).expect("bind the agents socket");
            // SAFETY: getuid(2) cannot fail and touches no memory.
            let uid = unsafe { libc::getuid() };
            let service = tokio::spawn(serve(listener, uid, || false, std::future::pending()));
            let mut runner = runner;
            let task = tokio::spawn(async move {
                let channel = Channel::connect(&socket, uid, this_process())
                    .await
                    .expect("connect to the second service");
                runner.spawner = Spawner::Channel(channel);
                runner.run(shutdown).await;
            });
            (
                task,
                Some(AgentsService {
                    _dir: dir,
                    task: service.abort_handle(),
                }),
            )
        }
    }
}

struct Harness {
    commands: mpsc::Sender<ProcessCommand>,
    events: mpsc::Receiver<(usize, ProcessEvent)>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    _service: Option<AgentsService>,
}

/// A `Runner` with everything the test does not care about filled in. `install` and `apply_grace`
/// are what the package tests vary; `version_probe` is set only where the probe is the subject.
fn runner(
    via: Via,
    install: Option<InstallTarget>,
    apply_grace: Duration,
    version_probe: Option<VersionProbe>,
    build: impl Fn() -> Option<ProcessSpec> + Send + Sync + 'static,
) -> Harness {
    runner_retaining(
        via,
        install,
        apply_grace,
        Duration::ZERO,
        version_probe,
        build,
    )
}

fn runner_retaining(
    via: Via,
    install: Option<InstallTarget>,
    apply_grace: Duration,
    retain_previous: Duration,
    version_probe: Option<VersionProbe>,
    build: impl Fn() -> Option<ProcessSpec> + Send + Sync + 'static,
) -> Harness {
    runner_full(
        via,
        install,
        apply_grace,
        retain_previous,
        version_probe,
        None,
        None,
        build,
    )
}

#[allow(clippy::too_many_arguments)]
fn runner_full(
    via: Via,
    install: Option<InstallTarget>,
    apply_grace: Duration,
    retain_previous: Duration,
    version_probe: Option<VersionProbe>,
    preflight: Option<Preflight>,
    reload_signal: Option<i32>,
    build: impl Fn() -> Option<ProcessSpec> + Send + Sync + 'static,
) -> Harness {
    let (event_tx, events) = mpsc::channel(64);
    let (commands, command_rx) = mpsc::channel(16);
    let (shutdown_tx, shutdown) = shutdown_channel();
    let runner = Runner {
        endpoint_token: zeroize::Zeroizing::default(),
        name: "test".to_string(),
        stop_timeout: Duration::from_secs(5),
        apply_grace,
        retain_previous,
        install,
        archive_key: None,
        version_probe,
        preflight,
        reload_signal,
        spawner: Spawner::Local,
        process_account_group: None,
        supervisor_dir: std::env::temp_dir(),
        events: EventSender::new(0, event_tx),
        commands: command_rx,
        build: Box::new(build),
    };
    let (task, service) = launch(via, runner, shutdown);
    Harness {
        commands,
        events,
        shutdown_tx,
        task,
        _service: service,
    }
}

/// Zero grace: the pre-grace instant acknowledgement most supervision tests exercise.
fn start(via: Via, build: impl Fn() -> Option<ProcessSpec> + Send + Sync + 'static) -> Harness {
    runner(via, None, Duration::ZERO, None, build)
}

fn start_with_grace(
    via: Via,
    apply_grace: Duration,
    build: impl Fn() -> Option<ProcessSpec> + Send + Sync + 'static,
) -> Harness {
    runner(via, None, apply_grace, None, build)
}

async fn next_health(events: &mut mpsc::Receiver<(usize, ProcessEvent)>) -> ComponentHealth {
    loop {
        let (_, event) = tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("an event in time")
            .expect("an open channel");
        if let ProcessEvent::Health(health) = event {
            return health;
        }
    }
}

async fn next_ack(
    events: &mut mpsc::Receiver<(usize, ProcessEvent)>,
) -> (Vec<u8>, Result<(), String>) {
    loop {
        let (_, event) = tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("an event in time")
            .expect("an open channel");
        if let ProcessEvent::ConfigApplied { hash, result } = event {
            return (hash, result);
        }
    }
}

async fn next_package_ack(
    events: &mut mpsc::Receiver<(usize, ProcessEvent)>,
) -> (Vec<u8>, Result<String, String>) {
    loop {
        let (_, event) = tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("an event in time")
            .expect("an open channel");
        if let ProcessEvent::PackageApplied { hash, result } = event {
            return (hash, result);
        }
    }
}

async fn apply(harness: &Harness, hash: &[u8]) {
    harness
        .commands
        .send(ProcessCommand::ApplyConfig {
            config: AgentRemoteConfig {
                config_hash: hash.to_vec(),
                ..Default::default()
            },
            // The apply's span (ADR-0016). The core opens a real one; a test drives the Runner
            // directly, so what it hands over is the span it is already running in.
            span: tracing::Span::current(),
        })
        .await
        .expect("send the command");
}

async fn apply_package(
    harness: &mut Harness,
    staged: &Path,
    version: &str,
) -> (Vec<u8>, Result<String, String>) {
    harness
        .commands
        .send(ProcessCommand::ApplyPackage {
            staged: staged.to_path_buf(),
            version: version.to_string(),
            hash: version.as_bytes().to_vec(),
            span: tracing::Span::current(),
        })
        .await
        .expect("send");
    next_package_ack(&mut harness.events).await
}

// ── The directories an agent writes into ─────────────────────────────────────

/// An agent the fleet delivers arrives on a host nobody prepared, and several of the agents this
/// project wraps create nothing themselves: Icinga 2 exits when `DataDir` is absent, the GLPI Agent
/// exits when `--vardir` is. So the kind names what its agent writes into and the spawn makes it —
/// otherwise a correct installation ends in a crash loop over a missing directory.
async fn the_directories_an_agent_writes_into_are_made_before_it_runs(via: Via) {
    let dir = tempfile::tempdir().expect("tempdir");
    // Two levels deep and nested under a parent that does not exist either, because the failure
    // this prevents is exactly the one nobody created a parent for.
    let state = dir.path().join("agent-state").join("inventory");
    let program = PathBuf::from(env!("CARGO_BIN_EXE_stub_agent"));
    let marker = dir.path().join("started");
    assert!(!state.exists());

    let mut harness = start(via, {
        let (state, program, marker) = (state.clone(), program.clone(), marker.clone());
        move || {
            Some(ProcessSpec {
                program: program.clone(),
                args: vec!["--touch".to_string(), marker.display().to_string()],
                env: Vec::new(),
                working_dir: None,
                own_process_group: false,
                ensure_dirs: vec![state.clone()],
            })
        }
    });
    let _ = next_health(&mut harness.events).await;
    wait_until_started(&marker).await;
    assert!(
        state.is_dir(),
        "the agent's own directory was not made for it"
    );

    // And made again on the next spawn, so one an operator removed under a running fleet comes
    // back instead of taking the Supervisor down.
    std::fs::remove_dir_all(&state).expect("remove it under the running process");
    std::fs::remove_file(&marker).expect("clear the marker");
    apply(&harness, b"hash").await;
    wait_until_started(&marker).await;
    assert!(
        state.is_dir(),
        "a removed directory did not come back on the restart"
    );

    harness.shutdown_tx.send(true).expect("shutdown");
    harness.task.await.expect("join");
}
both!(the_directories_an_agent_writes_into_are_made_before_it_runs);

/// A program named by a **relative** path starts, though the process begins in its own directory
/// (ADR-0017).
///
/// `Command` does `chdir` *before* `exec` on Unix, so a relative program is resolved against the
/// directory it was just moved into: `<dir>/<dir>/<program>`, which is nothing. The Client's own
/// default makes this the ordinary case rather than a corner — `state_dir = "client-state"` is
/// relative, so every Managed Process under a default configuration would fail to spawn, with a
/// bare `No such file or directory` naming a file that is plainly there.
async fn a_program_named_by_a_relative_path_still_starts_in_its_own_directory(via: Via) {
    // **Under** this test's working directory, so the relative path is a plain descent with no
    // `..` in it — which is what a Client's own `state_dir = "client-state"` looks like, and what
    // makes the fixture mean the same thing on every platform. Counting `..` to the root does not:
    // it is drive-relative on Windows, and exactly as many as the new working directory is deep
    // climb back out to the same file, so the test would pass whether or not the path is made
    // absolute.
    let here = std::env::current_dir().expect("cwd");
    let dir = tempfile::tempdir_in(&here).expect("tempdir under the working directory");
    let program_dir = dir.path().join("a/b/c/d/program");
    std::fs::create_dir_all(&program_dir).expect("program dir");
    let program = program_dir.join(program_name("stub_agent"));
    std::fs::copy(stub_agent(), &program).expect("copy the stub");

    let relative = program
        .strip_prefix(&here)
        .expect("the fixture lives under the working directory")
        .to_path_buf();
    assert!(relative.is_relative());
    assert!(
        !program_dir.join(&relative).exists(),
        "the test must stage the failure: resolved from the program's own directory this path has \
         to point at nothing, or it passes for the wrong reason"
    );

    let marker = dir.path().join("started");
    let mut harness = start(via, {
        let (relative, marker) = (relative.clone(), marker.clone());
        move || {
            Some(ProcessSpec {
                program: relative.clone(),
                args: vec!["--touch".to_string(), marker.display().to_string()],
                env: Vec::new(),
                working_dir: None,
                own_process_group: false,
                ensure_dirs: Vec::new(),
            })
        }
    });
    let _ = next_health(&mut harness.events).await;
    wait_until_started(&marker).await;

    harness.shutdown_tx.send(true).expect("shutdown");
    harness.task.await.expect("join");
}
both!(a_program_named_by_a_relative_path_still_starts_in_its_own_directory);

// ── The version probe ────────────────────────────────────────────────────────

#[tokio::test]
async fn the_probe_reports_a_version_description() {
    let (event_tx, mut events) = mpsc::channel(4);
    probe_version(
        Spawner::Local,
        "test".to_string(),
        stub_agent(),
        vec!["--version".to_string()],
        None,
        EventSender::new(0, event_tx),
    )
    .await;
    let (_, event) = events.recv().await.expect("a probed description");
    let ProcessEvent::Description(description) = event else {
        panic!("expected a Description event, got {event:?}");
    };
    assert_eq!(description.identifying_attributes[0].key, "service.version");
}

#[tokio::test]
async fn a_failing_or_versionless_probe_stays_silent() {
    let (event_tx, mut events) = mpsc::channel(4);
    probe_version(
        Spawner::Local,
        "test".to_string(),
        PathBuf::from("nonexistent-definitely-not-here"),
        vec![],
        None,
        EventSender::new(0, event_tx.clone()),
    )
    .await;
    // Runs, says nothing a version can be read out of, and exits: a Foreign Agent whose version
    // flag is not the one the operator configured.
    probe_version(
        Spawner::Local,
        "test".to_string(),
        stub_agent(),
        vec!["--exit-code".to_string(), "0".to_string()],
        None,
        EventSender::new(0, event_tx),
    )
    .await;
    assert!(
        events.try_recv().is_err(),
        "neither probe may emit an event"
    );
}

async fn next_probed_version(events: &mut mpsc::Receiver<(usize, ProcessEvent)>) -> Option<String> {
    loop {
        let (_, event) = tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("a probed description in time")
            .expect("an open channel");
        if let ProcessEvent::Description(description) = event {
            return description
                .identifying_attributes
                .iter()
                .find(|kv| kv.key == "service.version")
                .and_then(|kv| kv.value.clone())
                .and_then(|v| v.value)
                .map(|v| match v {
                    opamp::proto::any_value::Value::StringValue(s) => s,
                    other => panic!("expected a string version, got {other:?}"),
                });
        }
    }
}

/// A swapped program is a different program, and only the program knows its own version — so the
/// swap has to ask again. Without this the Agent reports the package as installed while going on
/// describing the version it replaced (or none at all, on a first install onto an empty
/// `program/`), and only a restart of the Client ever corrects it.
///
/// Both probes here read the same stub and therefore the same version; what the second event
/// proves is that the swap asked at all, which is the whole of the regression. Draining the
/// startup probe's answer first is what makes "the second one" mean something: one probe emits at
/// most one event, so anything arriving after it was asked by the swap.
async fn a_swapped_binary_is_probed_again_for_its_version(via: Via) {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join(program_name("agent"));
    std::fs::write(&binary, bytes_of(&stub_agent())).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    let staged = dir.path().join("downloaded.staged");
    std::fs::write(&staged, bytes_of(&stub_agent())).expect("stage");

    let mut harness = runner(
        via,
        Some(InstallTarget::Binary(binary.clone())),
        Duration::from_millis(200),
        Some(VersionProbe {
            program: binary.clone(),
            args: vec!["--version".to_string()],
            parse: None,
        }),
        || None, // an unconfigured Collector: nothing runs, the version is still owed
    );
    assert_eq!(
        next_probed_version(&mut harness.events).await.as_deref(),
        Some("9.9.9"),
        "the startup probe reports what is on disk before the swap"
    );

    let (_, result) = apply_package(&mut harness, &staged, "9.9.9").await;
    assert_eq!(result, Ok("9.9.9".to_string()));
    assert_eq!(
        next_probed_version(&mut harness.events).await.as_deref(),
        Some("9.9.9"),
        "the swap must ask the newly installed program for its version"
    );

    harness.shutdown_tx.send(true).expect("shutdown");
    let _ = harness.task.await;
}
both!(a_swapped_binary_is_probed_again_for_its_version);

// ── The second service (ADR-0059) ────────────────────────────────────────────

/// The shipped program is the second service under `run --agents`. It will not serve its own
/// account as the Client's (ADR-0059 clause 1); serving another, it refuses this test at the socket
/// and ends cleanly on `SIGTERM`. A program started through it needs a second account to connect
/// from; the cases above run the same service in-process, under this test's own uid.
/// Verifies: ADR-0059
#[cfg(unix)]
#[tokio::test]
async fn the_shipped_program_serves_as_the_second_service() {
    use fleet_agent::supervisor::channel::{Channel, ServiceProcess};

    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("agents.sock");
    // SAFETY: getuid(2) cannot fail and touches no memory.
    let uid = unsafe { libc::getuid() };

    let own = tokio::process::Command::new(env!("CARGO_BIN_EXE_supervisor"))
        .args(["run", "--agents"])
        .arg(&socket)
        .args(["--client-uid", &uid.to_string()])
        .output()
        .await
        .expect("run the second service");
    assert!(!own.status.success(), "it served its own account");
    assert!(
        String::from_utf8_lossy(&own.stderr).contains("process account"),
        "{}",
        String::from_utf8_lossy(&own.stderr)
    );
    assert!(!socket.exists(), "it listened anyway");

    let mut service = tokio::process::Command::new(env!("CARGO_BIN_EXE_supervisor"))
        .args(["run", "--agents"])
        .arg(&socket)
        .args(["--client-uid", &uid.wrapping_add(1).max(1).to_string()])
        .kill_on_drop(true)
        .spawn()
        .expect("start the second service");
    // The service is this test's child, which the test names as the second service's process.
    let pid = service.id().expect("running");
    let named = ServiceProcess::named(move || Ok(Some(pid)));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match Channel::connect(&socket, uid, named.clone()).await {
            Ok(_) => panic!("a connection from another uid was served"),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => break,
            Err(e) => {
                assert!(std::time::Instant::now() < deadline, "never listened: {e}");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }

    let pid = pid as libc::pid_t;
    // SAFETY: plain kill(2) on the service's pid; no memory is touched.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    let ended = tokio::time::timeout(Duration::from_secs(15), service.wait())
        .await
        .expect("the service ended in time")
        .expect("a status");
    assert!(ended.success(), "{ended}");
    assert!(!socket.exists(), "the service removes its socket");
}

/// A `SIGTERM` that comes the moment the second service's socket exists ends it cleanly: its
/// handler is in place before the socket is bound, so the signal never meets the default
/// disposition, and the socket is removed.
#[cfg(unix)]
#[tokio::test]
async fn a_sigterm_as_soon_as_the_socket_exists_ends_the_second_service_cleanly() {
    // SAFETY: getuid(2) cannot fail and touches no memory.
    let uid = unsafe { libc::getuid() };
    for _ in 0..5 {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agents.sock");
        let mut service = tokio::process::Command::new(env!("CARGO_BIN_EXE_supervisor"))
            .args(["run", "--agents"])
            .arg(&socket)
            .args(["--client-uid", &uid.wrapping_add(1).max(1).to_string()])
            .kill_on_drop(true)
            .spawn()
            .expect("start the second service");
        let pid = libc::pid_t::try_from(service.id().expect("running")).expect("a pid");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "never bound its socket"
            );
            std::thread::yield_now();
        }
        // SAFETY: plain kill(2) on the service's pid; no memory is touched.
        unsafe { libc::kill(pid, libc::SIGTERM) };
        let ended = tokio::time::timeout(Duration::from_secs(15), service.wait())
            .await
            .expect("the service ended in time")
            .expect("a status");
        assert!(ended.success(), "{ended}");
        assert!(!socket.exists(), "the service removes its socket");
    }
}

/// Whether this process holds `CAP_SYS_PTRACE` (capability 19) in its effective set.
#[cfg(target_os = "linux")]
fn holds_cap_sys_ptrace() -> bool {
    let status = std::fs::read_to_string("/proc/self/status").expect("/proc/self/status");
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|caps| u64::from_str_radix(caps.trim(), 16).ok())
        .expect("CapEff");
    effective & (1 << 19) != 0
}

/// The shipped second service closes its process to its own account (ADR-0059 clause 4): once
/// listening it reports itself not dumpable, and this test — its parent, of its account and without
/// `CAP_SYS_PTRACE`, which Yama's `ptrace_scope` 1 would let attach to a descendant — is refused
/// `PTRACE_ATTACH`, its `/proc/<pid>/mem` and `pidfd_getfd`.
/// Verifies: ADR-0059
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_second_service_closes_its_process_to_its_own_account() {
    use tokio::io::AsyncBufReadExt as _;

    assert!(
        !holds_cap_sys_ptrace(),
        "this test holds CAP_SYS_PTRACE, which passes every check it makes: run it without"
    );
    // At 2 and 3 Yama refuses the attach whatever the service does, and nothing would be decided.
    let scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map_or(0, |scope| scope.trim().parse::<u8>().expect("ptrace_scope"));
    assert!(
        scope < 2,
        "kernel.yama.ptrace_scope is {scope}, which refuses this test's attach to a child itself: \
         run it where it is 0 or 1"
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("agents.sock");
    // SAFETY: getuid(2) cannot fail and touches no memory.
    let uid = unsafe { libc::getuid() };
    let mut service = tokio::process::Command::new(env!("CARGO_BIN_EXE_supervisor"))
        .args(["run", "--agents"])
        .arg(&socket)
        .args(["--client-uid", &uid.wrapping_add(1).max(1).to_string()])
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start the second service");
    let pid = service.id().expect("running");
    let mut lines = tokio::io::BufReader::new(service.stdout.take().expect("stdout")).lines();
    let listening = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(line) = lines.next_line().await.expect("stdout") {
            if line.contains("second service listening") {
                return line;
            }
        }
        panic!("the second service ended before it listened");
    })
    .await
    .expect("the second service listened in time");
    assert!(listening.contains("dumpable=0"), "{listening}");
    // What the service smoke looks at: the files under /proc/<pid>/ of a process that is not
    // dumpable belong to root, while the directory keeps the process's own uid.
    {
        use std::os::unix::fs::MetadataExt as _;
        let owner = |path: String| std::fs::metadata(&path).expect("/proc").uid();
        assert_eq!(owner(format!("/proc/{pid}/environ")), 0, "dumpable");
        assert_eq!(
            owner(format!("/proc/{pid}")),
            uid,
            "the directory changed hands"
        );
    }

    let target = libc::pid_t::try_from(pid).expect("a pid");
    // SAFETY: ptrace(2) with no memory passed; a successful attach is undone below.
    let attached = unsafe {
        libc::ptrace(
            libc::PTRACE_ATTACH,
            target,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    let attach_error = std::io::Error::last_os_error();
    if attached == 0 {
        let _ = service.start_kill();
    }
    assert_eq!(attached, -1, "attached to the second service");
    assert_eq!(
        attach_error.raw_os_error(),
        Some(libc::EPERM),
        "{attach_error}"
    );

    let mem = std::fs::File::open(format!("/proc/{pid}/mem"))
        .expect_err("opened the second service's memory");
    assert_eq!(mem.kind(), std::io::ErrorKind::PermissionDenied, "{mem}");

    // SAFETY: pidfd_open(2) with no memory passed; the descriptor is owned below.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, target, 0) };
    assert!(
        pidfd >= 0,
        "pidfd_open: {}",
        std::io::Error::last_os_error()
    );
    let pidfd = i32::try_from(pidfd).expect("a descriptor");
    // SAFETY: a descriptor just opened, owned from here.
    let pidfd = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(pidfd) };
    // Its stderr: a descriptor the service holds for certain.
    // SAFETY: pidfd_getfd(2) with no memory passed; a descriptor it returns is closed below.
    let taken = unsafe {
        libc::syscall(
            libc::SYS_pidfd_getfd,
            std::os::fd::AsRawFd::as_raw_fd(&pidfd),
            2,
            0,
        )
    };
    let take_error = std::io::Error::last_os_error();
    if let Ok(taken) = i32::try_from(taken) {
        if taken >= 0 {
            // SAFETY: the descriptor pidfd_getfd(2) just gave this process.
            unsafe { libc::close(taken) };
        }
    }
    assert_eq!(taken, -1, "took a descriptor of the second service");
    assert_eq!(take_error.raw_os_error(), Some(libc::EPERM), "{take_error}");

    // SAFETY: plain kill(2) on the service's pid; no memory is touched.
    unsafe { libc::kill(target, libc::SIGTERM) };
    let ended = tokio::time::timeout(Duration::from_secs(15), service.wait())
        .await
        .expect("the service ended in time")
        .expect("a status");
    assert!(ended.success(), "{ended}");
}

/// The shipped second service does not listen while it is traced: a tracer attached before it
/// marks itself not dumpable stays attached, so it ends with an error, and the service manager
/// starts it again (ADR-0059 clause 4).
/// Verifies: ADR-0059
#[cfg(target_os = "linux")]
#[test]
fn the_second_service_does_not_listen_while_it_is_traced() {
    use std::io::Read as _;
    use std::os::unix::process::CommandExt as _;

    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("agents.sock");
    // SAFETY: getuid(2) cannot fail and touches no memory.
    let uid = unsafe { libc::getuid() };
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_supervisor"));
    command
        .args(["run", "--agents"])
        .arg(&socket)
        .args(["--client-uid", &uid.wrapping_add(1).max(1).to_string()])
        .stderr(std::process::Stdio::piped());
    // SAFETY: ptrace(2) alone between the fork and the exec, which is async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            if libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // Reaped by waitpid(2) below, which also sees its stops: `Child::wait` would see neither.
    #[allow(clippy::zombie_processes)]
    let mut service = command.spawn().expect("start the second service traced");
    let pid = libc::pid_t::try_from(service.id()).expect("a pid");
    // This thread is the tracer: it lets every stop go on until the service ends, or gives up.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let status = loop {
        let mut status = 0;
        // SAFETY: waits for this test's own child, without blocking.
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(waited >= 0, "waitpid: {}", std::io::Error::last_os_error());
        if waited == 0 {
            if std::time::Instant::now() >= deadline {
                // SAFETY: plain kill(2) on this test's child.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                panic!("the traced second service did not end: it listens");
            }
            std::thread::sleep(Duration::from_millis(20));
            continue;
        }
        if libc::WIFSTOPPED(status) {
            let signal = match libc::WSTOPSIG(status) {
                libc::SIGTRAP => 0,
                other => other,
            };
            // SAFETY: continues the stopped tracee with the signal it stopped for, or none.
            unsafe {
                libc::ptrace(
                    libc::PTRACE_CONT,
                    pid,
                    std::ptr::null_mut::<libc::c_void>(),
                    signal as usize as *mut libc::c_void,
                )
            };
            continue;
        }
        break status;
    };
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) != 0,
        "the traced service ended with {status:#x}"
    );
    let mut said = String::new();
    service
        .stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut said)
        .expect("stderr");
    assert!(said.contains("traced by process"), "{said}");
    assert!(!socket.exists(), "it listened while it was traced");
}

// ── Reload and uninstall (ADR-0017) ──────────────────────────────────────────

/// The pid the spawn reported — how these tests tell a kept process from a fresh one.
#[cfg(unix)]
async fn next_spawned_pid(events: &mut mpsc::Receiver<(usize, ProcessEvent)>) -> u32 {
    loop {
        let (_, event) = tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("an event in time")
            .expect("an open channel");
        if let ProcessEvent::Pid(Some(pid)) = event {
            return pid;
        }
    }
}

/// Drains events until the apply's acknowledgement, collecting every pid spawned on the way — a
/// reload keeps the process, so any pid before the ack means a restart happened.
#[cfg(unix)]
async fn ack_and_spawned_pids(
    events: &mut mpsc::Receiver<(usize, ProcessEvent)>,
) -> (Result<(), String>, Vec<u32>) {
    let mut pids = Vec::new();
    loop {
        let (_, event) = tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("an event in time")
            .expect("an open channel");
        match event {
            ProcessEvent::Pid(Some(pid)) => pids.push(pid),
            ProcessEvent::ConfigApplied { result, .. } => return (result, pids),
            _ => {}
        }
    }
}

/// Waits until the stub has written its marker file — the point at which it has run code of its
/// own, rather than merely having been spawned.
///
/// A pid says the process exists, not that it has got anywhere: between `spawn` and the stub's
/// first statement lie process creation and dynamic loading. Two tests need the distinction for
/// different reasons — a reload must not race the signal disposition the stub installs (Unix), and
/// a test that compares the marker across a package apply must have one to compare. The marker
/// counts once it holds something: the stub creates it empty and writes it after, so a marker that
/// merely exists may still read as nothing.
async fn wait_until_started(marker: &Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::fs::metadata(marker).map_or(true, |meta| meta.len() == 0) {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for the stub to start"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The Managed Process finds the Supervisor Endpoint's token in its environment, and no block's
/// `env` can put another one in its place.
/// Verifies: ADR-0015
async fn the_managed_process_is_handed_the_endpoint_token(via: Via) {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("running");
    let program = stub_agent();
    let marker_arg = marker.display().to_string();
    let (event_tx, _events) = mpsc::channel(64);
    let (_commands, command_rx) = mpsc::channel(16);
    let (_shutdown_tx, shutdown) = shutdown_channel();
    let runner = Runner {
        endpoint_token: zeroize::Zeroizing::new("the-token".to_string()),
        name: "test".to_string(),
        stop_timeout: Duration::from_secs(5),
        apply_grace: Duration::ZERO,
        retain_previous: Duration::ZERO,
        install: None,
        archive_key: None,
        version_probe: None,
        preflight: None,
        reload_signal: None,
        spawner: Spawner::Local,
        process_account_group: None,
        supervisor_dir: std::env::temp_dir(),
        events: EventSender::new(0, event_tx),
        commands: command_rx,
        build: Box::new(move || {
            Some(ProcessSpec {
                program: program.clone(),
                args: vec!["--touch".to_string(), marker_arg.clone()],
                env: vec![(
                    "OPAMP_SUPERVISOR_TOKEN".to_string(),
                    "a-block-tried".to_string(),
                )],
                working_dir: None,
                own_process_group: false,
                ensure_dirs: Vec::new(),
            })
        }),
    };
    let (task, _service) = launch(via, runner, shutdown);
    wait_until_started(&marker).await;
    let text = std::fs::read_to_string(&marker).expect("marker");
    assert!(text.contains("token=the-token\n"), "{text}");
    task.abort();
}
both!(the_managed_process_is_handed_the_endpoint_token);

/// A kind that declared a reload applies a configuration in place (ADR-0017): the process is
/// signalled, survives the grace, and the apply is acknowledged without a restart — the process
/// that was running is still the one running.
#[cfg(unix)]
async fn a_declared_reload_applies_without_a_restart(via: Via) {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("started");
    let marker_arg = marker.clone();
    let mut harness = runner_full(
        via,
        None,
        Duration::from_millis(300),
        Duration::ZERO,
        None,
        None,
        Some(libc::SIGHUP),
        move || {
            let mut spec = spec(&stub_agent());
            spec.args = vec![
                "--ignore-hup".to_string(),
                "--touch".to_string(),
                marker_arg.display().to_string(),
            ];
            Some(spec)
        },
    );
    let pid = next_spawned_pid(&mut harness.events).await;
    // The reload is only in place if the process is there to receive it with SIGHUP ignored.
    wait_until_started(&marker).await;

    apply(&harness, b"reload").await;
    let (result, spawned) = ack_and_spawned_pids(&mut harness.events).await;
    assert_eq!(result, Ok(()));
    assert!(
        spawned.is_empty(),
        "an in-place reload spawns nothing; a fresh pid would mean a restart: {spawned:?}"
    );
    // SAFETY: signal 0 probes existence only; no signal is delivered, no memory is touched.
    assert_eq!(
        unsafe { libc::kill(pid as libc::pid_t, 0) },
        0,
        "the process that was signalled is still the one running"
    );
    harness.shutdown_tx.send(true).expect("signal shutdown");
    let _ = harness.task.await;
}
both!(
    #[cfg(unix)]
    a_declared_reload_applies_without_a_restart
);

/// `reload-or-restart` (ADR-0017): a process that dies on its reload signal — the stub without
/// `--ignore-hup` keeps SIGHUP's default disposition, termination — is restarted on the new
/// files, and the apply is acknowledged from that restart rather than failed.
// Verifies: ADR-0017
#[cfg(unix)]
async fn a_process_that_dies_on_the_reload_signal_is_restarted_instead(via: Via) {
    let mut harness = runner_full(
        via,
        None,
        Duration::from_millis(300),
        Duration::ZERO,
        None,
        None,
        Some(libc::SIGHUP),
        || Some(spec(&stub_agent())),
    );
    let first = next_spawned_pid(&mut harness.events).await;

    apply(&harness, b"reload").await;
    let (result, spawned) = ack_and_spawned_pids(&mut harness.events).await;
    assert_eq!(result, Ok(()), "the fallback restart is the apply");
    assert_eq!(spawned.len(), 1, "exactly one respawn carries the fallback");
    assert_ne!(
        spawned[0], first,
        "a fresh process replaced the one that died"
    );
    harness.shutdown_tx.send(true).expect("signal shutdown");
    let _ = harness.task.await;
}
both!(
    #[cfg(unix)]
    a_process_that_dies_on_the_reload_signal_is_restarted_instead
);

/// The generic uninstall (ADR-0017): the graceful stop plus the answer, which is the adapter's
/// last event — the adapter exits on the command itself, no shutdown ever fired. The answer
/// coming last is what lets the core purge the directory only after the kind is done (ADR-0017).
async fn an_uninstall_stops_the_process_answers_and_exits(via: Via) {
    let mut harness = start(via, || Some(spec(&stub_agent())));
    let health = next_health(&mut harness.events).await;
    assert!(health.healthy);

    harness
        .commands
        .send(ProcessCommand::Uninstall)
        .await
        .expect("send the command");
    let result = loop {
        let (_, event) = tokio::time::timeout(Duration::from_secs(10), harness.events.recv())
            .await
            .expect("an event in time")
            .expect("an open channel");
        if let ProcessEvent::Uninstalled { result } = event {
            break result;
        }
    };
    assert_eq!(result, Ok(()));
    tokio::time::timeout(Duration::from_secs(10), harness.task)
        .await
        .expect("the adapter exits on the command itself")
        .expect("no panic");
}
both!(an_uninstall_stops_the_process_answers_and_exits);

// ── Supervision ──────────────────────────────────────────────────────────────

async fn a_long_running_process_reports_healthy_and_stops_on_shutdown(via: Via) {
    let mut harness = start(via, || Some(spec(&stub_agent())));
    let health = next_health(&mut harness.events).await;
    assert!(health.healthy);
    harness.shutdown_tx.send(true).expect("signal shutdown");
    tokio::time::timeout(Duration::from_secs(10), harness.task)
        .await
        .expect("the runner exits in time")
        .expect("no panic");
}
both!(a_long_running_process_reports_healthy_and_stops_on_shutdown);

async fn an_exiting_process_turns_unhealthy_and_is_restarted(via: Via) {
    let mut harness = start(via, || Some(spec(&stub_crasher())));
    let first = next_health(&mut harness.events).await;
    assert!(first.healthy, "the spawn itself succeeds");
    let exited = next_health(&mut harness.events).await;
    assert!(!exited.healthy);
    assert!(exited.status.contains("exited unexpectedly"));
    // The watchdog respawns (backoff starts at one second).
    let respawned = next_health(&mut harness.events).await;
    assert!(respawned.healthy);
    harness.shutdown_tx.send(true).expect("signal shutdown");
    let _ = harness.task.await;
}
both!(an_exiting_process_turns_unhealthy_and_is_restarted);

/// A Supervisor whose program is not on the machine keeps running and says so. The wording is the
/// point: what the Server should read is the situation — there is no process — not the syscall that
/// reported it. This is the state a failed *first* install leaves behind, once the artifact it could
/// not run has been removed again.
async fn a_missing_program_is_reported_as_no_process_not_fatal(via: Via) {
    let mut harness = start(via, || {
        Some(spec(Path::new("nonexistent-definitely-not-here")))
    });
    let health = next_health(&mut harness.events).await;
    assert!(!health.healthy);
    assert_eq!(health.status, "no process installed");
    assert!(
        health.last_error.contains("definitely-not-here"),
        "the detail still names the path: {}",
        health.last_error
    );
    harness.shutdown_tx.send(true).expect("signal shutdown");
    let _ = harness.task.await;
}
both!(a_missing_program_is_reported_as_no_process_not_fatal);

/// A program that exists but cannot be executed is a different situation, and keeps the wording
/// that describes it. Unix says so through the mode, Windows through the file not being a program
/// at all; both reach the same branch, which is what this asserts.
async fn an_unexecutable_program_is_reported_as_a_spawn_failure(via: Via) {
    let dir = tempfile::tempdir().expect("tempdir");
    let program = dir.path().join(program_name("not-executable"));
    std::fs::write(&program, b"data").expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    }

    let mut harness = start(via, move || Some(spec(&program)));
    let health = next_health(&mut harness.events).await;
    assert!(!health.healthy);
    assert_eq!(health.status, "spawn failed");
    harness.shutdown_tx.send(true).expect("signal shutdown");
    let _ = harness.task.await;
}
both!(an_unexecutable_program_is_reported_as_a_spawn_failure);

async fn nothing_to_run_reports_awaiting_configuration(via: Via) {
    let mut harness = start(via, || None);
    let health = next_health(&mut harness.events).await;
    assert!(!health.healthy);
    assert_eq!(health.status, "awaiting configuration");
    harness.shutdown_tx.send(true).expect("signal shutdown");
    let _ = harness.task.await;
}
both!(nothing_to_run_reports_awaiting_configuration);

// ── The health-gated configuration apply ─────────────────────────────────────

async fn a_process_surviving_the_apply_grace_is_acknowledged_applied(via: Via) {
    let mut harness = start_with_grace(via, Duration::from_millis(200), || {
        Some(spec(&stub_agent()))
    });
    apply(&harness, b"h1").await;
    let (hash, result) = next_ack(&mut harness.events).await;
    assert_eq!(hash, b"h1".to_vec());
    assert!(result.is_ok(), "survived the grace: {result:?}");
    harness.shutdown_tx.send(true).expect("signal shutdown");
    let _ = harness.task.await;
}
both!(a_process_surviving_the_apply_grace_is_acknowledged_applied);

async fn a_process_exiting_within_the_grace_fails_the_apply_and_stays_supervised(via: Via) {
    let mut harness = start_with_grace(via, Duration::from_millis(500), || {
        Some(spec(&stub_crasher()))
    });
    apply(&harness, b"h1").await;
    let (hash, result) = next_ack(&mut harness.events).await;
    assert_eq!(hash, b"h1".to_vec());
    let error = result.expect_err("the exit within the grace fails the apply");
    assert!(error.contains("apply grace"), "{error}");
    // The watchdog keeps trying with backoff — the process is not abandoned.
    let respawned = next_health(&mut harness.events).await;
    assert!(respawned.healthy, "the backoff respawn happened");
    harness.shutdown_tx.send(true).expect("signal shutdown");
    let _ = harness.task.await;
}
both!(a_process_exiting_within_the_grace_fails_the_apply_and_stays_supervised);

async fn shutdown_during_the_grace_stops_promptly_without_an_ack(via: Via) {
    let mut harness = start_with_grace(via, Duration::from_secs(600), || Some(spec(&stub_agent())));
    apply(&harness, b"h1").await;
    // The spawn health event arrives; then the runner sits in the grace.
    let started = next_health(&mut harness.events).await;
    assert!(started.healthy);
    harness.shutdown_tx.send(true).expect("signal shutdown");
    tokio::time::timeout(Duration::from_secs(10), harness.task)
        .await
        .expect("the runner exits in time despite the long grace")
        .expect("no panic");
    // No ConfigApplied was ever emitted.
    while let Ok((_, event)) = harness.events.try_recv() {
        assert!(
            !matches!(event, ProcessEvent::ConfigApplied { .. }),
            "no acknowledgement during shutdown"
        );
    }
}
both!(shutdown_during_the_grace_stops_promptly_without_an_ack);

async fn a_restart_command_cycles_the_process_without_a_config_ack(via: Via) {
    let mut harness = start(via, || Some(spec(&stub_agent())));
    let first = next_health(&mut harness.events).await;
    assert!(first.healthy);

    harness
        .commands
        .send(ProcessCommand::Restart)
        .await
        .expect("send the restart");

    // The respawned process reports healthy again — and nothing acknowledges a config, because
    // none changed.
    let respawned = next_health(&mut harness.events).await;
    assert!(respawned.healthy);
    assert!(
        harness.events.try_recv().is_err(),
        "a restart must not emit a ConfigApplied"
    );
    harness.shutdown_tx.send(true).expect("signal shutdown");
    let _ = harness.task.await;
}
both!(a_restart_command_cycles_the_process_without_a_config_ack);

async fn apply_config_restarts_and_acknowledges(via: Via) {
    let mut harness = start(via, || Some(spec(&stub_agent())));
    let _ = next_health(&mut harness.events).await;

    apply(&harness, b"h1").await;

    let (hash, result) = next_ack(&mut harness.events).await;
    assert_eq!(hash, b"h1".to_vec());
    assert!(result.is_ok(), "{result:?}");
    harness.shutdown_tx.send(true).expect("signal shutdown");
    let _ = harness.task.await;
}
both!(apply_config_restarts_and_acknowledges);

// ── The binary swap (ADR-0026) ───────────────────────────────────────────────

/// A Runner that swaps one file and runs whatever is at it.
fn binary_harness(via: Via, binary: &Path, apply_grace: Duration) -> Harness {
    let program = binary.to_path_buf();
    runner(
        via,
        Some(InstallTarget::Binary(binary.to_path_buf())),
        apply_grace,
        None,
        move || Some(spec(&program)),
    )
}

/// ADR-0017 clause 57: a package is *proved to run* before it replaces what runs. The check fails here, so
/// nothing is swapped and — the point of the whole exercise — the running process is never stopped
/// for an artifact that could never have worked. Before this, the sequence was stop, swap, fail to
/// start, roll back, restart: an outage bought for nothing.
async fn a_package_that_cannot_run_here_is_refused_without_stopping_what_runs(via: Via) {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join(program_name("agent"));
    let good = bytes_of(&stub_agent());
    std::fs::write(&binary, &good).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    let marker = dir.path().join("running");
    let program = binary.clone();
    let mut harness = runner_full(
        via,
        Some(InstallTarget::Binary(binary.clone())),
        Duration::from_millis(200),
        Duration::ZERO,
        None,
        // The staged program is asked to exit non-zero: what a binary the host's libc cannot
        // satisfy does, with the linker's message in its place.
        Some(Preflight {
            args: vec!["--exit-code".to_string(), "1".to_string()],
            env: Vec::new(),
        }),
        None,
        move || {
            Some(ProcessSpec {
                program: program.clone(),
                args: vec!["--touch".to_string(), marker.display().to_string()],
                env: Vec::new(),
                working_dir: None,
                own_process_group: false,
                ensure_dirs: Vec::new(),
            })
        },
    );
    let _ = next_health(&mut harness.events).await;
    wait_until_started(&dir.path().join("running")).await;
    let running = std::fs::read_to_string(dir.path().join("running")).expect("the marker");

    let staged = dir.path().join("downloaded.staged");
    std::fs::write(&staged, bytes_of(&stub_agent())).expect("stage");
    let (hash, result) = apply_package(&mut harness, &staged, "9.9.9").await;

    assert_eq!(hash, b"9.9.9".to_vec());
    let error = result.expect_err("a package that will not run is refused");
    assert!(
        error.contains("does not run on this host"),
        "the refusal names what the program said: {error}"
    );
    assert_eq!(
        std::fs::read(&binary).expect("read"),
        good,
        "nothing was swapped"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("running")).expect("the marker"),
        running,
        "the running process was never restarted — the marker still holds its first pid"
    );

    harness.shutdown_tx.send(true).expect("shutdown");
    let _ = harness.task.await;
}
both!(a_package_that_cannot_run_here_is_refused_without_stopping_what_runs);

/// Verifies: ADR-0026
async fn apply_package_swaps_the_binary_and_acknowledges_installed(via: Via) {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join(program_name("agent"));
    // The host holds a program that will not stay up — the situation a package is sent to fix, and
    // what makes the assertion below say something: the bytes on disk afterwards are not the ones
    // that were there before.
    std::fs::write(&binary, bytes_of(&stub_crasher())).expect("write");
    let mut harness = binary_harness(via, &binary, Duration::from_millis(200));
    let _ = next_health(&mut harness.events).await; // initial spawn

    // The new version arrives as a downloaded *file*, the way the transport stages one.
    let new_bytes = bytes_of(&stub_agent());
    let staged = dir.path().join("downloaded.staged");
    std::fs::write(&staged, &new_bytes).expect("stage");

    let (hash, result) = apply_package(&mut harness, &staged, "2.0.0").await;
    assert_eq!(hash, b"2.0.0".to_vec());
    assert_eq!(result, Ok("2.0.0".to_string()));
    // The binary on disk is the swapped one, and the staged download is cleaned up.
    assert_eq!(std::fs::read(&binary).expect("read"), new_bytes);
    assert!(!staged.exists(), "the staged artifact is not left behind");
    assert!(
        !binary.with_extension("rollback").exists(),
        "a succeeded install keeps no backup"
    );

    harness.shutdown_tx.send(true).expect("shutdown");
    let _ = harness.task.await;
}
both!(apply_package_swaps_the_binary_and_acknowledges_installed);

/// The case ADR-0026 exists for: what upstream publishes is a `.tar.gz`, not a bare binary. The
/// Supervisor takes the member named after its own binary and installs that.
/// Verifies: ADR-0026
async fn a_package_delivered_as_a_tar_gz_is_unpacked_and_installed(via: Via) {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join(program_name("agent"));
    std::fs::write(&binary, bytes_of(&stub_crasher())).expect("write");

    // A release-shaped archive: the program under a versioned directory, next to other files.
    let program = bytes_of(&stub_agent());
    let staged = dir.path().join("release.tar.gz");
    tar_gz(
        &staged,
        &[
            ("agent-2.0.0/LICENSE".to_string(), b"text".to_vec()),
            (
                format!("agent-2.0.0/{}", program_name("agent")),
                program.clone(),
            ),
        ],
    );

    let mut harness = binary_harness(via, &binary, Duration::from_millis(200));
    let _ = next_health(&mut harness.events).await;

    let (hash, result) = apply_package(&mut harness, &staged, "2.0.0").await;
    assert_eq!(hash, b"2.0.0".to_vec());
    assert_eq!(
        result,
        Ok("2.0.0".to_string()),
        "the unpacked program stays up"
    );
    assert_eq!(
        std::fs::read(&binary).expect("read"),
        program,
        "the installed binary is the member, not the archive"
    );

    harness.shutdown_tx.send(true).expect("shutdown");
    let _ = harness.task.await;
}
both!(a_package_delivered_as_a_tar_gz_is_unpacked_and_installed);

/// Bringing a host into the fleet the other way round: the Supervisor is configured, the program is
/// not installed yet, and the Server delivers it. A plugin with nothing to run — a Collector
/// awaiting its configuration — must not turn that into a failed install, which would delete the
/// binary that was just put in place.
/// Verifies: ADR-0026
async fn an_install_with_nothing_to_run_yet_keeps_the_binary_and_succeeds(via: Via) {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join(program_name("otelcol"));
    assert!(
        !binary.exists(),
        "the program is not installed on this host"
    );

    let staged = dir.path().join("downloaded.staged");
    std::fs::write(&staged, bytes_of(&stub_agent())).expect("stage");

    // No configuration yet, so the plugin has nothing to run.
    let mut harness = runner(
        via,
        Some(InstallTarget::Binary(binary.clone())),
        Duration::from_millis(200),
        None,
        || None,
    );
    let _ = next_health(&mut harness.events).await; // "awaiting configuration"

    let (hash, result) = apply_package(&mut harness, &staged, "1.0.0").await;
    assert_eq!(hash, b"1.0.0".to_vec());
    assert_eq!(
        result,
        Ok("1.0.0".to_string()),
        "the artifact is installed; running it is the configuration's business"
    );
    assert!(binary.exists(), "the installed binary stays on disk");

    harness.shutdown_tx.send(true).expect("shutdown");
    let _ = harness.task.await;
}
both!(an_install_with_nothing_to_run_yet_keeps_the_binary_and_succeeds);

// Verifies: ADR-0026, G-10
async fn a_package_that_will_not_stay_up_is_rolled_back_and_fails(via: Via) {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join(program_name("agent"));
    let good = bytes_of(&stub_agent());
    std::fs::write(&binary, &good).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    let mut harness = binary_harness(via, &binary, Duration::from_millis(500));
    let _ = next_health(&mut harness.events).await;

    // A binary that exits at once: it fails the grace and must be rolled back.
    let staged = dir.path().join("downloaded.staged");
    std::fs::write(&staged, bytes_of(&stub_crasher())).expect("stage");
    let (hash, result) = apply_package(&mut harness, &staged, "9.9.9").await;
    assert_eq!(hash, b"9.9.9".to_vec());
    assert!(result.is_err(), "a binary that exits fails the install");
    // The binary on disk is the original one again.
    assert_eq!(std::fs::read(&binary).expect("read"), good, "rolled back");

    harness.shutdown_tx.send(true).expect("shutdown");
    let _ = harness.task.await;
}
both!(a_package_that_will_not_stay_up_is_rolled_back_and_fails);

/// ADR-0026: a *first* install that will not start has nothing to roll back to, so it is **kept**
/// rather than discarded — the verified binary stays in `program/`. Discarding it would empty the
/// directory and set the Server re-offering the same artifact in a loop.
/// Verifies: ADR-0026
async fn a_first_install_that_will_not_start_is_kept_not_discarded(via: Via) {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join(program_name("agent"));
    // Nothing on disk yet: a first install onto an empty program directory.
    let mut harness = binary_harness(via, &binary, Duration::from_millis(200));

    let staged = dir.path().join("downloaded.staged");
    let crasher = bytes_of(&stub_crasher());
    std::fs::write(&staged, &crasher).expect("stage");
    let (_, result) = apply_package(&mut harness, &staged, "9.9.9").await;
    assert!(result.is_err(), "a crasher fails the install");
    // Not rolled back to nothing: the verified program is still there.
    assert!(
        binary.exists(),
        "the first install is kept, not discarded (ADR-0026)"
    );
    assert_eq!(
        std::fs::read(&binary).expect("read"),
        crasher,
        "and it is the installed bytes"
    );

    harness.shutdown_tx.send(true).expect("shutdown");
    let _ = harness.task.await;
}
both!(a_first_install_that_will_not_start_is_kept_not_discarded);

/// ADR-0026: a program that keeps failing to start is **held** after a few tries, not restarted
/// forever — the loop that hammered the Server with re-downloads is bounded. A held Supervisor
/// reports it plainly.
// Verifies: ADR-0026
async fn a_program_that_keeps_crashing_is_held_not_looped(via: Via) {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join(program_name("agent"));
    let mut harness = binary_harness(via, &binary, Duration::from_millis(100));

    // Install a crasher as a first install: kept (no predecessor), and it keeps crashing.
    let staged = dir.path().join("downloaded.staged");
    std::fs::write(&staged, bytes_of(&stub_crasher())).expect("stage");
    let (_, result) = apply_package(&mut harness, &staged, "9.9.9").await;
    assert!(result.is_err());

    // Within a bounded time the Runner gives up and says so, instead of spinning forever.
    let held = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let health = next_health(&mut harness.events).await;
            if health.status.contains("not restarting") {
                return health;
            }
        }
    })
    .await
    .expect("the Runner holds instead of restarting forever");
    assert!(held.status.contains("not restarting"), "{}", held.status);

    harness.shutdown_tx.send(true).expect("shutdown");
    let _ = harness.task.await;
}
both!(a_program_that_keeps_crashing_is_held_not_looped);

/// Sends a package of `bytes` as `version`, staged in `dir`.
async fn offer_package(harness: &Harness, dir: &Path, bytes: &[u8], version: &str) {
    let staged = dir.join("downloaded.staged");
    std::fs::write(&staged, bytes).expect("stage");
    harness
        .commands
        .send(ProcessCommand::ApplyPackage {
            staged,
            version: version.to_string(),
            hash: version.as_bytes().to_vec(),
            span: tracing::Span::current(),
        })
        .await
        .expect("send");
}

/// ADR-0026 clause 63: a failed package is a failed start like any other. Where the predecessor it
/// is rolled back to will not start either, the Supervisor holds after three failed starts in a
/// row — the package's and two of the predecessor's — rather than granting the predecessor three
/// of its own after the package's.
/// Verifies: ADR-0026
async fn a_failed_package_counts_towards_the_hold_of_a_predecessor_that_fails_too(via: Via) {
    use fleet_agent::supervisor::restart::MAX_CRASH_RESTARTS;
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join(program_name("agent"));
    std::fs::write(&binary, bytes_of(&stub_crasher())).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    let mut harness = binary_harness(via, &binary, Duration::from_millis(300));
    // The predecessor keeps crashing from the start, and is held.
    loop {
        let health = next_health(&mut harness.events).await;
        if health.status.contains("not restarting") {
            break;
        }
    }

    offer_package(&harness, dir.path(), &bytes_of(&stub_crasher()), "9.9.9").await;
    let (mut starts, mut outcome) = (0, None);
    loop {
        let (_, event) = tokio::time::timeout(Duration::from_secs(20), harness.events.recv())
            .await
            .expect("the Supervisor holds in time")
            .expect("an open channel");
        match event {
            ProcessEvent::Health(health) if health.status == "running" => starts += 1,
            ProcessEvent::Health(health) if health.status.contains("not restarting") => break,
            ProcessEvent::PackageApplied { result, .. } => outcome = Some(result),
            _ => {}
        }
    }
    assert!(outcome.expect("an outcome").is_err());
    assert_eq!(
        starts, MAX_CRASH_RESTARTS,
        "the package's start is one of the failed starts"
    );

    harness.shutdown_tx.send(true).expect("shutdown");
    let _ = harness.task.await;
}
both!(a_failed_package_counts_towards_the_hold_of_a_predecessor_that_fails_too);

/// ADR-0026 clause 62: the predecessor a failed package is rolled back to is started once, and
/// that process stays; no second respawn replaces it while it runs.
/// Verifies: ADR-0026
async fn a_failed_package_starts_its_predecessor_exactly_once(via: Via) {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join(program_name("agent"));
    std::fs::write(&binary, bytes_of(&stub_agent())).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    let mut harness = binary_harness(via, &binary, Duration::from_millis(300));
    let running = next_health(&mut harness.events).await;
    assert_eq!(running.status, "running", "{running:?}");

    offer_package(&harness, dir.path(), &bytes_of(&stub_crasher()), "9.9.9").await;
    let (_, result) = next_package_ack(&mut harness.events).await;
    assert!(result.is_err(), "{result:?}");
    // Longer than the backoff a second respawn would have waited.
    let mut healths = Vec::new();
    let until = tokio::time::Instant::now() + Duration::from_millis(2500);
    while let Ok(Some((_, event))) = tokio::time::timeout_at(until, harness.events.recv()).await {
        if let ProcessEvent::Health(health) = event {
            healths.push(health.status);
        }
    }
    assert_eq!(
        healths,
        vec!["running".to_string()],
        "one start, which stays"
    );

    harness.shutdown_tx.send(true).expect("shutdown");
    let _ = harness.task.await;
}
both!(a_failed_package_starts_its_predecessor_exactly_once);

/// ADR-0026: a successful update does not delete the version it superseded — it is retained for the
/// window, with a marker recording the deadline, so an operator has a fallback.
/// Verifies: ADR-0026
async fn a_successful_update_keeps_the_previous_version_for_the_window(via: Via) {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join(program_name("agent"));
    // A predecessor that stays up.
    std::fs::write(&binary, bytes_of(&stub_agent())).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    let program = binary.clone();
    let mut harness = runner_retaining(
        via,
        Some(InstallTarget::Binary(binary.clone())),
        Duration::from_millis(200),
        Duration::from_secs(3600), // keep the predecessor an hour
        None,
        move || Some(spec(&program)),
    );
    let _ = next_health(&mut harness.events).await;

    // A new good version installs and stays up.
    let staged = dir.path().join("downloaded.staged");
    std::fs::write(&staged, bytes_of(&stub_agent())).expect("stage");
    let (_, result) = apply_package(&mut harness, &staged, "9.9.9").await;
    assert!(result.is_ok(), "a good binary applies");

    // The predecessor is retained, not deleted on success — its file and a deadline marker remain.
    let backup = binary.with_extension("rollback");
    assert!(
        backup.exists(),
        "the previous version is kept for the retention window"
    );
    let mut marker = backup.clone().into_os_string();
    marker.push(".until");
    assert!(
        PathBuf::from(marker).exists(),
        "a marker records the deadline"
    );

    harness.shutdown_tx.send(true).expect("shutdown");
    let _ = harness.task.await;
}
both!(a_successful_update_keeps_the_previous_version_for_the_window);

// ── The tree install (ADR-0026) ──────────────────────────────────────────────

/// Writes a `.tar.gz` holding `members` — (path inside the archive, contents).
fn tar_gz(path: &Path, members: &[(String, Vec<u8>)]) {
    let file = std::fs::File::create(path).expect("create");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
    let mut builder = tar::Builder::new(encoder);
    for (name, content) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, name, content.as_slice())
            .expect("append");
    }
    builder.into_inner().expect("tar").finish().expect("gzip");
}

/// A release-shaped `.tar.gz`: the program and a library it "loads", under one version-named
/// wrapper directory (ADR-0026).
fn tree_release(path: &Path, wrapper: &str, program: &Path, library: &[u8]) {
    tar_gz(
        path,
        &[
            (
                format!("{wrapper}/bin/{}", program_name("agent")),
                bytes_of(program),
            ),
            (format!("{wrapper}/lib/libagent.so"), library.to_vec()),
        ],
    );
}

/// A Runner installing into a tree, spawning whatever sits at `program/tree/bin/agent`.
fn tree_harness(via: Via, root: &Path) -> Harness {
    let inside = PathBuf::from("bin").join(program_name("agent"));
    let program = root.join(TREE_DIR).join(&inside);
    runner(
        via,
        Some(InstallTarget::Tree {
            root: root.to_path_buf(),
            program_path: inside,
        }),
        Duration::from_millis(200),
        None,
        move || Some(spec(&program)),
    )
}

/// The case ADR-0026 exists for: an agent that is a program *plus* what it loads, arriving with
/// nothing on the host first — and then being replaced the same way.
/// Verifies: ADR-0026
async fn a_tree_package_lands_whole_and_replaces_the_one_before_it(via: Via) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("program");
    std::fs::create_dir_all(&root).expect("create the program directory");

    let first = dir.path().join("agent-1.0.0.tar.gz");
    tree_release(&first, "agent-1.0.0", &stub_agent(), b"v1-library");
    let mut harness = tree_harness(via, &root);
    let _ = next_health(&mut harness.events).await; // nothing installed yet

    assert_eq!(
        apply_package(&mut harness, &first, "1.0.0").await.1,
        Ok("1.0.0".to_string()),
        "a first install needs nothing on the host"
    );
    assert_eq!(
        std::fs::read(root.join(TREE_DIR).join("lib/libagent.so")).expect("the library"),
        b"v1-library",
        "what the program loads came with it"
    );
    assert!(
        !root.join(format!("{TREE_DIR}.rollback")).exists(),
        "a first install leaves no rollback: there was nothing to keep"
    );
    assert!(!root.join(".staging").exists(), "staging does not survive");

    let second = dir.path().join("agent-2.0.0.tar.gz");
    tree_release(
        &second,
        "agent-2.0.0-linux-amd64",
        &stub_agent(),
        b"v2-library",
    );
    assert_eq!(
        apply_package(&mut harness, &second, "2.0.0").await.1,
        Ok("2.0.0".to_string())
    );
    assert_eq!(
        std::fs::read(root.join(TREE_DIR).join("lib/libagent.so")).expect("the library"),
        b"v2-library",
        "the wrapper directory was renamed between releases and nothing had to follow it"
    );
    assert!(
        !root.join(format!("{TREE_DIR}.rollback")).exists(),
        "a succeeded install keeps no previous tree"
    );

    harness.shutdown_tx.send(true).expect("shutdown");
    let _ = harness.task.await;
}
both!(a_tree_package_lands_whole_and_replaces_the_one_before_it);

/// The health gate, one level up: a tree whose program will not stay up puts the *whole* previous
/// tree back — libraries included, since half of each would run nothing.
/// Verifies: ADR-0026
async fn a_tree_that_will_not_stay_up_is_rolled_back_whole(via: Via) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("program");
    std::fs::create_dir_all(&root).expect("create the program directory");

    let good = dir.path().join("agent-1.0.0.tar.gz");
    tree_release(&good, "agent-1.0.0", &stub_agent(), b"v1-library");
    let mut harness = tree_harness(via, &root);
    let _ = next_health(&mut harness.events).await;
    assert_eq!(
        apply_package(&mut harness, &good, "1.0.0").await.1,
        Ok("1.0.0".to_string())
    );

    // A version that exits immediately — rejected by the apply grace.
    let bad = dir.path().join("agent-2.0.0.tar.gz");
    tree_release(&bad, "agent-2.0.0", &stub_crasher(), b"v2-library");
    assert!(
        apply_package(&mut harness, &bad, "2.0.0").await.1.is_err(),
        "a program that exits in the grace has rejected itself"
    );

    assert_eq!(
        std::fs::read(root.join(TREE_DIR).join("bin").join(program_name("agent")))
            .expect("the program"),
        bytes_of(&stub_agent()),
        "the program that ran before is back"
    );
    assert_eq!(
        std::fs::read(root.join(TREE_DIR).join("lib/libagent.so")).expect("the library"),
        b"v1-library",
        "and so is everything beside it — a rollback of half a tree is not a rollback"
    );
    assert!(
        !root.join(format!("{TREE_DIR}.rollback")).exists(),
        "nothing is left behind"
    );

    harness.shutdown_tx.send(true).expect("shutdown");
    let _ = harness.task.await;
}
both!(a_tree_that_will_not_stay_up_is_rolled_back_whole);

/// The archive names a member the configuration does not — refused, with the old tree left exactly
/// where it was.
/// Verifies: ADR-0026
async fn a_tree_missing_the_configured_program_is_refused_and_changes_nothing(via: Via) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("program");
    std::fs::create_dir_all(&root).expect("create the program directory");

    let good = dir.path().join("agent-1.0.0.tar.gz");
    tree_release(&good, "agent-1.0.0", &stub_agent(), b"v1-library");
    let mut harness = tree_harness(via, &root);
    let _ = next_health(&mut harness.events).await;
    assert_eq!(
        apply_package(&mut harness, &good, "1.0.0").await.1,
        Ok("1.0.0".to_string())
    );

    // Same shape, wrong program name: `bin/agent` is not in it.
    let wrong = dir.path().join("other.tar.gz");
    tar_gz(
        &wrong,
        &[(
            format!("other-1.0.0/bin/{}", program_name("other")),
            b"nope".to_vec(),
        )],
    );
    let outcome = apply_package(&mut harness, &wrong, "2.0.0").await.1;
    assert!(outcome.is_err(), "{outcome:?}");

    assert_eq!(
        std::fs::read(root.join(TREE_DIR).join("lib/libagent.so")).expect("the library"),
        b"v1-library",
        "the tree that was running is untouched"
    );
    assert!(!root.join(".staging").exists(), "staging does not survive");

    harness.shutdown_tx.send(true).expect("shutdown");
    let _ = harness.task.await;
}
both!(a_tree_missing_the_configured_program_is_refused_and_changes_nothing);

// ── The trace an install leaves (ADR-0016) ───────────────────────────────────

/// Every span this test binary's subscriber saw: its id, the parent the registry gave it, and its
/// name. Enough to answer the one question worth asking of the instrumentation — *what hangs off
/// what* — and nothing more, so no exporter and no OTLP is involved.
#[derive(Default)]
struct Recorded(std::sync::Mutex<Vec<(tracing::span::Id, Option<tracing::span::Id>, String)>>);

struct RecordingLayer(std::sync::Arc<Recorded>);

impl<S> tracing_subscriber::Layer<S> for RecordingLayer
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        // The registry's parent — the same one `tracing-opentelemetry` reads to build a trace, so
        // asserting on it asserts on what would be exported.
        let parent = ctx.span(id).and_then(|span| span.parent().map(|p| p.id()));
        self.0 .0.lock().expect("the recorder").push((
            id.clone(),
            parent,
            attrs.metadata().name().to_string(),
        ));
    }
}

/// The subscriber, installed once for this binary. Global rather than scoped on purpose: the
/// Runner drives the install in a **task of its own**, and a thread-local subscriber would not
/// reach it — which is exactly the boundary this test exists to cross.
fn recorder() -> std::sync::Arc<Recorded> {
    static RECORDER: std::sync::OnceLock<std::sync::Arc<Recorded>> = std::sync::OnceLock::new();
    RECORDER
        .get_or_init(|| {
            use tracing_subscriber::layer::SubscriberExt as _;
            let recorded = std::sync::Arc::new(Recorded::default());
            let subscriber = tracing_subscriber::registry().with(RecordingLayer(recorded.clone()));
            // A second call would fail; the `OnceLock` means there is none.
            let _ = tracing::subscriber::set_global_default(subscriber);
            recorded
        })
        .clone()
}

/// The names of every span descending from `root`, however deep.
fn descendants_of(recorded: &Recorded, root: &tracing::span::Id) -> Vec<String> {
    let spans = recorded.0.lock().expect("the recorder").clone();
    let mut family = vec![root.clone()];
    let mut names = Vec::new();
    // The list is in creation order, so one pass reaches every generation: a child is always
    // recorded after its parent.
    for (id, parent, name) in spans {
        if parent.is_some_and(|parent| family.contains(&parent)) {
            family.push(id);
            names.push(name);
        }
    }
    names
}

/// ADR-0016's central mechanical claim: an install is **one** trace, although it is begun by the
/// task that downloaded the artifact and finished by the Supervisor's own.
///
/// The span travels with the command through the Port; if it did not, each phase would open a trace
/// of its own and "which phase failed" — the question the dashboard is built around — would have no
/// span to answer with. Asserted against the real Runner swapping a real program, because the hand
/// -over is the thing under test and a mock of it would test the mock.
/// Verifies: ADR-0016
#[tokio::test]
async fn the_phases_of_an_install_hang_off_the_span_that_came_with_it() {
    let recorded = recorder();
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join(program_name("agent"));
    std::fs::write(&binary, bytes_of(&stub_crasher())).expect("write");
    let mut harness = binary_harness(Via::Local, &binary, Duration::from_millis(200));
    let _ = next_health(&mut harness.events).await; // initial spawn

    let staged = dir.path().join("downloaded.staged");
    std::fs::write(&staged, bytes_of(&stub_agent())).expect("stage");

    // The span the transport would open around the download, handed over exactly as it is there.
    let operation = tracing::info_span!("package.install");
    let root = operation
        .id()
        .expect("the recording subscriber is in force");
    harness
        .commands
        .send(ProcessCommand::ApplyPackage {
            staged: staged.clone(),
            version: "2.0.0".to_string(),
            hash: b"2.0.0".to_vec(),
            span: operation,
        })
        .await
        .expect("send");
    let (_, result) = next_package_ack(&mut harness.events).await;
    assert_eq!(result, Ok("2.0.0".to_string()));

    let phases = descendants_of(&recorded, &root);
    for phase in ["stage", "swap", "gate"] {
        assert!(
            phases.iter().any(|name| name == phase),
            "the {phase} phase belongs to the install that was handed over, got {phases:?}"
        );
    }

    harness.shutdown_tx.send(true).expect("shutdown");
    let _ = harness.task.await;
}

// ── An apply while the second service is away (ADR-0059 clause 2) ───────────

/// An apply that does not reach the second service, or whose program goes with the service during
/// the apply grace, is neither applied nor failed: nothing is reported, a package is neither
/// rolled back nor refused, and the start that reaches the service again is gated in its place.
#[cfg(unix)]
mod an_apply_while_the_second_service_is_away {
    use super::*;
    use fleet_agent::supervisor::channel::{bind, serve, Channel, Served};
    use tokio::sync::oneshot;

    /// What a Supervisor reports while the second service cannot be reached.
    const UNREACHABLE: &str = "the second service cannot be reached";

    fn own_uid() -> u32 {
        // SAFETY: getuid(2) cannot fail and touches no memory.
        unsafe { libc::getuid() }
    }

    /// The second service on `socket`, in this process, until [`Service::stop`].
    struct Service {
        stop: Option<oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<Served>,
    }

    impl Service {
        fn up(socket: &Path) -> Service {
            let listener = bind(socket).expect("bind the agents socket");
            let (stop, stopped) = oneshot::channel::<()>();
            let task = tokio::spawn(serve(listener, own_uid(), || false, async {
                let _ = stopped.await;
            }));
            Service {
                stop: Some(stop),
                task,
            }
        }

        /// Stops it as its service manager does, with every program it started.
        async fn stop(mut self) {
            let _ = self.stop.take().expect("running").send(());
            assert_eq!(
                (&mut self.task).await.expect("the service ended"),
                Served::Stopped
            );
        }
    }

    struct Away {
        dir: tempfile::TempDir,
        binary: PathBuf,
        socket: PathBuf,
        harness: Harness,
    }

    /// A Runner that swaps one file holding `program`'s bytes and runs it through the second
    /// service, which is up; started and running.
    async fn running(program: &Path, apply_grace: Duration) -> (Away, Service) {
        let dir = tempfile::tempdir().expect("tempdir");
        write_executable(&dir.path().join("agent"), &bytes_of(program));
        let socket = dir.path().join("agents.sock");
        let service = Service::up(&socket);
        let mut away = on(dir, apply_grace, Duration::ZERO);
        let health = next_health(&mut away.harness.events).await;
        assert_eq!(health.status, "running", "{health:?}");
        (away, service)
    }

    /// A Runner over `dir`'s `agent`, started through the second service on `dir`'s socket,
    /// keeping a predecessor for `retain_previous`.
    fn on(dir: tempfile::TempDir, apply_grace: Duration, retain_previous: Duration) -> Away {
        on_with(dir, apply_grace, retain_previous, None)
    }

    /// [`on`], proving a staged package with `preflight` first.
    fn on_with(
        dir: tempfile::TempDir,
        apply_grace: Duration,
        retain_previous: Duration,
        preflight: Option<Preflight>,
    ) -> Away {
        let binary = dir.path().join("agent");
        let install = InstallTarget::Binary(binary.clone());
        on_target(
            dir,
            install,
            binary,
            apply_grace,
            retain_previous,
            preflight,
        )
    }

    /// [`on_with`], installing into `install` and running `binary`.
    fn on_target(
        dir: tempfile::TempDir,
        install: InstallTarget,
        binary: PathBuf,
        apply_grace: Duration,
        retain_previous: Duration,
        preflight: Option<Preflight>,
    ) -> Away {
        let socket = dir.path().join("agents.sock");
        let (event_tx, events) = mpsc::channel(64);
        let (commands, command_rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown) = shutdown_channel();
        let live = binary.clone();
        let runner = Runner {
            endpoint_token: zeroize::Zeroizing::default(),
            name: "test".to_string(),
            stop_timeout: Duration::from_secs(5),
            apply_grace,
            retain_previous,
            install: Some(install),
            archive_key: None,
            version_probe: None,
            preflight,
            reload_signal: None,
            spawner: Spawner::Channel(Channel::new(&socket, own_uid(), this_process())),
            process_account_group: None,
            supervisor_dir: std::env::temp_dir(),
            events: EventSender::new(0, event_tx),
            commands: command_rx,
            build: Box::new(move || Some(spec(&live))),
        };
        let task = tokio::spawn(runner.run(shutdown));
        Away {
            dir,
            binary,
            socket,
            harness: Harness {
                commands,
                events,
                shutdown_tx,
                task,
                _service: None,
            },
        }
    }

    /// Hands the Runner a package of `bytes` as `version`, whose hash is the version's bytes.
    async fn offer(away: &Away, bytes: &[u8], version: &str) {
        let staged = away.dir.path().join(format!("downloaded-{version}"));
        std::fs::write(&staged, bytes).expect("stage");
        away.harness
            .commands
            .send(ProcessCommand::ApplyPackage {
                staged,
                version: version.to_string(),
                hash: version.as_bytes().to_vec(),
                span: tracing::Span::current(),
            })
            .await
            .expect("send");
    }

    /// Until the package of `bytes` is staged beside the program, waiting for the service.
    async fn staged_beside(away: &Away, bytes: &[u8]) {
        let staged = away.binary.with_extension("staged");
        tokio::time::timeout(Duration::from_secs(10), async {
            while std::fs::read(&staged).ok().as_deref() != Some(bytes) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the package is staged in time");
    }

    /// The outcomes of a package and a configuration, in whichever order they come.
    async fn both_outcomes(
        events: &mut mpsc::Receiver<(usize, ProcessEvent)>,
    ) -> (
        (Vec<u8>, Result<String, String>),
        (Vec<u8>, Result<(), String>),
    ) {
        let (mut package, mut config) = (None, None);
        while package.is_none() || config.is_none() {
            let (_, event) = tokio::time::timeout(Duration::from_secs(20), events.recv())
                .await
                .expect("an event in time")
                .expect("an open channel");
            match event {
                ProcessEvent::PackageApplied { hash, result } => {
                    assert!(package.is_none(), "a second package outcome");
                    package = Some((hash, result));
                }
                ProcessEvent::ConfigApplied { hash, result } => {
                    assert!(config.is_none(), "a second configuration outcome");
                    config = Some((hash, result));
                }
                _ => {}
            }
        }
        (package.expect("package"), config.expect("config"))
    }

    fn write_executable(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, bytes).expect("write");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    /// `stub_agent`, told apart from the program it replaces by bytes it never reads.
    fn another_build_of_the_agent() -> Vec<u8> {
        let mut bytes = bytes_of(&stub_agent());
        bytes.extend_from_slice(b"another build");
        bytes
    }

    /// Events until the next health, none of them an outcome of an apply.
    async fn next_health_and_no_outcome(
        events: &mut mpsc::Receiver<(usize, ProcessEvent)>,
        within: Duration,
    ) -> ComponentHealth {
        loop {
            let (_, event) = tokio::time::timeout(within, events.recv())
                .await
                .expect("an event in time")
                .expect("an open channel");
            match event {
                ProcessEvent::Health(health) => return health,
                ProcessEvent::ConfigApplied { result, .. } => {
                    panic!("a configuration reported while the second service is away: {result:?}")
                }
                ProcessEvent::PackageApplied { result, .. } => {
                    panic!("a package reported while the second service is away: {result:?}")
                }
                _ => {}
            }
        }
    }

    /// The second service goes, and the program with it: the Supervisor says so.
    async fn the_service_goes(away: &mut Away, service: Service) {
        service.stop().await;
        let gone = next_health(&mut away.harness.events).await;
        assert_eq!(gone.status, UNREACHABLE, "{gone:?}");
    }

    /// The start an apply makes does not reach the service: the Supervisor says so, and reports
    /// no outcome. That start waits out the reconnect window first.
    async fn the_apply_finds_it_away(away: &mut Away) {
        let health =
            next_health_and_no_outcome(&mut away.harness.events, Duration::from_secs(30)).await;
        assert_eq!(health.status, UNREACHABLE, "{health:?}");
        tokio::time::sleep(Duration::from_millis(300)).await;
        while let Ok((_, event)) = away.harness.events.try_recv() {
            assert!(
                !matches!(
                    event,
                    ProcessEvent::ConfigApplied { .. } | ProcessEvent::PackageApplied { .. }
                ),
                "an outcome reported while the second service is away: {event:?}"
            );
        }
    }

    /// For `span`, the program live is `bytes` at every look, and no apply reports an outcome.
    async fn stays_live(away: &mut Away, bytes: &[u8], span: Duration) {
        let until = tokio::time::Instant::now() + span;
        while tokio::time::Instant::now() < until {
            assert!(
                std::fs::read(&away.binary).ok().as_deref() == Some(bytes),
                "another program is live"
            );
            while let Ok((_, event)) = away.harness.events.try_recv() {
                assert!(
                    !matches!(
                        event,
                        ProcessEvent::ConfigApplied { .. } | ProcessEvent::PackageApplied { .. }
                    ),
                    "an outcome reported while the second service is away: {event:?}"
                );
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn shut_down(away: Away) {
        away.harness.shutdown_tx.send(true).expect("shutdown");
        tokio::time::timeout(Duration::from_secs(10), away.harness.task)
            .await
            .expect("the Runner ends on the shutdown")
            .expect("cleanly");
    }

    /// A package offered while the second service is away is staged and kept, never swapped in:
    /// what ran stays in place, and nothing is reported. Once the service is back it is swapped in
    /// and gated as its own start would have been — here it fails the grace, and is rolled back
    /// to the program that ran and reported `InstallFailed`.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_package_waits_staged_while_the_service_is_away_and_is_swapped_in_once_it_is_back() {
        let (mut away, service) = running(&stub_agent(), Duration::from_millis(500)).await;
        let good = bytes_of(&stub_agent());
        the_service_goes(&mut away, service).await;

        let staged = away.dir.path().join("downloaded.staged");
        std::fs::write(&staged, bytes_of(&stub_crasher())).expect("stage");
        away.harness
            .commands
            .send(ProcessCommand::ApplyPackage {
                staged,
                version: "9.9.9".to_string(),
                hash: b"9.9.9".to_vec(),
                span: tracing::Span::current(),
            })
            .await
            .expect("send");
        staged_beside(&away, &bytes_of(&stub_crasher())).await;
        // What ran stays in place, and nothing is reported.
        stays_live(&mut away, &good, Duration::from_secs(1)).await;

        let _service = Service::up(&away.socket);
        let (hash, result) = next_package_ack(&mut away.harness.events).await;
        assert_eq!(hash, b"9.9.9".to_vec());
        let error = result.expect_err("the package fails the grace once it runs");
        assert!(error.contains("apply grace"), "{error}");
        assert_eq!(
            std::fs::read(&away.binary).expect("read"),
            good,
            "rolled back once it failed"
        );
        shut_down(away).await;
    }

    /// [`a_package_waits_staged_while_the_service_is_away_and_is_swapped_in_once_it_is_back`] for a
    /// package that is a tree (ADR-0026 clause 58): staged beside what runs and kept, the whole
    /// previous tree in place while the service is away, and swapped in whole once it is back —
    /// here it survives its grace and is `Installed`.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_tree_package_waits_staged_while_the_service_is_away_and_is_swapped_in_once_it_is_back(
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("program");
        let inside = PathBuf::from("bin").join("agent");
        let live = root.join(TREE_DIR);
        let old = bytes_of(&stub_agent());
        std::fs::create_dir_all(live.join("bin")).expect("mkdir");
        write_executable(&live.join(&inside), &old);
        std::fs::create_dir_all(live.join("lib")).expect("mkdir");
        std::fs::write(live.join("lib/libagent.so"), b"v1-library").expect("write");
        let service = Service::up(&dir.path().join("agents.sock"));
        let install = InstallTarget::Tree {
            root: root.clone(),
            program_path: inside.clone(),
        };
        let mut away = on_target(
            dir,
            install,
            live.join(&inside),
            Duration::from_millis(500),
            Duration::ZERO,
            None,
        );
        let health = next_health(&mut away.harness.events).await;
        assert_eq!(health.status, "running", "{health:?}");
        the_service_goes(&mut away, service).await;

        let new = another_build_of_the_agent();
        let artifact = away.dir.path().join("agent-2.0.0.tar.gz");
        tar_gz(
            &artifact,
            &[
                ("agent-2.0.0/bin/agent".to_string(), new.clone()),
                (
                    "agent-2.0.0/lib/libagent.so".to_string(),
                    b"v2-library".to_vec(),
                ),
            ],
        );
        away.harness
            .commands
            .send(ProcessCommand::ApplyPackage {
                staged: artifact,
                version: "2.0.0".to_string(),
                hash: b"2.0.0".to_vec(),
                span: tracing::Span::current(),
            })
            .await
            .expect("send");
        let staging = root.join(".staging");
        tokio::time::timeout(Duration::from_secs(10), async {
            while std::fs::read(staging.join("lib/libagent.so"))
                .ok()
                .as_deref()
                != Some(b"v2-library".as_slice())
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the tree is staged in time");
        // What ran stays in place, the whole tree, and nothing is reported.
        stays_live(&mut away, &old, Duration::from_secs(1)).await;
        assert_eq!(
            std::fs::read(live.join("lib/libagent.so")).expect("the library"),
            b"v1-library"
        );

        let _service = Service::up(&away.socket);
        let (hash, result) = next_package_ack(&mut away.harness.events).await;
        assert_eq!(hash, b"2.0.0".to_vec());
        assert_eq!(result, Ok("2.0.0".to_string()));
        assert!(std::fs::read(live.join(&inside)).expect("the program") == new);
        assert_eq!(
            std::fs::read(live.join("lib/libagent.so")).expect("the library"),
            b"v2-library",
            "swapped in whole"
        );
        assert!(!staging.exists(), "staging does not survive");
        shut_down(away).await;
    }

    /// A retry that does not reach the second service never swaps the package that waits in, not
    /// even for the time it waits for the service: what ran is live throughout, so a Client that
    /// ends meanwhile, however it ends, leaves the program the record names.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_retry_without_the_service_never_puts_the_waiting_package_live() {
        let (mut away, service) = running(&stub_agent(), Duration::from_millis(500)).await;
        let old = bytes_of(&stub_agent());
        the_service_goes(&mut away, service).await;
        let new = another_build_of_the_agent();
        offer(&away, &new, "2.0.0").await;
        staged_beside(&away, &new).await;
        // The first retry is due within a second, and waits for the service for longer than this.
        stays_live(&mut away, &old, Duration::from_secs(3)).await;
        shut_down(away).await;
    }

    /// The predecessor a successful update retained (ADR-0026 clause 64) outlasts the retries a
    /// package that waits for the second service makes: one that does not reach the service sets
    /// nothing aside. The swap once the service is back replaces it, as any next update does.
    /// Verifies: ADR-0026, ADR-0059
    #[tokio::test]
    async fn a_retained_predecessor_outlasts_the_retries_while_a_package_waits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = bytes_of(&stub_agent());
        write_executable(&dir.path().join("agent"), &first);
        let service = Service::up(&dir.path().join("agents.sock"));
        let mut away = on(dir, Duration::from_millis(500), Duration::from_secs(3600));
        let health = next_health(&mut away.harness.events).await;
        assert_eq!(health.status, "running", "{health:?}");
        let second = another_build_of_the_agent();
        offer(&away, &second, "2.0.0").await;
        let (_, result) = next_package_ack(&mut away.harness.events).await;
        assert_eq!(result, Ok("2.0.0".to_string()));
        let backup = away.binary.with_extension("rollback");
        let marker = away.dir.path().join("agent.rollback.until");
        assert!(std::fs::read(&backup).expect("retained") == first);
        assert!(marker.exists(), "the window is recorded");

        the_service_goes(&mut away, service).await;
        let mut third = another_build_of_the_agent();
        third.extend_from_slice(b", and a third");
        offer(&away, &third, "3.0.0").await;
        staged_beside(&away, &third).await;
        // The first retry is due within a second, and waits for the service for longer than this.
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(
            std::fs::read(&backup).expect("still retained") == first,
            "a retry set the retained predecessor aside"
        );
        assert!(marker.exists(), "the window is kept");

        let _service = Service::up(&away.socket);
        let (hash, result) = next_package_ack(&mut away.harness.events).await;
        assert_eq!(hash, b"3.0.0".to_vec());
        assert_eq!(result, Ok("3.0.0".to_string()));
        assert!(std::fs::read(&away.binary).expect("read") == third);
        assert!(
            std::fs::read(&backup).expect("retained") == second,
            "the swap replaces the retained predecessor"
        );
        shut_down(away).await;
    }

    /// A configuration applied while the second service is away is reported `APPLIED` once the
    /// program has run on it, after the service is back, and not `FAILED` before.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_configuration_applied_while_the_service_is_away_is_gated_once_it_is_back() {
        let (mut away, service) = running(&stub_agent(), Duration::from_millis(500)).await;
        the_service_goes(&mut away, service).await;

        apply(&away.harness, b"cfg").await;
        the_apply_finds_it_away(&mut away).await;

        let _service = Service::up(&away.socket);
        let (hash, result) = next_ack(&mut away.harness.events).await;
        assert_eq!(hash, b"cfg".to_vec());
        assert_eq!(result, Ok(()));
        shut_down(away).await;
    }

    /// A configuration whose retry reaches the second service but whose program does not start —
    /// it is not there — is `FAILED`, as the apply itself would have been, and is not started
    /// again: a respawn is for a program that ran and exited within the grace (ADR-0026 clause
    /// 63), and a start that did not happen has nothing to respawn.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_retry_whose_program_does_not_start_fails_the_configuration_and_respawns_nothing() {
        let (mut away, service) = running(&stub_agent(), Duration::from_millis(500)).await;
        the_service_goes(&mut away, service).await;
        apply(&away.harness, b"cfg").await;
        the_apply_finds_it_away(&mut away).await;
        std::fs::remove_file(&away.binary).expect("remove the program");

        let _service = Service::up(&away.socket);
        let (hash, result) = next_ack(&mut away.harness.events).await;
        assert_eq!(hash, b"cfg".to_vec());
        let error = result.expect_err("the program did not start");
        assert!(error.contains("did not start"), "{error}");
        // A respawn would be due within a second.
        tokio::time::sleep(Duration::from_secs(3)).await;
        while let Ok((_, event)) = away.harness.events.try_recv() {
            assert!(
                !matches!(event, ProcessEvent::Health(_)),
                "a start after the configuration failed: {event:?}"
            );
        }
        shut_down(away).await;
    }

    /// The second service goes during a package's apply grace, and the program with it: the
    /// program rejected nothing, so the package is neither installed nor refused; it is taken back
    /// out to wait, what ran before is put back, and the swap once the service is back decides —
    /// here it survives, and is `Installed`.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_package_whose_service_goes_in_the_grace_is_gated_once_it_is_back() {
        let (mut away, service) = running(&stub_agent(), Duration::from_secs(3)).await;
        let new_bytes = another_build_of_the_agent();
        let staged = away.dir.path().join("downloaded.staged");
        std::fs::write(&staged, &new_bytes).expect("stage");
        away.harness
            .commands
            .send(ProcessCommand::ApplyPackage {
                staged,
                version: "2.0.0".to_string(),
                hash: b"2.0.0".to_vec(),
                span: tracing::Span::current(),
            })
            .await
            .expect("send");
        let started =
            next_health_and_no_outcome(&mut away.harness.events, Duration::from_secs(10)).await;
        assert_eq!(started.status, "running", "{started:?}");

        // Within the grace.
        service.stop().await;
        let gone =
            next_health_and_no_outcome(&mut away.harness.events, Duration::from_secs(10)).await;
        assert_eq!(gone.status, UNREACHABLE, "{gone:?}");
        staged_beside(&away, &new_bytes).await;
        assert_eq!(
            std::fs::read(&away.binary).expect("read"),
            bytes_of(&stub_agent()),
            "what ran before is put back"
        );

        let _service = Service::up(&away.socket);
        let (hash, result) = next_package_ack(&mut away.harness.events).await;
        assert_eq!(hash, b"2.0.0".to_vec());
        assert_eq!(result, Ok("2.0.0".to_string()));
        assert_eq!(
            std::fs::read(&away.binary).expect("read"),
            new_bytes,
            "not rolled back"
        );
        shut_down(away).await;
    }

    /// The second service goes during a configuration's apply grace: no `FAILED` for a program
    /// that went with the service; `APPLIED` once it has run on the configuration after.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_configuration_whose_service_goes_in_the_grace_is_gated_once_it_is_back() {
        let (mut away, service) = running(&stub_agent(), Duration::from_secs(3)).await;
        apply(&away.harness, b"cfg").await;
        let started =
            next_health_and_no_outcome(&mut away.harness.events, Duration::from_secs(10)).await;
        assert_eq!(started.status, "running", "{started:?}");

        service.stop().await;
        let gone =
            next_health_and_no_outcome(&mut away.harness.events, Duration::from_secs(10)).await;
        assert_eq!(gone.status, UNREACHABLE, "{gone:?}");

        let _service = Service::up(&away.socket);
        let (hash, result) = next_ack(&mut away.harness.events).await;
        assert_eq!(hash, b"cfg".to_vec());
        assert_eq!(result, Ok(()));
        shut_down(away).await;
    }

    /// A restart command while a configuration and a package wait for the second service respawns
    /// on the current files and does no more (ADR-0017 clause 8): its start, though it reaches the
    /// service, acknowledges nothing and swaps nothing in. The retry it makes due at once does
    /// both, with a start of its own that is gated.
    /// Verifies: ADR-0017, ADR-0059
    #[tokio::test]
    async fn a_restart_while_something_waits_only_respawns_and_the_retry_decides() {
        let (mut away, service) = running(&stub_agent(), Duration::from_millis(500)).await;
        the_service_goes(&mut away, service).await;
        apply(&away.harness, b"cfg").await;
        the_apply_finds_it_away(&mut away).await;
        let new = another_build_of_the_agent();
        offer(&away, &new, "2.0.0").await;
        staged_beside(&away, &new).await;
        // A retry finds the service away too; the next one is at least a second off.
        let again =
            next_health_and_no_outcome(&mut away.harness.events, Duration::from_secs(30)).await;
        assert_eq!(again.status, UNREACHABLE, "{again:?}");

        let _service = Service::up(&away.socket);
        away.harness
            .commands
            .send(ProcessCommand::Restart)
            .await
            .expect("send");
        let restarted =
            next_health_and_no_outcome(&mut away.harness.events, Duration::from_secs(10)).await;
        assert_eq!(restarted.status, "running", "{restarted:?}");
        let retried =
            next_health_and_no_outcome(&mut away.harness.events, Duration::from_secs(10)).await;
        assert_eq!(
            retried.status, "running",
            "the retry starts on its own: {retried:?}"
        );
        let ((package, installed), (config, applied)) =
            both_outcomes(&mut away.harness.events).await;
        assert_eq!(package, b"2.0.0".to_vec());
        assert_eq!(installed, Ok("2.0.0".to_string()));
        assert_eq!(config, b"cfg".to_vec());
        assert_eq!(applied, Ok(()));
        assert_eq!(std::fs::read(&away.binary).expect("read"), new);
        shut_down(away).await;
    }

    /// The second service goes during a package's apply grace, and the predecessor the package
    /// would be taken back out for cannot be put back — it is gone. The package stays live and is
    /// reported `InstallFailed`: `program/` is never left empty (ADR-0026 clause 62).
    /// Verifies: ADR-0026, ADR-0059
    #[tokio::test]
    async fn a_package_whose_predecessor_cannot_be_put_back_stays_live() {
        let (mut away, service) = running(&stub_agent(), Duration::from_secs(3)).await;
        let new = another_build_of_the_agent();
        offer(&away, &new, "2.0.0").await;
        let started =
            next_health_and_no_outcome(&mut away.harness.events, Duration::from_secs(10)).await;
        assert_eq!(started.status, "running", "{started:?}");
        std::fs::remove_file(away.binary.with_extension("rollback"))
            .expect("the predecessor is set aside");

        // Within the grace.
        service.stop().await;
        let (hash, result) = next_package_ack(&mut away.harness.events).await;
        assert_eq!(hash, b"2.0.0".to_vec());
        let error = result.expect_err("neither proved nor taken back out");
        assert!(error.contains("cannot restore"), "{error}");
        assert!(
            std::fs::read(&away.binary).ok() == Some(new),
            "program/ is left without the package"
        );
        assert!(!away.binary.with_extension("staged").exists());
        shut_down(away).await;
    }

    /// A first install whose start finds the service away is taken back out, and a second package
    /// offered meanwhile replaces it: once the service is back only the second is swapped in and
    /// gated, and the first, which never ran, is nobody's predecessor.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_newer_package_replaces_the_waiting_one_and_nothing_unrun_is_kept_to_go_back_to() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = Service::up(&dir.path().join("agents.sock"));
        let mut away = on(dir, Duration::from_millis(500), Duration::from_secs(3600));
        let health = next_health(&mut away.harness.events).await;
        assert_eq!(health.status, "no process installed", "{health:?}");
        service.stop().await;

        let first = bytes_of(&stub_agent());
        offer(&away, &first, "1.0.0").await;
        the_apply_finds_it_away(&mut away).await;
        staged_beside(&away, &first).await;
        assert!(!away.binary.exists(), "the first install is taken back out");

        let second = another_build_of_the_agent();
        offer(&away, &second, "2.0.0").await;
        staged_beside(&away, &second).await;

        let _service = Service::up(&away.socket);
        let (hash, result) = next_package_ack(&mut away.harness.events).await;
        assert_eq!(
            hash,
            b"2.0.0".to_vec(),
            "only the newer package is reported"
        );
        assert_eq!(result, Ok("2.0.0".to_string()));
        assert_eq!(std::fs::read(&away.binary).expect("read"), second);
        assert!(
            !away.binary.with_extension("rollback").exists(),
            "a program that never ran is kept to go back to"
        );
        assert!(!away.binary.with_extension("staged").exists());
        shut_down(away).await;
    }

    /// A Client that stops while a package waits leaves the program the record names, and nothing
    /// staged; offered again after the restart, the package installs over that program, which is
    /// then its predecessor.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_client_that_stops_while_a_package_waits_leaves_what_the_record_names() {
        let (mut away, service) = running(&stub_agent(), Duration::from_millis(500)).await;
        let old = bytes_of(&stub_agent());
        the_service_goes(&mut away, service).await;
        let new = another_build_of_the_agent();
        offer(&away, &new, "2.0.0").await;
        away.harness
            .commands
            .send(ProcessCommand::Shutdown)
            .await
            .expect("send");
        tokio::time::timeout(Duration::from_secs(30), &mut away.harness.task)
            .await
            .expect("the Runner ends on the shutdown")
            .expect("cleanly");
        assert_eq!(
            std::fs::read(&away.binary).expect("read"),
            old,
            "the program the record names"
        );
        assert!(!away.binary.with_extension("staged").exists());
        assert!(!away.binary.with_extension("rollback").exists());

        let Away { dir, .. } = away;
        let _service = Service::up(&dir.path().join("agents.sock"));
        let mut away = on(dir, Duration::from_millis(500), Duration::from_secs(3600));
        let health = next_health(&mut away.harness.events).await;
        assert_eq!(health.status, "running", "{health:?}");
        offer(&away, &new, "2.0.0").await;
        let (hash, result) = next_package_ack(&mut away.harness.events).await;
        assert_eq!(hash, b"2.0.0".to_vec());
        assert_eq!(result, Ok("2.0.0".to_string()));
        assert_eq!(std::fs::read(&away.binary).expect("read"), new);
        assert_eq!(
            std::fs::read(away.binary.with_extension("rollback")).expect("a predecessor"),
            old,
            "the predecessor is the program that ran"
        );
        shut_down(away).await;
    }

    /// A configuration owed its acknowledgement is decided by the start that reaches the service:
    /// where the waiting package that start swaps in fails its grace, by the start of the
    /// predecessor it is rolled back to, which survives — `APPLIED`, though the package failed.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_failed_package_does_not_fail_the_configuration_its_predecessor_runs() {
        let (mut away, service) = running(&stub_agent(), Duration::from_millis(500)).await;
        the_service_goes(&mut away, service).await;
        apply(&away.harness, b"cfg").await;
        the_apply_finds_it_away(&mut away).await;
        offer(&away, &bytes_of(&stub_crasher()), "9.9.9").await;
        staged_beside(&away, &bytes_of(&stub_crasher())).await;

        let _service = Service::up(&away.socket);
        let ((package, installed), (config, applied)) =
            both_outcomes(&mut away.harness.events).await;
        assert_eq!(package, b"9.9.9".to_vec());
        assert!(installed.is_err(), "{installed:?}");
        assert_eq!(config, b"cfg".to_vec());
        assert_eq!(applied, Ok(()), "decided by the predecessor's start");
        assert_eq!(
            std::fs::read(&away.binary).expect("read"),
            bytes_of(&stub_agent())
        );
        shut_down(away).await;
    }

    /// A swap that fails before anything starts decides no configuration: the program that stays
    /// in place is started, and its start acknowledges the configuration.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_swap_that_fails_before_a_start_does_not_fail_the_configuration() {
        let (mut away, service) = running(&stub_agent(), Duration::from_millis(500)).await;
        the_service_goes(&mut away, service).await;
        apply(&away.harness, b"cfg").await;
        the_apply_finds_it_away(&mut away).await;
        // The predecessor's name is taken by a directory that cannot be removed as a file, so the
        // swap cannot set the program aside.
        let blocker = away.binary.with_extension("rollback");
        std::fs::create_dir(&blocker).expect("mkdir");
        std::fs::write(blocker.join("keep"), b"x").expect("write");
        let new = another_build_of_the_agent();
        offer(&away, &new, "2.0.0").await;
        staged_beside(&away, &new).await;

        let _service = Service::up(&away.socket);
        let ((package, installed), (config, applied)) =
            both_outcomes(&mut away.harness.events).await;
        assert_eq!(package, b"2.0.0".to_vec());
        let error = installed.expect_err("the swap fails");
        assert!(error.contains("aside"), "{error}");
        assert_eq!(config, b"cfg".to_vec());
        assert_eq!(
            applied,
            Ok(()),
            "decided by the start of what stayed in place"
        );
        assert_eq!(
            std::fs::read(&away.binary).expect("read"),
            bytes_of(&stub_agent())
        );
        shut_down(away).await;
    }

    /// A second service that is reached and refused — here its socket is served by another
    /// account than the process account — is what the Supervisor's health names while a
    /// configuration and a package wait for it, and so what the Agent names as their reason.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn what_waits_for_a_refused_service_names_the_refusal() {
        const REFUSED: &str =
            "the second service is refused: another account, another build, or it refuses this Client";
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = dir.path().join("agent");
        write_executable(&binary, &bytes_of(&stub_agent()));
        let socket = dir.path().join("agents.sock");
        let _service = Service::up(&socket);
        let (event_tx, mut events) = mpsc::channel(64);
        let (commands, command_rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown) = shutdown_channel();
        let live = binary.clone();
        let runner = Runner {
            endpoint_token: zeroize::Zeroizing::default(),
            name: "test".to_string(),
            stop_timeout: Duration::from_secs(5),
            apply_grace: Duration::from_millis(500),
            retain_previous: Duration::ZERO,
            install: Some(InstallTarget::Binary(binary.clone())),
            archive_key: None,
            version_probe: None,
            preflight: None,
            reload_signal: None,
            // The process account is another uid than the one that serves the socket.
            spawner: Spawner::Channel(Channel::new(&socket, own_uid() + 1, this_process())),
            process_account_group: None,
            supervisor_dir: std::env::temp_dir(),
            events: EventSender::new(0, event_tx),
            commands: command_rx,
            build: Box::new(move || Some(spec(&live))),
        };
        let task = tokio::spawn(runner.run(shutdown));
        // A refusal is met again until the reconnect window ends.
        let health = next_health_and_no_outcome(&mut events, Duration::from_secs(30)).await;
        assert_eq!(health.status, REFUSED, "{health:?}");

        commands
            .send(ProcessCommand::ApplyConfig {
                config: AgentRemoteConfig {
                    config_hash: b"cfg".to_vec(),
                    ..Default::default()
                },
                span: tracing::Span::current(),
            })
            .await
            .expect("send");
        let health = next_health_and_no_outcome(&mut events, Duration::from_secs(30)).await;
        assert_eq!(health.status, REFUSED, "{health:?}");
        let staged = dir.path().join("downloaded");
        std::fs::write(&staged, another_build_of_the_agent()).expect("stage");
        commands
            .send(ProcessCommand::ApplyPackage {
                staged,
                version: "2.0.0".to_string(),
                hash: b"2.0.0".to_vec(),
                span: tracing::Span::current(),
            })
            .await
            .expect("send");
        let health = next_health_and_no_outcome(&mut events, Duration::from_secs(30)).await;
        assert_eq!(health.status, REFUSED, "{health:?}");
        shutdown_tx.send(true).expect("shutdown");
        tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("the Runner ends on the shutdown")
            .expect("cleanly");
    }

    /// The preflight runs through the second service (ADR-0059 clause 3): a package offered while
    /// the service is away is staged unchecked and waits, and once the service is back the
    /// preflight runs before the swap — here it passes, and the package is installed.
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_package_whose_preflight_found_the_service_away_is_checked_once_it_is_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_executable(&dir.path().join("agent"), &bytes_of(&stub_agent()));
        let service = Service::up(&dir.path().join("agents.sock"));
        let preflight = Preflight {
            args: vec!["--version".to_string()],
            env: Vec::new(),
        };
        let mut away = on_with(
            dir,
            Duration::from_millis(500),
            Duration::ZERO,
            Some(preflight),
        );
        let health = next_health(&mut away.harness.events).await;
        assert_eq!(health.status, "running", "{health:?}");
        the_service_goes(&mut away, service).await;

        let new = another_build_of_the_agent();
        offer(&away, &new, "2.0.0").await;
        staged_beside(&away, &new).await;
        let _service = Service::up(&away.socket);
        let (hash, result) = next_package_ack(&mut away.harness.events).await;
        assert_eq!(hash, b"2.0.0".to_vec());
        assert_eq!(result, Ok("2.0.0".to_string()));
        shut_down(away).await;
    }

    /// A package that waited for the second service without its preflight is refused by the
    /// preflight that runs once the service is back, before anything is stopped: it is reported
    /// failed, and what ran stays in place (ADR-0059 clause 3, ADR-0017 clause 57).
    /// Verifies: ADR-0059
    #[tokio::test]
    async fn a_package_whose_preflight_found_the_service_away_is_refused_once_it_is_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let old = bytes_of(&stub_agent());
        write_executable(&dir.path().join("agent"), &old);
        let service = Service::up(&dir.path().join("agents.sock"));
        // The stub exits with the code it is given: every staged program fails this preflight.
        let preflight = Preflight {
            args: vec!["--exit-code".to_string(), "3".to_string()],
            env: Vec::new(),
        };
        let mut away = on_with(
            dir,
            Duration::from_millis(500),
            Duration::ZERO,
            Some(preflight),
        );
        let health = next_health(&mut away.harness.events).await;
        assert_eq!(health.status, "running", "{health:?}");
        the_service_goes(&mut away, service).await;

        let new = another_build_of_the_agent();
        offer(&away, &new, "2.0.0").await;
        staged_beside(&away, &new).await;
        let _service = Service::up(&away.socket);
        let (hash, result) = next_package_ack(&mut away.harness.events).await;
        assert_eq!(hash, b"2.0.0".to_vec());
        let refused = result.expect_err("the preflight refuses it");
        assert!(refused.contains("does not run on this host"), "{refused}");
        assert_eq!(
            std::fs::read(&away.binary).expect("the program"),
            old,
            "what ran stays in place"
        );
        assert!(
            !away.binary.with_extension("staged").exists(),
            "the refused package is thrown away"
        );
        shut_down(away).await;
    }
}
