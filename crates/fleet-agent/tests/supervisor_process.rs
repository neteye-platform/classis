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
use fleet_agent::shutdown::shutdown_channel;
use fleet_agent::supervisor::ports::{EventSender, InstallTarget, ProcessCommand, ProcessEvent};
use fleet_agent::supervisor::process::{
    probe_version, Preflight, ProcessSpec, Runner, VersionProbe,
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

struct Harness {
    commands: mpsc::Sender<ProcessCommand>,
    events: mpsc::Receiver<(usize, ProcessEvent)>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

/// A `Runner` with everything the test does not care about filled in. `install` and `apply_grace`
/// are what the package tests vary; `version_probe` is set only where the probe is the subject.
fn runner(
    install: Option<InstallTarget>,
    apply_grace: Duration,
    version_probe: Option<VersionProbe>,
    build: impl Fn() -> Option<ProcessSpec> + Send + Sync + 'static,
) -> Harness {
    runner_retaining(install, apply_grace, Duration::ZERO, version_probe, build)
}

fn runner_retaining(
    install: Option<InstallTarget>,
    apply_grace: Duration,
    retain_previous: Duration,
    version_probe: Option<VersionProbe>,
    build: impl Fn() -> Option<ProcessSpec> + Send + Sync + 'static,
) -> Harness {
    runner_full(
        install,
        apply_grace,
        retain_previous,
        version_probe,
        None,
        None,
        build,
    )
}

fn runner_full(
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
        endpoint_token: String::new(),
        name: "test".to_string(),
        stop_timeout: Duration::from_secs(5),
        apply_grace,
        retain_previous,
        install,
        archive_key: None,
        version_probe,
        preflight,
        reload_signal,
        events: EventSender::new(0, event_tx),
        commands: command_rx,
        build: Box::new(build),
    };
    Harness {
        commands,
        events,
        shutdown_tx,
        task: tokio::spawn(runner.run(shutdown)),
    }
}

/// Zero grace: the pre-grace instant acknowledgement most supervision tests exercise.
fn start(build: impl Fn() -> Option<ProcessSpec> + Send + Sync + 'static) -> Harness {
    runner(None, Duration::ZERO, None, build)
}

fn start_with_grace(
    apply_grace: Duration,
    build: impl Fn() -> Option<ProcessSpec> + Send + Sync + 'static,
) -> Harness {
    runner(None, apply_grace, None, build)
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
#[tokio::test]
async fn the_directories_an_agent_writes_into_are_made_before_it_runs() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Two levels deep and nested under a parent that does not exist either, because the failure
    // this prevents is exactly the one nobody created a parent for.
    let state = dir.path().join("agent-state").join("inventory");
    let program = PathBuf::from(env!("CARGO_BIN_EXE_stub_agent"));
    let marker = dir.path().join("started");
    assert!(!state.exists());

    let mut harness = start({
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

/// A program named by a **relative** path starts, though the process begins in its own directory
/// (ADR-0017).
///
/// `Command` does `chdir` *before* `exec` on Unix, so a relative program is resolved against the
/// directory it was just moved into: `<dir>/<dir>/<program>`, which is nothing. The Client's own
/// default makes this the ordinary case rather than a corner — `state_dir = "client-state"` is
/// relative, so every Managed Process under a default configuration would fail to spawn, with a
/// bare `No such file or directory` naming a file that is plainly there.
#[tokio::test]
async fn a_program_named_by_a_relative_path_still_starts_in_its_own_directory() {
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
    let mut harness = start({
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

// ── The version probe ────────────────────────────────────────────────────────

#[tokio::test]
async fn the_probe_reports_a_version_description() {
    let (event_tx, mut events) = mpsc::channel(4);
    probe_version(
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
        PathBuf::from("nonexistent-definitely-not-here"),
        vec![],
        None,
        EventSender::new(0, event_tx.clone()),
    )
    .await;
    // Runs, says nothing a version can be read out of, and exits: a Foreign Agent whose version
    // flag is not the one the operator configured.
    probe_version(
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
#[tokio::test]
async fn a_swapped_binary_is_probed_again_for_its_version() {
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
/// a test that compares the marker across a package apply must have one to compare.
async fn wait_until_started(marker: &Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !marker.exists() {
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
#[tokio::test]
async fn the_managed_process_is_handed_the_endpoint_token() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("running");
    let program = stub_agent();
    let marker_arg = marker.display().to_string();
    let (event_tx, _events) = mpsc::channel(64);
    let (_commands, command_rx) = mpsc::channel(16);
    let (_shutdown_tx, shutdown) = shutdown_channel();
    let runner = Runner {
        endpoint_token: "the-token".to_string(),
        name: "test".to_string(),
        stop_timeout: Duration::from_secs(5),
        apply_grace: Duration::ZERO,
        retain_previous: Duration::ZERO,
        install: None,
        archive_key: None,
        version_probe: None,
        preflight: None,
        reload_signal: None,
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
    let task = tokio::spawn(runner.run(shutdown));
    wait_until_started(&marker).await;
    let text = std::fs::read_to_string(&marker).expect("marker");
    assert!(text.contains("token=the-token\n"), "{text}");
    task.abort();
}

/// A kind that declared a reload applies a configuration in place (ADR-0017): the process is
/// signalled, survives the grace, and the apply is acknowledged without a restart — the process
/// that was running is still the one running.
#[cfg(unix)]
#[tokio::test]
async fn a_declared_reload_applies_without_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("started");
    let marker_arg = marker.clone();
    let mut harness = runner_full(
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

/// `reload-or-restart` (ADR-0017): a process that dies on its reload signal — the stub without
/// `--ignore-hup` keeps SIGHUP's default disposition, termination — is restarted on the new
/// files, and the apply is acknowledged from that restart rather than failed.
// Verifies: ADR-0017
#[cfg(unix)]
#[tokio::test]
async fn a_process_that_dies_on_the_reload_signal_is_restarted_instead() {
    let mut harness = runner_full(
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

/// The generic uninstall (ADR-0017): the graceful stop plus the answer, which is the adapter's
/// last event — the adapter exits on the command itself, no shutdown ever fired. The answer
/// coming last is what lets the core purge the directory only after the kind is done (ADR-0017).
#[tokio::test]
async fn an_uninstall_stops_the_process_answers_and_exits() {
    let mut harness = start(|| Some(spec(&stub_agent())));
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

// ── Supervision ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_long_running_process_reports_healthy_and_stops_on_shutdown() {
    let mut harness = start(|| Some(spec(&stub_agent())));
    let health = next_health(&mut harness.events).await;
    assert!(health.healthy);
    harness.shutdown_tx.send(true).expect("signal shutdown");
    tokio::time::timeout(Duration::from_secs(10), harness.task)
        .await
        .expect("the runner exits in time")
        .expect("no panic");
}

#[tokio::test]
async fn an_exiting_process_turns_unhealthy_and_is_restarted() {
    let mut harness = start(|| Some(spec(&stub_crasher())));
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

/// A Supervisor whose program is not on the machine keeps running and says so. The wording is the
/// point: what the Server should read is the situation — there is no process — not the syscall that
/// reported it. This is the state a failed *first* install leaves behind, once the artifact it could
/// not run has been removed again.
#[tokio::test]
async fn a_missing_program_is_reported_as_no_process_not_fatal() {
    let mut harness = start(|| Some(spec(Path::new("nonexistent-definitely-not-here"))));
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

/// A program that exists but cannot be executed is a different situation, and keeps the wording
/// that describes it. Unix says so through the mode, Windows through the file not being a program
/// at all; both reach the same branch, which is what this asserts.
#[tokio::test]
async fn an_unexecutable_program_is_reported_as_a_spawn_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let program = dir.path().join(program_name("not-executable"));
    std::fs::write(&program, b"data").expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    }

    let mut harness = start(move || Some(spec(&program)));
    let health = next_health(&mut harness.events).await;
    assert!(!health.healthy);
    assert_eq!(health.status, "spawn failed");
    harness.shutdown_tx.send(true).expect("signal shutdown");
    let _ = harness.task.await;
}

#[tokio::test]
async fn nothing_to_run_reports_awaiting_configuration() {
    let mut harness = start(|| None);
    let health = next_health(&mut harness.events).await;
    assert!(!health.healthy);
    assert_eq!(health.status, "awaiting configuration");
    harness.shutdown_tx.send(true).expect("signal shutdown");
    let _ = harness.task.await;
}

// ── The health-gated configuration apply ─────────────────────────────────────

#[tokio::test]
async fn a_process_surviving_the_apply_grace_is_acknowledged_applied() {
    let mut harness = start_with_grace(Duration::from_millis(200), || Some(spec(&stub_agent())));
    apply(&harness, b"h1").await;
    let (hash, result) = next_ack(&mut harness.events).await;
    assert_eq!(hash, b"h1".to_vec());
    assert!(result.is_ok(), "survived the grace: {result:?}");
    harness.shutdown_tx.send(true).expect("signal shutdown");
    let _ = harness.task.await;
}

#[tokio::test]
async fn a_process_exiting_within_the_grace_fails_the_apply_and_stays_supervised() {
    let mut harness = start_with_grace(Duration::from_millis(500), || Some(spec(&stub_crasher())));
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

#[tokio::test]
async fn shutdown_during_the_grace_stops_promptly_without_an_ack() {
    let mut harness = start_with_grace(Duration::from_secs(600), || Some(spec(&stub_agent())));
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

#[tokio::test]
async fn a_restart_command_cycles_the_process_without_a_config_ack() {
    let mut harness = start(|| Some(spec(&stub_agent())));
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

#[tokio::test]
async fn apply_config_restarts_and_acknowledges() {
    let mut harness = start(|| Some(spec(&stub_agent())));
    let _ = next_health(&mut harness.events).await;

    apply(&harness, b"h1").await;

    let (hash, result) = next_ack(&mut harness.events).await;
    assert_eq!(hash, b"h1".to_vec());
    assert!(result.is_ok(), "{result:?}");
    harness.shutdown_tx.send(true).expect("signal shutdown");
    let _ = harness.task.await;
}

// ── The binary swap (ADR-0026) ───────────────────────────────────────────────

/// A Runner that swaps one file and runs whatever is at it.
fn binary_harness(binary: &Path, apply_grace: Duration) -> Harness {
    let program = binary.to_path_buf();
    runner(
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
#[tokio::test]
async fn a_package_that_cannot_run_here_is_refused_without_stopping_what_runs() {
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

/// Verifies: ADR-0026
#[tokio::test]
async fn apply_package_swaps_the_binary_and_acknowledges_installed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join(program_name("agent"));
    // The host holds a program that will not stay up — the situation a package is sent to fix, and
    // what makes the assertion below say something: the bytes on disk afterwards are not the ones
    // that were there before.
    std::fs::write(&binary, bytes_of(&stub_crasher())).expect("write");
    let mut harness = binary_harness(&binary, Duration::from_millis(200));
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

/// The case ADR-0026 exists for: what upstream publishes is a `.tar.gz`, not a bare binary. The
/// Supervisor takes the member named after its own binary and installs that.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_package_delivered_as_a_tar_gz_is_unpacked_and_installed() {
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

    let mut harness = binary_harness(&binary, Duration::from_millis(200));
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

/// Bringing a host into the fleet the other way round: the Supervisor is configured, the program is
/// not installed yet, and the Server delivers it. A plugin with nothing to run — a Collector
/// awaiting its configuration — must not turn that into a failed install, which would delete the
/// binary that was just put in place.
/// Verifies: ADR-0026
#[tokio::test]
async fn an_install_with_nothing_to_run_yet_keeps_the_binary_and_succeeds() {
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

// Verifies: ADR-0026, G-10
#[tokio::test]
async fn a_package_that_will_not_stay_up_is_rolled_back_and_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join(program_name("agent"));
    let good = bytes_of(&stub_agent());
    std::fs::write(&binary, &good).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    let mut harness = binary_harness(&binary, Duration::from_millis(500));
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

/// ADR-0026: a *first* install that will not start has nothing to roll back to, so it is **kept**
/// rather than discarded — the verified binary stays in `program/`. Discarding it would empty the
/// directory and set the Server re-offering the same artifact in a loop.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_first_install_that_will_not_start_is_kept_not_discarded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join(program_name("agent"));
    // Nothing on disk yet: a first install onto an empty program directory.
    let mut harness = binary_harness(&binary, Duration::from_millis(200));

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

/// ADR-0026: a program that keeps failing to start is **held** after a few tries, not restarted
/// forever — the loop that hammered the Server with re-downloads is bounded. A held Supervisor
/// reports it plainly.
// Verifies: ADR-0026
#[tokio::test]
async fn a_program_that_keeps_crashing_is_held_not_looped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join(program_name("agent"));
    let mut harness = binary_harness(&binary, Duration::from_millis(100));

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

/// ADR-0026: a successful update does not delete the version it superseded — it is retained for the
/// window, with a marker recording the deadline, so an operator has a fallback.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_successful_update_keeps_the_previous_version_for_the_window() {
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
fn tree_harness(root: &Path) -> Harness {
    let inside = PathBuf::from("bin").join(program_name("agent"));
    let program = root.join(TREE_DIR).join(&inside);
    runner(
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
#[tokio::test]
async fn a_tree_package_lands_whole_and_replaces_the_one_before_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("program");
    std::fs::create_dir_all(&root).expect("create the program directory");

    let first = dir.path().join("agent-1.0.0.tar.gz");
    tree_release(&first, "agent-1.0.0", &stub_agent(), b"v1-library");
    let mut harness = tree_harness(&root);
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

/// The health gate, one level up: a tree whose program will not stay up puts the *whole* previous
/// tree back — libraries included, since half of each would run nothing.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_tree_that_will_not_stay_up_is_rolled_back_whole() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("program");
    std::fs::create_dir_all(&root).expect("create the program directory");

    let good = dir.path().join("agent-1.0.0.tar.gz");
    tree_release(&good, "agent-1.0.0", &stub_agent(), b"v1-library");
    let mut harness = tree_harness(&root);
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

/// The archive names a member the configuration does not — refused, with the old tree left exactly
/// where it was.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_tree_missing_the_configured_program_is_refused_and_changes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("program");
    std::fs::create_dir_all(&root).expect("create the program directory");

    let good = dir.path().join("agent-1.0.0.tar.gz");
    tree_release(&good, "agent-1.0.0", &stub_agent(), b"v1-library");
    let mut harness = tree_harness(&root);
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
    let mut harness = binary_harness(&binary, Duration::from_millis(200));
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
